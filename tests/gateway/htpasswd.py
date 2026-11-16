#!/usr/bin/env python3
"""`auth basic users=FILE` with htpasswd's bcrypt lines ($2b$, $2y$), on one
engine (argument), checked by okena-bcrypt, not a worker: the right password
gets in (its name to the backend), a wrong one and an unknown name get 401;
passwords of 72 bytes, UTF-8, empty; the old salted SHA-256 lines beside
them; a repeat answered from the shared table; twenty at once; while a
costly check runs, the worker serves other requests at once; a flood of
wrong passwords costs okena-bcrypt, the worker stays quick; a reload;
costs out of range refused."""
import base64
import http.client
import http.server
import hashlib
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import bcrypt
except ImportError:
    print("skip bcrypt: no bcrypt package")
    sys.exit(0)

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 26600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = (self.headers.get("x-user-id") or "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def get(path, user=None, pw=None, timeout=10):
    c = http.client.HTTPConnection("127.0.0.1", L, timeout=timeout)
    h = {}
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(user.encode() + b":" + pw).decode()
    t0 = time.time()
    c.request("GET", path, headers=h)
    r = c.getresponse()
    b = r.read().decode(errors="replace")
    c.close()
    return r.status, b, time.time() - t0


s = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=s.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
P72 = b"x" * 70 + b"yz"
users = {
    "alice": (b"correct horse", 4, "2b"),
    "bob": ("pässwörd ✓".encode(), 5, "2y"),
    "long": (P72, 4, "2b"),
    "empty": (b"", 4, "2b"),
    "slow": (b"slowpass", 12, "2b"),
}
lines = []
for name, (pw, cost, v) in users.items():
    h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=cost)).decode()
    lines.append(f"{name}:${v}$" + h[4:])
salt = "0011aabb"
lines.append(f"old:{salt}:" + hashlib.sha256(salt.encode() + b"oldpass").hexdigest())
(tmp / "users").write_text("# htpasswd -B\n" + "\n".join(lines) + "\n")
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 1; io_engine {ENGINE}; admin unix:{tmp}/admin.sock; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    route /private/* {{ auth basic users={tmp}/users realm=t; to 127.0.0.1:{BACK} }}
    route /open {{ respond 200 "open" }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    r = get("/private/a", "alice", b"correct horse")
    check("$2b$: the right password gets in, its name to the backend", r[:2] == (200, "alice"), str(r))
    r = get("/private/a", "alice", b"correct horsf")
    check("  a wrong one: 401", r[0] == 401, str(r))
    r = get("/private/a", "nobody", b"correct horse")
    check("  an unknown name: 401", r[0] == 401, str(r))
    r = get("/private/a", "bob", "pässwörd ✓".encode())
    check("$2y$ and a UTF-8 password", r[:2] == (200, "bob"), str(r))
    check("72 bytes", get("/private/a", "long", P72)[:2] == (200, "long"))
    check("  what bcrypt reads of it: 72 bytes; one less is not it", get("/private/a", "long", P72[:71])[0] == 401)
    check("an empty password", get("/private/a", "empty", b"")[:2] == (200, "empty"))
    check("the salted SHA-256 lines beside them", get("/private/a", "old", b"oldpass")[:2] == (200, "old")
          and get("/private/a", "old", b"x")[0] == 401)
    with ThreadPoolExecutor(20) as ex:
        res = list(ex.map(lambda _: get("/private/b", "bob", "pässwörd ✓".encode())[0], range(20)))
    check("twenty at once", res == [200] * 20, str(res))
    # a costly check (cost 12) while the worker serves something else
    th = ThreadPoolExecutor(1).submit(get, "/private/s", "slow", b"slowpass")
    time.sleep(0.02)
    quick = [get("/open")[2] for _ in range(10)]
    r = th.result()
    check("cost 12: in, and meanwhile the worker answers at once", r[:2] == (200, "slow") and max(quick) < r[2] / 3,
          f"{r} {[round(x, 3) for x in quick]}")
    t = [get("/private/s", "slow", b"slowpass")[2] for _ in range(5)]
    check("  a repeat: from the shared table, not bcrypt again", max(t) < r[2] / 3, f"{r[2]:.3f} {[round(x, 3) for x in t]}")
    with ThreadPoolExecutor(60) as ex:
        futs = [ex.submit(get, "/private/f", "alice", b"wrong%d" % i) for i in range(300)]
        quick = [get("/open")[2] for _ in range(10)]
        codes = [f.result()[0] for f in futs]
    check("a flood of wrong passwords: 401 or 503, never in; the worker stays quick",
          set(codes) <= {401, 503} and max(quick) < 0.25, f"{sorted(set(codes))} {[round(x, 3) for x in quick]}")
    q = subprocess.run([str(BIN), "reload", "-c", str(conf)], capture_output=True, text=True, timeout=30)
    r = get("/private/a", "alice", b"correct horse")
    check("after a reload", q.returncode == 0 and r[:2] == (200, "alice"), q.stdout + q.stderr + str(r))
    for cost in ("03", "17"):
        bad = tmp / "bad"
        bad.write_text("x:$2b$" + cost + "$" + "a" * 53 + "\n")
        c2 = tmp / "c2.conf"
        c2.write_text(f"http 127.0.0.1:1 {{ route / {{ auth basic users={bad} realm=t; respond 200 }} }}\n")
        q = subprocess.run([str(BIN), "check", str(c2)], capture_output=True, text=True, timeout=10)
        check(f"cost {cost}: refused", q.returncode != 0 and "cost" in q.stderr, q.stderr[-200:])
    log.seek(0)
    t = log.read()
    check("no crash", "killed by signal" not in t and "okena-bcrypt exited" not in t, t[-500:])
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read()[-2000:])
print(f"bcrypt ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
