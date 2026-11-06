#!/usr/bin/env python3
"""`auth` on a route, on one engine (argument): who gets in, and what can go wrong
with it: a forged identity, a credential reaching the backend, keys in the clear
in memory, an unknown name, each protocol."""
import base64
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 32000 + os.getpid() % 70 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
failures = 0
seen = []
KEY = "k3y-of-alice-" + os.urandom(8).hex()
UNSENT = "never-sent-" + os.urandom(8).hex()		# so it can only be in memory from the file


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen.append({k.lower(): v for k, v in self.headers.items()})
        seen[-1]["all-ids"] = [v for k, v in self.headers.items() if k.lower() in ("x-user-id", "x-who")]
        b = json.dumps(seen[-1]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def get(path, headers=None, conn=None):
    c = conn or http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    b = r.read()
    if conn is None:
        c.close()
    return r, b


def basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


CONF = """okena {{ workers 2; io_engine {engine} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys }}
}}
http 127.0.0.1:{lst} {{
    route /key {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys }}
    route /fwd {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys forward=on }}
    route /who {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys identity=x-who }}
    route /basic {{ to 127.0.0.1:{back}; auth basic users={tmp}/users realm=staff }}
    route /lim {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys; limit 1/h burst=2 key=auth.user }}
    route /cors {{ to 127.0.0.1:{back}; auth api_key header=x-api-key keys={tmp}/keys; cors origins=https://a.test }}
    route /open {{ to 127.0.0.1:{back} }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-auth-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=a.test",
                    "-addext", "subjectAltName=DNS:a.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    (tmp / "keys").write_text(f"# partners\nalice:{KEY}\nbob:second-key\r\ncarol:{UNSENT}\n\n")
    salt = "s4lt"
    (tmp / "users").write_text(f"ann:{salt}:{hashlib.sha256((salt + 'pass word:1').encode()).hexdigest()}\n")
    http.server.ThreadingHTTPServer.request_queue_size = 64
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    text = CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp)
    conf.write_text(text)
    p = subprocess.Popen(["timeout", "--foreground", "30", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        r, b = get("/key", {"x-api-key": KEY})
        h = json.loads(b)
        check("a good key: through, who it is told", r.status == 200 and h.get("x-user-id") == "alice", str(h))
        check("  the key itself stays here", "x-api-key" not in h, str(h))
        check("  a line with CRLF too", get("/key", {"x-api-key": "second-key"})[0].status == 200)
        n = len(seen)
        for bad in (None, "", "wrong", KEY[:-1], KEY + "x", KEY.upper(), "# partners", "alice"):
            r, _ = get("/key", {"x-api-key": bad} if bad is not None else {})
            check(f"key {bad!r:.24}: 401, with how", r.status == 401 and r.getheader("www-authenticate") == "ApiKey"
                  and bool(r.getheader("x-request-id")), f"{r.status} {r.getheaders()}")
        check("  the backend hears of none", len(seen) == n, str(len(seen) - n))
        r, b = get("/key", {"x-api-key": KEY, "X-User-Id": "root", "x-user-id": "admin"})
        h = json.loads(b)
        check("a forged x-user-id: gone, the real one alone in its place", h["all-ids"] == ["alice"], str(h))
        r, _ = get("/key", {"x-user-id": "alice"})
        check("  and it opens nothing", r.status == 401, str(r.status))
        r, b = get("/who", {"x-api-key": KEY, "x-who": "root"})
        check("identity=: another field, the same way", json.loads(b)["all-ids"] == ["alice"], str(b))
        r, b = get("/fwd", {"x-api-key": KEY})
        check("forward=on: the key goes on", json.loads(b).get("x-api-key") == KEY, str(b))
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        r1, _ = get("/key", {"x-api-key": "wrong"}, c)
        s1 = c.sock
        r2, _ = get("/key", {"x-api-key": KEY}, c)
        check("a 401 keeps the connection", r1.status == 401 and r2.status == 200 and c.sock is s1, f"{r1.status} {r2.status}")
        c.close()
        r, b = get("/basic", basic("ann", "pass word:1"))
        h = json.loads(b)
        check("basic: through, its password holding a colon", r.status == 200 and h.get("x-user-id") == "ann", str(h))
        check("  Authorization stays here", "authorization" not in h, str(h))
        for name, hdr in (("wrong password", basic("ann", "x")), ("unknown name", basic("zed", "pass word:1")),
                          ("empty password", basic("ann", "")), ("no colon", {"Authorization": "Basic " + base64.b64encode(b"ann").decode()}),
                          ("not base64", {"Authorization": "Basic @@@@"}), ("another scheme", {"Authorization": "Bearer x"}),
                          ("nothing", {}), ("too long", basic("ann", "x" * 5000))):
            r, _ = get("/basic", hdr)
            check(f"basic, {name}: 401", r.status == 401 and r.getheader("www-authenticate", "").startswith('Basic realm="staff"'),
                  f"{r.status} {r.getheaders()}")
        rs = [get("/lim", {"x-api-key": KEY})[0].status for _ in range(3)]
        q = get("/lim", {"x-api-key": "second-key"})[0].status
        check("limit key=auth.user: each one their own", rs == [200, 200, 429] and q == 200, f"{rs} {q}")
        r, _ = get("/cors", {"Origin": "https://a.test"})
        check("a 401 a script can read", r.status == 401 and r.getheader("access-control-allow-origin") == "https://a.test", str(r.getheaders()))
        r = get("/cors", {"Origin": "https://a.test", "Access-Control-Request-Method": "GET"})
        pre = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        pre.request("OPTIONS", "/cors", headers={"Origin": "https://a.test", "Access-Control-Request-Method": "GET"})
        x = pre.getresponse()
        x.read()
        pre.close()
        check("a preflight needs no credential", x.status == 204, str(x.status))
        check("a route without it: as ever", json.loads(get("/open", {"x-user-id": "me"})[1]).get("x-user-id") == "me")
        for proto, flag in (("h1", "--http1.1"), ("h2", "--http2"), ("h3", "--http3-only")):
            def curl(*a):
                return subprocess.run(["timeout", "6", "curl", "-sk", flag, "--resolve", f"a.test:{TLS}:127.0.0.1",
                                       f"https://a.test:{TLS}/x", "-w", "\n%{http_code}", *a], capture_output=True,
                                      text=True, stdin=subprocess.DEVNULL)
            g, b = curl("-H", f"x-api-key: {KEY}", "-H", "x-user-id: root"), curl()
            if g.returncode in (1, 2):
                print(f"skip {proto}")
                continue
            check(f"over {proto}: in, out, told who", g.stdout.endswith("200") and b.stdout.endswith("401")
                  and json.loads(g.stdout.rsplit("\n", 1)[0])["all-ids"] == ["alice"], f"{g.stdout[-160:]} {b.stdout[-20:]}")
        ws = subprocess.run(["pgrep", "-f", f"okena -c {conf}"], capture_output=True, text=True).stdout.split()
        leak = scanned = 0
        for w in ws:
            try:
                maps = open(f"/proc/{w}/maps").read().splitlines()
                mem = open(f"/proc/{w}/mem", "rb")
            except OSError:
                continue
            for line in maps:
                a, b2 = [int(x, 16) for x in line.split()[0].split("-")]
                if "rw" not in line.split()[1] or b2 - a > 1 << 26:
                    continue
                try:
                    mem.seek(a)
                    data = mem.read(b2 - a)
                    scanned += len(data)
                    if UNSENT.encode() in data:
                        leak += 1
                except (OSError, ValueError):
                    pass
        if scanned:
            check(f"a key from the file is nowhere in memory ({len(ws)} processes, {scanned >> 20} MiB)", leak == 0, str(leak))
        else:
            print("skip memory: not readable here")
    finally:
        p.terminate()
        p.wait(10)
    t = (tmp / "log").read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    (tmp / "dup").write_text("a:same\nb:same\n")
    (tmp / "noname").write_text(":key\n")
    (tmp / "long").write_text("n" * 21 + ":key\n")
    (tmp / "badu").write_text("ann:s:xyz\n")
    line = "auth basic users=" + str(tmp / "users") + " realm=staff"
    for bad in (f"auth api_key keys={tmp}/keys", "auth api_key header=x-a", "auth basic", "auth basic users=/no/such/file",
                f"auth api_key header=x-a keys={tmp}/dup", f"auth api_key header=x-a keys={tmp}/noname",
                f"auth api_key header=x-a keys={tmp}/long", f"auth basic users={tmp}/badu", "auth magic"):
        c = tmp / "bad.conf"
        c.write_text(text.replace(line, bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{bad.replace(str(tmp), '')[:40]}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[:90]}")
    print(f"auth {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
