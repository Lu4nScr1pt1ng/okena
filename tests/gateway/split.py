#!/usr/bin/env python3
"""`split` on a route, on one engine (argument): the shares, what sticks to a
client and for how long (a canary raised keeps those in it), each protocol, and
lines that make no sense refused."""
import http.client
import http.server
import os
import pathlib
import re
import signal
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
BASE = 28000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
ONE, TWO, LST, TLS = BASE, BASE + 1, BASE + 2, BASE + 3
failures = 0


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


def backend(port, name):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(name)))
            self.end_headers()
            self.wfile.write(name)

        def log_message(self, *a):
            pass
    http.server.ThreadingHTTPServer.request_queue_size = 64
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    b = r.read()
    c.close()
    return b, r


CONF = """okena {{ workers 2; io_engine {engine} }}
pool stable {{ server 127.0.0.1:{one} }}
pool canary {{ server 127.0.0.1:{two} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ split stable=50% canary=50% sticky=cookie:s }}
}}
http 127.0.0.1:{lst} {{
    route /free {{ split stable=80% canary=20% }}
    route /c {{ split stable={a}% canary={b}% sticky=cookie:okena_split }}
    route /h {{ split stable=50% canary=50% sticky=header:x-user }}
    route /fine {{ to pool stable }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-split-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=s.test",
                    "-addext", "subjectAltName=DNS:s.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    backend(ONE, b"one")
    backend(TWO, b"two")
    conf = tmp / "okena.conf"
    args = dict(engine=ENGINE, one=ONE, two=TWO, lst=LST, tls=TLS, tmp=tmp)
    text = CONF.format(a=95, b=5, **args)
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen(["timeout", "--foreground", "40", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = [get("/free")[0] for _ in range(600)]
        n = r.count(b"two")
        check(f"80/20 of 600: {n} to the second", 80 <= n <= 170 and r.count(b"one") + n == 600, str(n))
        b, q = get("/free")
        check("no sticky: no cookie", q.getheader("set-cookie") is None, str(q.getheaders()))
        check("a route with `to` as ever", get("/fine")[0] == b"one", "")
        given = []
        for _ in range(400):
            b, q = get("/c")
            m = re.fullmatch(r"okena_split=(\d+); Path=/; HttpOnly; SameSite=Lax", q.getheader("set-cookie") or "")
            given.append((m and int(m[1]), b))
        check("sticky: each new client gets a number of 0 to 99", all(x is not None and 0 <= x < 100 for x, _ in given),
              str(given[:4]))
        check("  which decides its pool", all((b == b"two") == (x >= 95) for x, b in given), str(given[:9]))
        seen = {}
        for v in (3, 94, 95, 99):
            rs = [get("/c", {"cookie": f"a=1; okena_split={v}; b=2"}) for _ in range(20)]
            seen[v] = {x[0] for x in rs}
            check(f"  the cookie {v} stays, and is not given again",
                  len(seen[v]) == 1 and all(x[1].getheader("set-cookie") is None for x in rs), str(seen[v]))
        check("  95% and 5%", seen[3] == {b"one"} and seen[94] == {b"one"} and seen[95] == {b"two"}, str(seen))
        got = {get("/c", {"cookie": "okena_split=hello"})[0] for _ in range(20)}
        check("a cookie that is no number: hashed, stays", len(got) == 1, str(got))
        check("  and is not replaced", get("/c", {"cookie": "okena_split=hello"})[1].getheader("set-cookie") is None)
        users = [f"user{i}" for i in range(60)]
        a = {u: get("/h", {"x-user": u})[0] for u in users}
        b = {u: get("/h", {"x-user": u})[0] for u in users}
        n = sum(v == b"two" for v in a.values())
        check(f"sticky=header: the same each time, spread ({n} of 60)", a == b and 15 <= n <= 45, str(n))
        # the canary raised: those in it stay, the next 5 join them
        conf.write_text(CONF.format(a=90, b=10, **args))
        master = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()[0]
        os.kill(int(master), signal.SIGHUP)
        for _ in range(60):
            if "reloaded" in log.read_text():
                break
            time.sleep(0.1)
        time.sleep(0.3)
        g = lambda v: {get("/c", {"cookie": f"okena_split={v}"})[0] for _ in range(10)}
        check("canary 5% to 10%: who was in it stays, the next 5% join, the rest do not move",
              g(99) == {b"two"} and g(95) == {b"two"} and g(92) == {b"two"} and g(89) == {b"one"} and g(3) == {b"one"},
              str((g(99), g(92), g(89))))
        for proto, flag in (("h1", "--http1.1"), ("h2", "--http2"), ("h3", "--http3-only")):
            q = subprocess.run(["timeout", "8", "curl", "-sk", flag, "-D", "-", "-o", "/dev/null",
                                "--resolve", f"s.test:{TLS}:127.0.0.1", f"https://s.test:{TLS}/x"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if q.returncode == 1 or "not support" in q.stderr or q.returncode == 2:
                print(f"skip {proto}: this curl does not speak it")
                continue
            head = q.stdout.lower()
            check(f"over {proto}: the cookie goes out", " 200" in head.split("\n")[0] and "set-cookie: s=" in head, q.stdout[:200])
    finally:
        p.terminate()
        p.wait(10)
    line = "split stable=80% canary=20%"
    for bad in ("split stable=80% canary=30%", "split stable=100%", "split nosuch=50% canary=50%", "split stable=x canary=y",
                "split stable=50% canary=50% sticky=ip", "split stable=0% canary=100%", "split stable=50% canary=50%; to pool stable"):
        c = tmp / "bad.conf"
        c.write_text(text.replace(line, bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{bad}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[:90]}")
    if failures:
        print(log.read_text()[-300:])
    print(f"split {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
