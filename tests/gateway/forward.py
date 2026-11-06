#!/usr/bin/env python3
"""`auth forward`, on one engine (argument): another service decides. Whatever
goes wrong with it must keep clients out, and a verdict must reach the request it
was for and no other: a yes that outlives its request opens the door."""
import http.client
import http.server
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
BASE = 14000 + os.getpid() % 50 * 14 + (7 if ENGINE == "epoll" else 0)	# ports 14000-14699: this suite's own
BACK, SSO, LST, FAST, FEW, TLS = (BASE + i for i in range(6))
fails = 0
asked = []
got = []


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class Sso(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        h = {k.lower(): v for k, v in self.headers.items()}
        asked.append((self.path, h))
        c = h.get("cookie", "")
        st, extra = 200, []
        if c.startswith("s=alice") or h.get("authorization") == "Bearer alice":
            extra = [("X-User-Id", "alice"), ("x-user-role", "admin")]
        elif c == "s=bob":
            extra = [("X-User-Id", "bob")]
        elif c == "s=long":
            extra = [("X-User-Id", "u" * 400)]
        elif c == "s=nofields":
            pass
        elif c == "s=boom":
            st = 500
        elif c == "s=slow":
            time.sleep(1.5)
        elif c == "s=cut":
            self.close_connection = True
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Le")
            return
        elif c == "s=forbidden":
            st = 403
        elif h.get("authorization"):
            st, extra = 401, [("WWW-Authenticate", 'Bearer realm="x"')]
        else:
            st, extra = 302, [("Location", "https://login.test/?next=" + h.get("x-forwarded-uri", "")),
                              ("Set-Cookie", "state=1; HttpOnly"), ("X-Secret", "not for the client")]
        self.send_response(st)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"body")

    def log_message(self, *a):
        pass


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def go(self):
        n = int(self.headers.get("content-length", 0))
        b = self.rfile.read(n) if n else b""
        got.append((self.path, self.headers.get("x-user-id"), self.headers.get("x-user-role"), b))
        r = (self.headers.get("x-user-id") or "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(r)))
        self.end_headers()
        self.wfile.write(r)

    do_GET = do_POST = go

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def get(path, method="GET", body=None, port=LST, conn=None, **hdr):
    c = conn or http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {k.replace("_", "-"): v for k, v in hdr.items()}
    t = time.time()
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    b = r.read().decode()
    if not conn:
        c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}, time.time() - t


CONF = """okena {{ workers 2; io_engine {engine} }}
pool b {{ server 127.0.0.1:{back} }}
pool sso {{ server 127.0.0.1:{sso} }}
pool nobody {{ server 127.0.0.1:1 }}
http 127.0.0.1:{lst} {{
    route /app/* {{ auth forward pool=sso path=/verify?x=1 copy=x-user-id,x-user-role timeout=500ms; to pool b }}
    route /short {{ auth forward pool=sso path=/v timeout=100ms; to pool b }}
    route /named {{ auth forward pool=sso path=/v copy=x-user-id identity=x-who; to pool b }}
    route /cached/* {{ auth forward pool=sso path=/v copy=x-user-id cache=1s; to pool b }}
    route /down {{ auth forward pool=nobody path=/v; to pool b }}
    route /lim {{ auth forward pool=sso path=/v copy=x-user-id; limit 2/s burst=1 key=auth.user; to pool b }}
    route /fault {{ auth forward pool=sso path=/v; fault abort=418 percent=100; to pool b }}
    route /open {{ to pool b }}
}}
http 127.0.0.1:{tls} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    route /app/* {{ auth forward pool=sso path=/verify copy=x-user-id timeout=500ms; to pool b }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-forward."))
    for port, h in ((BACK, Back), (SSO, Sso)):
        threading.Thread(target=S(("127.0.0.1", port), h).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    args = dict(engine=ENGINE, back=BACK, sso=SSO, lst=LST, tls=TLS, tmp=tmp)
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2",
                    "-out", tmp / "c.pem"], check=True)
    conf.write_text(CONF.format(**args))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        A = dict(Cookie="s=alice")
        r = get("/app/x?y=2", **A)
        check("a yes: the request goes on, told who", r[:2] == (200, "alice") and got[-1][:3] == ("/app/x?y=2", "alice", "admin"), (r, got[-1:]))
        q, h = asked[-1]
        check("  the service is asked what it needs", q == "/verify?x=1" and h.get("x-forwarded-method") == "GET" and
              h.get("x-forwarded-uri") == "/app/x?y=2" and h.get("cookie") == "s=alice", (q, h))
        n = len(got)
        r = get("/app/x")
        check("no credentials: its redirect reaches the client", r[0] == 302 and r[2].get("location") == "https://login.test/?next=/app/x"
              and r[2].get("set-cookie") == "state=1; HttpOnly", r[:3])
        check("  and nothing else of it", "x-secret" not in r[2] and r[1] == "", r[2])
        check("  the backend never heard", len(got) == n)
        r = get("/app/x", Authorization="Bearer wrong")
        check("its 401 and challenge", r[0] == 401 and "Bearer" in r[2].get("www-authenticate", ""), r[:3])
        check("its 403", get("/app/x", Cookie="s=forbidden")[0] == 403)
        n = len(got)
        for what, c in (("a 500", "s=boom"), ("an answer cut short", "s=cut")):
            r = get("/app/x", Cookie=c)
            check(f"{what}: 503", r[0] == 503, r[:2])
        r = get("/app/x", Cookie="s=slow")
        check("no answer in time: 503, in time", r[0] == 503 and 0.3 < r[3] < 1.2, r[0::3])
        r = get("/down", **A)
        check("the service down: 503, at once", r[0] == 503 and r[3] < 0.4, r[0::3])
        r = get("/app/x", Cookie="s=long")
        check("a field that does not fit: 503, not half of a name", r[0] == 503, r[:2])
        check("  the backend heard none of these", len(got) == n, got[n:])
        r = get("/app/x", Cookie="s=bob", x_user_id="root", x_user_role="admin")
        check("what the client says of those fields goes", r[:2] == (200, "bob") and got[-1][1:3] == ("bob", None), got[-1:])
        r = get("/app/x", Cookie="s=nofields", x_user_id="root")
        check("  even when the service says nothing of them", r[:2] == (200, "-"), r[:2])
        check("identity= is no way past it", get("/named", Cookie="s=bob")[0] == 200)
        r = get("/app/x", "POST", body=b"payload", **A)
        check("a body goes on after the wait", r[0] == 200 and got[-1][3] == b"payload", got[-1:])
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        seq = [get("/app/x", conn=c, Cookie=v)[0] for v in ("s=alice", "s=boom", "s=bob")] + [get("/app/x", conn=c)[0]]
        check("one connection, each request its own verdict", seq == [200, 503, 200, 302], seq)
        c.close()
        # a client that leaves while it waits
        for i in range(20):
            s = socket.create_connection(("127.0.0.1", LST))
            s.sendall(b"GET /app/x HTTP/1.1\r\nHost: x\r\nCookie: s=alice\r\n\r\n")
            s.close()
        time.sleep(0.2)
        check("clients that left: the next without credentials is not let in by them",
              all(get("/app/x")[0] == 302 for i in range(40)))
        time.sleep(0.8)
        codes = [get("/lim", Cookie="s=bob")[0] for i in range(6)]
        check("limits run after it, by who", codes[0] == 200 and 429 in codes, codes)
        check("  a fault too", get("/fault", Cookie="s=nofields")[0] == 418)
        check("  and neither before who it is", get("/fault")[0] == 302)

        # cache: per worker, so every worker is fed first
        def hits(f):
            n = len(asked)
            f()
            return len(asked) - n
        B = dict(Cookie="s=bob")
        for i in range(12):
            get("/cached/a", **A)
        check("cache: a yes is kept", hits(lambda: [get("/cached/a", **A) for i in range(8)]) == 0)
        r = get("/cached/a", **B)
        check("  not for someone else", r[:2] == (200, "bob"), r[:2])
        check("  nor for another path", hits(lambda: get("/cached/other", **A)) == 1)
        check("  nor for no credentials", get("/cached/a")[0] == 302)
        check("  what it told is kept too", get("/cached/a", **A)[:2] == (200, "alice"))
        time.sleep(1.1)
        check("  and it runs out", hits(lambda: get("/cached/a", **A)) == 1)
        for i in range(6):
            get("/cached/z", Cookie="s=forbidden")
        check("  a no is not kept", hits(lambda: get("/cached/z", Cookie="s=forbidden")) == 1)

        def curl(cookie, *a):
            q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "-o", "-", "-w", " %{http_code} %{http_version}",
                                "-H", "Cookie: " + cookie, f"https://localhost:{TLS}/app/x", *a], capture_output=True, text=True)
            return q.stdout
        check("over HTTP/2: told who", curl("s=alice") == "alice 200 2", curl("s=alice"))
        check("  refused", " 302 2" in curl("s=none"), curl("s=none"))
        check("  503", " 503 2" in curl("s=boom"), curl("s=boom"))
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{TLS}/app/x", "proto=h3", "conns=4", "workers=1",
                            "rate=200", "duration=1s", "warmup=0s", "format=kv", "header=cookie: s=alice"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
        check("over HTTP/3: 200 of them", kv.get("ok") == "200" and kv.get("errors") == "0", q.stdout[:120] + q.stderr[-100:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])

    # by the thousand, on few sessions: nothing stays behind
    subprocess.run(["gcc", "-O2", "-pthread", "-o", tmp / "l4bench", ROOT / "tests/bench/l4bench.c"], check=True)
    fast = subprocess.Popen(["timeout", "--foreground", "12", str(tmp / "l4bench"), "http", str(FAST), "2"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    few = tmp / "few.conf"
    few.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
pool fast {{ server 127.0.0.1:{FAST} }}
http 127.0.0.1:{FEW} {{
    route /a {{ auth forward pool=fast path=/v; to pool fast }}
}}
""")
    q = subprocess.Popen(["prlimit", "--nofile=1024:1024", "timeout", "--foreground", "10", str(BIN), "-c", str(few)],
                         stderr=open(tmp / "few.log", "w"))
    try:
        time.sleep(0.5)
        for round in (1, 2):
            r = subprocess.run(["timeout", "8", str(BIN), "bench", f"http://127.0.0.1:{FEW}/a", "conns=16", "workers=2",
                                "rate=4000", "duration=1s", "warmup=0s", "format=kv"], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL)
            kv = dict(x.split("=", 1) for x in r.stdout.split() if "=" in x)
            check(f"4000 questions on a few hundred sessions, {round}", kv.get("ok") == "4000" and kv.get("errors") == "0", str(kv)[:110])
    finally:
        q.terminate()
        q.wait(10)
        fast.terminate()
    text = CONF.format(**args)
    for what, bad in (("no pool", "auth forward path=/v;"), ("no such pool", "auth forward pool=nosuch path=/v;"),
                      ("no path", "auth forward pool=sso;"), ("a path with no slash", "auth forward pool=sso path=v;")):
        c = tmp / "bad.conf"
        c.write_text(text.replace("auth forward pool=sso path=/v timeout=100ms;", bad))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and "auth forward" in q.stderr, f"{q.returncode} {q.stderr[-160:]}")
    print(f"forward {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
