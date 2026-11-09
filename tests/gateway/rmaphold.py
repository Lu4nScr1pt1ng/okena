#!/usr/bin/env python3
"""`redirects` and `hold`, on one engine (argument)."""
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
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 7000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)
BACK, GONE, LST = BASE, BASE + 1, BASE + 2
fails = 0
got = []


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def go(self):
        n = int(self.headers.get("content-length", 0))
        b = self.rfile.read(n) if n else b""
        got.append((self.command, self.path, b))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = go

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def get(path, method="GET", body=None, timeout=6):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=timeout)
    t = time.time()
    c.request(method, path, body=body)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}, time.time() - t


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-rmap."))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    (tmp / "map").write_text("# old paths\n\n/old /new\n/gone https://else.test/there 302\n  /spaced\t/x   # with a comment\n/perm /p 308\n" +
                             "".join(f"/n{i} /t{i}\n" for i in range(20000)))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
pool g {{ server 127.0.0.1:{GONE} }}
http 127.0.0.1:{LST} {{
    route /h/* {{ hold 3s; to pool g }}
    route /short/* {{ hold 400ms; to pool g }}
    route /nohold/* {{ to pool g }}
    route /auth/* {{ auth api_key header=x-k keys={tmp}/map2; redirects {tmp}/map; to pool b }}
    route /* {{ redirects {tmp}/map; to pool b }}
}}
""")
    (tmp / "map2").write_text("a:k\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        r = get("/old")
        check("a path in the map", r[0] == 301 and r[2].get("location") == "/new", r[0::2])
        r = get("/gone")
        check("  its own code, a full URL", r[0] == 302 and r[2].get("location") == "https://else.test/there", r[0::2])
        check("  308", get("/perm")[0] == 308)
        check("  spaces and a comment", get("/spaced")[2].get("location") == "/x")
        check("  the query goes along", get("/old?a=1")[2].get("location") == "/new?a=1", get("/old?a=1")[2])
        check("  the last of 20000", get("/n19999")[2].get("location") == "/t19999")
        n = len(got)
        check("not in the map: the route", get("/other")[:2] == (200, b"ok") and len(got) == n + 1)
        check("  a path that only begins like one", get("/old/more")[0] == 200 and get("/ol")[0] == 200)
        check("  encoded the same, the same path", get("/%6Fld")[0] == 301, get("/%6Fld")[0])
        check("auth comes first", get("/auth/x")[0] == 401)
        r = get("/nohold/x")
        check("no hold: 502 at once", r[0] == 502 and r[3] < 0.5, r[0::3])
        r = get("/short/x")
        check("hold runs out: 502, in its time", r[0] == 502 and 0.3 < r[3] < 1.0, r[0::3])
        res = {}
        def held(key, *a, **k):
            res[key] = get(*a, **k)
        ts = [threading.Thread(target=held, args=("g", "/h/x")),
              threading.Thread(target=held, args=("p", "/h/p"), kwargs=dict(method="POST", body=b"payload"))]
        [t.start() for t in ts]
        time.sleep(0.8)
        n = len(got)
        r = get("/other")
        check("others go on while they wait", r[0] == 200 and r[3] < 0.3, r[0::3])
        s = socket.create_connection(("127.0.0.1", LST))
        s.sendall(b"GET /h/left HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.1)
        s.close()
        time.sleep(0.1)
        srv = S(("127.0.0.1", GONE), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        [t.join() for t in ts]
        check("the pool comes back: the request goes", res["g"][:2] == (200, b"ok") and 0.8 < res["g"][3] < 1.6, res["g"][0::3])
        check("  a POST with its body too", res["p"][0] == 200 and ("POST", "/h/p", b"payload") in got, res["p"][0::3])
        time.sleep(0.3)
        check("  once each", sum(1 for x in got if x[1] == "/h/x") == 1 and sum(1 for x in got if x[1] == "/h/p") == 1)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        seq = []
        for i in range(3):
            c.request("GET", "/h/y")
            r = c.getresponse()
            r.read()
            seq.append(r.status)
        c.close()
        check("  and then as ever", seq == [200] * 3, seq)
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    for what, m in (("a line with no target", "/a\n"), ("not a path", "a /b\n"), ("twice", "/a /b\n/a /c\n"), ("a bad code", "/a /b 200\n"), ("{*}", "/a /{*}\n")):
        (tmp / "bad.map").write_text(m)
        c = tmp / "bad.conf"
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ redirects {tmp}/bad.map; to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and "redirects" in q.stderr, f"{q.returncode} {q.stderr[-140:]}")
    print(f"rmaphold {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
