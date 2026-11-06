#!/usr/bin/env python3
"""`fault` on a route, on one engine (argument): the status it answers, the
share of the requests it takes, the routes without one untouched, and values
that make no sense refused."""
import http.client
import http.server
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 33000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
failures = 0
seen = [0]


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen[0] += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(path):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, r.reason


CONF = """okena {{ workers 1; io_engine {engine} }}
http 127.0.0.1:{lst} {{
    route /all {{ to 127.0.0.1:{back}; fault abort=503 }}
    route /half {{ to 127.0.0.1:{back}; fault abort=429 percent=50 }}
    route /fine {{ to 127.0.0.1:{back} }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-fault-"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(CONF.format(engine=ENGINE, lst=LST, back=BACK))
    p = subprocess.Popen(["timeout", "--foreground", "30", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        time.sleep(0.5)
        r = [get("/all") for _ in range(20)]
        check("abort=503: every request, the backend not asked",
              all(x == (503, "Service Unavailable") for x in r) and seen[0] == 0, f"{r[:3]} {seen[0]}")
        check("a route without one goes through", get("/fine")[0] == 200 and seen[0] == 1, str(seen[0]))
        r = [get("/half")[0] for _ in range(400)]
        n = r.count(429)
        check("percent=50: about half, the status named", 140 <= n <= 260 and set(r) == {200, 429}, f"{n} {set(r)}")
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("fault abort=200", "fault abort=700", "fault percent=50", "fault abort=503 percent=101"):
        c = tmp / "bad.conf"
        c.write_text(CONF.format(engine=ENGINE, lst=LST, back=BACK).replace("fault abort=503", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{bad}: refused", q.returncode not in (0, 124) and "fault" in q.stderr, f"{q.returncode} {q.stderr[:90]}")
    print(f"fault {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
