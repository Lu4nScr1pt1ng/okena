#!/usr/bin/env python3
"""`limit ... headers=on`, on one engine (argument): RateLimit-Limit,
-Remaining, -Reset and their X-RateLimit- twins on the route's answers, what is
left going down request by request, 0 and a reset on the 429; a route whose
limit does not say so answers without them."""
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 20400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L = BASE, BASE + 1
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(path, c):
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
    r = b""
    while b"\r\n\r\n" not in r:
        r += c.recv(4096)
    head, _, rest = r.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    h = {k.lower(): v for k, _, v in (x.partition(": ") for x in lines[1:])}
    n = int(h.get("content-length", "0")) - len(rest)
    while n > 0:
        n -= len(c.recv(n))
    return int(lines[0].split()[1]), h


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    route /said {{ limit 5/m burst=5 key=client.ip headers=on; to 127.0.0.1:{BACK} }}
    route /quiet {{ limit 5/m burst=5 key=client.ip; to 127.0.0.1:{BACK} }}
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
    c = socket.create_connection(("127.0.0.1", L), timeout=5)
    got = [get("/said", c) for _ in range(6)]
    left = [int(h.get("ratelimit-remaining", -1)) for _, h in got]
    check("RateLimit-Limit is the burst", all(h.get("ratelimit-limit") == "5" and h.get("x-ratelimit-limit") == "5"
                                              for _, h in got), str(got[0]))
    check("what is left goes down: 4 3 2 1 0, then the 429 says 0", left == [4, 3, 2, 1, 0, 0]
          and [s for s, _ in got] == [200] * 5 + [429], str(left))
    check("Reset: seconds until full again (a minute's worth)", 1 <= int(got[4][1]["ratelimit-reset"]) <= 61
          and got[4][1]["ratelimit-reset"] == got[4][1]["x-ratelimit-reset"], str(got[4][1]))
    check("the 429 has its Retry-After too", "retry-after" in got[5][1], str(got[5][1]))
    s, h = get("/quiet", c)
    check("a limit without headers=on: none", s == 200 and not any(k.startswith(("ratelimit", "x-ratelimit")) for k in h),
          str(h))
    c.close()
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures:
        log.seek(0)
        print(log.read())
print(f"ratelimit headers ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
