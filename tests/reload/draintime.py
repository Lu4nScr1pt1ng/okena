#!/usr/bin/env python3
"""`drain timeout=` is the whole time, whenever the stop comes (on one engine,
argument): a connection kept alive and idle at the stop is answered, with
Connection: close, by a request 300 ms after it under `timeout=1s`, wherever in
the worker's one-second tick the stop falls (it was rounded to ticks: a stop
just before one gave a drain of a few milliseconds)."""
import http.client
import http.server
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 29600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L = BASE, BASE + 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
good, n, errs = 0, 5, []
for i in range(n):
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "c").write_text(f"okena {{ overload off; workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}\n"
                           f"http 127.0.0.1:{L} {{ route /* {{ to 127.0.0.1:{BACK} }} }}\n")
    p = subprocess.Popen([str(BIN), "-c", str(tmp / "c")], stderr=subprocess.DEVNULL)
    c = None
    for _ in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", L, timeout=3)
            c.request("GET", "/")
            c.getresponse().read()
            break
        except OSError:
            time.sleep(0.05)
    time.sleep(i / n)                       # the stop at each fifth of a second
    p.send_signal(signal.SIGTERM)
    time.sleep(0.3)
    try:
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        good += r.getheader("connection", "").lower() == "close"
    except Exception as e:
        errs.append(repr(e))
    p.wait(10)
ok = good == n
print(("ok   " if ok else "FAIL ") + f"a kept connection answered 300 ms into a 1 s drain, wherever the stop falls: {good}/{n} {errs[:2]}")
print(f"drain time ({ENGINE}): {'all passed' if ok else '1 failed'}")
sys.exit(0 if ok else 1)
