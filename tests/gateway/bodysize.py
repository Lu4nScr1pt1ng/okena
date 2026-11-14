#!/usr/bin/env python3
"""body_size on routes and host blocks, on one engine (argument): a route's own
size above or below the listener's, a host's for its routes, `off`, a chunked
body cut when it grows past it, and 413 before any byte when the length says
so (no 100 Continue for it)."""
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
BASE = 16400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L = BASE, BASE + 1

failures = 0
got = {}


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            n = 0
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline()
                    break
                n += len(self.rfile.read(size))
                self.rfile.readline()
        else:
            n = len(self.rfile.read(int(self.headers["content-length"])))
        got[self.path] = n
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def post(path, size, host="a.test", chunked=False, expect=False):
    c = socket.create_connection(("127.0.0.1", L), timeout=5)
    head = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    if expect:
        head += "Expect: 100-continue\r\n"
    if chunked:
        c.sendall((head + "Transfer-Encoding: chunked\r\n\r\n").encode())
        try:
            for i in range(0, size, 1024):
                n = min(1024, size - i)
                c.sendall(b"%x\r\n%s\r\n" % (n, b"c" * n))
            c.sendall(b"0\r\n\r\n")
        except OSError:
            pass
    else:
        c.sendall((head + f"Content-Length: {size}\r\n\r\n").encode())
        if expect:
            first = c.recv(64)
            c.close()
            return first
        try:
            c.sendall(b"x" * size)
        except OSError:
            pass
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    return int(r.split(b" ")[1]) if r.startswith(b"HTTP/") else 0


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
srv.handle_error = lambda *a: None
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    limits {{ body_size 1KiB }}
    host big.test {{
        body_size 10KiB
        route /h {{ to 127.0.0.1:{BACK} }}
        route /h-own {{ body_size 100B; to 127.0.0.1:{BACK} }}
    }}
    route /upload {{ body_size 1MiB; to 127.0.0.1:{BACK} }}
    route /free {{ body_size off; to 127.0.0.1:{BACK} }}
    route /small {{ body_size 2KiB; to 127.0.0.1:{BACK} }}
    route /* {{ to 127.0.0.1:{BACK} }}
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

    check("the listener's 1 KiB: 1000 bytes through", post("/api", 1000) == 200 and got.get("/api") == 1000)
    check("  2 KiB: 413", post("/api2", 2048) == 413 and "/api2" not in got)
    check("a route's 1 MiB, above the listener's: 300 KB through",
          post("/upload", 300000) == 200 and got.get("/upload") == 300000)
    check("  past it: 413", post("/upload", 2 << 20) == 413)
    check("body_size off: 3 MB through", post("/free", 3 << 20) == 200 and got.get("/free") == 3 << 20)
    check("a host's 10 KiB for its routes: 8 KB through, 20 KB refused",
          post("/h", 8000, host="big.test") == 200 and post("/h", 20000, host="big.test") == 413)
    check("  a route of the host with its own size (100 B) wins", post("/h-own", 200, host="big.test") == 413)
    got.pop("/small", None)
    check("chunked: within the route's 2 KiB, through", post("/small", 1500, chunked=True) == 200
          and got.get("/small") == 1500)
    got.pop("/small", None)
    check("chunked: 413 once it grows past it, the backend gets no whole body",
          post("/small", 6000, chunked=True) == 413 and got.get("/small") is None, str(got.get("/small")))
    first = post("/api3", 5000, expect=True)
    check("Expect: 100-continue past the size: 413, no 100", first.startswith(b"HTTP/1.1 413"), first[:30])
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())

    bad = tmp / "bad.conf"
    bad.write_text("http 127.0.0.1:1 { route /a { body_size lots; respond 200 } }\n")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    check("check: a body_size that is no size", out.returncode != 0 and "lots" in out.stdout + out.stderr,
          out.stdout + out.stderr)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"body_size ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
