#!/usr/bin/env python3
"""Access log fields and choices, on one engine (argument): user_agent,
referer, tls (1.3, 1.2, null; an HTTP/2 stream's from its connection),
upstream_ms (the backend's time to its head), bytes_in (head and body,
counted and chunked); a route's `log off` and `log sample=`."""
import json
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import http.server

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 19400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L, LS = BASE, BASE + 1, BASE + 2

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except OSError:
            pass

    def body(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                n = int(self.rfile.readline().strip(), 16)
                if n == 0:
                    self.rfile.readline()
                    return
                self.rfile.read(n)
                self.rfile.readline()
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)

    def do_GET(self):
        self.body()
        if self.path.startswith("/slow"):
            time.sleep(0.08)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *a):
        pass


def raw(port, data, tls=None):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    if tls:
        c = tls.wrap_socket(c, server_hostname="log.test")
    c.sendall(data)
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    return r


def ctx(maxv=None):
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if maxv:
        c.maximum_version = maxv
    return c


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
srv.handle_error = lambda *a: None
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "l.key"],
               check=True, capture_output=True, cwd=tmp)
subprocess.run(["openssl", "req", "-new", "-x509", "-key", "l.key", "-subj", "/CN=log.test", "-addext",
                "subjectAltName=DNS:log.test", "-days", "2", "-out", "l.pem"], check=True, capture_output=True, cwd=tmp)
alog = tmp / "access.log"
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    access_log {alog}
    route /quiet {{ log off; to 127.0.0.1:{BACK} }}
    route /some/* {{ log sample=50%; to 127.0.0.1:{BACK} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{LS} {{
    tls {{ cert {tmp}/l.pem key={tmp}/l.key }}
    http2 on
    access_log {alog}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")


def lines(pred, n=1, wait=3.0):
    end = time.time() + wait
    while True:
        got = []
        if alog.exists():
            for x in alog.read_text().splitlines():
                try:
                    j = json.loads(x)
                except ValueError:
                    continue
                if pred(j):
                    got.append(j)
        if len(got) >= n or time.time() > end:
            return got
        time.sleep(0.05)


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

    head = b"GET /plain HTTP/1.1\r\nHost: log.test\r\nUser-Agent: tester/1.0 \"q\"\r\nReferer: https://ref.test/a?b=1\r\nConnection: close\r\n\r\n"
    raw(L, head)
    j = (lines(lambda j: j.get("target") == "/plain") or [{}])[0]
    check("user_agent and referer, JSON-escaped",
          j.get("user_agent") == 'tester/1.0 "q"' and j.get("referer") == "https://ref.test/a?b=1", str(j))
    check("tls: null on plain HTTP", "tls" in j and j["tls"] is None, str(j))
    check("bytes_in: the head", j.get("bytes_in") == len(head), f"{j.get('bytes_in')} {len(head)}")
    raw(L, b"GET /slow HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n")
    j = (lines(lambda j: j.get("target") == "/slow") or [{}])[0]
    check("upstream_ms: the backend's time to its head", (j.get("upstream_ms") or 0) >= 75
          and j.get("upstream_ms") <= j.get("duration_ms", 0) + 0.01, str(j))
    post = b"POST /p HTTP/1.1\r\nHost: log.test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
    raw(L, post + b"x" * 100)
    j = (lines(lambda j: j.get("target") == "/p") or [{}])[0]
    check("bytes_in: head and a counted body", j.get("bytes_in") == len(post) + 100, f"{j.get('bytes_in')}")
    ch = b"POST /c HTTP/1.1\r\nHost: log.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    raw(L, ch + b"64\r\n" + b"y" * 100 + b"\r\n" + b"c8\r\n" + b"z" * 200 + b"\r\n0\r\n\r\n")
    j = (lines(lambda j: j.get("target") == "/c") or [{}])[0]
    check("bytes_in: a chunked body's bytes", j.get("bytes_in") == len(ch) + 300, f"{j.get('bytes_in')}")
    raw(LS, b"GET /t13 HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n", ctx())
    raw(LS, b"GET /t12 HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n", ctx(ssl.TLSVersion.TLSv1_2))
    a = (lines(lambda j: j.get("target") == "/t13") or [{}])[0]
    b = (lines(lambda j: j.get("target") == "/t12") or [{}])[0]
    check("tls: 1.3 and 1.2 as negotiated", a.get("tls") == "1.3" and b.get("tls") == "1.2", f"{a} {b}")
    try:
        import h2.connection
        import h2.config
        c = ctx()
        c.set_alpn_protocols(["h2"])
        s = c.wrap_socket(socket.create_connection(("127.0.0.1", LS), timeout=5), server_hostname="log.test")
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        conn.send_headers(1, [(":method", "GET"), (":path", "/h2"), (":scheme", "https"), (":authority", "log.test")],
                          end_stream=True)
        s.sendall(conn.data_to_send())
        end = time.time() + 3
        done = False
        while not done and time.time() < end:
            d = s.recv(65536)
            if not d:
                break
            for ev in conn.receive_data(d):
                if type(ev).__name__ == "StreamEnded":
                    done = True
            s.sendall(conn.data_to_send())
        s.close()
        j = (lines(lambda j: j.get("target") == "/h2") or [{}])[0]
        check("an HTTP/2 stream: the TLS of its connection", j.get("tls") in ("1.3", "1.2"), str(j))
    except ImportError:
        print("skip h2: no h2 package")
    for _ in range(3):
        raw(L, b"GET /quiet HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n")
    def burst(n):
        for i in range(n):
            raw(L, f"GET /some/{i} HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n".encode())
    ts = [threading.Thread(target=burst, args=(50,)) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    raw(L, b"GET /last HTTP/1.1\r\nHost: log.test\r\nConnection: close\r\n\r\n")
    lines(lambda j: j.get("target") == "/last")
    quiet = lines(lambda j: j.get("target") == "/quiet", n=1, wait=0.3)
    some = lines(lambda j: str(j.get("target", "")).startswith("/some/"), n=200, wait=0.3)
    check("log off: no line", not quiet, str(quiet[:1]))
    check("log sample=50%: about half of 200", 50 <= len(some) <= 150, str(len(some)))
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
        print(alog.read_text()[-2000:] if alog.exists() else "(no log)")
print(f"access log fields ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
