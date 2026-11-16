#!/usr/bin/env python3
"""`limit_rate RATE [after=SIZE]`, on one engine (argument): an answer paced at
its rate (a file of 300 KB at 200 KiB/s takes about a second and a half,
every byte intact), after= sent at once first, twenty answers at once each at
the rate (a connection's rate, not the route's), a route without it at full
speed (and by its zero-copy paths), HTTP/2 paced too, clients that go
while they wait."""
import http.server
import os
import pathlib
import signal
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 22400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L, LS = BASE, BASE + 1, BASE + 2
BODY = bytes((i * 7) & 0xFF for i in range(300000))
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


def fetch(path):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", L), timeout=20)
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
    r = b""
    while (d := c.recv(65536)):
        r += d
    c.close()
    return time.time() - t0, r.partition(b"\r\n\r\n")[2]


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
srv.handle_error = lambda *a: None
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "site" / "file").mkdir(parents=True)
(tmp / "site" / "file" / "big.bin").write_bytes(BODY)
subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "l.key"],
               check=True, capture_output=True, cwd=tmp)
subprocess.run(["openssl", "req", "-new", "-x509", "-key", "l.key", "-subj", "/CN=p.test", "-days", "2", "-out", "l.pem"],
               check=True, capture_output=True, cwd=tmp)
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    route /paced {{ limit_rate 200KiB; to 127.0.0.1:{BACK} }}
    route /after {{ limit_rate 200KiB after=200KiB; to 127.0.0.1:{BACK} }}
    route /file/* {{ limit_rate 200KiB; files {tmp}/site }}
    route /free {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{LS} {{
    tls {{ cert {tmp}/l.pem key={tmp}/l.key }}
    http2 on
    route /paced {{ limit_rate 200KiB; to 127.0.0.1:{BACK} }}
}}
""")


def fetch_h2(path):
    import h2.config
    import h2.connection
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.set_alpn_protocols(["h2"])
    t0 = time.time()
    s = c.wrap_socket(socket.create_connection(("127.0.0.1", LS), timeout=20), server_hostname="p.test")
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1 << 20})
    conn.increment_flow_control_window(1 << 20)
    conn.send_headers(1, [(":method", "GET"), (":path", path), (":scheme", "https"), (":authority", "p.test")],
                      end_stream=True)
    s.sendall(conn.data_to_send())
    body, done = b"", False
    while not done:
        d = s.recv(65536)
        if not d:
            break
        for ev in conn.receive_data(d):
            n = type(ev).__name__
            if n == "DataReceived":
                body += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, 1)
            elif n in ("StreamEnded", "StreamReset"):
                done = True
        s.sendall(conn.data_to_send())
    s.close()
    return time.time() - t0, body
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
    t, b = fetch("/paced")
    check("300 KB at 200 KiB/s: about 1.46 s, every byte", b == BODY and 1.25 <= t <= 2.2, f"{t:.2f}s {len(b)}")
    t, b = fetch("/after")
    check("after=200KiB: those at once, the rest paced (about 0.5 s)", b == BODY and 0.35 <= t <= 1.0, f"{t:.2f}s")
    t, b = fetch("/file/big.bin")
    check("a file: paced too (not by sendfile)", b == BODY and 1.25 <= t <= 2.2, f"{t:.2f}s {len(b)}")
    t, b = fetch("/free")
    check("a route without limit_rate: at once", b == BODY and t < 0.5, f"{t:.2f}s")
    with ThreadPoolExecutor(20) as ex:
        t0 = time.time()
        res = list(ex.map(lambda _: fetch("/paced"), range(20)))
        tall = time.time() - t0
    check("twenty at once: each at the rate, together in about the time of one",
          all(r[1] == BODY for r in res) and 1.25 <= tall <= 3.0, f"{tall:.2f}s {[round(r[0], 2) for r in res][:5]}")
    socks = []
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", L), timeout=5)
        c.sendall(b"GET /paced HTTP/1.1\r\nHost: t\r\n\r\n")
        c.recv(1000)
        socks.append(c)
    for c in socks:
        c.close()
    t, b = fetch("/after")
    check("clients gone while they wait on the wheel: the rest still paced right", b == BODY and 0.35 <= t <= 1.0, f"{t:.2f}s")
    try:
        import h2.settings  # noqa: F401
        t, b = fetch_h2("/paced")
        check("HTTP/2: a stream paced too", b == BODY and 1.25 <= t <= 2.2, f"{t:.2f}s {len(b)}")
    except ImportError:
        print("skip h2: no h2 package")
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read())
print(f"limit_rate ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
