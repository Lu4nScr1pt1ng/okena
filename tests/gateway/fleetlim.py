#!/usr/bin/env python3
"""`fleet_limits` and `limit ... fleet=on`, on one engine (argument): three
instances side by side; what clients take on one is taken on the others
within an interval, so the fleet as a whole lets through the limit and no
more; a limit without fleet=on stays each instance's; an instance with
another key is not heard."""
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
BASE = 21400 + os.getpid() % 40 * 16 + (8 if ENGINE == "epoll" else 0)
BACK = BASE
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def codes(port, path, n):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    out = []
    for _ in range(n):
        c.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
        r = b""
        while b"\r\n\r\n" not in r:
            r += c.recv(4096)
        head, _, rest = r.partition(b"\r\n\r\n")
        st = int(head.split()[1])
        cl = [int(x.split(b":")[1]) for x in head.split(b"\r\n") if x.lower().startswith(b"content-length")]
        left = (cl[0] if cl else 0) - len(rest)
        while left > 0:
            left -= len(c.recv(left))
        out.append(st)
    c.close()
    return out


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "fleet.key").write_text("this-is-the-fleet-key-0123456789\n")
(tmp / "other.key").write_text("another-fleet-key-entirely-abcdef\n")
HTTP = [BASE + 1, BASE + 2, BASE + 3]
SYNC = [BASE + 4, BASE + 5, BASE + 6]
procs, logs = [], []
for i in range(3):
    peers = ",".join(f"127.0.0.1:{p}" for j, p in enumerate(SYNC) if j != i)
    key = tmp / ("other.key" if i == 2 else "fleet.key")
    conf = tmp / f"okena{i}.conf"
    conf.write_text(f"""
okena {{
    workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    fleet_limits bind=127.0.0.1:{SYNC[i]} peers={peers} key={key} interval=20ms
}}
http 127.0.0.1:{HTTP[i]} {{
    route /shared {{ limit 10/m burst=10 key=client.ip fleet=on; to 127.0.0.1:{BACK} }}
    route /own {{ limit 10/m burst=10 key=client.ip; to 127.0.0.1:{BACK} }}
}}
""")
    log = open(tmp / f"log{i}", "w+")
    logs.append(log)
    procs.append(subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log))
try:
    for log in logs:
        for _ in range(100):
            log.seek(0)
            if "started with" in log.read():
                break
            time.sleep(0.05)
    a = codes(HTTP[0], "/shared", 6)
    time.sleep(0.3)                     # (an interval and some)
    b = codes(HTTP[1], "/shared", 10)
    check("on A: 6 through", a.count(200) == 6, a)
    check("on B, after: only the 4 left of the fleet's 10", b.count(200) == 4 and b.count(429) == 6, b)
    time.sleep(0.3)
    a2 = codes(HTTP[0], "/shared", 3)
    check("A hears what B took: none left", a2.count(200) == 0, a2)
    c = codes(HTTP[2], "/shared", 10)
    check("C, another key: not of this fleet, its own 10", c.count(200) == 10, c)
    o1 = codes(HTTP[0], "/own", 10)
    time.sleep(0.3)
    o2 = codes(HTTP[1], "/own", 10)
    check("a limit without fleet=on: each instance's", o1.count(200) == 10 and o2.count(200) == 10, (o1, o2))
    for i, log in enumerate(logs):
        log.seek(0)
        t = log.read()
        check(f"instance {i}: no crash, its fleet process up", "killed by signal" not in t and "okena-fleet exited" not in t
              and "cannot be bound" not in t, t[-500:])
    bad = tmp / "bad.conf"
    bad.write_text(f"http 127.0.0.1:1 {{ route /a {{ limit 1/s fleet=on; respond 200 }} }}\n")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    check("fleet=on without fleet_limits: refused", out.returncode != 0, out.stdout + out.stderr)
finally:
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    if fails:
        for log in logs:
            log.seek(0)
            print(log.read()[-1500:])
print(f"fleet limits ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
