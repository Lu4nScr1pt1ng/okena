#!/usr/bin/env python3
"""`limit_rate RATE [upload=RATE] [after=SIZE]` on a tcp listener, on one
engine (argument): the upstream's bytes to the client at RATE (300 KB at
200 KiB/s: about a second and a half, every byte), the client's at upload=,
after= at once first, a listener without it at full speed, ten at once each
at the rate, clients that go while they wait."""
import os
import pathlib
import signal
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
BASE = 23500 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, LP, LA, LF = BASE, BASE + 1, BASE + 2, BASE + 3
BODY = bytes((i * 13) & 0xFF for i in range(300000))
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


def serve(c):
    """'D': BODY back, then the end; 'U': everything up to the end, then its length."""
    try:
        k = c.recv(1)
        if k == b"D":
            c.sendall(BODY)
        elif k == b"U":
            n = 0
            while (d := c.recv(65536)):
                n += len(d)
            c.sendall(str(n).encode())
    except OSError:
        pass
    c.close()


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(128)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def download(port):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port), timeout=20)
    c.sendall(b"D")
    r = b""
    while (d := c.recv(65536)):
        r += d
    c.close()
    return time.time() - t0, r


def upload(port, n):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port), timeout=20)
    c.sendall(b"U" + b"u" * n)
    c.shutdown(socket.SHUT_WR)
    r = b""
    while (d := c.recv(100)):
        r += d
    c.close()
    return time.time() - t0, r


threading.Thread(target=backend, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
tcp 127.0.0.1:{LP} {{ limit_rate 200KiB upload=100KiB; to 127.0.0.1:{BACK} }}
tcp 127.0.0.1:{LA} {{ limit_rate 200KiB after=200KiB; to 127.0.0.1:{BACK} }}
tcp 127.0.0.1:{LF} {{ to 127.0.0.1:{BACK} }}
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
    t, b = download(LP)
    check("300 KB down at 200 KiB/s: about 1.46 s, every byte", b == BODY and 1.25 <= t <= 2.2, f"{t:.2f}s {len(b)}")
    t, b = upload(LP, 150000)
    check("150 KB up at upload=100KiB: about 1.46 s, every byte", b == b"150000" and 1.2 <= t <= 2.2, f"{t:.2f}s {b}")
    t, b = download(LA)
    check("after=200KiB: those at once, the rest paced (about 0.5 s)", b == BODY and 0.35 <= t <= 1.0, f"{t:.2f}s")
    t, b = upload(LA, 150000)
    check("no upload=: the client's bytes free", b == b"150000" and t < 0.5, f"{t:.2f}s")
    t, b = download(LF)
    check("a listener without limit_rate: at once", b == BODY and t < 0.5, f"{t:.2f}s")
    with ThreadPoolExecutor(10) as ex:
        t0 = time.time()
        res = list(ex.map(lambda _: download(LP), range(10)))
        tall = time.time() - t0
    check("ten at once: each at the rate, together in about the time of one",
          all(r[1] == BODY for r in res) and 1.25 <= tall <= 3.0, f"{tall:.2f}s")
    socks = []
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", LP), timeout=5)
        c.sendall(b"D")
        c.recv(1000)
        socks.append(c)
    for c in socks:
        c.close()
    t, b = download(LA)
    check("clients gone while they wait: the rest still paced right", b == BODY and 0.35 <= t <= 1.0, f"{t:.2f}s")
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
print(f"tcp limit_rate ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
