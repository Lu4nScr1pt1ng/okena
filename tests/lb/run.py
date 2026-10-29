#!/usr/bin/env python3
"""Balancing behaviour, measured on the share of requests a server gets.

slow_start: a server that comes back (its health checks pass again) is
drawn rarely at first and gets its full share once the window is over;
without slow_start it gets its full share at once."""
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
# ports 28000-28999: this suite's own range
BASE = 28000 + os.getpid() % 99 * 10
B0, B1, SLOW, FAST = BASE, BASE + 1, BASE + 2, BASE + 3


class Backend:
    def __init__(self, port, tag):
        self.port, self.tag = port, tag
        self.start()

    def start(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port))
        s.listen(1024)
        self.sock = s

        def loop():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                try:
                    if c.recv(10):
                        c.sendall(self.tag)
                except OSError:
                    pass
                finally:
                    c.close()
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def who(port):
    c = socket.create_connection(("127.0.0.1", port), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r


def share(port, tag, seconds):
    """Requests for `seconds`; the fraction answered by `tag`."""
    n = hits = 0
    t0 = time.time()
    while time.time() - t0 < seconds:
        hits += who(port) == tag
        n += 1
    return hits / max(n, 1), n


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


b0 = Backend(B0, b"b0")
b1 = Backend(B1, b"b1")
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 1 }}
pool slow {{
    server 127.0.0.1:{B0}
    server 127.0.0.1:{B1}
    health tcp every=100ms timeout=200ms rise=1 fall=1
    slow_start 3s
}}
pool fast {{
    server 127.0.0.1:{B0}
    server 127.0.0.1:{B1}
    health tcp every=100ms timeout=200ms rise=1 fall=1
}}
tcp 127.0.0.1:{SLOW} {{ to pool slow }}
tcp 127.0.0.1:{FAST} {{ to pool fast }}
""")
log = open(tmp / "log", "w+")


def text():
    log.seek(0)
    return log.read()


def wait_log(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text().count(needle) >= count:
            return True
        time.sleep(0.02)
    return False


p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    assert wait_log("started with"), text()
    s, n = share(SLOW, b"b0", 0.5)
    check("both servers share the traffic at first", 0.3 < s < 0.7, f"b0 {s:.0%} of {n}")
    b0.stop()
    assert wait_log(f"127.0.0.1:{B0} is down", 2), text()   # (one line per pool)
    b0.start()
    assert wait_log(f"127.0.0.1:{B0} is up", 2), text()
    early, n1 = share(SLOW, b"b0", 0.8)
    fast, n2 = share(FAST, b"b0", 0.8)
    check("slow_start: a server that is back gets little at first (expected ~7%)", early < 0.15, f"b0 {early:.0%} of {n1}")
    check("without slow_start it gets its share at once", 0.3 < fast < 0.7, f"b0 {fast:.0%} of {n2}")
    time.sleep(2.5)                                          # past the 3 s window
    late, n3 = share(SLOW, b"b0", 0.8)
    check("after the window it has its full share", 0.3 < late < 0.7, f"b0 {late:.0%} of {n3}")
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        print(text())
# peak-ewma: a backend 20 ms slower gets little of a sequential load,
# where least-request (nothing ever in flight to compare) splits it evenly
H0, H1, EW, LR = BASE + 4, BASE + 5, BASE + 6, BASE + 7


def http_backend(port, tag, delay):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(256)

    def handle(c):
        f = c.makefile("rb")
        try:
            while True:
                line = f.readline()
                if not line:
                    return
                while f.readline() not in (b"\r\n", b""):
                    pass
                time.sleep(delay)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + tag)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


http_backend(H0, b"h0", 0)
http_backend(H1, b"h1", 0.02)
conf2 = tmp / "okena-ewma.conf"
conf2.write_text(f"""
okena {{ workers 1 }}
pool ewma {{
    balance peak-ewma
    server 127.0.0.1:{H0}
    server 127.0.0.1:{H1}
}}
pool lr {{
    server 127.0.0.1:{H0}
    server 127.0.0.1:{H1}
}}
http 127.0.0.1:{EW} {{ route /* {{ to pool ewma }} }}
http 127.0.0.1:{LR} {{ route /* {{ to pool lr }} }}
""")
log2 = open(tmp / "log2", "w+")
p2 = subprocess.Popen([str(BIN), "-c", str(conf2)], stderr=log2)


def slow_share(port, seconds):
    c = socket.create_connection(("127.0.0.1", port), timeout=3)
    f = c.makefile("rb")
    n = slow = 0
    t0 = time.time()
    while time.time() - t0 < seconds:
        c.sendall(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        f.readline()
        while f.readline() not in (b"\r\n", b""):
            pass
        slow += f.read(2) == b"h1"
        n += 1
    c.close()
    return slow / max(n, 1), n


try:
    for _ in range(100):
        log2.seek(0)
        if "started with" in log2.read():
            break
        time.sleep(0.02)
    lr, n1 = slow_share(LR, 1.5)
    ew, n2 = slow_share(EW, 1.5)
    check("least-request: a slow backend still gets about half of a sequential load", 0.3 < lr < 0.7, f"slow {lr:.0%} of {n1}")
    check("peak-ewma: the slow backend gets little of it", ew < 0.15, f"slow {ew:.0%} of {n2}")
    check("and the load goes faster", n2 > n1 * 1.5, f"{n2} requests against {n1}")
finally:
    p2.send_signal(signal.SIGTERM)
    try:
        p2.wait(10)
    except subprocess.TimeoutExpired:
        p2.kill()
    if failures:
        log2.seek(0)
        print(log2.read())

print(f"lb: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
