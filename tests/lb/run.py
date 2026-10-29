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
print(f"lb: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
