#!/usr/bin/env python3
"""Connection pressure: a listener full of idle connections makes room
for new clients by closing the longest idle, never the busy ones."""
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
# ports 22000-22999: this suite's own range (none overlap)
BASE = 22000 + os.getpid() % 99 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, MET = BASE, BASE + 1, BASE + 2


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(512)

    def handle(c):
        try:
            while (d := c.recv(4096)):
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def alive(c):
    try:
        c.sendall(b"p")
        return c.recv(1) == b"p"
    except OSError:
        return False


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


backend()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{
    workers 2
    io_engine {ENGINE}
    metrics 127.0.0.1:{MET}
}}
tcp 127.0.0.1:{LST} {{
    to 127.0.0.1:{BACK}
    limits {{ connections 40 }}
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
    idle = []
    for _ in range(60):                 # more than fit: some are refused
        c = socket.create_connection(("127.0.0.1", LST), timeout=3)
        if alive(c):
            idle.append(c)
        else:
            c.close()
    check("listener filled", len(idle) >= 30, f"{len(idle)} open")
    busy = idle[:4]                     # these keep talking
    stop = threading.Event()

    def talk():
        while not stop.is_set():
            for c in busy:
                alive(c)
            time.sleep(0.2)
    th = threading.Thread(target=talk)
    th.start()
    time.sleep(3.5)                     # ticks run the pressure manager
    fresh_ok = 0
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", LST), timeout=3)
        fresh_ok += alive(c)
        c.close()
    stop.set()
    th.join()
    check("new clients get in once idle ones are closed", fresh_ok == 10, f"{fresh_ok}/10")
    check("busy connections are never the ones closed", all(alive(c) for c in busy))
    closed = sum(not alive(c) for c in idle[4:])
    check("some idle ones were closed", closed > 0, f"{closed} closed")
    log.seek(0)
    check("pressure logged", "holds 90% of its connections" in log.read())
    time.sleep(1.2)
    text = urllib.request.urlopen(f"http://127.0.0.1:{MET}/metrics", timeout=3).read().decode()
    m = re.search(r'okena_listener_evicted_total\{listener="[^"]+"\} (\d+)', text)
    check("evictions in the metrics", m and int(m.group(1)) > 0, m.group(0) if m else "missing")
    for c in idle:
        c.close()
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures:
        log.seek(0)
        print(log.read())
print(f"overload ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
