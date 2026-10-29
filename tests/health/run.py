#!/usr/bin/env python3
"""Active health checks: down, up, black holes, panic, and the health
process itself dying."""
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
# ports 24000-24999: this suite's own range (none overlap)
BASE = 24000 + os.getpid() % 99 * 10
B0, B1, LST = BASE, BASE + 1, BASE + 2


class Backend:
    def __init__(self, port, tag):
        self.port, self.tag, self.sock = port, tag, None
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
                finally:
                    c.close()
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def who():
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", LST), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r, time.time() - t0


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
okena {{ workers 2 }}
pool web {{
    server 127.0.0.1:{B0}
    server 127.0.0.1:{B1}
    server 192.0.2.1:9          # never answers
    connect timeout=1s
    health tcp every=200ms timeout=200ms rise=2 fall=2
}}
tcp 127.0.0.1:{LST} {{ to pool web }}
""")
log = open(tmp / "log", "w+")


def text():
    log.seek(0)
    return log.read()


def wait_log(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text().count(needle) >= count:
            return time.time() - t0
        time.sleep(0.05)
    return None


p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    assert wait_log("started with") is not None, text()
    t = wait_log("backend 192.0.2.1:9 is down")
    check("black hole found by the health check", t is not None and t < 2, f"{t:.2f}s" if t else text())
    times = [who()[1] for _ in range(50)]
    check("requests no longer wait for the black hole", max(times) < 0.5, f"max {max(times) * 1000:.0f} ms")

    errors, seen = 0, set()
    error_kinds = []
    T0 = time.time()
    stop = threading.Event()

    def hammer():
        # paced below what the single-threaded test backend accepts
        global errors
        while not stop.is_set():
            try:
                r = who()[0]
                if r:
                    seen.add(r)
                else:
                    errors += 1
                    error_kinds.append(f"empty answer at {time.time() - T0:.2f}s")
            except OSError as e:
                errors += 1
                error_kinds.append(f"{e!r} at {time.time() - T0:.2f}s")
            time.sleep(0.002)
    th = threading.Thread(target=hammer)
    th.start()
    b1.stop()
    t = wait_log(f"backend 127.0.0.1:{B1} is down")
    check("stopped backend marked down", t is not None and t < 2, f"{t:.2f}s" if t else "")
    time.sleep(0.3)
    seen.clear()
    time.sleep(0.5)
    check("traffic only to the live backend", seen == {b"b0"}, str(seen))
    b1.start()
    t = wait_log(f"backend 127.0.0.1:{B1} is up")
    check("backend back up after rise checks", t is not None and t < 2, f"{t:.2f}s" if t else "")
    time.sleep(0.1)
    seen.clear()
    time.sleep(0.5)
    check("traffic returns to it at once", seen == {b"b0", b"b1"}, str(seen))
    if "-v" in sys.argv:
        print("errors so far", errors)
    stop.set()
    th.join()
    check("no client error through all of it", errors == 0, f"{errors} errors {error_kinds[:3]}")

    hp = int(subprocess.check_output(["pgrep", "-P", str(p.pid), "-x", "okena-health"]))
    os.kill(hp, signal.SIGKILL)
    t = wait_log("health process exited, restarting it")
    time.sleep(0.5)
    again = subprocess.run(["pgrep", "-P", str(p.pid), "-x", "okena-health"], capture_output=True).stdout.split()
    check("health process restarted after SIGKILL", t is not None and len(again) == 1)
    check("still serving", who()[0] in (b"b0", b"b1"))

    # everything down: panic, try them anyway rather than refuse
    b0.stop()
    b1.stop()
    wait_log(f"backend 127.0.0.1:{B0} is down")
    b0.start()
    r = who()[0]
    check("all marked down: servers are tried anyway (panic)", r == b"b0", str(r))
    check("each transition logged once", text().count(f"127.0.0.1:{B1} is down") == 2
          and text().count(f"127.0.0.1:{B1} is up") == 1, "")
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0] or "-v" in sys.argv:
        print(text())
print(f"health: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
