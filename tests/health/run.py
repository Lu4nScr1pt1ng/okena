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
# HTTP checks: a backend whose /healthz answer the test controls
H0, H1, HL = BASE + 3, BASE + 4, BASE + 5
seen_checks = []


def http_backend(port, tag, state):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(256)

    def handle(c):
        try:
            data = c.recv(4096)
            if data.startswith(b"GET /healthz") or data.startswith(b"HEAD /healthz"):
                seen_checks.append(data)
                if state["mode"] == "garbage":
                    c.sendall(b"nope, not http\r\n")
                else:
                    c.sendall(b"HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n" % state["status"])
            elif data:
                c.sendall(tag)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


h0 = {"status": 200, "mode": "http"}
http_backend(H0, b"h0", h0)
http_backend(H1, b"h1", {"status": 200, "mode": "http"})
conf2 = tmp / "okena-http.conf"
conf2.write_text(f"""
okena {{ workers 2 }}
pool app {{
    server 127.0.0.1:{H0}
    server 127.0.0.1:{H1}
    health http GET /healthz every=150ms timeout=300ms rise=2 fall=2 expect=200..299 host=svc.internal
}}
tcp 127.0.0.1:{HL} {{ to pool app }}
""")
log2 = open(tmp / "log2", "w+")
p2 = subprocess.Popen([str(BIN), "-c", str(conf2)], stderr=log2)


def text2():
    log2.seek(0)
    return log2.read()


def wait2(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text2().count(needle) >= count:
            return time.time() - t0
        time.sleep(0.05)
    return None


def who2():
    c = socket.create_connection(("127.0.0.1", HL), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r


try:
    wait2("started with")
    t0 = time.time()
    while not seen_checks and time.time() - t0 < 3:
        time.sleep(0.05)
    first = seen_checks[0] if seen_checks else b""
    check("http check: GET /healthz with the configured Host",
          first.startswith(b"GET /healthz HTTP/1.1\r\n") and b"\r\nHost: svc.internal\r\n" in first
          and b"Connection: close" in first, repr(first[:120]))
    h0["status"] = 503
    t = wait2(f"backend 127.0.0.1:{H0} is down (health check: HTTP status 503")
    check("a 503 takes the server out, saying why", t is not None and t < 2, f"{t}")
    seen = {who2() for _ in range(30)}
    check("then traffic only to the healthy one", seen == {b"h1"}, str(seen))
    h0["status"] = 204
    t = wait2(f"backend 127.0.0.1:{H0} is up")
    check("a status in expect brings it back", t is not None and t < 2, f"{t}")
    seen = {who2() for _ in range(40)}
    check("and traffic returns to it", seen == {b"h0", b"h1"}, str(seen))
    h0["mode"] = "garbage"
    t = wait2(f"backend 127.0.0.1:{H0} is down", 2)
    check("an answer that is not HTTP fails the check", t is not None and t < 2, f"{t}")
finally:
    p2.send_signal(signal.SIGTERM)
    try:
        p2.wait(10)
    except subprocess.TimeoutExpired:
        p2.kill()
    if failures:
        print(text2())

print(f"health: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
