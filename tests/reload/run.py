#!/usr/bin/env python3
"""Reload (SIGHUP) without dropping a connection.

Traffic runs continuously while the configuration changes: a pool moves
to another backend, a listener appears, one goes away, the worker count
changes. A long-lived connection opened before the reload must keep
working. An invalid file and a port another program holds must leave
the running configuration in place.
"""
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
BASE = 22000 + os.getpid() % 500 * 10
B0, B1, L1, L2, L3, BUSY = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5


def backend(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1024)

    def handle(c):
        try:
            while (d := c.recv(4096)):
                c.sendall(tag if d == b"who" else d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def who(port):
    c = socket.create_connection(("127.0.0.1", port), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r


def refused(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return False
    except ConnectionRefusedError:
        return True


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


backend(B0, b"b0")
backend(B1, b"b1")
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
log = open(tmp / "log", "w+")


def write(text):
    conf.write_text(text)


def text():
    log.seek(0)
    return log.read()


def wait_log(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text().count(needle) >= count:
            return True
        time.sleep(0.05)
    return False


def workers(p):
    return sorted(int(x) for x in subprocess.check_output(["pgrep", "-P", str(p.pid), "-x", "okena-worker"]).split())


write(f"""
okena {{ workers 2 }}
tcp 127.0.0.1:{L1} {{ to 127.0.0.1:{B0} }}
tcp 127.0.0.1:{L2} {{ to 127.0.0.1:{B0} }}
""")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    assert wait_log("started with"), text()
    check("starts", who(L1) == b"b0" and who(L2) == b"b0")

    # traffic all the time
    stop = threading.Event()
    stats = {"ok": 0, "fail": 0}

    def hammer():
        while not stop.is_set():
            try:
                r = who(L1)
                stats["ok" if r in (b"b0", b"b1") else "fail"] += 1
            except OSError:
                stats["fail"] += 1
    threads = [threading.Thread(target=hammer) for _ in range(4)]
    for t in threads:
        t.start()
    held = socket.create_connection(("127.0.0.1", L1), timeout=5)
    held.sendall(b"before")
    check("long-lived connection open", held.recv(10) == b"before")
    old = workers(p)

    write(f"""
okena {{ workers 3 }}
tcp 127.0.0.1:{L1} {{ to 127.0.0.1:{B1} }}
tcp 127.0.0.1:{L3} {{ to 127.0.0.1:{B1} }}
""")
    p.send_signal(signal.SIGHUP)
    check("reload applied", wait_log("configuration reloaded"), text()[-300:])
    time.sleep(0.5)
    check("changed pool takes new connections", all(who(L1) == b"b1" for _ in range(10)))
    check("new listener serves", who(L3) == b"b1")
    held.sendall(b"after")
    check("long-lived connection survives the reload", held.recv(10) == b"after")
    check("worker count follows the new file", len(set(workers(p)) - set(old)) == 3, str(workers(p)))
    check("removed listener announced", "stopped listening on 127.0.0.1:%d" % L2 in text())
    held.close()
    time.sleep(1.0)
    check("old generation exits once its connections end", not (set(old) & set(workers(p))), str(workers(p)))
    check("removed listener closed after that", refused(L2))

    # invalid file: nothing changes
    before = workers(p)
    write(f"tcp 127.0.0.1:{L1} {{ to 127.0.0.1:{B0}\n")
    p.send_signal(signal.SIGHUP)
    check("invalid file rejected", wait_log("reload rejected (errors above)"))
    check("its diagnostics are shown", "this block is never closed" in text())
    check("same workers after a rejected reload", workers(p) == before)
    check("still serving the running configuration", who(L1) == b"b1" and who(L3) == b"b1")

    # a port another program holds: rejected as a whole
    busy = socket.socket()
    busy.bind(("127.0.0.1", BUSY))
    busy.listen()
    write(f"""
okena {{ workers 3 }}
tcp 127.0.0.1:{L1} {{ to 127.0.0.1:{B0} }}
tcp 127.0.0.1:{BUSY} {{ to 127.0.0.1:{B0} }}
""")
    p.send_signal(signal.SIGHUP)
    check("busy port rejects the reload", wait_log("reload rejected (cannot listen"))
    check("and nothing of it was applied", who(L1) == b"b1" and workers(p) == before)
    busy.close()

    # several reloads in a row
    write(f"""
okena {{ workers 2 }}
tcp 127.0.0.1:{L1} {{ to 127.0.0.1:{B0} }}
""")
    n = text().count("configuration reloaded")
    for _ in range(5):
        p.send_signal(signal.SIGHUP)
        time.sleep(0.3)
    check("five reloads in a row", wait_log("configuration reloaded", n + 5))
    time.sleep(1)
    check("serving after them", who(L1) == b"b0")
    check("no leftover workers", len(workers(p)) == 2, str(workers(p)))

    stop.set()
    for t in threads:
        t.join()
    check("no failed request during all of it", stats["fail"] == 0, f"{stats['ok']} ok, {stats['fail']} failed")
    check("no crash, no watchdog kill", "killed by signal" not in text() and "has not made progress" not in text())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures:
        print(text())
print(f"reload: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
