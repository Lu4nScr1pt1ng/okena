#!/usr/bin/env python3
"""A request that kills workers twice is quarantined, on one engine
(argument): the worker's crash handler notes the head it was on (here the
watchdog's way, SIGABRT then SIGKILL, while the request waits for its
backend), the supervisor counts it, and at the second the same head is
answered 503 without reaching the backend, while a head that differs by one
byte still goes through."""
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 41000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B = BASE, BASE + 1
fails = 0
seen = []


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", B))
    s.listen(64)

    def one(c):
        try:
            d = c.recv(4096)
            seen.append(d)
            if b"/slow" in d:
                time.sleep(3)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()
    while True:
        c, _ = s.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def until(f, t=5):
    end = time.time() + t
    while time.time() < end:
        if f():
            return True
        time.sleep(0.02)
    return f()


def worker(sup):
    try:
        kids = open(f"/proc/{sup}/task/{sup}/children").read().split()
    except OSError:
        return 0
    for k in kids:
        try:
            if open(f"/proc/{k}/comm").read().strip() == "okena-worker":
                return int(k)
        except OSError:
            pass
    return 0


def caught(pid, sig):
    try:
        for x in open(f"/proc/{pid}/status"):
            if x.startswith("SigCgt:"):
                return bool(int(x.split()[1], 16) >> (sig - 1) & 1)
    except OSError:
        pass
    return False


HEAD = b"GET /slow HTTP/1.1\r\nHost: a\r\nX-Poison: 1\r\n\r\n"


def ask(head, wait=5):
    k = socket.create_connection(("127.0.0.1", L), 5)
    k.settimeout(wait)
    k.sendall(head)
    try:
        d = k.recv(4096)
    except OSError:
        d = b""
    k.close()
    return d


def main():
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-qz-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\nhttp 127.0.0.1:{L} {{ route /* {{ to 127.0.0.1:{B} }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        until(lambda: worker(p.pid) and b"200" in ask(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"))
        for n in (1, 2):
            w = worker(p.pid)
            if w <= 0:                                 # (never kill(0): our own group)
                check(f"crash {n}: a worker to crash", False, w)
                break
            k = socket.create_connection(("127.0.0.1", L), 5)
            before = len(seen)
            k.sendall(HEAD)
            until(lambda: len(seen) > before)          # it waits for its backend now
            os.kill(w, signal.SIGABRT)                 # the watchdog's first word: noted
            until(lambda: not caught(w, signal.SIGABRT))   # (its handler ran, and is reset)
            os.kill(w, signal.SIGKILL)
            k.close()
            until(lambda: worker(p.pid) not in (0, w))
            check(f"crash {n}: the worker replaced", worker(p.pid) not in (0, w))
        # (the supervisor may say so after the new worker is up)
        until(lambda: log.read_text().count("died on a request") >= 2 and "twice now" in log.read_text())
        t = log.read_text()
        check("the supervisor counts the head it died on, and quarantines it the second time",
              t.count("died on a request") == 2 and "twice now" in t, t[-600:])
        before = len(seen)
        r = ask(HEAD)
        check("the same head: 503, the backend not asked", r.startswith(b"HTTP/1.1 503") and len(seen) == before, (r[:60], len(seen) - before))
        r = ask(HEAD.replace(b"X-Poison: 1", b"X-Poison: 2").replace(b"/slow", b"/fast"))
        check("  a head one byte apart goes through", r.startswith(b"HTTP/1.1 200"), r[:60])
    finally:
        p.terminate()
        p.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"quarantine {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
