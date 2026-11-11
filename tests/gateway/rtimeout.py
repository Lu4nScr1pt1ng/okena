#!/usr/bin/env python3
"""A route's `timeout try= total=`, on one engine (argument): try=1s answers
504 from a backend that takes 4 s, where the listener's own response timeout
is 30 s; with `retry 1 on=timeout` the request goes on to the next server;
total=1s keeps that retry from starting; another route keeps the listener's."""
import http.client
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 45000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend(delay, name):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(64)

    def one(c):
        try:
            c.recv(4096)
            time.sleep(delay)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(name), name))
            c.recv(10)
        except OSError:
            pass
        c.close()

    def run():
        while True:
            c, _ = s.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()[1]


def get(path):
    t0 = time.time()
    try:
        c = http.client.HTTPConnection("127.0.0.1", L, timeout=10)
        c.request("GET", path)
        r = c.getresponse()
        b = r.read()
        c.close()
        return r.status, b, time.time() - t0
    except OSError as e:
        return 0, repr(e).encode(), time.time() - t0


def main():
    slow, slow2, fast = backend(4, b"slow"), backend(4, b"slow2"), backend(0, b"fast")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-rtimeout-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool s {{ server 127.0.0.1:{slow} }}
pool sf {{ balance first; server 127.0.0.1:{slow2}; server 127.0.0.1:{fast} }}
http 127.0.0.1:{L} {{
    timeout {{ response 30s }}
    route /try {{ to pool s; timeout try=1s }}
    route /retry {{ to pool sf; timeout try=1s; retry 1 on=timeout }}
    route /total {{ to pool sf; timeout try=1s total=1s; retry 1 on=timeout }}
    route /plain {{ to pool sf }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        st, b, dt = get("/try")
        check("try=1s: 504 within about two seconds (the listener's is 30 s)", st == 504 and 0.9 <= dt <= 3.2, (st, round(dt, 2)))
        st, b, dt = get("/retry")
        check("  retry on=timeout: the next server answers", st == 200 and b == b"fast" and dt <= 3.5, (st, b, round(dt, 2)))
        st, b, dt = get("/total")
        check("total=1s: no retry starts after it, 504", st == 504 and dt <= 3.5, (st, b, round(dt, 2)))
        st, b, dt = get("/plain")
        check("a route without one: the listener's (it waits the 4 s)", st == 200 and b == b"slow2" and dt >= 3.5, (st, b, round(dt, 2)))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"rtimeout {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
