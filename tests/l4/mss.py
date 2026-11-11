#!/usr/bin/env python3
"""`mss` on a listener, on one engine (argument): an http and a tcp listener
clamp the segments their clients may send (the SYN-ACK's MSS, read back on the
client as TCP_MAXSEG); a reload changes it on the socket that stays; a
listener without it has the kernel's."""
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 36000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LH, LT, LN, B = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def mss(port):
    for _ in range(100):
        try:
            k = socket.create_connection(("127.0.0.1", port), 2)
            break
        except OSError:
            time.sleep(0.02)
    m = k.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    k.close()
    return m


def conf(path, a, b):
    path.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{LH} {{ mss {a}; route /* {{ respond 404 }} }}
tcp 127.0.0.1:{LT} {{ mss {b}; to 127.0.0.1:{B} }}
http 127.0.0.1:{LN} {{ route /* {{ respond 404 }} }}
""")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mss-"))
    c = tmp / "okena.conf"
    conf(c, 1000, 1200)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(c)], stderr=open(log, "w"))
    try:
        free = mss(LN)
        h, t = mss(LH), mss(LT)
        check("http: mss 1000 clamps what the client sends", h <= 1000, h)
        check("tcp: mss 1200 clamps what the client sends", 1000 < t <= 1200, t)
        check("  a listener without it: the kernel's (loopback's, far larger)", free > 1200, free)
        conf(c, 600, 1200)
        p.send_signal(signal.SIGHUP)
        for _ in range(200):
            h = mss(LH)
            if h <= 600:
                break
            time.sleep(0.02)
        check("a reload: the socket that stays takes the new mss", h <= 600, h)
        check("  and the other keeps its own", 1000 < mss(LT) <= 1200)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"mss {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
