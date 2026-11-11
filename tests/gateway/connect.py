#!/usr/bin/env python3
"""A pool's `connect max= idle= warm=`, on one engine (argument): warm=3 has
three connections open to the server before any request, and a request goes
on one of them (no new one); max=0 keeps none (each request its own); idle=1s
closes a parked one within about two seconds; warm= toward a server that is
not there costs nothing (requests elsewhere served, no worker lost); rate=5/s
lets 15 new connections through in about two seconds (five at once, then five
a second), the requests waiting in line, none refused."""
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
BASE = 44000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LW, LM, LI, LD, LR = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class Back:
    def __init__(self):
        self.s = socket.socket()
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(64)
        self.port = self.s.getsockname()[1]
        self.accepted = 0
        self.closed = 0
        self.requests = 0
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            c, _ = self.s.accept()
            self.accepted += 1
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        buf = b""
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
                while b"\r\n\r\n" in buf:
                    _, _, buf = buf.partition(b"\r\n\r\n")
                    self.requests += 1
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        self.closed += 1
        c.close()


def get(port):
    k = socket.create_connection(("127.0.0.1", port), 5)
    k.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    d = b""
    k.settimeout(5)
    try:
        while True:
            x = k.recv(4096)
            if not x:
                break
            d += x
    except OSError:
        pass
    k.close()
    return d


def until(f, t=5):
    end = time.time() + t
    while time.time() < end:
        if f():
            return True
        time.sleep(0.02)
    return f()


def main():
    w, m, i, rb = Back(), Back(), Back(), Back()
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dport = dead.getsockname()[1]
    dead.close()                               # nothing listens there
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-connect-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool w {{ server 127.0.0.1:{w.port}; connect warm=3 }}
pool m {{ server 127.0.0.1:{m.port}; connect max=0 }}
pool i {{ server 127.0.0.1:{i.port}; connect idle=1s }}
pool d {{ server 127.0.0.1:{dport}; connect warm=2 }}
pool r {{ server 127.0.0.1:{rb.port}; connect max=0 rate=5/s; queue timeout=10s }}
http 127.0.0.1:{LW} {{ route /* {{ to pool w }} }}
http 127.0.0.1:{LM} {{ route /* {{ to pool m }} }}
http 127.0.0.1:{LI} {{ route /* {{ to pool i }} }}
http 127.0.0.1:{LD} {{ route /* {{ to pool d }} }}
http 127.0.0.1:{LR} {{ route /* {{ to pool r }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("warm=3: three connections open before any request", until(lambda: w.accepted >= 3) and w.requests == 0, (w.accepted, w.requests))
        a = w.accepted
        r = get(LW)
        check("  a request goes on one of them, no new connection", r.endswith(b"ok") and w.accepted == a, (r[:40], w.accepted, a))
        check("  and the pool stays at three", until(lambda: w.accepted - w.closed >= 3), (w.accepted, w.closed))
        r1, r2 = get(LM), get(LM)
        check("max=0: none kept, each request its own connection", r1.endswith(b"ok") and r2.endswith(b"ok") and m.accepted == 2
              and until(lambda: m.closed == 2), (m.accepted, m.closed))
        r = get(LI)
        check("idle=1s: a parked connection closed within about two seconds", r.endswith(b"ok") and until(lambda: i.closed == 1, 4) and i.accepted == 1,
              (i.accepted, i.closed))
        from concurrent.futures import ThreadPoolExecutor
        t0 = time.time()
        with ThreadPoolExecutor(15) as ex:
            rs = list(ex.map(lambda _: get(LR), range(15)))
        dt = time.time() - t0
        check("rate=5/s: 15 new connections in about two seconds, all answered", all(x.endswith(b"ok") for x in rs) and 1.5 <= dt <= 4.5
              and rb.accepted == 15, (round(dt, 2), rb.accepted, [x[:12] for x in rs if not x.endswith(b"ok")][:3]))
        r = get(LD)
        check("warm= toward a server not there: 502 for its requests, nothing else", r.startswith(b"HTTP/1.1 502") and get(LW).endswith(b"ok"), r[:40])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t and "restarting" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"connect {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
