#!/usr/bin/env python3
"""A pool's `source`, on one engine (argument): connections to its servers
leave from its addresses in turn (an http and a tcp listener); an address of
the other family is passed over; one this host does not have is a failed
connect (502), not a crash."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 39000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LH, LT, LX, B = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", B))
    s.listen(64)

    def one(c, a):
        try:
            d = c.recv(4096)
            if d.startswith(b"GET"):
                b = a[0].encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(b), b))
            else:
                c.sendall(a[0].encode())
        finally:
            c.close()
    while True:
        c, a = s.accept()
        threading.Thread(target=one, args=(c, a), daemon=True).start()


def get(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError as e:
        return 0, repr(e)


def tcp(port):
    k = socket.create_connection(("127.0.0.1", port), 5)
    k.sendall(b"hi")
    d = k.recv(100).decode()
    k.close()
    return d


def main():
    threading.Thread(target=serve, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-source-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool p {{ server 127.0.0.1:{B}; source 127.0.0.2 ::1 127.0.0.3 }}
pool x {{ server 127.0.0.1:{B}; source 192.0.2.77 }}
http 127.0.0.1:{LH} {{ route /* {{ to pool p }} }}
tcp 127.0.0.1:{LT} {{ to pool p }}
http 127.0.0.1:{LX} {{ route /* {{ to pool x }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            if get(LH)[0]:
                break
            time.sleep(0.05)
        r = [get(LH)[1] for _ in range(6)]
        check("http: its connections leave from 127.0.0.2 and 127.0.0.3 in turn (::1 passed over)",
              set(r) == {"127.0.0.2", "127.0.0.3"} and all(r[i] != r[i + 1] for i in range(5)), r)
        r = [tcp(LT) for _ in range(4)]
        check("tcp: the same", set(r) == {"127.0.0.2", "127.0.0.3"}, r)
        r = [get(LX)[0] for _ in range(3)]
        check("an address the host does not have: 502, as a failed connect", r == [502] * 3, r)
        check("  and okena still serves", get(LH)[0] == 200)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"source {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
