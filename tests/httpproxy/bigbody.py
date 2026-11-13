#!/usr/bin/env python3
"""Large response bodies through an `http` listener: a `Content-Length` body
past HC_MIN goes by the L4 relay (src/http/counted.inc), counted to the byte.

  keep-alive, sizes on both sides of the threshold, each body whole and the
    next response where it must be
  clients at once, 1 MB each, every byte checked
  a backend that cuts its body short: the client's connection closes, it is
    never told the body ended
  a HEAD for a large body: no body relayed

  tests/httpproxy/bigbody.py ENGINE      (io_uring | epoll)
"""
import hashlib
import os
import pathlib
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
# ports 30000-30999: this suite's own range (none overlap)
BASE = 30000 + os.getpid() % 99 * 10
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
fails = 0
BODY = os.urandom(4 << 20)


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend(port, cut=False):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def conn(c):
        f = c.makefile("rb")
        try:
            while True:
                line = f.readline()
                if not line:
                    break
                method, path = line.split()[:2]
                while f.readline() not in (b"\r\n", b""):
                    pass
                n = int(path[1:] or b"0")
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % n)
                if method == b"HEAD":
                    continue
                if cut:
                    c.sendall(BODY[:n // 2])
                    break
                c.sendall(BODY[:n])
        except OSError:
            pass
        c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=conn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def read_response(f, head=False):
    status = f.readline()
    h = {}
    while True:
        x = f.readline()
        if x in (b"\r\n", b""):
            break
        k, v = x.decode().split(":", 1)
        h[k.strip().lower()] = v.strip()
    n = int(h.get("content-length", "0"))
    return status, (b"" if head else f.read(n)), n


def main():
    b, cutb, lst = BASE, BASE + 1, BASE + 2
    backend(b)
    backend(cutb, cut=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-bigbody-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{b} }}
pool cut {{ server 127.0.0.1:{cutb} }}
http 127.0.0.1:{lst} {{
	route /c/* {{ rewrite path /c/{{*}} -> /{{*}}; to pool cut }}
	route /* {{ to pool b }}
}}
""")
    log = open(tmp / "log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", lst), 1).close()
                break
            except OSError:
                time.sleep(0.02)

        # keep-alive, sizes on both sides of the threshold
        rnd = random.Random(7)
        sizes = [10, 16383, 16384, 16385, 65536, 70000, 1 << 20, 5, 3_000_000, 0, 200_000]
        sizes += [rnd.randint(1, 2_000_000) for _ in range(30)]
        s = socket.create_connection(("127.0.0.1", lst), timeout=10)
        f = s.makefile("rb")
        bad = []
        for n in sizes:
            s.sendall(b"GET /%d HTTP/1.1\r\nHost: a\r\n\r\n" % n)
            st, body, _ = read_response(f)
            if not st.startswith(b"HTTP/1.1 200") or body != BODY[:n]:
                bad.append(n)
        s.close()
        check(f"keep-alive, {len(sizes)} bodies of 0 to 3 MB on one connection, each whole", not bad, str(bad[:5]))

        # a HEAD for a large body, then a GET on the same connection
        s = socket.create_connection(("127.0.0.1", lst), timeout=10)
        f = s.makefile("rb")
        s.sendall(b"HEAD /1048576 HTTP/1.1\r\nHost: a\r\n\r\n")
        st, _, n = read_response(f, head=True)
        s.sendall(b"GET /100000 HTTP/1.1\r\nHost: a\r\n\r\n")
        st2, body2, _ = read_response(f)
        s.close()
        check("a HEAD of 1 MB: no body; the next GET whole", n == 1048576 and body2 == BODY[:100000], f"{n} {len(body2)}")

        # clients at once
        res = []

        def one(i):
            try:
                c = socket.create_connection(("127.0.0.1", lst), timeout=20)
                cf = c.makefile("rb")
                ok = True
                for _ in range(3):
                    c.sendall(b"GET /1048576 HTTP/1.1\r\nHost: a\r\n\r\n")
                    _, body, _ = read_response(cf)
                    ok = ok and hashlib.sha256(body).digest() == hashlib.sha256(BODY[:1 << 20]).digest()
                c.close()
                res.append(ok)
            except OSError:
                res.append(False)
        ts = [threading.Thread(target=one, args=(i,)) for i in range(16)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        check("16 clients at once, 3 bodies of 1 MB each, every byte", len(res) == 16 and all(res), f"{sum(res)}/{len(res)}")

        # a client that reads slowly (a small window): the relay waits for room
        # many times, then the next response on the connection is whole; and 40
        # that leave in the middle of 3 MB (their pipes back), then 1 MB whole
        c = socket.socket()
        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        c.settimeout(10)
        c.connect(("127.0.0.1", lst))
        c.sendall(b"GET /2000000 HTTP/1.1\r\nHost: a\r\n\r\nGET /30000 HTTP/1.1\r\nHost: a\r\n\r\n")
        cf = c.makefile("rb")
        st, h = cf.readline(), b""
        n = 0
        while (line := cf.readline()) not in (b"\r\n", b""):
            if line.lower().startswith(b"content-length:"):
                n = int(line.split(b":")[1])
        body = b""
        while len(body) < n:
            body += cf.read1(min(4096, n - len(body)))
            if len(body) % 65536 < 4096:
                time.sleep(0.002)
        _, body2, _ = read_response(cf)
        c.close()
        check("a slow reader: 2 MB whole, then the next response", body == BODY[:2000000] and body2 == BODY[:30000],
              f"{len(body)} {len(body2)}")
        for _ in range(40):
            k = socket.create_connection(("127.0.0.1", lst), timeout=5)
            k.sendall(b"GET /3000000 HTTP/1.1\r\nHost: a\r\n\r\n")
            k.recv(20000)
            k.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            k.close()
        s = socket.create_connection(("127.0.0.1", lst), timeout=10)
        f = s.makefile("rb")
        s.sendall(b"GET /1048576 HTTP/1.1\r\nHost: a\r\n\r\n")
        check("  40 clients gone in the middle of 3 MB, then 1 MB whole", read_response(f)[1] == BODY[:1 << 20])
        s.close()

        # a body cut short by the backend
        s = socket.create_connection(("127.0.0.1", lst), timeout=5)
        f = s.makefile("rb")
        s.sendall(b"GET /c/1000000 HTTP/1.1\r\nHost: a\r\n\r\n")
        st = f.readline()
        while f.readline() not in (b"\r\n", b""):
            pass
        got = 0
        t0 = time.time()
        try:
            while True:
                d = f.read1(1 << 20)
                if not d:
                    break
                got += len(d)
        except OSError:
            pass
        s.close()
        check("a body cut short: the client's connection closes after what came",
              got == 500000 and time.time() - t0 < 4, f"{got} bytes, {time.time() - t0:.1f}s")

        s = socket.create_connection(("127.0.0.1", lst), timeout=5)
        f = s.makefile("rb")
        s.sendall(b"GET /20 HTTP/1.1\r\nHost: a\r\n\r\n")
        check("  and still serving", read_response(f)[1] == BODY[:20])
        s.close()
    finally:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    print("bigbody: " + ("all passed" if not fails else f"{fails} failed"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
