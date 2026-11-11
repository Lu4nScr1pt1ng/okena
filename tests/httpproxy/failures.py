#!/usr/bin/env python3
"""Backends that fail and clients that misbehave, on one engine (argument): a
backend that refuses (502); a pool whose servers health says are all down (503 and
Retry-After); a backend that resets in the middle of a body (the client sees it
cut); a kept connection the backend closes under the next request (a GET is sent
again on a new one, a POST never is); a head sent a byte at a time and a body that
stops (408); limits { body_size }: a Content-Length past it (413, before the
backend, Expect: 100-continue too) and a chunked body that grows past it (413); a
client that half-closes after its request still gets the answer."""
import os
import re
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
BASE = 30000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B_OK, B_DEAD, B_FLAKY, B_RST, B_DOWN = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5
fails = 0
seen = []
posts = []


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def listen(port, fn):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=fn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def read_req(c):
    d = b""
    while b"\r\n\r\n" not in d:
        x = c.recv(65536)
        if not x:
            return None
        d += x
    h, _, rest = d.partition(b"\r\n\r\n")
    n = 0
    for x in h.split(b"\r\n"):
        if x.lower().startswith(b"content-length:"):
            n = int(x.split(b":")[1])
    while len(rest) < n:
        x = c.recv(65536)
        if not x:
            break
        rest += x
    return h


def ok(c):
    try:
        while read_req(c) is not None:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except OSError:
        pass


def flaky(c):
    """answers a connection's first request, closes it when the next comes"""
    n = 0
    try:
        while True:
            h = read_req(c)
            if h is None:
                return
            n += 1
            seen.append(h.split(b" ")[0])
            if n >= 2:
                c.close()
                return
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except OSError:
        pass


def rst(c):
    read_req(c)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"x" * 1000)
    time.sleep(0.05)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    c.close()


def raw(data, wait=3, pause=None, shut=False):
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(wait)
    try:
        if pause:
            for b in data:
                k.send(bytes([b]))
                time.sleep(pause)
        else:
            k.sendall(data)
        if shut:
            k.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    out, end = b"", "open"
    try:
        while True:
            x = k.recv(65536)
            if not x:
                end = "closed"
                break
            out += x
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "reset"
    k.close()
    st = [int(m) for m in re.findall(rb"HTTP/1\.1 (\d{3}) ", out)]     # (heads right after a body)
    ra = [x for x in out.split(b"\r\n") if x.lower().startswith(b"retry-after")]
    return st, ra, end, out


def G(path):
    return f"GET {path} HTTP/1.1\r\nHost: a\r\n\r\n".encode()


def main():
    listen(B_OK, ok)
    listen(B_FLAKY, flaky)
    listen(B_RST, rst)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-failures-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool ok {{ server 127.0.0.1:{B_OK} }}
pool dead {{ server 127.0.0.1:{B_DEAD} }}
pool flaky {{ server 127.0.0.1:{B_FLAKY} }}
pool rst {{ server 127.0.0.1:{B_RST} }}
pool down {{ server 127.0.0.1:{B_DOWN}; health tcp every=100ms fall=1 rise=1 }}
http 127.0.0.1:{L} {{
    limits {{ body_size 1KiB }}
    timeout {{ header 1s; body_idle 1s; response 2s }}
    route /ok {{ to pool ok }}
    route /dead {{ to pool dead }}
    route /flaky {{ to pool flaky }}
    route /rst {{ to pool rst }}
    route /down {{ to pool down }}
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
        st, ra, end, out = raw(G("/dead"))
        check("a backend that refuses: 502", st == [502] and end == "closed", (st, end))
        for _ in range(60):                     # (health has seen it down)
            st, ra, end, out = raw(G("/down"))
            if st == [503]:
                break
            time.sleep(0.05)
        check("every server down by health (tried anyway): 503, Retry-After", st == [503] and ra == [b"Retry-After: 1"], (st, ra))
        st, ra, end, out = raw(G("/rst"))
        check("a backend that resets mid-body: the client sees it cut", st == [200] and end in ("closed", "reset")
              and len(out.partition(b"\r\n\r\n")[2]) < 100000, (st, end, len(out)))
        seen.clear()
        st, ra, end, out = raw(G("/flaky") + G("/flaky"), wait=1)
        check("a kept connection closed under a GET: sent again on a new one, both answered",
              st == [200, 200] and seen == [b"GET", b"GET", b"GET"], (st, seen))
        seen.clear()
        st, ra, end, out = raw(G("/flaky") + b"POST /flaky HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nab", wait=1)
        check("  under a POST: never sent again, 502", st == [200, 502] and seen.count(b"POST") == 1, (st, seen))
        res = {}

        def bg(name, *a, **kw):
            res[name] = raw(*a, **kw)
        jobs = [
            ("slowloris", b"GET /ok HTTP/1.1\r\nHost: a\r\nX: " + b"a" * 40, dict(wait=4, pause=0.05)),
            ("stall", b"POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nab", dict(wait=4)),
            ("big", b"POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n" + b"a" * 5000, {}),
            ("at", b"POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 1024\r\n\r\n" + b"a" * 1024, dict(wait=1)),
            ("chunked", b"POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
             + b"200\r\n" + b"a" * 512 + b"\r\n" + b"200\r\n" + b"a" * 512 + b"\r\n" + b"1\r\na\r\n0\r\n\r\n", {}),
            ("chunked ok", b"POST /ok HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
             + b"200\r\n" + b"a" * 512 + b"\r\n" + b"200\r\n" + b"a" * 512 + b"\r\n0\r\n\r\n", dict(wait=1)),
            ("expect", b"POST /ok HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\nExpect: 100-continue\r\n\r\n", dict(wait=2)),
            ("half", G("/ok"), dict(shut=True)),
        ]
        ts = [threading.Thread(target=bg, args=(n, d), kwargs=kw) for n, d, kw in jobs]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check("a head a byte at a time: 408, closed", res["slowloris"][0] == [408] and res["slowloris"][2] == "closed", res["slowloris"][:3])
        check("a body that stops: 408", res["stall"][0] == [408], res["stall"][:3])
        check("body_size: a Content-Length past it, 413 (all of it sent: no reset)",
              res["big"][0] == [413] and res["big"][2] == "closed", res["big"][:3])
        check("  one at it: taken", res["at"][0] == [200], res["at"][:3])
        check("  a chunked body that grows past it: 413", res["chunked"][0] == [413], res["chunked"][:3])
        check("  a chunked body within it: taken", res["chunked ok"][0] == [200], res["chunked ok"][:3])
        check("  Expect: 100-continue past it: 413, no 100", res["expect"][0] == [413], res["expect"][:3])
        check("a client that half-closes after its request: answered", res["half"][0] == [200], res["half"][:3])
    finally:
        t0 = time.time()
        p.terminate()
        p.wait(10)
        stop = time.time() - t0
    check("it stops at once: no session left behind by any of these", stop < 2, f"{stop:.2f} s")
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"failures {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
