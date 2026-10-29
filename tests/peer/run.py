#!/usr/bin/env python3
"""The client's address: PROXY protocol v1/v2 headers and per_source
limits, on one engine (argument: io_uring or epoll)."""
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 24000 + os.getpid() % 500 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, V1, V2, DUAL, LIM = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def read_header(c):
    """Parse a PROXY header; returns (family, src, dst, sport, dport)."""
    first = c.recv(16, socket.MSG_PEEK)
    if first.startswith(b"PROXY "):
        line = b""
        while not line.endswith(b"\r\n"):
            line += c.recv(1)
        _, fam, src, dst, sport, dport = line.decode().split()
        return fam, src, dst, int(sport), int(dport)
    hdr = c.recv(16)
    assert hdr[:12] == SIG and hdr[12] == 0x21, hdr
    length = struct.unpack("!H", hdr[14:16])[0]
    body = c.recv(length)
    if hdr[13] == 0x11:
        return ("TCP4", socket.inet_ntop(socket.AF_INET, body[0:4]), socket.inet_ntop(socket.AF_INET, body[4:8]),
                *struct.unpack("!HH", body[8:12]))
    return ("TCP6", socket.inet_ntop(socket.AF_INET6, body[0:16]), socket.inet_ntop(socket.AF_INET6, body[16:32]),
            *struct.unpack("!HH", body[32:36]))


seen = {}


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(256)

    def handle(c):
        try:
            h = read_header(c)
            tag = c.recv(64)
            seen[tag] = h
            c.sendall(b"ok")
        except Exception as e:
            seen[b"error"] = repr(e)
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def plain_backend(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(256)

    def handle(c):
        try:
            while (d := c.recv(100)):
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def through(host, port, tag):
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    c = socket.socket(fam)
    c.settimeout(3)
    c.connect((host, port))
    me = c.getsockname()
    c.sendall(tag)
    r = c.recv(10)
    c.close()
    time.sleep(0.05)
    return me, r, seen.get(tag)


backend()
plain_backend(BACK + 9)
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{
    workers 4
    io_engine {ENGINE}
}}
tcp 127.0.0.1:{V1} {{
    to 127.0.0.1:{BACK}
    proxy_protocol send v1
}}
tcp 127.0.0.1:{V2} {{
    to 127.0.0.1:{BACK}
    proxy_protocol send v2
}}
tcp :{DUAL} {{
    to 127.0.0.1:{BACK}
    proxy_protocol send v2
}}
tcp 127.0.0.1:{LIM} {{
    to 127.0.0.1:{BACK + 9}
    limits {{ per_source 3 }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    me, r, h = through("127.0.0.1", V1, b"v1")
    check("PROXY v1: header with the client's address and ports",
          r == b"ok" and h == ("TCP4", "127.0.0.1", "127.0.0.1", me[1], V1), str(h))
    me, r, h = through("127.0.0.1", V2, b"v2")
    check("PROXY v2: binary header, TCP over IPv4",
          r == b"ok" and h == ("TCP4", "127.0.0.1", "127.0.0.1", me[1], V2), str(h))
    me, r, h = through("::1", DUAL, b"v2six")
    check("PROXY v2 on a dual-stack listener, IPv6 client: TCP6 and the real destination",
          r == b"ok" and h == ("TCP6", "::1", "::1", me[1], DUAL), str(h))
    me, r, h = through("127.0.0.1", DUAL, b"v2mapped")
    check("IPv4 client on a dual-stack listener: TCP4, not a mapped address",
          r == b"ok" and h == ("TCP4", "127.0.0.1", "127.0.0.1", me[1], DUAL), str(h))
    check("the client's bytes follow the header intact", b"error" not in seen, str(seen.get(b"error")))

    # per_source 3 for the whole instance, across 4 workers
    held = []
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", LIM), timeout=3)
        c.sendall(b"x")
        assert c.recv(1) == b"x"
        held.append(c)
    extra_ok = 0
    for _ in range(8):                  # several tries: they land on different workers
        c = socket.create_connection(("127.0.0.1", LIM), timeout=3)
        try:
            c.sendall(b"y")
            extra_ok += c.recv(1) == b"y"
        except OSError:
            pass
        c.close()
    check("per_source: a 4th connection is refused, whatever the worker", extra_ok == 0, f"{extra_ok} let in")
    held.pop().close()
    time.sleep(0.2)
    c = socket.create_connection(("127.0.0.1", LIM), timeout=3)
    c.sendall(b"z")
    check("per_source: a closed connection frees its place", c.recv(1) == b"z")
    c.close()
    for c in held:
        c.close()
    time.sleep(0.2)
    n = 0
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", LIM), timeout=3)
        c.sendall(b"w")
        n += c.recv(1) == b"w"
        held.append(c)
    check("per_source: back to 3 once all closed", n == 3)
    for c in held:
        c.close()
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures:
        log.seek(0)
        print(log.read())
print(f"peer ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
