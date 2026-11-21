#!/usr/bin/env python3
"""WebSocket through an https listener whose records okena seals itself (the
default): after the 101 the relay opens the client's records for the backend
and seals the backend's bytes for the client. Frames of 0 B to 1 MB echoed
whole, several on one connection, both ways at once, and the plain listener
beside it; one engine (argument)."""
import base64
import hashlib
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 19400 + os.getpid() % 50 * 4
BACK, PLAIN, TLS = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


def recv_exact(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            raise EOFError
        d += c
    return d


def read_frame(s):
    """(opcode, payload, masked) of one frame"""
    b0, b1 = recv_exact(s, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(s, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(s, 8))[0]
    mask = recv_exact(s, 4) if b1 & 0x80 else None
    data = recv_exact(s, n)
    if mask:
        data = bytes(x ^ mask[i % 4] for i, x in enumerate(data))
    return b0 & 0x0F, data


def frame(op, data, mask):
    n = len(data)
    head = bytes([0x80 | op])
    m = 0x80 if mask else 0
    if n < 126:
        head += bytes([m | n])
    elif n < 65536:
        head += bytes([m | 126]) + struct.pack(">H", n)
    else:
        head += bytes([m | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + data
    k = os.urandom(4)
    return head + k + bytes(x ^ k[i % 4] for i, x in enumerate(data))


def backend():
    """an echo server: each frame back as it came, a close answered"""
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BACK))
    ls.listen(64)

    def one(c):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                head += c.recv(4096)
            key = [x.split(b":", 1)[1].strip() for x in head.split(b"\r\n") if x.lower().startswith(b"sec-websocket-key:")][0]
            acc = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Sec-WebSocket-Accept: " + acc + b"\r\n\r\n")
            while True:
                op, data = read_frame(c)
                c.sendall(frame(op, data, False))
                if op == 8:
                    break
        except (EOFError, OSError, IndexError):
            pass
        c.close()

    while True:
        c, _ = ls.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def client(port, tls):
    s = socket.create_connection(("127.0.0.1", port), 10)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname="localhost")
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(4096)
    return s, head.split(b"\r\n")[0]


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-wss-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"],
                   check=True, capture_output=True)
    threading.Thread(target=backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ overload off; workers 1; io_engine {ENGINE} }}
pool echo {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool echo }} }}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem key={tmp}/k.pem }}
    route /* {{ to pool echo }}
}}
""")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", TLS), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        sizes = [0, 1, 125, 126, 16000, 16384, 20000, 36000, 65536, 1000000]
        for port, tls, what in ((TLS, True, "wss"), (PLAIN, False, "ws")):
            s, status = client(port, tls)
            ok, detail = status.startswith(b"HTTP/1.1 101"), status
            for n in sizes:
                if not ok:
                    break
                data = os.urandom(n)
                s.sendall(frame(2, data, True))
                op, back = read_frame(s)
                if op != 2 or back != data:
                    ok, detail = False, (n, op, len(back))
            check(f"{what}: frames of 0 B to 1 MB echoed whole, one connection", ok, detail)
            s.close()
        # both ways at once: the client sends while echoes come back
        s, _ = client(TLS, True)
        msgs = [os.urandom(30000) for _ in range(20)]
        got = []

        def reader():
            try:
                for _ in msgs:
                    got.append(read_frame(s)[1])
            except (EOFError, OSError):
                pass
        t = threading.Thread(target=reader)
        t.start()
        for m in msgs:
            s.sendall(frame(2, m, True))
        t.join(10)
        check("wss: twenty frames sent while their echoes come back, in order", got == msgs, len(got))
        s.sendall(frame(8, b"\x03\xe8", True))
        op, _ = read_frame(s)
        check("  the close handshake goes through", op == 8, op)
        s.close()
    finally:
        p.terminate()
        p.wait(10)
    log = (tmp / "log").read_text()
    check("no worker died", "killed" not in log and "restarting" not in log, log[-300:])
    print(f"wss {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
