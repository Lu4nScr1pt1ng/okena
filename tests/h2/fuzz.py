#!/usr/bin/env python3
"""HTTP/2 frame fuzzing against a live okena (argument: io_uring or epoll,
then how many connections). Each connection sends the preface and then a
random mix: valid frames of every type with mutated fields (lengths, flags,
stream ids, padding, priority), HPACK blocks from the hpack package with
bytes flipped, truncated frames, garbage. After each batch a well-formed
request must still be answered, and in the end no worker may have died or
stalled (the watchdog would say so in the log)."""
import os
import pathlib
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 300
BASE = 25000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

try:
    import hpack
except ImportError:
    hpack = None


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(512)

    def handle(c):
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                _, buf = buf.split(b"\r\n\r\n", 1)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def fr(typ, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) + struct.pack(">I", sid & 0xFFFFFFFF) + payload


def block(rng):
    hdrs = [(":method", rng.choice(["GET", "POST", "HEAD", "CONNECT", "X"])), (":scheme", "http"),
            (":authority", "x"), (":path", rng.choice(["/", "/a?b", "", "*", "/" + "z" * 300]))]
    for _ in range(rng.randint(0, 6)):
        hdrs.append((rng.choice(["x-a", "cookie", "content-length", "te", "Upper", "connection", ":status"]),
                     rng.choice(["1", "trailers", "a\r\nb", "", "x" * 100, "-5"])))
    b = bytearray(hpack.Encoder().encode(hdrs, huffman=rng.random() < 0.5))
    for _ in range(rng.choice([0, 0, 1, 3])):
        b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def random_frames(rng):
    out = []
    sid = 1
    for _ in range(rng.randint(1, 30)):
        kind = rng.randrange(12)
        s_ = rng.choice([sid, sid, sid + 2, 0, rng.randrange(1, 100), 2 ** 31 - 1])
        if kind == 0:                                        # HEADERS, maybe split
            b = block(rng)
            flags = rng.choice([4, 5, 0, 1, 0x25, 0x2d, 8 | 5])
            if flags & 8:
                pad = rng.randrange(0, 20)
                b = bytes([pad]) + b + b"\0" * rng.choice([pad, pad + 3])
            if flags & 0x20:
                b = struct.pack(">IB", rng.choice([0, s_, 3]), 16) + b
            if not flags & 4 and rng.random() < 0.7:
                cut = len(b) // 2
                out.append(fr(1, flags, s_, b[:cut]))
                out.append(fr(9, 4, s_, b[cut:]))
            else:
                out.append(fr(1, flags, s_, b))
            sid += 2
        elif kind == 1:
            out.append(fr(0, rng.choice([0, 1, 8, 9]), s_, os.urandom(rng.choice([0, 1, 100, 16384]))))
        elif kind == 2:
            out.append(fr(2, 0, s_, os.urandom(rng.choice([5, 5, 4, 6]))))
        elif kind == 3:
            out.append(fr(3, 0, s_, os.urandom(rng.choice([4, 4, 3]))))
        elif kind == 4:
            n = rng.choice([0, 6, 12, 5])
            p = b"".join(struct.pack(">HI", rng.randrange(8), rng.choice([0, 1, 16384, 2 ** 31, 2 ** 32 - 1]))
                         for _ in range(n // 6)) + b"\0" * (n % 6)
            out.append(fr(4, rng.choice([0, 0, 1]), rng.choice([0, 0, 1]), p))
        elif kind == 5:
            out.append(fr(5, 4, s_, os.urandom(8)))
        elif kind == 6:
            out.append(fr(6, rng.choice([0, 1]), rng.choice([0, 0, 1]), os.urandom(rng.choice([8, 8, 7]))))
        elif kind == 7:
            out.append(fr(7, 0, rng.choice([0, 0, 1]), os.urandom(rng.choice([8, 12, 3]))))
        elif kind == 8:
            out.append(fr(8, 0, s_, struct.pack(">I", rng.choice([0, 1, 65535, 2 ** 31 - 1, 2 ** 31]))))
        elif kind == 9:
            out.append(fr(9, rng.choice([0, 4]), s_, os.urandom(rng.randrange(0, 40))))
        elif kind == 10:
            out.append(fr(rng.randrange(10, 256), rng.randrange(256), s_, os.urandom(rng.randrange(0, 50))))
        else:
            out.append(os.urandom(rng.randrange(1, 40)))      # garbage
    data = b"".join(out)
    if rng.random() < 0.2:
        data = data[:rng.randrange(len(data) + 1)]           # cut anywhere
    return data


def one(data):
    s = socket.create_connection(("127.0.0.1", LST), timeout=1)
    try:
        s.sendall(PREFACE + fr(4, 0, 0) + data)
        s.settimeout(0.3)
        while s.recv(65536):
            pass
    except (OSError, socket.timeout):
        pass
    finally:
        s.close()


def healthy():
    s = socket.create_connection(("127.0.0.1", LST), timeout=3)
    b = hpack.Encoder().encode([(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/ok")])
    s.sendall(PREFACE + fr(4, 0, 0) + fr(1, 5, 1, b))
    data = b""
    try:
        while not (b"ok" in data and data.count(b"\x00\x00\x00\x00\x01\x00\x00\x00\x01") >= 0):
            d = s.recv(65536)
            if not d:
                break
            data += d
            if b"\x01\x00\x00\x00\x01ok" in data or data.endswith(b"ok"):
                break
    except socket.timeout:
        pass
    s.close()
    return b"ok" in data


def main():
    if hpack is None:
        print("skip h2 fuzz: pip install hpack")
        return 0
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h2f-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\nhttp 127.0.0.1:{LST} {{\n    http2 on\n"
                    f"    route /* {{ to 127.0.0.1:{BACK} }}\n}}\n")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    failures = 0
    try:
        time.sleep(0.4)
        seed = int.from_bytes(os.urandom(4), "little")
        rng = random.Random(seed)
        bad_health = 0
        for i in range(COUNT):
            one(random_frames(rng))
            if i % 50 == 49 and not healthy():
                bad_health += 1
        ok = healthy()
        log.seek(0)
        text = log.read()
        died = "killed" in text or "exited with status" in text or "refused system call" in text
        print(("ok   " if ok and not bad_health else "FAIL ") + f"{COUNT} fuzzed connections (seed {seed}): "
              f"a request is still answered" + ("" if ok and not bad_health else f" ({bad_health} checks failed)"))
        print(("ok   " if not died else "FAIL ") + "no worker died or stalled" + ("" if not died else ": " + text[-400:]))
        failures = (not ok or bad_health > 0) + died
    finally:
        p.terminate()
        p.wait(10)
    print(f"h2 fuzz {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
