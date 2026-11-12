#!/usr/bin/env python3
"""Bulk through a `tcp` listener: directions that move a lot (large buffers,
and on io_uring reads and writes in the loop, src/l4/bulk.inc).

  many at once: 16 connections, 4 MB each way at the same time, every byte
    checked (SHA-256), half-close at the end
  backpressure: a backend that reads slowly; the client's 24 MB all arrive,
    in order, none lost while the proxy waits for room
  an abort: a client that resets in the middle of a stream; the backend sees
    the reset, not a clean end
  a clean end the other way: the backend sends 8 MB and closes; the client
    gets them all and then the end

  tests/l4/bulk.py ENGINE      (io_uring | epoll)
"""
import hashlib
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
# ports 27000-27999: this suite's own range (none overlap)
BASE = 27000 + os.getpid() % 99 * 10
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def listen(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)
    return s


def serve(port, handler):
    s = listen(port)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def echo(c):
    try:
        while True:
            d = c.recv(1 << 20)
            if not d:
                break
            c.sendall(d)
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    c.close()


slow_got = {}


def slow(c):
    # reads 64 KiB every 2 ms: about 32 MB/s, far below what the client sends
    h = hashlib.sha256()
    n = 0
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            h.update(d)
            n += len(d)
            time.sleep(0.002)
    except OSError:
        pass
    slow_got["n"], slow_got["h"] = n, h.digest()
    c.close()


reset_seen = {}


def watch(c):
    # how a stream from the client ends: "reset" or "clean"
    try:
        while True:
            if not c.recv(1 << 20):
                reset_seen["end"] = "clean"
                break
    except ConnectionResetError:
        reset_seen["end"] = "reset"
    except OSError as e:
        reset_seen["end"] = repr(e)
    c.close()


payload = os.urandom(8_000_000)


def sender(c):
    try:
        c.sendall(payload)
    except OSError:
        pass
    c.close()


def main():
    e, s, w, d, lst = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
    serve(e, echo)
    serve(s, slow)
    serve(w, watch)
    serve(d, sender)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-bulk-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
tcp 127.0.0.1:{lst} {{ to 127.0.0.1:{e} }}
tcp 127.0.0.1:{lst + 1} {{ to 127.0.0.1:{s} }}
tcp 127.0.0.1:{lst + 2} {{ to 127.0.0.1:{w} }}
tcp 127.0.0.1:{lst + 3} {{ to 127.0.0.1:{d} }}
""")
    log = open(tmp / "log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", lst + 3), 1).close()
                break
            except OSError:
                time.sleep(0.02)

        # many at once, both ways
        res = []

        def one(i):
            data = os.urandom(4_000_000)
            c = socket.create_connection(("127.0.0.1", lst), timeout=20)
            got = bytearray()
            t = threading.Thread(target=lambda: [got.extend(x) for x in iter(lambda: c.recv(1 << 20), b"")])
            t.start()
            c.sendall(data)
            c.shutdown(socket.SHUT_WR)
            t.join(20)
            c.close()
            res.append(hashlib.sha256(got).digest() == hashlib.sha256(data).digest())
        ts = [threading.Thread(target=one, args=(i,)) for i in range(16)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        check("16 connections, 4 MB each way at once, every byte back", len(res) == 16 and all(res),
              f"{sum(res)} of {len(res)} whole")

        # backpressure: a slow reader
        data = os.urandom(24_000_000)
        c = socket.create_connection(("127.0.0.1", lst + 1), timeout=30)
        c.sendall(data)
        c.close()
        t0 = time.time()
        while "n" not in slow_got and time.time() - t0 < 20:
            time.sleep(0.02)
        check("a slow reader: 24 MB, all of it, in order", slow_got.get("h") == hashlib.sha256(data).digest(),
              f"{slow_got.get('n')} bytes")

        # an abort in the middle of a stream
        c = socket.create_connection(("127.0.0.1", lst + 2), timeout=10)
        c.sendall(os.urandom(4_000_000))
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        c.close()
        t0 = time.time()
        while "end" not in reset_seen and time.time() - t0 < 5:
            time.sleep(0.01)
        check("a client's reset mid-stream reaches the backend as a reset", reset_seen.get("end") == "reset",
              reset_seen.get("end", "nothing in 5 s"))

        # the other way, ending clean
        c = socket.create_connection(("127.0.0.1", lst + 3), timeout=20)
        got = bytearray()
        try:
            for x in iter(lambda: c.recv(1 << 20), b""):
                got.extend(x)
            end = "clean"
        except OSError as ex:
            end = repr(ex)
        c.close()
        check("8 MB from the backend, then its end", bytes(got) == payload and end == "clean",
              f"{len(got)} bytes, {end}")

        # still serving after all that
        c = socket.create_connection(("127.0.0.1", lst), timeout=5)
        c.sendall(b"ping")
        check("  and still serving", c.recv(10) == b"ping")
        c.close()
    finally:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
        log.seek(0)
        text = log.read()
        if "crash" in text or "signal" in text and "killed" in text:
            check("no worker crashed", False, text[-500:])
    print("bulk: " + ("all passed" if not fails else f"{fails} failed"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
