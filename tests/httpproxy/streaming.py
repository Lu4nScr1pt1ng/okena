#!/usr/bin/env python3
"""Streams and tunnels, on one engine (argument): Server-Sent Events go out as the
backend writes them (no buffering), with gaps longer than body_idle and the
response timeout; a client that leaves an endless stream lets its backend go at
once; a long poll answered within `response` is served; a WebSocket tunnel is not
cut by body_idle, is cut by `idle` only when nothing moves either way, carries a
half-close to the backend, and is closed within the drain timeout on a stop."""
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 32000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B = BASE, BASE + 1
fails = 0
ev = {}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def serve(c):
    d = b""
    while b"\r\n\r\n" not in d:
        x = c.recv(65536)
        if not x:
            return
        d += x
    path = d.split(b" ")[1]
    try:
        if path == b"/sse":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            for i in range(3):
                msg = b"data: %d %f\n\n" % (i, time.time())
                c.sendall(b"%x\r\n%s\r\n" % (len(msg), msg))
                time.sleep(1.3)
            c.sendall(b"0\r\n\r\n")
        elif path == b"/forever":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            try:
                while True:
                    c.sendall(b"6\r\ndata:\n\n\r\n")
                    time.sleep(0.1)
            except OSError:
                ev["gone"] = time.time()
        elif path == b"/poll":
            time.sleep(1.5)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npoll")
        elif path == b"/ws":
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            c.settimeout(30)
            while True:
                x = c.recv(65536)
                if not x:
                    c.sendall(b"BYE")
                    c.close()
                    return
                c.sendall(x.upper())
    except OSError:
        pass


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", B))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def conn(path, extra=b""):
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(8)
    k.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: a\r\n" + extra + b"\r\n")
    return k


WS = b"Upgrade: websocket\r\nConnection: Upgrade\r\n"


def main():
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-streaming-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=2s }}\npool b {{ server 127.0.0.1:{B} }}\n"
                    f"http 127.0.0.1:{L} {{ timeout {{ idle 2s; body_idle 1s; response 1s }}; route /* {{ to pool b }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        res = {}

        def sse():
            k = conn(b"/sse")
            lat, buf = [], b""
            while True:
                try:
                    x = k.recv(65536)
                except socket.timeout:
                    break
                if not x:
                    break
                buf += x
                for part in x.split(b"data: ")[1:]:
                    lat.append(time.time() - float(part.split(b" ")[1].split(b"\n")[0]))
                if buf.endswith(b"0\r\n\r\n"):
                    break
            k.close()
            res["sse"] = (lat, buf.endswith(b"0\r\n\r\n"), buf[:120])

        def forever():
            k = conn(b"/forever")
            k.recv(1000)
            t0 = time.time()
            k.close()
            while "gone" not in ev and time.time() - t0 < 5:
                time.sleep(0.05)
            res["forever"] = ev.get("gone", t0 + 99) - t0

        def poll():
            k = conn(b"/poll")
            res["poll"] = k.recv(1000)
            k.close()

        def ws_idle():
            k = conn(b"/ws", WS)
            k.recv(1000)
            t0 = time.time()
            try:
                x = k.recv(100)
            except OSError:
                x = b"?"
            res["idle"] = (x, time.time() - t0)

        def ws_busy():
            k = conn(b"/ws", WS)
            k.recv(1000)
            k.settimeout(1)
            got = []
            for _ in range(4):                  # 4 s of traffic: past idle and body_idle
                k.sendall(b"ping")
                got.append(k.recv(10))
                time.sleep(1)
            k.shutdown(socket.SHUT_WR)
            got.append(k.recv(10))
            k.close()
            res["busy"] = got
        ts = [threading.Thread(target=f) for f in (sse, forever, poll, ws_idle, ws_busy)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        lat, ended, head = res["sse"]
        check("Server-Sent Events: each one out as it is written, gaps past body_idle and response kept",
              len(lat) == 3 and max(lat) < 0.2 and ended, (lat, ended, head))
        check("a client that leaves an endless stream: its backend let go at once", res["forever"] < 1.5, res["forever"])
        check("a long poll answered in 1.5 s (response 1s bounds the head): served", res["poll"].startswith(b"HTTP/1.1 200"),
              res["poll"][:40])
        x, took = res["idle"]
        check("a WebSocket with nothing moving: closed by idle", x == b"" and 1.5 < took < 4, (x, took))
        check("  one with traffic: past idle and body_idle, then its half-close reaches the backend",
              res["busy"] == [b"PING"] * 4 + [b"BYE"], res["busy"])
        k = conn(b"/ws", WS)
        k.recv(1000)
        t0 = time.time()
        p.send_signal(signal.SIGTERM)
        try:
            x = k.recv(100)
        except OSError:
            x = b""
        check("a stop: an open tunnel closed within the drain timeout", x == b"" and time.time() - t0 < 4, time.time() - t0)
        p.wait(10)
    finally:
        if p.poll() is None:
            p.terminate()
            p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"streaming {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
