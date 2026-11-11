#!/usr/bin/env python3
"""`tcp` at its edges, on one engine (argument): a backend that resets in the middle
of a stream ends the client's with what had come, then a close; a backend that
closes its side first still gets what the client sends after; a client that
resets lets the backend's connection go at once; PROXY v1 for an IPv6 client is
TCP6 with its address in RFC 5952's form."""
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 33000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, LP, B = BASE, BASE + 1, BASE + 2
fails = 0
ev = []
mode = {"m": "echo"}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def serve(c):
    m = mode["m"]
    try:
        if m == "rst":
            c.recv(100)
            c.sendall(b"partial")
            time.sleep(0.05)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.close()
        elif m == "fin":
            c.sendall(b"bye")
            c.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                x = c.recv(100)
                if not x:
                    break
                got += x
            ev.append(got)
            c.close()
        elif m == "watch":
            t0 = time.time()
            try:
                while c.recv(100):
                    pass
            except OSError:
                pass
            ev.append(time.time() - t0)
        elif m == "pp":
            c.settimeout(5)
            got = b""
            while not got.endswith(b"DATA"):          # (the header and the data may come apart)
                x = c.recv(200)
                if not x:
                    break
                got += x
            ev.append(got)
            c.close()
    except OSError:
        pass


def backend():
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", B))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def until(fn, secs=3):
    t = time.time()
    while time.time() - t < secs:
        if fn():
            return True
        time.sleep(0.02)
    return False


def main():
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-l4edges-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\ntcp 127.0.0.1:{L} {{ to 127.0.0.1:{B} }}\n"
                    f"tcp :{LP} {{ proxy_protocol send v1; to 127.0.0.1:{B} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        mode["m"] = "rst"
        k = socket.create_connection(("127.0.0.1", L))
        k.settimeout(3)
        k.sendall(b"hi")
        out = b""
        try:
            while True:
                x = k.recv(100)
                if not x:
                    break
                out += x
        except OSError:
            pass
        k.close()
        check("a backend reset mid-stream: what came, then the end", out == b"partial", out)
        mode["m"] = "fin"
        ev.clear()
        k = socket.create_connection(("127.0.0.1", L))
        k.settimeout(3)
        first = k.recv(100) + (k.recv(100) or b"<EOF>")
        k.sendall(b"still talking")
        k.shutdown(socket.SHUT_WR)
        check("a backend that closes first: the client sees its end, and still sends to it",
              first == b"bye<EOF>" and until(lambda: ev == [b"still talking"]), (first, ev))
        k.close()
        mode["m"] = "watch"
        ev.clear()
        k = socket.create_connection(("127.0.0.1", L))
        time.sleep(0.1)
        k.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        k.close()
        check("a client that resets: its backend let go at once", until(lambda: ev) and ev[0] < 1, ev)
        mode["m"] = "pp"
        ev.clear()
        k = socket.socket(socket.AF_INET6)
        k.connect(("::1", LP))
        port = k.getsockname()[1]
        k.sendall(b"DATA")
        until(lambda: ev)
        k.close()
        check("PROXY v1, an IPv6 client: TCP6 in RFC 5952's form", ev and ev[0] == f"PROXY TCP6 ::1 ::1 {port} {LP}\r\nDATA".encode(), ev)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"l4 edges {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
