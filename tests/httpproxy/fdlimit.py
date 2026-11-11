#!/usr/bin/env python3
"""Out of file descriptors, on one engine (argument): okena started with a low
RLIMIT_NOFILE and held by more half-sent requests than it has descriptors for:
no busy loop on accept (its worker stays near idle), and once they go it serves
again at once."""
import http.server
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
BASE = 34000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def worker_ticks(master):
    tot = 0
    for d in pathlib.Path("/proc").iterdir():
        try:
            if d.name.isdigit() and (d / "comm").read_text().strip() == "okena-worker":
                f = (d / "stat").read_text().rsplit(")", 1)[1].split()
                if f[1] == str(master):         # (this instance's: prlimit execs okena)
                    tot += int(f[11]) + int(f[12])
        except OSError:
            pass
    return tot


def get():
    try:
        k = socket.create_connection(("127.0.0.1", L), timeout=2)
        k.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        r = k.recv(100)
        k.close()
        return r.startswith(b"HTTP/1.1 200")
    except OSError:
        return False


def main():
    if not shutil.which("prlimit"):
        print("skip fdlimit: no prlimit")
        return
    threading.Thread(target=S(("127.0.0.1", B), H).serve_forever, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-fdlimit-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\npool b {{ server 127.0.0.1:{B} }}\n"
                    f"http 127.0.0.1:{L} {{ route /* {{ to pool b }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen(["prlimit", "--nofile=96", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            if get():
                break
            time.sleep(0.05)
        check("serving with 96 descriptors", get())
        held = []
        for _ in range(400):
            try:
                k = socket.create_connection(("127.0.0.1", L), timeout=1)
                k.sendall(b"GET / HTTP/1.1\r\nHost: a\r\n")
                held.append(k)
            except OSError:
                break
        t0 = worker_ticks(p.pid)
        time.sleep(1.5)
        spent = worker_ticks(p.pid) - t0
        check(f"{len(held)} half-sent requests, more than its descriptors: no busy loop", spent < 30, f"{spent} ticks in 1.5 s")
        for k in held:
            k.close()
        ok = False
        for _ in range(60):
            if get() and get():
                ok = True
                break
            time.sleep(0.05)
        check("  once they go: serving again", ok)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"fdlimit {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
