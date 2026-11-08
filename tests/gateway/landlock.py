#!/usr/bin/env python3
"""Landlock, seen from outside, on one engine (argument): the logger writes in
its access logs' directories and nowhere else (an access log that is a
symlink to another directory is refused by the kernel, EACCES), and a log
rotated away is made again. Skipped where the kernel has no Landlock."""
import ctypes
import http.client
import http.server
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 39000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, OTHER, BACK = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(port, path="/"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def main():
    abi = ctypes.CDLL(None, use_errno=True).syscall(444, None, 0, 1)
    if abi <= 0:
        print(f"skip landlock {ENGINE}: this kernel has no Landlock")
        return 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-landlock-", dir="/tmp"))
    a, b = tmp / "logs", tmp / "elsewhere"
    a.mkdir()
    b.mkdir()
    (a / "sneaky.log").symlink_to(b / "target.log")       # in A, writing to B
    threading.Thread(target=http.server.HTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{ access_log {a}/access.log; route /* {{ to pool b }} }}
http 127.0.0.1:{OTHER} {{ access_log {a}/sneaky.log; route /* {{ to pool b }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get(LST) == 200), log.read_text()[-300:])
        get(LST, "/one")
        check("the logger writes in its logs' directory", until(lambda: "/one" in (a / "access.log").read_text()))
        get(OTHER, "/two")
        time.sleep(1.5)
        t = log.read_text()
        check("  and not through a link out of it: the kernel says no", f"{a}/sneaky.log: cannot open it (errno 13)" in t
              and not (b / "target.log").exists(), t[-400:])
        # logrotate: moved away, then USR1: made again, in the same place
        (a / "access.log").rename(a / "access.log.1")
        p.send_signal(signal.SIGUSR1)
        time.sleep(0.5)
        get(LST, "/three")
        check("  a log rotated away is made again", until(lambda: (a / "access.log").exists() and "/three" in (a / "access.log").read_text()))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"landlock {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    return 1 if fails else 0


sys.exit(main())
