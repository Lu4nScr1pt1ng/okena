#!/usr/bin/env python3
"""The overload manager and `priority`, on one engine (argument): with a worker
pressed, bulk routes go first, then normal ones, and critical ones never; a late
loop counts as much as full sessions; and all of it is undone as it eases."""
import http.client
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 31000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
failures = 0
release = threading.Event()


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/hold":
            release.wait(30)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(path):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    r.read()
    c.close()
    return r


CONF = """okena {{ workers 1; io_engine {engine}; watchdog 10s }}
http 127.0.0.1:{lst} {{
    limits {{ connections 100 }}
    route /hold {{ to 127.0.0.1:{back}; priority critical }}
    route /critical {{ to 127.0.0.1:{back}; priority critical }}
    route /normal {{ to 127.0.0.1:{back} }}
    route /explicit {{ to 127.0.0.1:{back}; priority normal }}
    route /bulk {{ to 127.0.0.1:{back}; priority bulk }}
}}
"""


def statuses():
    return get("/critical").status, get("/normal").status, get("/explicit").status, get("/bulk").status


def wait_level(log, n, secs=8):
    end = time.time() + secs
    want = f"at level {n}"
    while time.time() < end:
        if log.read_text().rstrip().endswith(want) or want in log.read_text().splitlines()[-1]:
            return True
        time.sleep(0.05)
    return False


held = []


def hold(n):
    def one():
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=30)
        c.request("GET", "/hold")
        try:
            c.getresponse().read()
        except Exception:
            pass
        c.close()
    for _ in range(n):
        t = threading.Thread(target=one, daemon=True)
        t.start()
        held.append(t)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-over-"))
    http.server.ThreadingHTTPServer.request_queue_size = 256
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    text = CONF.format(engine=ENGINE, lst=LST, back=BACK)
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen(["timeout", "--foreground", "60", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        check("quiet: all served", statuses() == (200, 200, 200, 200), str(statuses()))
        hold(87)
        check("87% full: level 2", wait_level(log, 2), log.read_text()[-120:])
        r = get("/normal")
        check("  `Connection: close`, all still served", r.getheader("connection") == "close" and
              statuses() == (200, 200, 200, 200), f"{r.getheaders()} {statuses()}")
        hold(5)
        check("92% full: level 3", wait_level(log, 3), log.read_text()[-120:])
        s = statuses()
        check("  bulk refused, the rest served", s == (200, 200, 200, 503), str(s))
        r = get("/bulk")
        check("  with 503 and when to come back", r.status == 503 and r.getheader("retry-after") == "1", str(r.getheaders()))
        hold(6)
        check("98% full: level 4", wait_level(log, 4), log.read_text()[-120:])
        s = statuses()
        check("  only critical served", s == (200, 503, 503, 503), str(s))
        release.set()
        check("released: back to 0, a step at a time", wait_level(log, 0, 20), log.read_text()[-200:])
        lv = [l.rsplit(" ", 1)[1] for l in log.read_text().splitlines() if "at level" in l]
        check("  each step said", lv == ["1", "2", "3", "4", "3", "2", "1", "0"] or lv[-4:] == ["3", "2", "1", "0"], str(lv))
        check("  and all served again", statuses() == (200, 200, 200, 200), str(statuses()))
        # a worker that does not get to run is a late loop
        worker = subprocess.run(["pgrep", "-P", subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                 text=True).stdout.split()[0]], capture_output=True, text=True).stdout.split()
        release.clear()
        before = log.read_text().count("at level")
        for w in worker:
            os.kill(int(w), signal.SIGSTOP)
        time.sleep(1.7)				# (more than a tick: one of them has to be late)
        for w in worker:
            os.kill(int(w), signal.SIGCONT)
        time.sleep(0.2)
        t = log.read_text()
        lv = [l.rsplit(" ", 1)[1] for l in t.splitlines() if "at level" in l][before // 1:]
        check("a loop at least 700 ms late: pressed", bool(lv) and int(lv[0]) >= 3, str(lv))
        s = get("/critical").status
        check("  critical still served", s == 200, str(s))
        check("  and it eases", wait_level(log, 0, 20), t[-160:])
    finally:
        release.set()
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    c = tmp / "bad.conf"
    c.write_text(text.replace("priority bulk", "priority urgent", 1))
    q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
    check("priority urgent: refused", q.returncode not in (0, 124) and "priority" in q.stderr, f"{q.returncode} {q.stderr[:90]}")
    print(f"overload {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
