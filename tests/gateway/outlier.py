#!/usr/bin/env python3
"""A pool's `outlier` and `retry_budget`, on one engine (argument): errors=2
ejects after two failing answers in a row, for eject=2s, then the server is
back; errors=0 never ejects on answers; max_ejected= caps how many of a pool
are out; retry_budget 0% min=1/s retries about one request a second, and the
default (20% min=10/s) retries more."""
import http.client
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 37000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LE, LZ, LM, LB, LD = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
fails = 0
hits = {}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        sv = self.server
        with sv.lock:
            hits[sv.name] = hits.get(sv.name, 0) + 1
        b = sv.name.encode()
        self.send_response(sv.status)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):                 # (a connection retried away from: reset)
        pass


def backend(name, status):
    s = S(("127.0.0.1", 0), H)
    s.name, s.status, s.lock = name, status, threading.Lock()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return f"127.0.0.1:{s.server_address[1]}"


def get(port):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/")
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def until(f, t=5):
    end = time.time() + t
    while time.time() < end:
        if f():
            return True
        time.sleep(0.02)
    return f()


def main():
    good, bad = backend("good", 200), backend("bad", 503)
    z1, z2 = backend("z1", 503), backend("z2", 503)
    m1, m2 = backend("m1", 503), backend("m2", 503)
    b1, b2 = backend("b1", 503), backend("b2", 503)
    d1, d2 = backend("d1", 503), backend("d2", 503)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-outlier-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool e {{ balance round-robin; server {good}; server {bad}; outlier errors=2 eject=2s }}
pool z {{ balance round-robin; server {z1}; server {z2}; outlier errors=0; retry_budget 0% min=1/s }}
pool m {{ balance round-robin; server {m1}; server {m2}; outlier errors=1 eject=30s max_ejected=50%; retry_budget 0% min=1/s }}
pool b {{ balance round-robin; server {b1}; server {b2}; outlier errors=0; retry_budget 0% min=1/s }}
pool d {{ balance round-robin; server {d1}; server {d2}; outlier errors=0 }}
http 127.0.0.1:{LE} {{ route /* {{ to pool e }} }}
http 127.0.0.1:{LZ} {{ route /* {{ to pool z }} }}
http 127.0.0.1:{LM} {{ route /* {{ to pool m }} }}
http 127.0.0.1:{LB} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{LD} {{ route /* {{ to pool d }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        until(lambda: get(LE)[0] != 0)
        # errors=2: the bad one goes after two 503s in a row (each retried on the good one)
        r = [get(LE) for _ in range(6)]
        check("errors=2: every answer good (503s retried elsewhere)", all(x == (200, "good") for x in r), r)
        check("  ejected after 2 failing answers, for 2 s", until(lambda: "ejected for 2 s after 2 failing answers" in log.read_text()),
              log.read_text()[-300:])
        n = hits.get("bad", 0)
        for _ in range(10):
            get(LE)
        check("  while out it gets nothing", hits.get("bad", 0) == n, (n, hits.get("bad")))
        check("  and after 2 s it is asked again", until(lambda: (get(LE), hits.get("bad", 0) > n)[1], 6), hits)
        # errors=0: never on answers
        for _ in range(20):
            get(LZ)
        t = log.read_text()
        check("errors=0: answers never eject", "127.0.0.1:" + z1.split(":")[1] + " ejected" not in t
              and "127.0.0.1:" + z2.split(":")[1] + " ejected" not in t, t[-300:])
        # max_ejected=50% of two: one out at most
        for _ in range(10):
            get(LM)
        t = log.read_text()
        out = [x for x in (m1, m2) if f"{x} ejected" in t]
        check("max_ejected=50%: of two failing servers one is out, not both", len(out) == 1, out)
        # the budget: 0% min=1/s retries about one a second; the default many more
        h0 = hits.get("b1", 0) + hits.get("b2", 0)
        t0 = time.time()
        for _ in range(30):
            get(LB)
        dt = time.time() - t0
        extra = hits.get("b1", 0) + hits.get("b2", 0) - h0 - 30
        check("retry_budget 0% min=1/s: about one retry a second", 0 <= extra <= 2 + dt, (extra, round(dt, 2)))
        h0 = hits.get("d1", 0) + hits.get("d2", 0)
        for _ in range(30):
            get(LD)
        extra = hits.get("d1", 0) + hits.get("d2", 0) - h0 - 30
        check("  the default (20% min=10/s): more", extra >= 10, extra)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"outlier {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
