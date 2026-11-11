#!/usr/bin/env python3
"""A pool's `concurrency`, on one engine (argument): concurrency 2 lets two
requests at the backend at once and answers the rest 503 at once;
concurrency adaptive starts high enough for 20 at a time against a quick
backend, and when the backend slows tenfold the limit falls within seconds:
503s at the edge, fewer at the backend."""
import http.client
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
from concurrent.futures import ThreadPoolExecutor

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 50000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LF, LA = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        sv = self.server
        with sv.lock:
            sv.now += 1
            sv.most = max(sv.most, sv.now)
        time.sleep(sv.delay)
        with sv.lock:
            sv.now -= 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


def backend(delay):
    s = S(("127.0.0.1", 0), H)
    s.delay, s.now, s.most, s.lock = delay, 0, 0, threading.Lock()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def get(port):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        c.close()
        return r.status
    except OSError:
        return 0


def main():
    f, a = backend(0.6), backend(0.01)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-cc-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool f {{ server 127.0.0.1:{f.server_address[1]}; concurrency 2 }}
pool a {{ server 127.0.0.1:{a.server_address[1]}; concurrency adaptive min=2 max=200 }}
http 127.0.0.1:{LF} {{ route /* {{ to pool f }} }}
http 127.0.0.1:{LA} {{ route /* {{ to pool a }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LA), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        t0 = time.time()
        with ThreadPoolExecutor(6) as ex:
            r = list(ex.map(lambda _: (get(LF), time.time() - t0), range(6)))
        ok = [x for x in r if x[0] == 200]
        shed = [x for x in r if x[0] == 503]
        check("concurrency 2: two at the backend, the rest 503 at once", len(ok) == 2 and len(shed) == 4 and f.most == 2
              and all(x[1] < 0.4 for x in shed), (r, f.most))
        # adaptive: 20 at a time, quick: none shed
        stop = [False]
        res = []

        def client():
            while not stop[0]:
                res.append((time.time(), get(LA)))
        ts = [threading.Thread(target=client, daemon=True) for _ in range(20)]
        for t in ts:
            t.start()
        time.sleep(1.5)
        quick = [s for (_, s) in res]
        check("adaptive, a quick backend under 20 at a time: nothing shed", quick and all(s == 200 for s in quick), quick.count(503))
        a.delay = 0.1                           # the backend slows tenfold
        slowed = time.time()
        a.most = 0
        time.sleep(4.5)
        a.most = 0
        time.sleep(1.5)
        late = [s for (t, s) in res if t > slowed + 4.5]
        stop[0] = True
        for t in ts:
            t.join(15)
        check("  slowed tenfold: within seconds, 503s at the edge", 503 in late and 200 in late, (late.count(200), late.count(503)))
        check("  and fewer at the backend at once than the 20 asking", a.most < 16, a.most)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"concurrency {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
