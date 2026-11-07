#!/usr/bin/env python3
"""`server ADDR max=N`, `queue timeout=` and `balance first`, on one engine
(argument): a server never has more than its max at once, across workers,
requests wait their turn, and the first servers are filled first."""
import collections
import http.client
import http.server
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
from concurrent.futures import ThreadPoolExecutor

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LIM, SHORT, FIRST, TCP = 18670, 18671, 18672, 18673
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        sv = self.server
        with sv.lock:
            sv.now += 1
            sv.most = max(sv.most, sv.now)
            sv.seen += 1
        time.sleep(float(self.path.split("=")[1]) if "=" in self.path else 0)
        with sv.lock:
            sv.now -= 1
        b = sv.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


def backend(name):
    s = S(("127.0.0.1", 0), H)
    s.name, s.now, s.most, s.seen, s.lock = name, 0, 0, 0, threading.Lock()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"127.0.0.1:{s.server_address[1]}"


def get(port, path="/"):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", path)
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def reset(*bs):
    for s, a in bs:
        s.most = s.now = s.seen = 0


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-max-", dir="/tmp"))
    conf = tmp / "okena.conf"
    a, b = backend("a"), backend("b")
    f = [backend(f"f{i}") for i in range(3)]
    t = socket.socket()
    t.bind(("127.0.0.1", 0))
    t.listen(16)
    held = []
    threading.Thread(target=lambda: [held.append(t.accept()) for _ in iter(int, 1)], daemon=True).start()
    conf.write_text(f"""okena {{ workers 4; io_engine {ENGINE} }}
pool lim {{ server {a[1]} max=2; server {b[1]} max=2 }}
pool short {{ queue timeout=300ms; server {a[1]} max=1 }}
pool fst {{ balance first; {''.join(f'server {x[1]} max=2; ' for x in f)}}}
pool tl {{ server 127.0.0.1:{t.getsockname()[1]} max=1 }}
http 127.0.0.1:{LIM} {{ route /* {{ to pool lim }} }}
http 127.0.0.1:{SHORT} {{ route /* {{ to pool short }} }}
http 127.0.0.1:{FIRST} {{ route /* {{ to pool fst }} }}
tcp 127.0.0.1:{TCP} {{ to pool tl }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(100):
            if get(LIM)[0] == 200:
                break
            time.sleep(0.05)
        reset(a, b)
        t0 = time.time()
        with ThreadPoolExecutor(16) as ex:
            r = list(ex.map(lambda i: get(LIM, "/?s=0.4"), range(16)))
        dt = time.time() - t0
        check("16 at once on 4 places, over 4 workers: all served", [x[0] for x in r] == [200] * 16, collections.Counter(x[0] for x in r))
        check("  no server ever had more than its max", a[0].most <= 2 and b[0].most <= 2, (a[0].most, b[0].most))
        check("  and both were used to the full", a[0].most == 2 and b[0].most == 2, (a[0].most, b[0].most))
        check("  in turns: about four of 0.4 s", 1.5 <= dt <= 2.6, round(dt, 2))
        reset(a, b)
        with ThreadPoolExecutor(96) as ex:              # workers racing for the last place
            r = list(ex.map(lambda i: get(LIM, "/?s=0.01"), range(800)))
        check("800 short ones, 96 at a time: all served, never past the max", r.count((200, "a")) + r.count((200, "b")) == 800 and a[0].most <= 2 and b[0].most <= 2,
              (collections.Counter(x[0] for x in r), a[0].most, b[0].most))

        # waiting longer than the queue lets: 503
        reset(a, b)
        with ThreadPoolExecutor(6) as ex:
            r = list(ex.map(lambda i: get(SHORT, "/?s=0.5"), range(6)))
        n = collections.Counter(x[0] for x in r)
        check("a queue of 300 ms in front of a server of one, 6 asking for 0.5 s each: some 503", n[503] >= 2 and n[200] >= 1 and a[0].most <= 1,
              (n, a[0].most))
        check("  and the server was never asked for two at once", a[0].most == 1, a[0].most)

        # first: the first servers fill first
        for x in f:
            reset(x)
        for i in range(10):
            get(FIRST)
        check("first: one at a time, all to the first", [x[0].seen for x in f] == [10, 0, 0], [x[0].seen for x in f])
        for x in f:
            reset(x)
        with ThreadPoolExecutor(5) as ex:
            r = list(ex.map(lambda i: get(FIRST, "/?s=0.4"), range(5)))
        check("  five at once: two, two, one", [x[0].most for x in f] == [2, 2, 1] and all(x[0] == 200 for x in r), ([x[0].most for x in f], r))

        # tcp does not queue
        c1 = socket.create_connection(("127.0.0.1", TCP), 2)
        time.sleep(0.2)
        c2 = socket.create_connection(("127.0.0.1", TCP), 2)
        c2.settimeout(2)
        try:
            got = c2.recv(10)
        except OSError as e:
            got = e
        check("tcp, a server of one, taken: the next connection is closed", got == b"" or isinstance(got, ConnectionResetError), got)
        time.sleep(0.2)
        check("  and the server saw one", len(held) == 1, len(held))
        c1.close()
        c2.close()

        # a worker killed with connections in use gives its places back
        reset(a, b)
        kids = subprocess.run(["pgrep", "-P", str(p.pid), "-x", "okena"], capture_output=True, text=True).stdout.split()
        with ThreadPoolExecutor(4) as ex:
            futs = [ex.submit(get, LIM, "/?s=1.5") for i in range(4)]
            time.sleep(0.4)
            for k in kids:
                try:
                    os.kill(int(k), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            [x.result() for x in futs]
        time.sleep(1.0)
        reset(a, b)
        with ThreadPoolExecutor(8) as ex:
            r = list(ex.map(lambda i: get(LIM, "/?s=0.3"), range(8)))
        check("workers killed while full: their places come back", [x[0] for x in r] == [200] * 8 and a[0].most == 2 and b[0].most == 2,
              (collections.Counter(x[0] for x in r), a[0].most, b[0].most))
    finally:
        p.terminate()
        p.wait(10)
    text = log.read_text()
    check("no worker died but those killed", "seccomp" not in text and text.count("killed by signal 9") <= 4, text[-300:])

    def bad(what, body):
        g = tmp / "bad.conf"
        g.write_text(f"pool p {{ {body} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("max=0", "server 127.0.0.1:1 max=0")
    bad("max=many", "server 127.0.0.1:1 max=many")
    bad("queue with no time", "queue timeout=soon; server 127.0.0.1:1")
    bad("first with a key", "balance first key=source; server 127.0.0.1:1")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"maxconn {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
