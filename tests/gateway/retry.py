#!/usr/bin/env python3
"""A route's `retry N on=...`, on one engine (argument): retry 0 lets a 503
through; retry 3 goes past three failing servers; on=500 retries what the
default leaves; on=timeout moves on from a silent backend (the default: 504);
a request with a body is never sent twice."""
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
BASE = 38000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, LT = BASE, BASE + 1
fails = 0
hits = {}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def answer(self):
        sv = self.server
        with sv.lock:
            hits[sv.name] = hits.get(sv.name, 0) + 1
        if sv.status == 0:
            time.sleep(3)
            return
        b = sv.name.encode()
        self.send_response(sv.status)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.answer()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.answer()

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def backend(name, status):
    s = S(("127.0.0.1", 0), H)
    s.name, s.status, s.lock = name, status, threading.Lock()
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return f"127.0.0.1:{s.server_address[1]}"


def req(port, path, method="GET", body=None):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.request(method, path, body=body)
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def main():
    f = [backend(f"f{i}", 503) for i in range(3)]
    ok = backend("ok", 200)
    e500, ok2 = backend("e500", 500), backend("ok2", 200)
    slow, ok3 = backend("slow", 0), backend("ok3", 200)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-retry-"))
    conf = tmp / "okena.conf"
    pools = lambda n, xs: f"pool {n} {{ balance round-robin; outlier errors=0; retry_budget 100% min=100/s; " + "".join(f"server {x}; " for x in xs) + "}\n"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
{pools("four", f + [ok])}{pools("two", [f[0], ok])}{pools("five", [e500, ok2])}{pools("slow", [slow, ok3])}
http 127.0.0.1:{L} {{
    route /none {{ to pool two; retry 0 }}
    route /three {{ to pool four; retry 3 idempotent-only }}
    route /once {{ to pool four }}
    route /500 {{ to pool five; retry 1 on=500,503 }}
    route /500d {{ to pool five }}
    route /post {{ to pool four; retry 3 }}
}}
http 127.0.0.1:{LT} {{
    timeout {{ response 1s }}
    route /t {{ to pool slow; retry 1 on=timeout }}
    route /td {{ to pool slow }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            if req(L, "/none")[0]:
                break
            time.sleep(0.05)
        r = [req(L, "/none")[0] for _ in range(6)]
        check("retry 0: a 503 reaches the client", 503 in r and 200 in r, r)
        r = [req(L, "/three") for _ in range(8)]
        check("retry 3: past three failing servers, every answer good", all(x == (200, "ok") for x in r), r)
        r = [req(L, "/once")[0] for _ in range(8)]
        check("  the default (once): some 503s get through", 503 in r, r)
        r = [req(L, "/500") for _ in range(6)]
        check("on=500: a 500 is retried", all(x == (200, "ok2") for x in r), r)
        r = [req(L, "/500d")[0] for _ in range(6)]
        check("  the default leaves a 500 alone", 500 in r, r)
        h0 = sum(hits.get(f"f{i}", 0) for i in range(3)) + hits.get("ok", 0)
        r = [req(L, "/post", "POST", b"x" * 10)[0] for _ in range(8)]
        h1 = sum(hits.get(f"f{i}", 0) for i in range(3)) + hits.get("ok", 0)
        check("a request with a body is never sent twice (retry 3)", h1 - h0 == 8 and 503 in r, (h1 - h0, r))
        r = []
        for _ in range(2):
            t0 = time.time()
            r.append((req(LT, "/t"), round(time.time() - t0, 1)))
        check("on=timeout: a silent backend, then the next one answers", all(x[0] == (200, "ok3") for x in r), r)
        r = [req(LT, "/td")[0] for _ in range(2)]
        check("  the default: 504", 504 in r, r)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"retry {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
