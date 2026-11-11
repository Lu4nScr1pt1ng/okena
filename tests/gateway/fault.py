#!/usr/bin/env python3
"""`fault` on a route, on one engine (argument): the status it answers, how
long it holds a request, the share of the requests it takes, the routes without one untouched, and values
that make no sense refused."""
import http.client
import http.server
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 25000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
failures = 0
seen = [0]


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen[0] += 1
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
    return r.status, r.reason


CONF = """okena {{ workers 1; io_engine {engine}; drain delay=0s timeout=1s }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ to 127.0.0.1:{back}; fault delay=100ms }}
}}
http 127.0.0.1:{lst} {{
    route /all {{ to 127.0.0.1:{back}; fault abort=503 }}
    route /half {{ to 127.0.0.1:{back}; fault abort=429 percent=50 }}
    route /fine {{ to 127.0.0.1:{back} }}
    route /slow {{ to 127.0.0.1:{back}; fault delay=200ms }}
    route /slowfail {{ to 127.0.0.1:{back}; fault delay=200ms abort=503 }}
    route /short {{ to 127.0.0.1:{back}; fault delay=50ms }}
    route /someslow {{ to 127.0.0.1:{back}; fault delay=100ms percent=50 }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-fault-"))
    http.server.ThreadingHTTPServer.request_queue_size = 256	# (a burst of connections)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=f.test",
                    "-addext", "subjectAltName=DNS:f.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    conf.write_text(CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp))
    p = subprocess.Popen(["timeout", "--foreground", "30", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        time.sleep(0.5)
        r = [get("/all") for _ in range(20)]
        check("abort=503: every request, the backend not asked",
              all(x == (503, "Service Unavailable") for x in r) and seen[0] == 0, f"{r[:3]} {seen[0]}")
        check("a route without one goes through", get("/fine")[0] == 200 and seen[0] == 1, str(seen[0]))
        with ThreadPoolExecutor(16) as ex:      # (each on its own: the share is per request)
            r = list(ex.map(lambda i: get("/half")[0], range(400)))
        n = r.count(429)
        check("percent=50: about half, the status named", 140 <= n <= 260 and set(r) == {200, 429}, f"{n} {set(r)}")
        t0 = time.time()
        s = get("/slow")
        dt = time.time() - t0
        check("delay=200ms: answered, that much later", s[0] == 200 and 0.19 < dt < 0.4, f"{s} {dt:.3f}")
        t0 = time.time()
        s = get("/slowfail")
        dt = time.time() - t0
        check("delay and abort: the status, that much later", s[0] == 503 and 0.19 < dt < 0.4, f"{s} {dt:.3f}")
        before = seen[0]
        t0 = time.time()
        with ThreadPoolExecutor(32) as ex:
            r = list(ex.map(get, ["/slow"] * 32))
        dt = time.time() - t0
        check("32 at once, held together, none lost", r.count((200, "OK")) == 32 and seen[0] == before + 32
              and dt < 1.5, f"{r[:2]} {seen[0] - before} {dt:.3f}")   # (one after another: 6.4 s)
        def timed(i):
            t0 = time.time()
            get("/someslow")
            return time.time() - t0
        with ThreadPoolExecutor(12) as ex:      # (each timed on its own)
            ts = list(ex.map(timed, range(60)))
        n = sum(x > 0.09 for x in ts)
        check("percent=50: about half wait", 15 <= n <= 45, str(n))
        with ThreadPoolExecutor(2) as ex:			# a shorter wait behind a longer one
            t0 = time.time()
            ex.submit(get, "/slow")
            time.sleep(0.02)
            get("/short")
            dt = time.time() - t0
        check("  a shorter wait after a longer one: its own", 0.05 < dt < 0.17, f"{dt:.3f}")
        for proto in ("h1", "h2", "h3"):			# parsed again: each way a request comes
            r = subprocess.run(["timeout", "10", str(BIN), "bench", f"https://127.0.0.1:{TLS}/", f"proto={proto}",
                                "conns=2", "duration=1s", "warmup=0s", "workers=1", "format=kv"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            kv = dict(x.split("=", 1) for x in r.stdout.split() if "=" in x)
            check(f"over {proto}: held, then answered", int(kv.get("ok", 0)) >= 10 and kv.get("errors") == "0"
                  and 90e6 < float(kv.get("c_p50_ns", 0)) < 160e6, r.stdout[:120])
        c = socket.create_connection(("127.0.0.1", LST))		# a client that goes while held
        c.sendall(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
        c.close()
        time.sleep(0.3)
        check("  its client gone: the worker goes on", get("/fine")[0] == 200)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)	# keep-alive across a held request
        c.request("GET", "/slow")
        a = c.getresponse()
        a.read()
        c.request("GET", "/fine")
        b = c.getresponse()
        b.read()
        c.close()
        check("  the connection stays usable after it", (a.status, b.status) == (200, 200), f"{a.status} {b.status}")
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("fault abort=200", "fault abort=700", "fault percent=50", "fault abort=503 percent=101",
                "fault delay=0ms", "fault delay=11m"):
        c = tmp / "bad.conf"
        c.write_text(CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp).replace("fault abort=503", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{bad}: refused", q.returncode not in (0, 124) and "fault" in q.stderr, f"{q.returncode} {q.stderr[:90]}")
    print(f"fault {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
