#!/usr/bin/env python3
"""`hedge` on a route, on one engine (argument): a slow server's requests answered
by the other, once and whole, with what the client would have had; what must not
be hedged; an answer of 5xx not winning; the budget; each protocol."""
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

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 30000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
FAST, SLOW, BAD, LST, TLS = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
failures = 0
hits = {}
lock = threading.Lock()


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


SLOW_DELAY = 0.3                    # six times `after=50ms`: a hedge is told from no hedge


def backend(port, name, delay=0, status=200):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def answer(self):
            with lock:
                hits[(name, self.path)] = hits.get((name, self.path), 0) + 1
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n:
                self.rfile.read(n)
            time.sleep(delay)
            body = name.encode() * (50000 if "big" in self.path else 1)
            self.send_response(status)
            if "chunked" in self.path:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for i in range(3):
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(body), body))
                self.wfile.write(b"0\r\n\r\n")
                return
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_HEAD = answer

        def log_message(self, *a):
            pass
    class S(http.server.ThreadingHTTPServer):
        request_queue_size = 256
        daemon_threads = True

        def handle_error(self, *a):
            # a hedge that won closes the loser's connection: its resets are
            # expected, and tracebacks from daemon threads at exit abort Python
            pass
    srv = S(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path, method="GET", body=None, headers=None, conn=None):
    c = conn or http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    b = r.read()
    if conn is None:
        c.close()
    return r, b


CONF = """okena {{ drain delay=0s timeout=1s; workers 2; io_engine {engine}; watchdog 5s }}
pool two {{ server 127.0.0.1:{fast}; server 127.0.0.1:{slow} }}
pool withbad {{ server 127.0.0.1:{slow}; server 127.0.0.1:{bad} }}
pool one {{ server 127.0.0.1:{slow} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    access_log {tmp}/access.log
    route /* {{ to pool two; hedge after=50ms }}
}}
http 127.0.0.1:{lst} {{
    route /h/* {{ to pool two; hedge after=50ms }}
    route /p {{ to pool two; hedge after=p95 }}
    route /bad/* {{ to pool withbad; hedge after=50ms }}
    route /one {{ to pool one; hedge after=50ms }}
    route /cors {{ to pool two; hedge after=50ms; cors origins=https://a.test }}
    route /plain/* {{ to pool two }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-hedge-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h.test",
                    "-addext", "subjectAltName=DNS:h.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    backend(FAST, "fast")
    backend(SLOW, "slow", delay=SLOW_DELAY)
    backend(BAD, "bad", status=503)
    conf = tmp / "okena.conf"
    args = dict(engine=ENGINE, fast=FAST, slow=SLOW, bad=BAD, lst=LST, tls=TLS, tmp=tmp)
    text = CONF.format(**args)
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen(["timeout", "--foreground", "90", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        get("/h/warm")              # (the first request after the start pays for it,
        ts, bodies = [], []         # which under a loaded host is not the hedge's time)
        for i in range(30):
            t0 = time.time()
            r, b = get(f"/h/{i}")
            ts.append(time.time() - t0)
            bodies.append((r.status, b))
        check(f"a slow server's requests hedged: worst {max(ts) * 1000:.0f} ms, not {SLOW_DELAY * 1000:.0f}",
              max(ts) < SLOW_DELAY and all(s == 200 for s, _ in bodies), str(ts))   # (not hedged: the slow one's time at least)
        check("  answered by the other, once", all(b == b"fast" for _, b in bodies)
              and all(hits.get(("fast", f"/h/{i}")) == 1 for i in range(30)), str(bodies[:3]))
        n = sum(1 for i in range(30) if ("slow", f"/h/{i}") in hits)
        check(f"  and hedges happened ({n} of 30)", n >= 5, str(n))
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        r = [get(f"/h/k{i}", conn=c)[1] for i in range(12)]
        check("a kept connection goes on after a hedge won", r == [b"fast"] * 12, str(r))
        c.close()
        rs = [get(f"/h/big{i}")[1] for i in range(12)]
        check("a body bigger than a buffer, whole", all(x == b"fast" * 50000 for x in rs), str([len(x) for x in rs]))
        rs = [get(f"/h/chunked{i}")[1] for i in range(12)]
        check("a chunked answer, whole", all(x == b"fast" * 3 for x in rs), str(rs[:2]))
        rs = [get(f"/h/head{i}", "HEAD") for i in range(12)]
        check("HEAD", all(x[0].status == 200 and x[1] == b"" for x in rs), str([x[0].status for x in rs]))
        before = hits.get(("slow", "/h/post"), 0) + hits.get(("fast", "/h/post"), 0)
        with ThreadPoolExecutor(12) as ex:      # (at once: each is its own exchange)
            list(ex.map(lambda i: get("/h/post", "POST", b"x"), range(12)))
        time.sleep(SLOW_DELAY + 0.1)
        after = hits.get(("slow", "/h/post"), 0) + hits.get(("fast", "/h/post"), 0)
        check("POST: never twice", after - before == 12, str(after - before))
        def timed(path):
            t0 = time.time()
            get(path)
            return time.time() - t0
        with ThreadPoolExecutor(10) as ex:
            ts = list(ex.map(lambda i: timed("/one"), range(10)))
        check("a pool of one: nothing to hedge to", min(ts) > SLOW_DELAY * 0.9 and hits[("slow", "/one")] == 10, str(hits[("slow", "/one")]))
        with ThreadPoolExecutor(10) as ex:
            r = list(ex.map(lambda i: get(f"/bad/{i}"), range(20)))
        got = {(x[0].status, x[1]) for x in r}
        check("a 503 does not beat the slow answer", (200, b"slow") in got and all(s != 500 for s, _ in got)
              and sum(1 for x in r if x[0].status == 200) >= 8, str(got))
        with ThreadPoolExecutor(16) as ex:
            list(ex.map(lambda i: get("/p"), range(120)))
        time.sleep(SLOW_DELAY + 0.1)
        check("after=p95: warm, slow ones hedged", hits.get(("fast", "/p"), 0) > 60, str((hits.get(("fast", "/p")), hits.get(("slow", "/p")))))
        r = [get("/cors", headers={"Origin": "https://a.test"})[0] for _ in range(10)]
        check("what the route adds is on a hedge's answer too",
              all(x.getheader("access-control-allow-origin") == "https://a.test" for x in r),
              str([x.getheader("access-control-allow-origin") for x in r]))
        with ThreadPoolExecutor(16) as ex:
            r = list(ex.map(lambda i: get(f"/h/load{i}")[0].status, range(400)))
        check("400 of them, 16 at a time: all answered", r.count(200) == 400, str({x: r.count(x) for x in set(r)}))
        for proto, flag in (("h1", "--http1.1"), ("h2", "--http2"), ("h3", "--http3-only")):
            good = slow = 0
            wrong = []
            def curl(job):
                path, i = job
                return path, i, subprocess.run(["timeout", "6", "curl", "-sSkv", flag, "--resolve", f"h.test:{TLS}:127.0.0.1",
                                                f"https://h.test:{TLS}/{path}{proto}{i}", "-w", "\\n%{http_code}"],
                                               capture_output=True, stdin=subprocess.DEVNULL)
            with ThreadPoolExecutor(8) as ex:
                runs = list(ex.map(curl, [(path, i) for path in ("x", "big", "chunked") for i in range(8)]))
            if True:
                for path, i, q in runs:
                    if q.returncode in (1, 2):
                        break
                    n = 50000 if path == "big" else 3 if path == "chunked" else 1
                    # (the slow server's, when the budget left no hedge: whole just the same)
                    if q.stdout == b"fast" * n + b"\n200":
                        good += 1
                    elif q.stdout == b"slow" * n + b"\n200":
                        slow += 1
                    else:
                        wrong.append((path, i, q.returncode, q.stderr.decode(errors="replace")[-700:]))
            check(f"over {proto}: answers whole, chunked and big ({good} hedged or fast, {slow} slow)",
                  good + slow == 24 and good >= 12, str(wrong[:3]))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    for bad in ("hedge", "hedge after=abc", "hedge after=p95 max=2", "hedge after=p0x"):
        c = tmp / "bad.conf"
        c.write_text(text.replace("hedge after=p95", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{bad}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[:90]}")
    print(f"hedge {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
