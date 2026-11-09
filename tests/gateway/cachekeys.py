#!/usr/bin/env python3
"""What `cache` keeps an answer under, what it tells, and what it does when the
backend fails, on one engine (argument): query= (all, none, the parameters named, in
their order), host=off, Accept-Encoding in vary= as the codings it takes; Cache-Status
(RFC 9211) on every answer of a cached route; stale-if-error, the route's and the
origin's, from memory and from disk, and must-revalidate taking it away."""
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

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 48000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, DOWN = BASE, BASE + 1, BASE + 2
fails = 0
BIG = bytes(range(256)) * 400                  # 102400 bytes
hits = {}
state = {"fail": set(), "n": 0}
lock = threading.Lock()


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
    protocol_version = "HTTP/1.1"

    def answer(self):
        if self.server.dead:                    # (its kept-alive connections too)
            self.close_connection = True
            return
        path = self.path.split("?")[0]
        with lock:
            hits[path] = hits.get(path, 0) + 1
            state["n"] += 1
            n = state["n"]
        n_ = int(self.headers.get("Content-Length", 0) or 0)
        if n_:
            self.rfile.read(n_)
        if path in state["fail"]:
            b = b"backend down"
            self.send_response(503)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        b = f"{path} #{n}".encode()
        if path.startswith("/rng/"):
            b = BIG
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        if path.startswith("/cc/"):
            self.send_header("Cache-Control", path.split("/")[2].replace("_", ", ").replace("-eq-", "="))
        if path.startswith("/nostore"):
            self.send_header("Cache-Control", "no-store")
        if path.startswith("/ae"):
            self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        self.wfile.write(b)
    do_GET = do_POST = answer

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    dead = False

    def handle_error(self, *a):
        pass


def get(path, host="t", method="GET", headers=None, port=LST, full=False):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host}
    h.update(headers or {})
    c.request(method, path, body=b"x" if method == "POST" else None, headers=h)
    r = c.getresponse()
    b = r.read()
    c.close()
    if full:
        return r.status, b, r.getheader("cache-status", ""), r
    return r.status, b, r.getheader("cache-status", "")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ckeys-", dir="/tmp"))
    (tmp / "store").mkdir()
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    down = S(("127.0.0.1", DOWN), H)
    threading.Thread(target=down.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 4; io_engine {ENGINE}; drain delay=0s timeout=1s
    cache_memory 1MiB; cache_disk {tmp}/store size=8MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
pool d {{ server 127.0.0.1:{DOWN} }}
http 127.0.0.1:{LST} {{
    route /qnone/* {{ cache 1h query=none; to pool b }}
    route /qsome/* {{ cache 1h query=v,lang; to pool b }}
    route /nohost/* {{ cache 1h host=off; to pool b }}
    route /ae/* {{ cache 1h vary=accept-encoding; to pool b }}
    route /sie/* {{ cache 1s stale-if-error=60s; to pool b }}
    route /short/* {{ cache 1s stale-if-error=1s; to pool b }}
    route /down/* {{ cache 1s stale-if-error=60s; to pool d }}
    route /nocache/* {{ to pool b }}
    route /* {{ cache 1h; to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get("/up")[0] == 200), log.read_text()[-300:])

        # the key
        a = [get(f"/qnone/a?x={i}") for i in range(4)]
        check("query=none: the query is not in the key", hits["/qnone/a"] == 1 and len({x[1] for x in a}) == 1, hits["/qnone/a"])
        b1 = get("/qsome/b?v=1&lang=pt&utm=a")
        b2 = get("/qsome/b?utm=zz&lang=pt&v=1&x=9")
        check("query=v,lang: only those, whatever their order and the rest", hits["/qsome/b"] == 1 and b1[1] == b2[1], hits["/qsome/b"])
        get("/qsome/b?v=2&lang=pt")
        check("  another value: another answer", hits["/qsome/b"] == 2)
        get("/qsome/b?lang=pt")
        get("/qsome/b?v=&lang=pt")
        check("  absent and empty are not the same", hits["/qsome/b"] == 4, hits["/qsome/b"])
        get("/nohost/c", host="a.example")
        s, body, cs = get("/nohost/c", host="b.example")
        check("host=off: one answer for every host", hits["/nohost/c"] == 1 and "hit" in cs, (hits["/nohost/c"], cs))
        get("/d", host="a.example")
        get("/d", host="b.example")
        get("/d?x=1", host="a.example")
        check("by default: host and the whole target", hits["/d"] == 3, hits["/d"])

        # Accept-Encoding: the codings, not the words
        same = ["gzip, br", "br,gzip", "br;q=1, gzip;q=0.5", "br, gzip, identity", "br;q=0.0001, gzip"]
        for v in same:
            get("/ae/e", headers={"Accept-Encoding": v})
        check("Accept-Encoding in vary=: the same codings, one answer", hits["/ae/e"] == 1, hits["/ae/e"])
        get("/ae/e", headers={"Accept-Encoding": "gzip"})
        get("/ae/e")
        check("  others: gzip alone, none at all", hits["/ae/e"] == 3, hits["/ae/e"])
        get("/ae/e", headers={"Accept-Encoding": "br;q=0"})
        get("/ae/e", headers={"Accept-Encoding": "gzip;q=0.000, identity"})
        get("/ae/e", headers={"Accept-Encoding": "br;q=0, gzip"})
        check("  q=0 takes a coding away: br;q=0 is none, br;q=0, gzip is gzip alone", hits["/ae/e"] == 3, hits["/ae/e"])

        # Cache-Status
        st = {
            "a miss, kept": get("/cs1")[2],
            "a hit": get("/cs1")[2],
            "not kept (no-store)": get("/nostore1")[2],
            "for one person (Cookie)": get("/cs2", headers={"Cookie": "a=b"})[2],
            "a range": get("/cs3", headers={"Range": "bytes=0-1"})[2],
            "a POST": get("/cs4", method="POST")[2],
            "a route without cache": get("/nocache/x")[2],
        }
        want = {"a miss, kept": "okena; fwd=miss; stored", "not kept (no-store)": "okena; fwd=miss",
                "for one person (Cookie)": "okena; fwd=bypass", "a range": "okena; fwd=miss",
                "a POST": "okena; fwd=method", "a route without cache": ""}
        check("Cache-Status on every answer of a cached route (RFC 9211)",
              all(st[k] == v for k, v in want.items()) and st["a hit"].startswith("okena; hit; ttl="), st)

        # Range: a hit answers it
        rp = "/rng/a"
        r = get(rp, headers={"Range": "bytes=0-9"}, full=True)
        check("a Range on a miss: to the backend, and nothing kept", r[1] in (BIG, BIG[:10]) and "stored" not in r[2], r[2])
        get(rp)
        h0 = hits[rp]
        N = len(BIG)
        cases = {"bytes=0-99": (0, 99), "bytes=100-199": (100, 199), f"bytes={N - 10}-": (N - 10, N - 1),
                 "bytes=-5": (N - 5, N - 1), f"bytes=50000-{N * 3}": (50000, N - 1), "bytes=-999999": (0, N - 1)}
        ok = True
        bad = []
        for rv, (a, b) in cases.items():
            s, body, cs, r = get(rp, headers={"Range": rv}, full=True)
            good = (s == 206 and body == BIG[a:b + 1] and r.getheader("content-range") == f"bytes {a}-{b}/{N}"
                    and r.getheader("content-length") == str(b - a + 1) and cs.startswith("okena; hit"))
            ok &= good
            if not good:
                bad.append((rv, s, len(body), r.getheader("content-range"), cs))
        check("a hit answers a Range: 206, its bytes, Content-Range (a-b, a-, -n, an end past it)", ok and hits[rp] == h0, bad)
        s, body, cs, r = get(rp, headers={"Range": f"bytes={N}-"}, full=True)
        check("  past the end: 416, Content-Range: bytes */N", s == 416 and body == b"" and r.getheader("content-range") == f"bytes */{N}",
              (s, r.getheader("content-range")))
        outs = [get(rp, headers={"Range": v}) for v in ("bytes=0-1,5-6", "items=0-1", "bytes=x-y")]
        outs.append(get(rp, headers={"Range": "bytes=0-1", "If-Range": '"abc"'}))
        check("  several ranges, another unit, garbage, If-Range: all of it (200)", all(o[0] == 200 and o[1] == BIG for o in outs),
              [(o[0], len(o[1])) for o in outs])
        s, body, cs, r = get(rp, method="HEAD", headers={"Range": "bytes=10-19"}, full=True)
        check("  HEAD with a Range: the 206 head, no body", s == 206 and body == b"" and r.getheader("content-length") == "10", (s, r.getheader("content-length")))
        outs = [get(rp, headers={"Range": "bytes=1000-1999"}, full=True) for _ in range(12)]
        check("  from disk on the other workers too", all(o[0] == 206 and o[1] == BIG[1000:2000] for o in outs)
              and any("detail=disk" in o[2] for o in outs) and hits[rp] == h0, {o[2] for o in outs})

        # stale-if-error: the route's
        p1 = "/sie/a"
        s, first, _ = get(p1)
        time.sleep(1.3)
        state["fail"].add(p1)
        s, b, cs = get(p1)
        check("stale-if-error: the backend answers 503, the stale copy answers instead",
              s == 200 and b == first and cs.startswith("okena; fwd=stale; fwd-status=503; ttl=-"), (s, b, cs))
        out = [get(p1) for _ in range(12)]
        check("  on every worker (from disk where memory has none)", all(o[0] == 200 and o[1] == first for o in out)
              and any("detail=disk" in o[2] for o in out), {o[2] for o in out})
        state["fail"].discard(p1)
        s, b, cs = get(p1)
        check("  the backend back: a fresh answer, kept", s == 200 and b != first and "fwd=miss; stored" in cs, (s, b, cs))

        # a backend that is not there at all: okena's own 502
        p2 = "/down/a"
        s, first, _ = get(p2)
        time.sleep(1.3)
        down.dead = True
        down.shutdown()
        down.server_close()
        s, b, cs = get(p2)
        check("a backend gone (502): the stale copy", s == 200 and b == first and "fwd-status=502" in cs, (s, b, cs))

        # past the window: the error goes through
        p3 = "/short/a"
        get(p3)
        time.sleep(2.4)
        state["fail"].add(p3)
        s, b, cs = get(p3)
        check("past stale-if-error: the error is the answer", s == 503 and b == b"backend down", (s, b, cs))

        # the origin's, and must-revalidate
        p4 = "/cc/max-age-eq-1_stale-if-error-eq-60/a"
        s, first, _ = get(p4)
        time.sleep(1.3)
        state["fail"].add(p4)
        s, b, cs = get(p4)
        check("the origin's stale-if-error (Cache-Control)", s == 200 and b == first and "fwd=stale" in cs, (s, b, cs))
        p5 = "/cc/max-age-eq-1_must-revalidate_stale-if-error-eq-60/a"
        get(p5)
        time.sleep(1.3)
        state["fail"].add(p5)
        s, b, cs = get(p5)
        check("  must-revalidate takes it away", s == 503, (s, b, cs))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"cachekeys {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
