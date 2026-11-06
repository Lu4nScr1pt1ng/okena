#!/usr/bin/env python3
"""`cache` on a route, on one engine (argument). What must not happen comes first:
one person's answer reaching another, a cut body kept as if it were whole. Then
that it works: the backend hears once, a popular object that expires costs one
request, what okena adds to an answer is fresh on a hit."""
import hashlib
import http.client
import http.server
import os
import pathlib
import random
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
BASE = 13000 + os.getpid() % 90 * 8 + (4 if ENGINE == "epoll" else 0)	# ports 13000-13719: this suite's own
BACK, LST, TLS, SMALL = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
hits = {}
BIG = random.Random(7).randbytes(300000)
HUGE = b"x" * (2 << 20)
ver = {"n": 0}


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send(self, body, status=200, **h):
        self.send_response(status)
        for k, v in h.items():
            self.send_header(k.replace("_", "-"), v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0].split("/")[-1]
        hits[self.path] = hits.get(self.path, 0) + 1
        n = hits[self.path]
        c = f"{self.path} #{n}".encode()
        if p == "plain":
            self.send(c, x_backend="yes")
        elif p == "chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (c, b"-tail"):
                self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif p == "noframe":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(c)
            self.close_connection = True
        elif p == "cut":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"short")
            self.wfile.flush()
            self.close_connection = True
        elif p == "chunkcut":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"5\r\nshort\r\n")
            self.wfile.flush()
            self.close_connection = True
        elif p == "nostore":
            self.send(c, Cache_Control="no-store")
        elif p == "private":
            self.send(c, Cache_Control="private, max-age=100")
        elif p == "nocache":
            self.send(c, Cache_Control='no-cache="x", max-age=100')
        elif p == "twocc":
            self.send_response(200)
            self.send_header("Cache-Control", "max-age=100")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(c)))
            self.end_headers()
            self.wfile.write(c)
        elif p == "cookie":
            self.send(c, Set_Cookie="s=1")
        elif p == "varyother":
            self.send(c, Vary="x-other")
        elif p == "varystar":
            self.send(c, Vary="*")
        elif p == "vary":
            self.send(c + b" " + self.headers.get("accept-encoding", "-").encode(), Vary="Accept-Encoding")
        elif p == "short":
            self.send(c, Cache_Control="max-age=1")
        elif p == "smax":
            self.send(c, Cache_Control="max-age=100, s-maxage=1")
        elif p == "big":
            self.send(BIG)
        elif p == "drip":
            self.send_response(200)
            self.send_header("Content-Length", "20000")
            self.end_headers()
            self.wfile.write(b"a" * 10000)
            self.wfile.flush()
            time.sleep(0.3)
            self.wfile.write(b"b" * 10000)
        elif p == "bigchunk":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(30):
                self.wfile.write(b"2710\r\n" + b"c" * 10000 + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif p == "huge":
            self.send(HUGE)
        elif p == "e500":
            self.send(c, 500)
        elif p == "e404":
            self.send(c, 404)
        elif p == "slow":
            time.sleep(0.3)
            self.send(c)
        elif p == "slow500":
            time.sleep(0.2)
            self.send(c, 500)
        elif p == "swr":
            time.sleep(0.2 if n > 1 else 0)
            self.send(c, Cache_Control="max-age=1")
        elif p == "strict":
            self.send(c, Cache_Control="max-age=1, must-revalidate")
        elif p == "who":
            self.send(self.headers.get("cookie", "-").encode() + (self.headers.get("x-user-id") or "-").encode())
        else:
            self.send(c)

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, *a):
        pass


def get(path, port=LST, method="GET", conn=None, **hdr):
    c = conn or http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    c.request(method, path, headers={k.replace("_", "-"): v for k, v in hdr.items()})
    r = c.getresponse()
    b = r.read()
    if not conn:
        c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


def status_of(r):
    return r[2].get("cache-status", "")


def hit(r):
    return "hit" in status_of(r)


CONF = """okena {{ workers 1; io_engine {engine} }}
pool b {{ server 127.0.0.1:{back} }}
http 127.0.0.1:{lst} {{
    route /c/* {{ cache 60s vary=accept-encoding; to pool b }}
    route /t/* {{ cache 1s; to pool b }}
    route /s/* {{ cache 1s stale-while-revalidate=4s; to pool b }}
    route /shared/* {{ cache 60s shared=on; to pool b }}
    route /key/* {{ auth api_key header=x-api-key keys={tmp}/keys; cache 60s; to pool b }}
    route /max/* {{ cache 60s max=4KiB; to pool b }}
    route /cors/* {{ cors origins=https://a.test,https://b.test; cache 60s; response header set x-mine okena; to pool b }}
    route /none/* {{ to pool b }}
}}
http 127.0.0.1:{tls} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    route /c/* {{ cache 60s; to pool b }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-cache."))
    (tmp / "keys").write_text("alice:ka\nbob:kb\n")
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2",
                    "-out", tmp / "c.pem"], check=True)
    threading.Thread(target=S(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(CONF.format(engine=ENGINE, back=BACK, lst=LST, tls=TLS, tmp=tmp))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        a = get("/c/plain")
        b = get("/c/plain")
        check("a miss, then a hit, the backend once", a[1] == b[1] == b"/c/plain #1" and hits["/c/plain"] == 1 and hit(b), (a[:2], b[:2], status_of(b)))
        check("  the backend's fields are kept", b[2].get("x-backend") == "yes")
        check("  it says how old", "age" in b[2], b[2])
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        seq = [get("/c/plain", conn=c)[1] for i in range(5)]
        check("hits on one connection", seq == [b"/c/plain #1"] * 5 and hits["/c/plain"] == 1, seq)
        c.close()
        r = get("/c/plain", method="HEAD")
        check("HEAD reads what GET kept", r[0] == 200 and r[1] == b"" and hit(r) and int(r[2]["content-length"]) == 11, r)
        get("/c/head-first", method="HEAD")
        r = get("/c/head-first")
        check("  and fills nothing", r[1] == b"/c/head-first #2", r[:2])

        get("/c/chunked")
        r = get("/c/chunked")
        check("a chunked answer is kept, its length told", r[1] == b"/c/chunked #1-tail" and hit(r) and r[2].get("content-length") == "18", r)
        get("/c/big")
        r = get("/c/big")
        check("300 KB through many blocks, byte for byte", hit(r) and hashlib.sha256(r[1]).digest() == hashlib.sha256(BIG).digest(), len(r[1]))

        for what, path in (("no length, so a cut cannot be told", "/c/noframe"), ("no-store", "/c/nostore"), ("private", "/c/private"),
                           ("no-cache", "/c/nocache"), ("no-store in a second field", "/c/twocc"), ("Set-Cookie", "/c/cookie"),
                           ("Vary on a field not in the key", "/c/varyother"), ("Vary: *", "/c/varystar"), ("a 500", "/c/e500")):
            x, y = get(path), get(path)
            time.sleep(1.05 if False else 0)
            check(f"{what}: not kept", not hit(y) and hits[path] == 2, (hits.get(path), y[:2]))
        x = get("/c/cut") if False else None
        for what, path in (("a body shorter than it said", "/c/cut"), ("a chunked body that stops", "/c/chunkcut")):
            for i in range(2):
                try:
                    get(path)
                except (http.client.HTTPException, OSError):
                    pass
                time.sleep(1.1)
            check(f"{what}: not kept", hits[path] == 2, hits.get(path))
        r = get("/c/e404"), get("/c/e404")
        check("a 404 is kept", hit(r[1]) and r[1][0] == 404, r[1][:2])
        get("/max/big")
        time.sleep(1.1)
        r = get("/max/big")
        check("bigger than max=: passes, whole", hits["/max/big"] == 2 and len(r[1]) == len(BIG), hits.get("/max/big"))
        r = get("/max/bigchunk")
        time.sleep(1.1)
        get("/max/bigchunk")
        check("bigger than max= with no length said: passes, whole", hits["/max/bigchunk"] == 2 and len(r[1]) == 300000, (hits.get("/max/bigchunk"), len(r[1])))
        get("/c/huge")
        r = get("/c/huge")
        check("over the default 1 MiB too", len(r[1]) == len(HUGE), len(r[1]))

        # one person's answer, another's
        n = hits.get("/c/who", 0)
        r1, r2 = get("/c/who", Cookie="s=alice"), get("/c/who", Cookie="s=bob")
        check("Cookie: neither kept nor served", r1[1].startswith(b"s=alice") and r2[1].startswith(b"s=bob"), (r1[1], r2[1]))
        get("/c/mine")
        r = get("/c/mine", Authorization="Bearer x")
        check("Authorization: goes to the backend", not hit(r), status_of(r))
        r = get("/c/mine", Cookie="a=1")
        check("  so does Cookie, with one kept", not hit(r))
        r1, r2 = get("/key/who", x_api_key="ka"), get("/key/who", x_api_key="kb")
        check("a route with auth: each their own", not hit(r2) and hits["/key/who"] == 2, status_of(r2))
        check("  no key, no answer, kept or not", get("/key/who")[0] == 401)
        get("/shared/who", Cookie="s=one")
        r = get("/shared/who", Cookie="s=two")
        check("shared=on says it is the same for all", hit(r) and r[1].startswith(b"s=one"), r[1])

        # Vary
        a, b = get("/c/vary", Accept_Encoding="gzip"), get("/c/vary", Accept_Encoding="br")
        c = get("/c/vary", Accept_Encoding="gzip")
        check("Vary: each its own", b"gzip" in a[1] and b"br" in b[1] and not hit(b) and hit(c) and b"gzip" in c[1], (a[1], b[1], c[1]))
        # what okena adds is the client's
        a = get("/cors/o", Origin="https://a.test")
        b = get("/cors/o", Origin="https://b.test")
        c = get("/cors/o", Origin="https://evil.test")
        check("CORS is the client's, on a hit", hit(b) and b[2].get("access-control-allow-origin") == "https://b.test" and
              "access-control-allow-origin" not in c[2], (b[2], c[2]))
        check("  `response` rules too", b[2].get("x-mine") == "okena")

        # time
        get("/t/plain")
        check("fresh", hit(get("/t/plain")))
        time.sleep(1.2)
        r = get("/t/plain")
        check("expired: fetched again", not hit(r) and hits["/t/plain"] == 2, status_of(r))
        get("/c/short")
        time.sleep(1.2)
        get("/c/short")
        check("max-age over the route's time", hits["/c/short"] == 2, hits["/c/short"])
        get("/c/smax")
        time.sleep(1.2)
        get("/c/smax")
        check("s-maxage over max-age", hits["/c/smax"] == 2)

        # stale-while-revalidate
        get("/s/swr")
        time.sleep(1.2)
        t = time.time()
        r = get("/s/swr")
        check("stale: at once, and old", time.time() - t < 0.15 and hit(r) and r[1] == b"/s/swr #1" and "ttl=-" in status_of(r), (time.time() - t, r[1], status_of(r)))
        time.sleep(0.4)
        r = get("/s/swr")
        check("  fetched behind it, one time", hits["/s/swr"] == 2 and r[1] == b"/s/swr #2" and "ttl=-" not in status_of(r), (hits["/s/swr"], r[1], status_of(r)))
        get("/s/strict")
        time.sleep(1.2)
        r = get("/s/strict")
        check("must-revalidate has no stale window", not hit(r) and hits["/s/strict"] == 2, hits.get("/s/strict"))
        get("/s/gone")
        time.sleep(5.3)
        r = get("/s/gone")
        check("past the window: a miss", not hit(r) and hits["/s/gone"] == 2, hits.get("/s/gone"))

        # many at once
        res = []
        th = [threading.Thread(target=lambda: res.append(get("/c/slow")[1])) for i in range(30)]
        [t.start() for t in th]
        [t.join() for t in th]
        check("30 at once: the backend once, all answered", hits["/c/slow"] == 1 and res == [b"/c/slow #1"] * 30, (hits["/c/slow"], res[:3]))
        res = []
        th = [threading.Thread(target=lambda: res.append(get("/c/slow500")[0])) for i in range(6)]
        [t.start() for t in th]
        [t.join() for t in th]
        check("a fill that fails: nobody is left waiting", res == [500] * 6, res)
        # who fills leaves
        s = socket.create_connection(("127.0.0.1", LST))
        s.sendall(f"GET /c/drip HTTP/1.1\r\nHost: 127.0.0.1:{LST}\r\nAccept-Encoding: identity\r\n\r\n".encode())
        s.recv(100)
        s.close()
        time.sleep(0.05)
        t = time.time()
        r = get("/c/drip")
        check("a client that leaves mid-fill leaves nothing half, and nobody waiting", r[1] == b"a" * 10000 + b"b" * 10000 and
              time.time() - t < 1.5, (len(r[1]), time.time() - t, hits["/c/drip"]))

        q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "-o", "-", "-D", "-", f"https://localhost:{TLS}/c/plain2",
                            f"https://localhost:{TLS}/c/plain2"], capture_output=True, text=True)
        check("over HTTP/2", q.stdout.count("cache-status: okena; hit") == 1 and "HTTP/2 200" in q.stdout and hits["/c/plain2"] == 1, q.stdout[-300:])
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{TLS}/c/plain3", "proto=h3", "conns=4", "workers=1",
                            "rate=400", "duration=1s", "warmup=0s", "format=kv"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
        check("over HTTP/3", kv.get("ok") == "400" and hits["/c/plain3"] == 1, (str(kv)[:90], hits.get("/c/plain3")))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])

    # little memory, much to keep
    small = tmp / "small.conf"
    small.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; cache_memory 1MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{SMALL} {{ route /e/* {{ cache 60s; to pool b }} }}
""")
    log2 = tmp / "log2"
    p = subprocess.Popen([str(BIN), "-c", str(small)], stderr=open(log2, "w"))
    try:
        time.sleep(0.4)
        bad = 0
        for i in range(12):
            r = get(f"/e/{i}/big", port=SMALL)
            bad += r[1] != BIG
        check("memory runs out: the old go, what is served stays whole", bad == 0, bad)
        r1, r2 = get("/e/11/big", port=SMALL), get("/e/0/big", port=SMALL)
        check("  the last is kept, the first went", hit(r1) and not hit(r2) and r1[1] == BIG, (status_of(r1), status_of(r2)))
        def reader():
            for i in range(30):
                assert get(f"/e/{i % 5}/big", port=SMALL)[1] == BIG
        th = [threading.Thread(target=reader) for i in range(6)]
        res = []
        for t in th:
            t.start()
        for t in th:
            t.join()
        check("many readers, all evicting", "killed" not in log2.read_text(), log2.read_text()[-200:])
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("cache 0s", "cache 10s max=0B", "cache 10s vary=a,b,c,d,e", "cache"):
        c = tmp / "bad.conf"
        c.write_text(CONF.format(engine=ENGINE, back=BACK, lst=LST, tls=TLS, tmp=tmp).replace("cache 60s vary=accept-encoding", bad))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{bad}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"cache {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
