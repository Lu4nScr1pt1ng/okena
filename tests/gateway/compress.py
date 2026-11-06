#!/usr/bin/env python3
"""`compress` on one engine (argument). The bytes that come back, decompressed by a
real gzip, must be the bytes the backend sent, whatever their shape, length and the
way they arrive: a compressor that is wrong now and then is the worst kind. And what
must not be compressed is not."""
import gzip
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zlib

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 10000 + os.getpid() % 90 * 4 + (2 if ENGINE == "epoll" else 0)	# ports 10000-10360: this suite's own
BACK, LST = BASE, BASE + 1
TLS = BASE + 2 - (2 if False else 0)
fails = 0
R = random.Random(11)
BODIES = {}


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


def words(n):
    w = [bytes(R.choices(b"abcdefghij klmnop", k=R.randint(2, 9))) for i in range(300)]
    out = bytearray()
    while len(out) < n:
        out += R.choice(w) + b" "
    return bytes(out[:n])


BODIES["html"] = b"<li class=x>hello</li>\n" * 3000
BODIES["words"] = words(300000)
BODIES["random"] = R.randbytes(200000)
BODIES["zeros"] = bytes(500000)
BODIES["one"] = b"a" * 5000
BODIES["long"] = words(3 << 20)
BODIES["far"] = R.randbytes(30000) + BODIES["html"][:2000] + R.randbytes(2000) + BODIES["html"][:2000]
for n in (1, 2, 3, 4, 257, 258, 259, 260, 1023, 1024, 16383, 16384, 16385, 32768, 32769, 65536):
    BODIES[f"n{n}"] = words(n)


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path.split("/")[-1].split("?")[0]
        q = self.path.split("?")[1] if "?" in self.path else ""
        b = BODIES.get(p, b"small")
        ct = "text/html; charset=utf-8"
        h = {}
        if p == "png":
            ct, b = "image/png", BODIES["html"]
        if p == "json":
            ct, b = "application/json", json.dumps({"a": ["x" * 40] * 200}).encode()
        if p == "encoded":
            h["Content-Encoding"] = "br"
            b = BODIES["html"]
        if p == "nt":
            h["Cache-Control"] = "public, no-transform"
            b = BODIES["html"]
        if p == "etag":
            h["ETag"] = '"abc"'
            b = BODIES["html"]
        if p == "e404":
            self.send_response(404)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(BODIES["html"])))
            self.end_headers()
            self.wfile.write(BODIES["html"])
            return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        for k, v in h.items():
            self.send_header(k, v)
        if "chunks" in q:
            size = int(q.split("=")[1])
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(b), size):
                c = b[i:i + size]
                self.wfile.write(b"%x\r\n" % len(c) + c + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        elif "close" in q:
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b)
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b)

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def get(path, method="GET", gz=True, conn=None, **hdr):
    c = conn or http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
    c.putrequest(method, path, skip_accept_encoding=True)
    if gz:
        c.putheader("Accept-Encoding", "gzip")
    for k, v in hdr.items():
        c.putheader(k.replace("_", "-"), v)
    c.endheaders()
    r = c.getresponse()
    b = r.read()
    if not conn:
        c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


def plain(r):
    return gzip.decompress(r[1]) if r[2].get("content-encoding") == "gzip" else r[1]


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-compress."))
    threading.Thread(target=S(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2", "-out", tmp / "c.pem"], check=True)
    (tmp / "site").mkdir()
    (tmp / "site" / "f").mkdir()
    (tmp / "site" / "f" / "a.html").write_bytes(BODIES["html"])
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    compress gzip min=64B
    route /off/* {{ compress off; to pool b }}
    route /small/* {{ compress gzip min=100KiB; to pool b }}
    route /cached/* {{ cache 60s; to pool b }}
    route /f/* {{ files {tmp}/site }}
    route /* {{ to pool b }}
}}
http 127.0.0.1:{BASE + 2} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    compress gzip min=64B
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        r = get("/x/html")
        check("compressed, a real gzip reads it", r[2].get("content-encoding") == "gzip" and gzip.decompress(r[1]) == BODIES["html"], r[2])
        check("  it says it varies", "accept-encoding" in r[2].get("vary", "").lower())
        check("  no length of the other bytes", "content-length" not in r[2] or int(r[2]["content-length"]) == len(r[1]), r[2])
        check("  it is smaller", len(r[1]) * 5 < len(BODIES["html"]), len(r[1]))
        r = get("/x/words")
        print("     text ratio", round(len(BODIES["words"]) / len(r[1]), 2), "gzip -1:", round(len(BODIES["words"]) / len(gzip.compress(BODIES["words"], 1)), 2), flush=True)
        check("  no trailing bytes after the stream", zlib.decompressobj(31).decompress(r[1]) == BODIES["words"])
        for name in BODIES:
            for how, q in (("length", ""), ("chunks of 1000", "?chunks=1000"), ("close", "?close=1")):
                if name == "long" and how != "length":
                    continue
                if BODIES[name] and len(BODIES[name]) < 64 and how == "length":
                    r = get("/x/" + name)
                    check(f"{name}: too small to bother", "content-encoding" not in r[2] and r[1] == BODIES[name], r[2])
                    continue
                r = get(f"/x/{name}{q}")
                try:
                    ok = plain(r) == BODIES[name]
                except Exception as e:
                    ok = False
                if not ok:
                    check(f"{name}, {how}", False, (len(r[1]), r[2]))
        check("every shape, every way it can come, byte for byte", True)
        ok = True
        for i in range(200):
            n = R.randint(0, 70000)
            s = R.choice((1, 3, 7, 16, 100, 4096))
            b = bytes(R.choices(b"ab", k=n)) if i % 3 == 0 else words(n)
            BODIES["fz"] = b
            r = get(f"/x/fz?chunks={R.randint(1, 20000)}")
            if plain(r) != b:
                ok = False
                check(f"fuzz {i}", False, (n, s))
                break
        check("200 random bodies in random pieces", ok)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        ok = all(plain(get("/x/html", conn=c)) == BODIES["html"] for i in range(5))
        ok = ok and get("/x/png", conn=c)[1] == BODIES["html"]
        ok = ok and plain(get("/x/html", conn=c)) == BODIES["html"]
        check("one connection, many answers", ok)
        c.close()

        check("no Accept-Encoding: as it is", get("/x/html", gz=False)[1] == BODIES["html"])
        check("gzip;q=0: as it is", "content-encoding" not in get("/x/html", gz=False, Accept_Encoding="gzip;q=0")[2])
        check("JSON is text", get("/x/json")[2].get("content-encoding") == "gzip")
        check("an image is not", "content-encoding" not in get("/x/png")[2])
        r = get("/x/encoded")
        check("encoded already: left alone", r[2].get("content-encoding") == "br" and r[1] == BODIES["html"], r[2])
        check("no-transform", "content-encoding" not in get("/x/nt")[2])
        check("HEAD", get("/x/html", "HEAD")[1] == b"")
        check("a 404: left alone", "content-encoding" not in get("/x/e404")[2])
        check("compress off on a route", "content-encoding" not in get("/off/html")[2])
        check("min= of a route", "content-encoding" not in get("/small/html2")[2])
        check("no ETag of other bytes", "etag" not in get("/x/etag")[2])
        s = socket.create_connection(("127.0.0.1", LST), 3)
        s.sendall(b"GET /x/html HTTP/1.0\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
        d = b""
        s.settimeout(3)
        try:
            while True:
                x = s.recv(65536)
                if not x:
                    break
                d += x
        except OSError:
            pass
        check("HTTP/1.0 has no chunks: as it is", b"Content-Encoding" not in d.split(b"\r\n\r\n")[0] and d.endswith(BODIES["html"][-20:]), d[:200])

        for i in range(16):				# (a cache is a worker's: each one's)
            get("/cached/html", gz=False)
        a, b = get("/cached/html"), get("/cached/html", gz=False)
        check("the cache keeps the original: each gets what it takes", plain(a) == BODIES["html"] and "hit" in a[2].get("cache-status", "") and
              "content-encoding" not in b[2] and b[1] == BODIES["html"], (a[2], b[2]))
        r = get("/f/a.html")
        check("a file too", plain(r) == BODIES["html"] and r[2].get("content-encoding") == "gzip", r[2])

        q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "--compressed", "-o", "-", "-w", "\n%{http_version}", f"https://localhost:{BASE + 2}/x/words"], capture_output=True)
        check("over HTTP/2", q.stdout.endswith(b"\n2") and q.stdout[:-2] == BODIES["words"], (len(q.stdout), q.stderr[-100:]))
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{BASE + 2}/x/html", "proto=h3", "conns=2", "workers=1", "rate=100", "duration=1s", "warmup=0s", "format=kv",
                            "header=accept-encoding: gzip"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
        check("over HTTP/3", kv.get("errors") == "0" and kv.get("ok") == "100", q.stdout[:100])

        # more at once than there are contexts, some leaving midway
        errs = []
        def many():
            for i in range(8):
                r = get("/x/long")
                if plain(r) != BODIES["long"]:
                    errs.append(len(r[1]))
        th = [threading.Thread(target=many) for i in range(10)]
        for t in th:
            t.start()
        for i in range(30):
            s = socket.create_connection(("127.0.0.1", LST))
            s.sendall(b"GET /x/long HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
            s.recv(100)
            s.close()
        for t in th:
            t.join()
        check("many at once, clients leaving midway", not errs, errs[:3])
        r = [get("/x/html") for i in range(70)]
        check("  every context came back", all(x[2].get("content-encoding") == "gzip" for x in r))
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text() and "restarting" not in log.read_text(), log.read_text()[-300:])
    for what, line in (("zstd", "compress zstd"), ("something else", "compress lz4"), ("gzip and a word", "compress gzip now")):
        c = tmp / "bad.conf"
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ {line}; route /* {{ to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"compress {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
