#!/usr/bin/env python3
"""`compress zstd` on one engine (argument). What comes back, decoded by the real
zstd, must be the bytes the backend sent, whatever their shape and the way they
arrive: random bodies in random pieces, alphabets of one to five symbols (RLE
literals, Huffman ones), skewed ones whose Huffman codes would be deeper than 11
bits, literals past 128 (raw), long matches, what does not compress (raw
blocks). Each piece decodes as it comes (a stream is not held back). The
client's Accept-Encoding and the order written choose between zstd, br and
gzip."""
import gzip
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

try:
    import zstandard
except ImportError:
    print("skip zstd: no zstandard package")
    sys.exit(0)
try:
    import brotli
except ImportError:
    brotli = None


def unzstd(b):
    return zstandard.ZstdDecompressor().decompressobj().decompress(b)

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 63400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
fails = 0
R = random.Random(int(os.environ.get("ZSTD_SEED", "7")))
BODIES = {}
GATE = threading.Event()


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


def fib_bytes(n):
    """byte i about fib(i) times: a Huffman tree some 20 deep"""
    f = [1, 1]
    while len(f) < 24:
        f.append(f[-1] + f[-2])
    pool = b"".join(bytes([i]) * f[i] for i in range(24))
    return bytes(R.choice(pool) for _ in range(n))


BODIES["html"] = b"<li class=x>hello</li>\n" * 3000
BODIES["words"] = words(300000)
BODIES["random"] = R.randbytes(100000)
BODIES["zeros"] = bytes(100000)
BODIES["fib"] = fib_bytes(60000)
_r = R.randbytes(6000)
BODIES["twice"] = _r + _r                   # (literals past 128: raw)
BODIES["utf8"] = ("naïve café – ação ünïcödé " * 4000).encode()
BODIES["ascii128"] = bytes(R.choices(range(129), k=50000))   # (the largest a direct weight reaches)
BODIES["long"] = (b"x" * 5000 + b"y" * 3 + b"x" * 9000) * 4
for k in range(1, 6):
    BODIES[f"alpha{k}"] = bytes(R.choices(b"abcde"[:k], k=40000))
for n in (64, 65, 257, 1023, 16383, 16384, 16385, 32768, 32769, 65536, 65537):
    BODIES[f"n{n}"] = words(n)


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path.split("/")[-1].split("?")[0]
        q = self.path.split("?")[1] if "?" in self.path else ""
        if p == "stream":                   # two pieces, the second once the first is read
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i, c in enumerate((BODIES["words"][:3000], BODIES["words"][3000:6000])):
                self.wfile.write(b"%x\r\n" % len(c) + c + b"\r\n")
                self.wfile.flush()
                if i == 0:
                    GATE.wait(5)
            self.wfile.write(b"0\r\n\r\n")
            return
        b = BODIES.get(p, b"")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if "chunks" in q:
            size = int(q.split("=")[1])
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(b), size):
                c = b[i:i + size]
                self.wfile.write(b"%x\r\n" % len(c) + c + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif "close" in q:
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b)
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def get(path, ae="zstd"):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
    c.putrequest("GET", path, skip_accept_encoding=True)
    if ae:
        c.putheader("Accept-Encoding", ae)
    c.endheaders()
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


def plain(r):
    ce = r[2].get("content-encoding")
    return (unzstd(r[1]) if ce == "zstd" else brotli.decompress(r[1]) if ce == "br"
            else gzip.decompress(r[1]) if ce == "gzip" else r[1])


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-zstd."))
    threading.Thread(target=S(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2",
                    "-out", tmp / "c.pem"], check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ overload off; drain delay=0s timeout=1s; workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    compress zstd br gzip min=64B
    route /gzfirst/* {{ compress gzip br zstd min=64B; to pool b }}
    route /gzonly/* {{ compress gzip min=64B; to pool b }}
    route /zonly/* {{ compress zstd min=64B; to pool b }}
    route /* {{ priority critical; to pool b }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    compress zstd min=64B
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = get("/x/html")
        check("zstd, the real zstd reads it", r[2].get("content-encoding") == "zstd" and plain(r) == BODIES["html"], r[2])
        check("  it says it varies", "accept-encoding" in r[2].get("vary", "").lower(), r[2])
        check("  it is smaller", len(r[1]) * 20 < len(BODIES["html"]), len(r[1]))
        r = get("/x/words")
        print("     text ratio", round(len(BODIES["words"]) / len(r[1]), 2), "zstd -1:",
              round(len(BODIES["words"]) / len(zstandard.ZstdCompressor(level=1).compress(BODIES["words"])), 2), flush=True)
        r = get("/x/utf8")
        check("UTF-8 text (literals past 128): read back, smaller", plain(r) == BODIES["utf8"]
              and len(r[1]) * 5 < len(BODIES["utf8"]), len(r[1]))
        r = get("/x/random")
        check("what does not compress: stored, hardly larger", plain(r) == BODIES["random"]
              and len(r[1]) < len(BODIES["random"]) * 1.001 + 64, len(r[1]))
        bad = []
        for name in BODIES:
            for how, q in (("length", ""), ("chunks of 1000", "?chunks=1000"), ("chunks of 7", "?chunks=7"), ("close", "?close=1")):
                if how == "chunks of 7" and len(BODIES[name]) > 20000:
                    continue
                r = get(f"/x/{name}{q}")
                try:
                    ok = r[2].get("content-encoding") == "zstd" and plain(r) == BODIES[name]
                except Exception as e:
                    ok = False
                if not ok:
                    bad.append((name, how, len(r[1]), r[2].get("content-encoding")))
        check("every shape, every way it comes, byte for byte (skewed, 1 to 5 symbols, past 128, long matches, raw)", not bad, bad[:4])
        bad = []
        for i in range(150):
            n = R.randint(64, 70000)
            k = i % 5
            b = (bytes(R.choices(b"ab", k=n)) if k == 0 else fib_bytes(n) if k == 1 else R.randbytes(n) if k == 2
                 else bytes(R.choices(bytes(range(R.randint(1, 200))), k=n)) if k == 3 else words(n))
            BODIES["fz"] = b
            r = get(f"/x/fz?chunks={R.randint(1, 20000)}")
            try:
                ok = plain(r) == b
            except Exception as e:
                ok = False
            if not ok:
                bad.append((i, n, k))
        check("150 random bodies in random pieces", not bad, bad[:4])

        # each piece decodes as it comes
        s = socket.create_connection(("127.0.0.1", LST), 5)
        s.sendall(b"GET /x/stream HTTP/1.1\r\nHost: x\r\nAccept-Encoding: zstd\r\n\r\n")
        raw, out, t0 = b"", b"", time.time()
        while len(out) < 3000 and time.time() - t0 < 4:
            raw += s.recv(65536)
            if b"\r\n\r\n" not in raw:
                continue
            head, body = raw.split(b"\r\n\r\n", 1)
            out, rest = b"", body                   # (de-chunk what is whole, decode it)
            dd = zstandard.ZstdDecompressor().decompressobj()
            while b"\r\n" in rest:
                n, after = rest.split(b"\r\n", 1)
                n = int(n, 16)
                if len(after) < n + 2 or n == 0:
                    break
                out += dd.decompress(after[:n])
                rest = after[n + 2:]
        GATE.set()
        check("a stream: its first piece decodes before the second is sent", out == BODIES["words"][:3000],
              (len(out), raw[:120]))
        s.close()

        check("gzip, br, zstd: zstd first, as written", get("/x/html", "gzip, br, zstd")[2].get("content-encoding") == "zstd")
        check("gzip, br: br, the next written", get("/x/html", "gzip, br")[2].get("content-encoding") == "br")
        check("gzip only: gzip", plain(r := get("/x/html", "gzip")) == BODIES["html"] and r[2].get("content-encoding") == "gzip", r[2])
        check("zstd;q=0, gzip: gzip", get("/x/html", "zstd;q=0, gzip")[2].get("content-encoding") == "gzip")
        check("`compress gzip br zstd`, the client all: gzip", get("/gzfirst/html", "zstd, br, gzip")[2].get("content-encoding") == "gzip")
        check("  the client zstd and br: br", get("/gzfirst/html", "zstd, br")[2].get("content-encoding") == "br")
        check("  the client zstd only: zstd", get("/gzfirst/html", "zstd")[2].get("content-encoding") == "zstd")
        check("`compress gzip`, a client of zstd only: as it is", "content-encoding" not in get("/gzonly/html", "zstd")[2])
        check("`compress zstd`, a client of gzip only: as it is", "content-encoding" not in get("/zonly/html", "gzip")[2])
        check("none asked: as it is", get("/x/html", None)[1] == BODIES["html"])

        q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "-H", "accept-encoding: zstd",
                            "-D", "-", "-o", str(tmp / "h2"), f"https://localhost:{TLS}/x/words"], capture_output=True, text=True)
        try:
            ok = unzstd((tmp / "h2").read_bytes()) == BODIES["words"]
        except Exception:
            ok = False
        check("over HTTP/2", ok and q.returncode == 0 and "content-length" not in q.stdout.lower() and "content-encoding: zstd" in q.stdout.lower(), q.stdout[:200])
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    for what, line in (("zstd twice", "compress zstd br zstd"), ("zstd and something else", "compress zstd lz4")):
        c = tmp / "bad.conf"
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ {line}; route /* {{ to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "check", "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and "zstd, br, gzip or several" in q.stderr, f"{q.returncode} {q.stderr[-140:]}")
    print(f"zstd {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
