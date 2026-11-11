#!/usr/bin/env python3
"""HTTP/2 abuse, on one engine (argument), by prior knowledge: floods of SETTINGS,
empty DATA, PRIORITY and WINDOW_UPDATE (GOAWAY ENHANCE_YOUR_CALM); RST_STREAM on
idle streams (PROTOCOL_ERROR); more than 100 streams at once (REFUSED_STREAM). A
head larger than okena takes is that stream's alone: 431 for it (and NO_ERROR when
it meant to send a body), the next request on the connection served, the HPACK
table still the client's (decoded to the end, a scratch area for what is dropped);
indexed references past that cost nothing; insertions that would make a few bytes
copy megabytes are a bomb (GOAWAY ENHANCE_YOUR_CALM)."""
import http.server
import os
import pathlib
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    import hpack
except ImportError:
    print("skip h2 abuse: no hpack package")
    sys.exit(0)

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 31500 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B = BASE, BASE + 1
PRE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    do_POST = do_GET

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def fr(t, f, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([t, f]) + struct.pack(">I", sid) + payload


SETTINGS = fr(4, 0, 0)
BASE_IN = PRE + SETTINGS


def hdrs(path="/", method="GET", extra=(), enc=None):
    enc = enc or hpack.Encoder()
    return enc.encode([(":method", method), (":scheme", "http"), (":authority", "a.test"), (":path", path)] + list(extra))


def frames(data):
    out, i = [], 0
    while i + 9 <= len(data):
        n = int.from_bytes(data[i:i + 3], "big")
        out.append((data[i + 3], data[i + 4], int.from_bytes(data[i + 5:i + 9], "big") & 0x7FFFFFFF, data[i + 9:i + 9 + n]))
        i += 9 + n
    return out


def go(data, wait=1.0):
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(wait)
    try:
        k.sendall(data)
    except OSError:
        pass
    out = b""
    try:
        while True:
            x = k.recv(65536)
            if not x:
                break
            out += x
    except (socket.timeout, OSError):
        pass
    k.close()
    fs = frames(out)
    dec = hpack.Decoder()
    st = {}
    for t, f, sid, p in fs:
        if t == 1:
            st[sid] = dict(dec.decode(p)).get(":status")
    return dict(goaway=[int.from_bytes(p[4:8], "big") for t, f, sid, p in fs if t == 7],
                rst=[(sid, int.from_bytes(p[:4], "big")) for t, f, sid, p in fs if t == 3], status=st)


BIG = [("x-a", "a" * 9000), ("x-b", "b" * 9000)]


def main():
    threading.Thread(target=S(("127.0.0.1", B), H).serve_forever, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h2abuse-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\npool b {{ server 127.0.0.1:{B} }}\n"
                    f"http 127.0.0.1:{L} {{ http2 on; route /* {{ to pool b }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = go(BASE_IN + fr(1, 5, 1, hdrs()))
        check("a request: 200", r["status"] == {1: "200"}, r)
        for name, data in (("SETTINGS", SETTINGS * 20000), ("empty DATA", fr(1, 4, 1, hdrs("/", "POST")) + fr(0, 0, 1) * 20000),
                           ("PRIORITY", fr(2, 0, 3, b"\0\0\0\0\x10") * 20000),
                           ("WINDOW_UPDATE", fr(8, 0, 0, struct.pack(">I", 1)) * 20000)):
            r = go(BASE_IN + data)
            check(f"a {name} flood: GOAWAY ENHANCE_YOUR_CALM", r["goaway"] == [11], r)
        r = go(BASE_IN + fr(3, 0, 1, struct.pack(">I", 8)))
        check("RST_STREAM on an idle stream: GOAWAY PROTOCOL_ERROR", r["goaway"] == [1], r)
        r = go(BASE_IN + b"".join(fr(1, 4, i, hdrs("/", "POST")) for i in range(1, 221, 2)))
        check("past 100 streams at once: REFUSED_STREAM for the rest", (201, 7) in r["rst"] and (199, 7) not in r["rst"], r["rst"][:4])
        r = go(BASE_IN + fr(1, 5, 1, hdrs(extra=BIG)) + fr(1, 5, 3, hdrs()))
        check("a head past 16 KiB: 431 for that stream, the next served", r["status"] == {1: "431", 3: "200"} and not r["goaway"], r)
        enc = hpack.Encoder()
        big = hdrs(extra=BIG + [("x-keep", "kept")], enc=enc)
        after = hdrs(extra=[("x-keep", "kept")], enc=enc)    # refers to what the refused block inserted
        r = go(BASE_IN + fr(1, 5, 1, big) + fr(1, 5, 3, after))
        check("  the HPACK table stays the client's", r["status"] == {1: "431", 3: "200"} and not r["goaway"], r)
        r = go(BASE_IN + fr(1, 4, 1, hdrs("/", "POST", extra=BIG)) + fr(0, 1, 1, b"body") + fr(1, 5, 3, hdrs()))
        check("  one that meant to send a body: 431, then RST_STREAM NO_ERROR", r["status"].get(1) == "431"
              and (1, 0) in r["rst"] and r["status"].get(3) == "200", r)
        enc = hpack.Encoder()
        one = hdrs(extra=[("x-big", "a" * 3000)], enc=enc)
        refs = hdrs(extra=[("x-big", "a" * 3000)] * 200, enc=enc)
        r = go(BASE_IN + fr(1, 5, 1, one) + fr(1, 5, 3, refs) + fr(1, 5, 5, hdrs(enc=enc)))
        check("200 references to a 3 KB entry: 431, nothing else", r["status"] == {1: "200", 3: "431", 5: "200"} and not r["goaway"], r)
        # a 4000-byte name, then 2-byte insertions that each copy it: a bomb
        name = b"n" * 4000
        first = bytes([0x40]) + bytes([0x7F]) + bytes([(4000 - 127) & 0x7F | 0x80, (4000 - 127) >> 7]) + name + b"\x00"
        # a literal with incremental indexing, a new name of 4000 bytes, an empty value
        block = hdrs() + first + (b"\x7e\x00" * 300)        # each: index 62 (that name), empty value, inserted again
        r = go(BASE_IN + fr(1, 5, 1, block))
        check("insertions that copy 4 KB per 2 bytes: GOAWAY ENHANCE_YOUR_CALM", r["goaway"] == [11], r)
        r = go(BASE_IN + fr(1, 5, 1, hdrs()))
        check("still serving", r["status"] == {1: "200"}, r)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"h2 abuse {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
