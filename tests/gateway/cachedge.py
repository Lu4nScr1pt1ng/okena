#!/usr/bin/env python3
"""The cache's edges, on one engine (argument): a conditional request on a hit
gets a 304 when its validators match what is kept (If-None-Match by weak
comparison, a list, `*`; If-Modified-Since the very Last-Modified; If-None-Match
first), from memory and from disk, and a 200 otherwise; Expires counts when no
max-age or s-maxage does (past or not a date: not kept; ahead: for that long);
what is never kept (no-cache, private, Vary: *, Set-Cookie, max-age=0); and
X-Original-URL / X-Rewrite-URL from a client never reach the origin, so they
cannot poison what is kept for a path."""
import email.utils
import http.server
import os
import pathlib
import re
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
BASE = 32500 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, LD, B = BASE, BASE + 1, BASE + 2
LM = "Wed, 21 Oct 2015 07:28:00 GMT"
fails = 0
hits = {}
lock = threading.Lock()


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path.split("?")[0]
        with lock:
            hits[p] = hits.get(p, 0) + 1
        seen = {k.lower(): v for k, v in self.headers.items()}
        ahead = email.utils.formatdate(time.time() + 120, usegmt=True)
        hdr = {"/etag": [("ETag", '"v1"'), ("Last-Modified", LM)], "/weak": [("ETag", 'W/"w1"')],
               "/past": [("Expires", "Wed, 21 Oct 2015 07:28:00 GMT")], "/zero": [("Expires", "0")],
               "/ahead": [("Expires", ahead)], "/both": [("Expires", "Wed, 21 Oct 2015 07:28:00 GMT"), ("Cache-Control", "max-age=60")],
               "/nocache": [("Cache-Control", "no-cache")], "/private": [("Cache-Control", "private")],
               "/vary": [("Vary", "*")], "/cookie": [("Set-Cookie", "a=1")], "/agezero": [("Cache-Control", "max-age=0")],
               }.get(p, [])
        body = f"{p} xou={seen.get('x-original-url')} xrw={seen.get('x-rewrite-url')}".encode()
        self.send_response(200)
        for k, v in hdr:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def get(path, extra=b"", port=L, method=b"GET"):
    k = socket.create_connection(("127.0.0.1", port))
    k.settimeout(3)
    k.sendall(method + b" " + path.encode() + b" HTTP/1.1\r\nHost: a\r\nConnection: close\r\n" + extra + b"\r\n")
    out = b""
    try:
        while True:
            x = k.recv(65536)
            if not x:
                break
            out += x
    except OSError:
        pass
    k.close()
    head, _, body = out.partition(b"\r\n\r\n")
    h = {x.split(b":")[0].lower().decode(): x.split(b":", 1)[1].strip().decode() for x in head.split(b"\r\n")[1:] if b":" in x}
    return int(head[9:12] or 0), h, body


def main():
    threading.Thread(target=S(("127.0.0.1", B), H).serve_forever, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-cachedge-"))
    (tmp / "store").mkdir()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; cache_disk {tmp}/store size=16MiB }}
pool b {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{ route /* {{ cache 1h; to pool b }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        get("/etag")
        st, h, body = get("/etag")
        check("a hit: 200, its ETag", st == 200 and h.get("etag") == '"v1"' and "hit" in h.get("cache-status", ""), (st, h))
        for name, extra, want in (
                ("If-None-Match, the tag kept", b'If-None-Match: "v1"\r\n', 304),
                ("If-None-Match, weak form of it", b'If-None-Match: W/"v1"\r\n', 304),
                ("If-None-Match, a list holding it", b'If-None-Match: "a", "v1" ,"b"\r\n', 304),
                ("If-None-Match: *", b"If-None-Match: *\r\n", 304),
                ("If-None-Match, another tag", b'If-None-Match: "v0"\r\n', 200),
                ("If-Modified-Since, the very Last-Modified", f"If-Modified-Since: {LM}\r\n".encode(), 304),
                ("If-Modified-Since, another date", b"If-Modified-Since: Thu, 22 Oct 2015 07:28:00 GMT\r\n", 200),
                ("If-None-Match first: another tag, the right date", b'If-None-Match: "v0"\r\nIf-Modified-Since: ' + LM.encode() + b"\r\n", 200)):
            st, h, body = get("/etag", extra)
            ok = st == want and (body == b"" if want == 304 else body.startswith(b"/etag"))
            if want == 304:
                ok = ok and h.get("etag") == '"v1"' and "content-length" not in h and "hit" in h.get("cache-status", "")
            check(f"{name}: {want}", ok, (st, h, body[:30]))
        check("  the origin asked once for all of it", hits.get("/etag") == 1, hits.get("/etag"))
        get("/weak")
        st, h, body = get("/weak", b'If-None-Match: "w1"\r\n')
        check("a weak tag kept, its strong form asked: 304 (weak comparison)", st == 304, (st, h))
        st, h, body = get("/etag", b'If-None-Match: "v1"\r\n', method=b"HEAD")
        check("HEAD with the tag: 304 too", st == 304, (st, h))
        # from disk: a second okena on the same store, its memory empty
        conf2 = tmp / "okena2.conf"
        conf2.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; cache_disk {tmp}/store size=16MiB }}
pool b {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{LD} {{ route /* {{ cache 1h; to pool b }} }}
""")
        p2 = subprocess.Popen([str(BIN), "-c", str(conf2)], stderr=open(tmp / "log2", "w"))
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", LD), 1).close()
                    break
                except OSError:
                    time.sleep(0.05)
            st, h, body = get("/etag", b'If-None-Match: "v1"\r\n', port=LD)
            check("a hit from disk with the tag: 304", st == 304 and "disk" in h.get("cache-status", "") and body == b"", (st, h))
            st, h, body = get("/etag", port=LD)
            check("  without it: 200 from disk, the body whole", st == 200 and body.startswith(b"/etag"), (st, body[:30]))
        finally:
            p2.terminate()
            p2.wait(10)
        for path, kept in (("/past", False), ("/zero", False), ("/ahead", True), ("/both", True), ("/nocache", False),
                           ("/private", False), ("/vary", False), ("/cookie", False), ("/agezero", False)):
            get(path)
            st, h, body = get(path)
            cs = h.get("cache-status", "")
            check(f"{path}: {'kept' if kept else 'not kept'}", ("hit" in cs) == kept and hits.get(path) == (1 if kept else 2), (cs, hits.get(path)))
            if path == "/ahead":
                ttl = int(re.search(r"ttl=(-?\d+)", cs).group(1)) if "ttl=" in cs else -1
                check("  Expires 120 s ahead: kept for that, not the route's hour", 110 <= ttl <= 120, cs)
        st, h, body = get("/poison", b"X-Original-URL: /admin\r\nX-Rewrite-URL: /admin\r\n")
        check("X-Original-URL and X-Rewrite-URL from a client: not passed on", body == b"/poison xou=None xrw=None", body)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"cachedge {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
