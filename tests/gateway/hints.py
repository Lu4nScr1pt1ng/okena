#!/usr/bin/env python3
"""`early_hints` and `headers preset=secure`, on one engine (argument)."""
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

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 9000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)	# ports 9000-9540: this suite's own
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
fails = 0
tries = {}


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path
        tries[p] = tries.get(p, 0) + 1
        if p == "/own103":
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nLink: </b.css>; rel=preload\r\n\r\n")
            self.wfile.flush()
        extra = [("X-Frame-Options", "DENY")] if p.startswith("/hdr/framed") else []
        time.sleep(0.4 if p.startswith("/slow") else 0)
        self.send_response(200)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"ok")

    do_HEAD = do_POST = do_GET

    def log_message(self, *a):
        pass


def raw(req):
    s = socket.create_connection(("127.0.0.1", LST), 3)
    s.settimeout(0.6)
    s.sendall(req)
    d, t0, first = b"", time.time(), None
    try:
        while True:
            x = s.recv(65536)
            if not x:
                break
            if first is None:
                first = time.time() - t0
            d += x
            if b"\r\n\r\nok" in d:
                break
    except OSError:
        pass
    s.close()
    return d, first


def get(path):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-hints."))
    S = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=S.serve_forever, daemon=True).start()
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2", "-out", tmp / "c.pem"], check=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    headers preset=secure
    route /slow {{ early_hints /a.css /b.js /c.woff2 /d.png /e; to pool b }}
    route /own103 {{ early_hints /a.css; to pool b }}
    route /hdr/mine {{ response header set referrer-policy no-referrer; to pool b }}
    route /hdr/none {{ headers preset=none; to pool b }}
    route /* {{ to pool b }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    route /slow {{ early_hints /a.css; to pool b }}
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
        for i in range(100):                # every worker serving: the 103's time, not a start's
            if "started with" in log.read_text():
                break
            time.sleep(0.05)
        d, first = raw(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
        heads = d.split(b"\r\n\r\n")
        check("a 103 first, then the answer", heads[0].startswith(b"HTTP/1.1 103") and heads[1].startswith(b"HTTP/1.1 200") and d.endswith(b"ok"), d[:300])
        check("  long before the backend answers (0.4 s)", first is not None and first < 0.3, first)
        h = heads[0].decode()
        for s in ("</a.css>; rel=preload; as=style", "</b.js>; rel=preload; as=script", "</c.woff2>; rel=preload; as=font; crossorigin", "</d.png>; rel=preload; as=image", "</e>; rel=preload\r"):
            check(f"  {s[:30]}", s in h + "\r", h)
        check("HTTP/1.0 has no 1xx", raw(b"GET /slow HTTP/1.0\r\nHost: x\r\n\r\n")[0].startswith(b"HTTP/1.1 200"))
        check("not for a POST", raw(b"POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")[0].startswith(b"HTTP/1.1 200"))
        check("not for a HEAD", b"103" not in raw(b"HEAD /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")[0])
        d = raw(b"GET /own103 HTTP/1.1\r\nHost: x\r\n\r\n")[0]
        check("the backend's own 103 goes too", d.count(b"103 Early Hints") == 2 and d.endswith(b"ok"), d[:200])
        c = socket.create_connection(("127.0.0.1", LST), 3)
        c.settimeout(1)
        d = b""
        for i in range(3):
            c.sendall(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            b = b""
            while not b.endswith(b"ok"):
                b += c.recv(65536)
            d += b
        c.close()
        check("each request on a connection has its own", d.count(b"103 Early") == 3, d.count(b"103 Early"))
        q = subprocess.run(["timeout", "--foreground", "5", "curl", "-q", "-skv", "--http2", "-o", "/dev/null", f"https://localhost:{TLS}/slow"], capture_output=True, text=True)
        check("over HTTP/2", "HTTP/2 103" in q.stderr or "103" in q.stderr and "link:" in q.stderr.lower(), q.stderr[-400:])

        r = get("/x")
        check("preset=secure", r[1].get("x-content-type-options") == "nosniff" and r[1].get("x-frame-options") == "SAMEORIGIN" and
              r[1].get("strict-transport-security") == "max-age=63072000" and r[1].get("referrer-policy") == "strict-origin-when-cross-origin", r[1])
        r = get("/hdr/framed")
        check("  over the backend's", r[1].get("x-frame-options") == "SAMEORIGIN", r[1])
        r = get("/hdr/mine")
        check("  a route's own stands, once", r[1].get("referrer-policy") == "no-referrer" and r[1].get("x-content-type-options") == "nosniff", r[1])
        check("  preset=none", "x-frame-options" not in get("/hdr/none")[1])
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    for line in ("early_hints a.css", 'early_hints "/a>b"', "headers preset=nosuch"):
        c = tmp / "bad.conf"
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ {line}; to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{line}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"hints {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
