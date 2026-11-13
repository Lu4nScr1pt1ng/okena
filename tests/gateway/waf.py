#!/usr/bin/env python3
"""The reference WAF addon (addons/coraza, Coraza with the OWASP CRS), on one
engine (argument): an ordinary request goes on; SQL injection and XSS in the
query, path traversal and a scanner's user agent are refused with 403 and
logged; over HTTP/2 too; in -detect mode the request goes on and the backend
hears which rules matched. Skipped when build/coraza-okena is not there
(Go, or its modules, missing)."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import http.server

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
WAF = ROOT / "build" / "coraza-okena"
L = 42000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B = L + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = -1

    def do_GET(self):
        n = int(self.headers.get("content-length") or 0)
        got = self.rfile.read(n) if n else b""
        b = (self.requestline + "\n" + str(self.headers)).encode() + b"body: " + got
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_POST = do_GET

    def log_message(self, *a):
        pass


def get(path, headers=(), body=None):
    k = socket.create_connection(("127.0.0.1", L), 5)
    hs = list(headers) + ([("Content-Length", str(len(body)))] if body is not None else [])
    k.sendall((f"{'POST' if body is not None else 'GET'} {path} HTTP/1.1\r\nHost: shop.example\r\n" + "".join(f"{a}: {b}\r\n" for a, b in hs)
               + "Connection: close\r\n\r\n").encode() + (body or b""))
    d = b""
    while True:
        x = k.recv(65536)
        if not x:
            break
        d += x
    k.close()
    head, _, body = d.partition(b"\r\n\r\n")
    return int(head.split()[1]) if head else 0, body


def main():
    if not os.access(WAF, os.X_OK):
        print("waf: skipped (no build/coraza-okena: Go or the modules of addons/coraza missing)")
        return
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-waf-"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", B), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
addon waf {{
    run {WAF} -workers 2
    timeout 500ms
}}
addon wafb {{
    run {WAF} -workers 2
    phases request_body
    body 16KiB
    timeout 500ms
}}
addon wafd {{
    run {WAF} -detect -workers 1
    timeout 500ms
}}
pool echo {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{
    http2 on
    route /d/* {{ addon wafd; to pool echo }}
    route /b/* {{ addon wafb; to pool echo }}
    route /* {{ addon waf; to pool echo }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        end = time.time() + 10
        while time.time() < end and "started with" not in log.read_text():
            time.sleep(0.02)
        ua = [("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"), ("Accept", "text/html")]
        s, b = get("/products?category=shoes&page=2", ua)
        check("an ordinary request goes on", s == 200 and b"GET /products?category=shoes&page=2" in b, (s, b))
        for name, path, hs in (("SQL injection in the query", "/item?id=1%27%20OR%20%271%27=%271", ua),
                               ("XSS in the query", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", ua),
                               ("path traversal", "/download?file=../../../../etc/passwd", ua),
                               ("a scanner's user agent", "/", [("User-Agent", "Nikto/2.1.6"), ("Accept", "*/*")])):
            s, b = get(path, hs)
            check(f"refused, 403: {name}", s == 403 and b"web application firewall" in b, (s, b))
        if shutil.which("curl"):
            c = subprocess.run(["curl", "-q", "-s", "--http2-prior-knowledge", "-o", "/dev/null", "-w", "%{http_code}",
                                "-A", "Mozilla/5.0", f"http://127.0.0.1:{L}/item?id=1%27%20OR%20%271%27=%271"],
                               capture_output=True, text=True, timeout=10)
            check("HTTP/2: refused too", c.stdout == "403", c.stdout)
        form = [("Content-Type", "application/x-www-form-urlencoded")]
        s, b = get("/b/login", ua + form, b"user=admin&pass=1%27%20OR%20%271%27%3D%271")
        check("request_body: SQL injection in a form body refused", s == 403, (s, b))
        s, b = get("/b/api", ua + [("Content-Type", "application/json")], b'{"comment": "<script>alert(document.cookie)</script>"}')
        check("  XSS in a JSON body refused", s == 403, (s, b))
        s, b = get("/b/login", ua + form, b"user=alice&pass=correct-horse-battery")
        check("  an ordinary form: on, the backend gets its body", s == 200 and b"body: user=alice&pass=correct-horse-battery" in b, (s, b))
        s, b = get("/login", ua + form, b"user=admin&pass=1%27%20OR%20%271%27%3D%271")
        check("  without request_body: the body is not judged", s == 200, s)
        s, b = get("/d/item?id=1%27%20OR%20%271%27=%271", ua)
        check("-detect: it goes on, the backend hears the rules (942100: SQL injection)", s == 200 and b"x-waf-rules:" in b
              and b"942100" in b, (s, b))
        t = log.read_text()
        check("refusals logged with their rules", "coraza-okena: GET /item?id=1" in t and "942100" in t, t[-600:])
    finally:
        p.terminate()
        p.wait(10)
    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"waf {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
