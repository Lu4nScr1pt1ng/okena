#!/usr/bin/env python3
"""Envoy's ext_authz and ext_proc services through okena's adapter addon
(addons/envoyext), on one engine (argument), against a gRPC service of both
kinds written as for Envoy (tests/envoyext). ext_authz: OK lets the request
on with its headers set, a field removed and a query parameter set, and it
was told the client's address; a denial is its status, fields and body;
over HTTP/2 too. ext_proc: a header mutation (a field set, one removed, the
path moved, which routes the request again); an immediate response. The
service down: on_error deny is 503 at once. Skipped without
build/ext-okena."""
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
EXT = ROOT / "build" / "ext-okena"
SRV = ROOT / "build" / "envoyext-test-server"
L = 45000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, G = L + 1, L + 2
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
    k.sendall((f"{'POST' if body is not None else 'GET'} {path} HTTP/1.1\r\nHost: t\r\n" + "".join(f"{a}: {b}\r\n" for a, b in hs)
               + "Connection: close\r\n\r\n").encode() + (body or b""))
    d = b""
    while True:
        x = k.recv(65536)
        if not x:
            break
        d += x
    k.close()
    head, _, body = d.partition(b"\r\n\r\n")
    hs = {}
    for l in head.decode("latin-1").split("\r\n")[1:]:
        if ":" in l:
            a, b = l.split(":", 1)
            hs[a.strip().lower()] = b.strip()
    return (int(head.split()[1]) if head else 0), hs, body


def main():
    if not (os.access(EXT, os.X_OK) and os.access(SRV, os.X_OK)):
        print("envoyext: skipped (no build/ext-okena or its test service: Go or the modules missing)")
        return
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-envoyext-"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", B), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    g = subprocess.Popen([str(SRV), f"127.0.0.1:{G}"])
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
addon authz {{
    run {EXT} -authz 127.0.0.1:{G}
    timeout 1s
}}
addon proc {{
    run {EXT} -proc 127.0.0.1:{G} -timeout 500ms
    timeout 1s
}}
addon authzb {{
    run {EXT} -authz 127.0.0.1:{G} -authz-body
    phases request_body
    timeout 1s
}}
addon procb {{
    run {EXT} -proc 127.0.0.1:{G} -proc-body
    phases request_body
    timeout 1s
}}
addon procr {{
    run {EXT} -proc 127.0.0.1:{G} -proc-body
    phases request_headers response_body
    body 4KiB
    timeout 1s
}}
addon gone {{
    run {EXT} -authz 127.0.0.1:1 -timeout 300ms
    timeout 1s
}}
pool echo {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{
    http2 on
    route /p/* {{ addon proc; to pool echo }}
    route /gone/* {{ addon gone; to pool echo }}
    route /ab/* {{ addon authzb; to pool echo }}
    route /pb/* {{ addon procb; to pool echo }}
    route /pr/* {{ addon procr; to pool echo }}
    route /moved {{ to pool echo }}
    route /* {{ addon authz; to pool echo }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        end = time.time() + 15
        while time.time() < end and "started with" not in log.read_text():
            time.sleep(0.02)
        while time.time() < end:			# (the gRPC service listening)
            try:
                socket.create_connection(("127.0.0.1", G), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        s, h, b = get("/a?x=1", [("Authorization", "Bearer good"), ("X-Drop", "1")])
        check("ext_authz OK: on, with its fields set, one removed, a query parameter set", s == 200 and b"x-user: alice" in b
              and b"X-Drop" not in b and b"GET /a?via=authz&x=1 HTTP/1.1" in b, (s, b))
        check("  it was told the client's address", b"x-client: 127.0.0.1" in b, b)
        s, h, b = get("/a", [("Authorization", "Bearer bad")])
        check("ext_authz denied: its status, fields and body", s == 401 and h.get("www-authenticate") == "Bearer"
              and b == b"authz says no\n", (s, h, b))
        if shutil.which("curl"):
            c = subprocess.run(["curl", "-q", "-s", "--http2-prior-knowledge", "-o", "/dev/null", "-w", "%{http_code}",
                                f"http://127.0.0.1:{L}/a"], capture_output=True, text=True, timeout=10)
            check("  over HTTP/2", c.stdout == "401", c.stdout)
        s, h, b = get("/p/x", [("X-Drop", "1")])
        check("ext_proc: a field set and one removed", s == 200 and b"x-proc: seen" in b and b"X-Drop" not in b, (s, b))
        s, h, b = get("/p/move")
        check("  :path moved: routed again, the backend sees it", s == 200 and b"GET /moved HTTP/1.1" in b, (s, b))
        s, h, b = get("/p/immediate")
        check("  an immediate response", s == 418 and h.get("x-proc") == "immediate" and b == b"short and stout\n", (s, h, b))
        s, h, b = get("/ab/x", [("Authorization", "Bearer good")], body=b"please deny me")
        check("ext_authz with_request_body: the service judges the body", s == 403 and b == b"its body says no\n", (s, b))
        s, h, b = get("/ab/x", [("Authorization", "Bearer good")], body=b"fine")
        check("  a body it lets on", s == 200 and b"x-user: alice" in b, (s, b))
        s, h, b = get("/pb/x", body=b"12345")
        check("ext_proc: the body after the headers, its answer applied", s == 200 and b"x-proc: seen" in b and b"x-proc-body: 5" in b, (s, b))
        s, h, b = get("/pr/page")
        check("ext_proc response phases: on the request's stream (it kept the path), a field set, one removed",
              s == 200 and h.get("x-proc-resp") == "seen /pr/page" and "server" not in h and b"x-proc: seen" in b, (s, h))
        s, h, b = get("/pr/page", [("X-Note", "a secret")])
        check("  the response's body judged: an immediate response replaces it", s == 500 and b == b"withheld\n", (s, b))
        t = time.monotonic()
        s, h, b = get("/gone/x")
        d = time.monotonic() - t
        check("the service down: on_error deny, 503, without waiting for the addon's timeout", s == 503 and d < 0.9, (s, d))
    finally:
        p.terminate()
        p.wait(10)
        g.terminate()
        g.wait(5)
    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"envoyext {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
