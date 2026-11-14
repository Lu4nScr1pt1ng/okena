#!/usr/bin/env python3
"""`response rewrite`, on one engine (argument): Location and Content-Location
put the way the client sees them (`auto`: the backend's own URLs, relative
ones under the route's rewrite path, the client's own Host on http behind
TLS; FROM -> TO prefixes), a Set-Cookie's Domain and Path, a listener's
lines for its routes, and what is not the backend's left alone."""
import http.server
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 17400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L, LS = BASE, BASE + 1, BASE + 2

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


ANSWERS = {
    "/login-abs": [("Location", f"http://127.0.0.1:{BACK}/login?next=%2F")],
    "/login-rel": [("Location", "/login")],
    "/idp": [("Location", "https://idp.test/authorize?x=1")],
    "/own": [("Location", "http://front.test/home")],
    "/internal": [("Location", "http://internal:9000/a/b"), ("Content-Location", "http://internal:9000/c")],
    "/cookie": [("Set-Cookie", "sid=42; Domain=internal.test; Path=/app; HttpOnly"),
                ("Set-Cookie", "pref=dark; domain=.internal.test; path=/app/x; Secure"),
                ("Set-Cookie", "other=1; Domain=else.test; Path=/elsewhere")],
}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(302)
        for k, v in ANSWERS.get(self.path.split("?")[0], []):
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def get(path, port=L, tls=False):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c = ctx.wrap_socket(c, server_hostname="front.test")
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: front.test\r\nConnection: close\r\n\r\n".encode())
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    head = r.split(b"\r\n\r\n")[0].decode()
    out = {}
    for line in head.split("\r\n")[1:]:
        k, _, v = line.partition(": ")
        out.setdefault(k.lower(), []).append(v)
    return out


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "f.key"],
               check=True, capture_output=True, cwd=tmp)
subprocess.run(["openssl", "req", "-new", "-x509", "-key", "f.key", "-subj", "/CN=front.test", "-addext",
                "subjectAltName=DNS:front.test", "-days", "2", "-out", "f.pem"], check=True, capture_output=True, cwd=tmp)
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    response rewrite location auto
    route /v1/* {{
        rewrite path /v1/{{*}} -> /{{*}}
        response rewrite cookie_domain internal.test -> front.test
        response rewrite cookie_path /app -> /v1/app
        to 127.0.0.1:{BACK}
    }}
    route /internal {{
        response rewrite location http://internal:9000/ -> https://public.test/
        to 127.0.0.1:{BACK}
    }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{LS} {{
    tls {{ cert {tmp}/f.pem key={tmp}/f.key }}
    route /* {{ response rewrite location auto; to 127.0.0.1:{BACK} }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())

    h = get("/v1/login-abs")
    check("auto: the server's own URL becomes the client's, under the route's prefix",
          h.get("location") == ["http://front.test/v1/login?next=%2F"], str(h.get("location")))
    h = get("/v1/login-rel")
    check("auto: a relative one under the route's prefix", h.get("location") == ["/v1/login"], str(h.get("location")))
    h = get("/v1/idp")
    check("auto: someone else's URL left alone", h.get("location") == ["https://idp.test/authorize?x=1"],
          str(h.get("location")))
    h = get("/own", port=LS, tls=True)
    check("auto behind TLS: the client's Host on http:// gets https://",
          h.get("location") == ["https://front.test/home"], str(h.get("location")))
    h = get("/login-rel")
    check("a listener's line for a route without one, no rewrite path: as it is",
          h.get("location") == ["/login"], str(h.get("location")))
    h = get("/internal")
    check("FROM -> TO: the route's own first, Content-Location too",
          h.get("location") == ["https://public.test/a/b"] and h.get("content-location") == ["https://public.test/c"],
          str(h))
    h = get("/v1/cookie")
    check("cookies: Domain and Path rewritten, the rest as it was",
          h.get("set-cookie", [])[:2] == ["sid=42; Domain=front.test; Path=/v1/app; HttpOnly",
                                          "pref=dark; domain=front.test; path=/v1/app/x; Secure"], str(h.get("set-cookie")))
    check("  a cookie of another domain and path untouched",
          h.get("set-cookie", [""])[-1] == "other=1; Domain=else.test; Path=/elsewhere", str(h.get("set-cookie")))
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())

    bad = tmp / "bad.conf"
    bad.write_text("""http 127.0.0.1:1 {
    route /a { response rewrite location somewhere; respond 200 }
    route /b { response rewrite cookie_domain a.test b.test; respond 200 }
    route /c { response rewrite nothing x -> y; respond 200 }
}
""")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    msg = out.stdout + out.stderr
    check("check: a line without auto or FROM -> TO, an unknown field",
          out.returncode != 0 and msg.count("response rewrite takes") == 3, msg)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"response rewrite ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
