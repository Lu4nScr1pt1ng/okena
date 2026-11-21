#!/usr/bin/env python3
"""What a pool's backends are verified against, on one engine (argument):
`trust FILE` with every certificate of a bundle (the right root not first),
`trust system` (here $SSL_CERT_FILE, as on any host), `verify off` (a
self-signed backend whose name matches nothing), a root that did not sign the
chain (502), and what `okena check` says about them."""
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
BASE = 9600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
CHAINED, SELF, FRONT = BASE, BASE + 1, BASE + 2

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


tmp = pathlib.Path(tempfile.mkdtemp())


def sh(*a):
    subprocess.run(a, check=True, capture_output=True, cwd=tmp)


def key(n):
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", f"{n}.key")


(tmp / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
(tmp / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:api.backend.test\n")
for n in ("root", "other", "inter", "leaf", "self"):
    key(n)
for n, cn in (("root", "Test Root"), ("other", "Other Root")):
    sh("openssl", "req", "-new", "-x509", "-key", f"{n}.key", "-subj", f"/CN={cn}", "-days", "2",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
       "-out", f"{n}.pem")
sh("openssl", "req", "-new", "-key", "inter.key", "-subj", "/CN=Test Intermediate", "-out", "inter.csr")
sh("openssl", "x509", "-req", "-in", "inter.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
   "-days", "2", "-extfile", "ca.ext", "-out", "inter.pem")
sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=api.backend.test", "-out", "leaf.csr")
sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "inter.pem", "-CAkey", "inter.key", "-CAcreateserial",
   "-days", "2", "-extfile", "leaf.ext", "-out", "leaf.pem")
sh("openssl", "req", "-new", "-x509", "-key", "self.key", "-subj", "/CN=whatever", "-days", "2", "-out", "self.pem")
(tmp / "chain.pem").write_text((tmp / "leaf.pem").read_text() + (tmp / "inter.pem").read_text())
(tmp / "bundle.pem").write_text((tmp / "other.pem").read_text() + (tmp / "root.pem").read_text())


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def tls_server(port, cert, k):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    s.handle_error = lambda *a: None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / cert, tmp / k)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()


tls_server(CHAINED, "chain.pem", "leaf.key")
tls_server(SELF, "self.pem", "self.key")

conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool bundle {{ server 127.0.0.1:{CHAINED}; host api.backend.test; tls {{ trust {tmp}/bundle.pem }} }}
pool system {{ server 127.0.0.1:{CHAINED}; host api.backend.test; tls {{ trust system }} }}
pool wrong {{ server 127.0.0.1:{CHAINED}; host api.backend.test; tls {{ trust {tmp}/other.pem }} }}
pool noverify {{ server 127.0.0.1:{SELF}; host api.backend.test; tls {{ verify off }} }}
pool selfcheck {{ server 127.0.0.1:{SELF}; host api.backend.test; tls {{ trust {tmp}/root.pem }} }}
http 127.0.0.1:{FRONT} {{
    route /bundle {{ to pool bundle; retry 0 }}
    route /system {{ to pool system; retry 0 }}
    route /wrong {{ to pool wrong; retry 0 }}
    route /noverify {{ to pool noverify; retry 0 }}
    route /selfcheck {{ to pool selfcheck; retry 0 }}
}}
""")


def get(path):
    c = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: front.test\r\nConnection: close\r\n\r\n".encode())
    r = b""
    while (d := c.recv(4096)):
        r += d
    c.close()
    return int(r.split(b" ")[1]) if r.startswith(b"HTTP/") else 0


env = dict(os.environ, SSL_CERT_FILE=str(tmp / "bundle.pem"))
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log, env=env)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    check("trust FILE: a bundle, the root that signed the chain second in it", get("/bundle") == 200)
    check("trust system: the system's roots ($SSL_CERT_FILE here)", get("/system") == 200)
    check("a root that did not sign the chain: 502", get("/wrong") == 502)
    check("verify off: a self-signed backend, its name matching nothing", get("/noverify") == 200)
    check("the same backend verified: 502", get("/selfcheck") == 502)
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())

    bad = tmp / "bad.conf"
    bad.write_text(f"""pool a {{ server 127.0.0.1:1; tls {{ sni a.test }} }}
pool b {{ server 127.0.0.1:1; tls {{ trust {tmp}/leaf.key }} }}
pool c {{ server 127.0.0.1:1; tls {{ trust system }} }}
http 127.0.0.1:2 {{
    route /a {{ to pool a }}
    route /b {{ to pool b }}
    route /c {{ to pool c }}
}}
""")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True,
                         env=dict(os.environ, SSL_CERT_FILE=str(tmp / "missing.pem")))
    msg = out.stdout + out.stderr
    check("check: no trust (verify off named in the help), a file of no certificate, no system bundle",
          out.returncode != 0 and "verify off" in msg and "cannot load the `trust` file" in msg
          and "no CA bundle found" in msg, msg)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"upstream trust ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
