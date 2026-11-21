#!/usr/bin/env python3
"""A pool's `host`: the Host its backends get, on one engine (argument). The
client's own Host goes on in X-Forwarded-Host (a trusted proxy's is kept, not
doubled); HTTP/1.0 without a Host gets the pool's; an HTTP/2 backend gets it
as :authority; TLS asks for it in SNI and verifies it when the pool has no
`sni`; the health check sends it too; a pool without `host` is unchanged."""
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
BASE = 26500 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, TLSBACK, FRONT, INNER = BASE, BASE + 1, BASE + 2, BASE + 3

failures = 0
seen = []          # (path, Host, X-Forwarded-Host) the plain backend got
sni_seen = []


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        host = self.headers.get("host") or "-"
        xfh = self.headers.get_all("x-forwarded-host") or []
        seen.append((self.path, host, xfh))
        body = f"{host}|{','.join(xfh)}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def get(path, host="client.test", extra="", version="1.1"):
    c = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
    hl = f"Host: {host}\r\n" if host else ""
    c.sendall(f"GET {path} HTTP/{version}\r\n{hl}{extra}Connection: close\r\n\r\n".encode())
    r = b""
    while (d := c.recv(4096)):
        r += d
    c.close()
    head, _, body = r.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), body.decode()


tmp = pathlib.Path(tempfile.mkdtemp())
subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "o.key"],
               check=True, capture_output=True, cwd=tmp)
subprocess.run(["openssl", "req", "-new", "-x509", "-key", "o.key", "-subj", "/CN=origin.test", "-addext",
                "subjectAltName=DNS:origin.test", "-addext", "basicConstraints=critical,CA:TRUE",
                "-days", "2", "-out", "o.pem"], check=True, capture_output=True, cwd=tmp)

hs = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Echo)
hs.handle_error = lambda *a: None          # (health checks hang up after the status)
threading.Thread(target=hs.serve_forever, daemon=True).start()
ths = http.server.ThreadingHTTPServer(("127.0.0.1", TLSBACK), Echo)
ths.handle_error = lambda *a: None
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(tmp / "o.pem", tmp / "o.key")
ctx.sni_callback = lambda s, name, c: sni_seen.append(name)
ths.socket = ctx.wrap_socket(ths.socket, server_side=True)
threading.Thread(target=ths.serve_forever, daemon=True).start()

conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off
    workers 2
    io_engine {ENGINE}
    drain delay=0s timeout=1s
}}
pool named {{
    server 127.0.0.1:{BACK}
    host api.origin.test:8443
    health http GET /healthz every=200ms
}}
pool plain {{ server 127.0.0.1:{BACK} }}
pool viah2 {{
    server 127.0.0.1:{INNER}
    protocol h2
    host h2.origin.test
}}
pool tlsorigin {{
    server 127.0.0.1:{TLSBACK}
    host origin.test
    tls {{ trust {tmp}/o.pem }}
}}
http 127.0.0.1:{FRONT} {{
    trusted_proxies 10.0.0.0/8 127.0.0.2
    route /named/* {{ to pool named }}
    route /plain/* {{ to pool plain }}
    route /h2/* {{ to pool viah2 }}
    route /tls/* {{ to pool tlsorigin }}
}}
http 127.0.0.1:{INNER} {{
    http2 on
    trusted_proxies 127.0.0.0/8
    route /* {{ to 127.0.0.1:{BACK} }}
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

    st, body = get("/named/a")
    check("the pool's host to the backend, the client's in X-Forwarded-Host",
          st == 200 and body == "api.origin.test:8443|client.test", f"{st} {body}")
    st, body = get("/plain/a")
    check("a pool without host: the client's Host, no X-Forwarded-Host added",
          st == 200 and body == "client.test|", f"{st} {body}")
    st, body = get("/named/b", host=None, version="1.0")
    check("HTTP/1.0 without Host: the pool's", st == 200 and body.startswith("api.origin.test:8443|"), f"{st} {body}")
    st, body = get("/h2/a")
    check("an HTTP/2 pool: :authority is the pool's host",
          st == 200 and body.startswith("h2.origin.test|"), f"{st} {body}")
    st, body = get("/tls/a")
    check("TLS without sni: the host asked for (SNI) and verified",
          st == 200 and body == "origin.test|client.test" and "origin.test" in sni_seen, f"{st} {body} {sni_seen}")
    # a trusted proxy's X-Forwarded-Host stands, and is not doubled
    c = socket.socket()
    c.bind(("127.0.0.2", 0))
    c.settimeout(5)
    c.connect(("127.0.0.1", FRONT))
    c.sendall(b"GET /named/c HTTP/1.1\r\nHost: edge.test\r\nX-Forwarded-Host: www.shop.test\r\n"
              b"Connection: close\r\n\r\n")
    r = b""
    while (d := c.recv(4096)):
        r += d
    c.close()
    body = r.partition(b"\r\n\r\n")[2].decode()
    check("from a trusted proxy: its X-Forwarded-Host, once", body == "api.origin.test:8443|www.shop.test", body)
    for _ in range(40):
        if any(s[0] == "/healthz" for s in seen):
            break
        time.sleep(0.05)
    hc = [s for s in seen if s[0] == "/healthz"]
    check("the health check sends the pool's host", hc and hc[0][1] == "api.origin.test:8443", str(hc[:1]))
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())

    bad = tmp / "bad.conf"
    bad.write_text("""pool a { server 127.0.0.1:1; host "a b" }
http 127.0.0.1:2 { route /* { header set host x.test; to pool a } }
""")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    msg = out.stdout + out.stderr
    check("check: a host with a space; header set host points at the pool's host",
          out.returncode != 0 and "host is the Host" in msg and "pool api { host" in msg, msg)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"host rewrite ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
