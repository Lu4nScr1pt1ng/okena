#!/usr/bin/env python3
"""TLS 1.2 for older clients: an http listener with tls { } accepts a TLS
1.2 client (ECDHE-ECDSA/AES-128-GCM), hands the connection to kTLS 1.2 and
proxies the request to the backend. Needs the kernel tls module (the 1.2
path is kTLS-only); skipped otherwise."""
import atexit
import http.server
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 33000 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, SNIL = BASE, BASE + 1, BASE + 2
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*a):
    subprocess.run(a, check=True, capture_output=True, cwd=tmp)


def have_ktls():
    try:
        s = socket.socket()
        s.connect_ex(("127.0.0.1", 1))
        s.setsockopt(socket.IPPROTO_TCP, 31, b"tls")   # TCP_ULP; ENOENT if no module
        s.close()
        return True
    except OSError as e:
        return e.errno != 2  # ENOENT = no module


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"backend:" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def backend():
    http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Handler).serve_forever()


def get12(port, path="/hello"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        with ctx.wrap_socket(s, server_hostname="okena.test") as t:
            ver = t.version()
            t.sendall(f"GET {path} HTTP/1.1\r\nHost: okena.test\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                b = t.recv(4096)
                if not b:
                    break
                data += b
        return ver, data
    except (OSError, ssl.SSLError) as e:
        return None, repr(e).encode()


def main():
    if not shutil.which("openssl"):
        print("skip tls12: openssl not found")
        return 0
    if not have_ktls():
        print("skip tls12: no kernel tls module (the 1.2 path is kTLS-only)")
        return 0
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
    sh("openssl", "req", "-new", "-x509", "-key", "leaf.key", "-subj", "/CN=okena.test",
       "-addext", "subjectAltName=DNS:okena.test", "-days", "2", "-out", "leaf.pem")
    for n, cn, san in (("a", "cert-a", "DNS:a.test"), ("b", "cert-b", "DNS:*.b.test")):
        sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", f"{n}.key")
        sh("openssl", "req", "-new", "-x509", "-key", f"{n}.key", "-subj", f"/CN={cn}",
           "-addext", f"subjectAltName={san}", "-days", "2", "-out", f"{n}.pem")
    threading.Thread(target=backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{LST} {{
    tls {{ cert {tmp / 'leaf.pem'}; key {tmp / 'leaf.key'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{SNIL} {{
    tls {{
        cert {tmp / 'a.pem'} key={tmp / 'a.key'}
        cert {tmp / 'b.pem'} key={tmp / 'b.key'}
    }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    check("okena check", r.returncode == 0, r.stderr[-200:])
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    for _ in range(100):
        if get12(LST)[0] is not None:
            break
        time.sleep(0.05)

    ver, data = get12(LST, "/hello")
    check("TLS 1.2 negotiated", ver == "TLSv1.2", str(ver))
    check("GET over TLS 1.2: 200 proxied from the backend",
          data.startswith(b"HTTP/1.1 200") and b"backend:/hello" in data, data[:80])
    # SNI picks the certificate on a 1.2 connection
    def peer_cn(port, sni, host=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            with ctx.wrap_socket(s, server_hostname=sni) as t:
                from cryptography import x509
                cn = x509.load_der_x509_certificate(t.getpeercert(binary_form=True)).subject.rfc4514_string()
                t.sendall(f"GET / HTTP/1.1\r\nHost: {host or sni}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while True:
                    b = t.recv(4096)
                    if not b:
                        break
                    data += b
                return cn, data
        except (OSError, ssl.SSLError) as e:
            return None, repr(e).encode()
    check("TLS 1.2 SNI: a.test gets cert-a", peer_cn(SNIL, "a.test")[0] == "CN=cert-a",
          str(peer_cn(SNIL, "a.test")[0]))
    check("TLS 1.2 SNI: x.b.test gets cert-b (wildcard)", peer_cn(SNIL, "x.b.test")[0] == "CN=cert-b",
          str(peer_cn(SNIL, "x.b.test")[0]))
    cn, data = peer_cn(SNIL, "a.test", host="evil.test")
    check("TLS 1.2 domain fronting: Host not named by the cert gets 421",
          b"421" in data[:20], data[:40])

    # a few more requests (fresh connections), to shake out the handshake
    oks = sum(get12(LST, f"/n{i}")[1].startswith(b"HTTP/1.1 200") for i in range(8))
    check("8 TLS 1.2 connections", oks == 8, f"{oks}/8")

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    print(f"tls12 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
