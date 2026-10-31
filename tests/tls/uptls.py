#!/usr/bin/env python3
"""TLS towards the backends: an http listener whose pool has `tls { }`
runs a TLS 1.3 client handshake to the backend, verifies its certificate
(chain to the configured trust anchor, validity, host name), hands the
keys to the kernel (kTLS) and proxies plaintext over the encrypted link.

A Python TLS/HTTP backend presents an EC P-256 certificate signed by a
local CA. The happy path proxies a request and its response; the rest
check that a wrong anchor, a name mismatch and a plaintext backend each
answer 502 rather than trusting an unverified connection."""
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
BASE = 31000 + os.getpid() % 50 * 10
BACK, PLAIN, LST, LST_BAD, LST_HOST = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
BACK12, BACK12R, LST12, LST12R = BASE + 5, BASE + 6, BASE + 7, BASE + 8
DRIB, LSTD = 33800 + os.getpid() % 50 * 2, 33801 + os.getpid() % 50 * 2   # a dribbling relay
LSTS = BASE + 9                                 # HTTPS in front (user-space records), TLS behind
BACKED, LSTED, LSTEDBAD = (33600 + os.getpid() % 50 * 3 + i for i in range(3))
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0
backend_conns = 0
backend_lock = threading.Lock()


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


# a local CA and an EC P-256 leaf for backend.test, signed by it
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key")
sh("openssl", "req", "-new", "-x509", "-key", "ca.key", "-sha256", "-subj", "/CN=test-ca", "-days", "2", "-out", "ca.pem")
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=backend.test", "-out", "leaf.csr")
(tmp / "ext.cnf").write_text("subjectAltName=DNS:backend.test\n")
sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
   "-days", "2", "-sha256", "-extfile", "ext.cnf", "-out", "leaf.pem")
# a second CA that signs nothing the backend serves (the "wrong anchor")
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "other.key")
sh("openssl", "req", "-new", "-x509", "-key", "other.key", "-sha256", "-subj", "/CN=other-ca", "-days", "2", "-out", "other.pem")
# an RSA leaf for backend.test, signed by the CA (for a TLS 1.2 ECDHE-RSA backend)
sh("openssl", "genrsa", "-out", "rsa.key", "2048")
sh("openssl", "req", "-new", "-key", "rsa.key", "-subj", "/CN=backend.test", "-out", "rsa.csr")
sh("openssl", "x509", "-req", "-in", "rsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
   "-days", "2", "-sha256", "-extfile", "ext.cnf", "-out", "rsa.pem")
# an Ed25519 CA and an Ed25519 leaf it signs (the chain verified with Ed25519)
sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", "edca.key")
sh("openssl", "req", "-new", "-x509", "-key", "edca.key", "-subj", "/CN=ed-ca", "-days", "2", "-out", "edca.pem")
sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", "ed.key")
sh("openssl", "req", "-new", "-key", "ed.key", "-subj", "/CN=backend.test", "-out", "ed.csr")
sh("openssl", "x509", "-req", "-in", "ed.csr", "-CA", "edca.pem", "-CAkey", "edca.key", "-CAcreateserial",
   "-days", "2", "-extfile", "ext.cnf", "-out", "ed.pem")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"               # keep-alive, so okena can pool the link

    def do_GET(self):
        body = b"backend-ok:" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except OSError:
            self.close_connection = True


class CountingHTTPServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        global backend_conns
        with backend_lock:
            backend_conns += 1
        return super().get_request()


def tls_backend(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "leaf.pem", tmp / "leaf.key")
    # the default backend sends NewSessionTickets after its Finished; okena
    # drains those kTLS control records (recvmsg) and proxies over the link
    httpd = CountingHTTPServer(("127.0.0.1", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def dribble_relay(port, target):
    # the backend's bytes to okena 100 at a time, so its flight arrives in
    # many reads and is processed again as each piece lands
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def pipe(a, b, slow):
        try:
            while (d := a.recv(65536)):
                if not slow:
                    b.sendall(d)
                    continue
                for i in range(0, len(d), 100):
                    b.sendall(d[i:i + 100])
                    time.sleep(0.002)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    while True:
        c, _ = s.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        u = socket.create_connection(("127.0.0.1", target))
        u.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=pipe, args=(c, u, False), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c, True), daemon=True).start()


def tls13_backend(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / cert, tmp / key)
    httpd = CountingHTTPServer(("127.0.0.1", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def tls12_backend(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tmp / cert, tmp / key)
    httpd = CountingHTTPServer(("127.0.0.1", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def plain_backend(port):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.serve_forever()


def get(port, path="/", host="t"):
    """(status, body) or (None, error) over plain HTTP to okena."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        status = int(head.split()[1])
        return status, body
    except (OSError, ValueError, IndexError) as e:
        return None, repr(e)


def main():
    if not shutil.which("openssl"):
        print("skip uptls: openssl not found")
        return 0
    if not pathlib.Path("/sys/module/tls").exists():
        print("skip uptls: TLS to backends runs on kTLS and the tls module is not loaded (sudo modprobe tls)")
        return 0
    threading.Thread(target=tls_backend, args=(BACK,), daemon=True).start()
    threading.Thread(target=plain_backend, args=(PLAIN,), daemon=True).start()
    threading.Thread(target=tls12_backend, args=(BACK12, "leaf.pem", "leaf.key"), daemon=True).start()
    threading.Thread(target=tls12_backend, args=(BACK12R, "rsa.pem", "rsa.key"), daemon=True).start()
    threading.Thread(target=tls13_backend, args=(BACKED, "ed.pem", "ed.key"), daemon=True).start()
    threading.Thread(target=dribble_relay, args=(DRIB, BACK), daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{LST}    {{ route /* {{ to pool good }} }}
http 127.0.0.1:{LST_BAD}  {{ route /* {{ to pool badanchor }} }}
http 127.0.0.1:{LST_HOST} {{ route /* {{ to pool plain }} }}
http 127.0.0.1:{LST12}  {{ route /* {{ to pool good12 }} }}
http 127.0.0.1:{LST12R} {{ route /* {{ to pool good12rsa }} }}
http 127.0.0.1:{LSTED}  {{ route /* {{ to pool gooded }} }}
http 127.0.0.1:{LSTEDBAD} {{ route /* {{ to pool badedanchor }} }}
http 127.0.0.1:{LSTD} {{ route /* {{ to pool dribble }} }}
pool dribble {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{DRIB}
}}
http 127.0.0.1:{LSTS} {{
    tls {{ cert {tmp}/leaf.pem; key {tmp}/leaf.key }}
    route /* {{ to pool good }}
}}
pool badedanchor {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{BACKED}
}}
pool gooded    {{
    tls {{ trust {tmp}/edca.pem; sni backend.test }}
    server 127.0.0.1:{BACKED}
}}
pool good      {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{BACK}
}}
pool good12    {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{BACK12}
}}
pool good12rsa {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{BACK12R}
}}
pool badanchor {{
    tls {{ trust {tmp}/other.pem; sni backend.test }}
    server 127.0.0.1:{BACK}
}}
pool plain {{
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
    server 127.0.0.1:{PLAIN}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    check("okena check: tls upstream config", r.returncode == 0, r.stderr[-300:])

    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    for _ in range(100):                        # wait for the backend + okena to serve
        if get(LST)[0] == 200:
            break
        time.sleep(0.05)

    st, body = get(LST, "/hello")
    check("verified TLS upstream: request and response proxied",
          st == 200 and body == b"backend-ok:/hello", f"{st} {body!r}")
    # the link really is encrypted end to end: many requests keep working
    oks = sum(get(LST, f"/n{i}")[1] == b"backend-ok:/n%d" % i for i in range(20))
    check("20 requests over the kTLS upstream", oks == 20, f"{oks}/20")

    # a TLS 1.2 backend (no TLS 1.3): the client falls back and verifies the
    # ServerKeyExchange signature (ECDHE-ECDSA for an EC leaf, ECDHE-RSA for RSA)
    for _ in range(100):
        if get(LST12)[0] == 200:
            break
        time.sleep(0.05)
    st, body = get(LST12, "/v12")
    check("TLS 1.2 upstream (ECDHE-ECDSA): request and response proxied",
          st == 200 and body == b"backend-ok:/v12", f"{st} {body!r}")
    for _ in range(100):
        if get(LSTED)[0] == 200:
            break
        time.sleep(0.05)
    st, body = get(LSTED, "/ed")
    check("Ed25519 backend: the chain (an Ed25519 CA) and CertificateVerify verified",
          st == 200 and body == b"backend-ok:/ed", f"{st} {body!r}")
    check("Ed25519 backend under an anchor that did not sign it: 502", get(LSTEDBAD)[0] == 502, str(get(LSTEDBAD)))
    st, body = get(LST12R, "/v12r")
    check("TLS 1.2 upstream (ECDHE-RSA): request and response proxied",
          st == 200 and body == b"backend-ok:/v12r", f"{st} {body!r}")
    oks = sum(get(LST12, f"/m{i}")[1] == b"backend-ok:/m%d" % i for i in range(10))
    check("10 requests over the TLS 1.2 kTLS upstream", oks == 10, f"{oks}/10")

    global backend_conns
    backend_conns = 0
    ok = True
    with socket.create_connection(("127.0.0.1", LST), timeout=5) as s:
        f = s.makefile("rwb")
        for i in range(30):                     # keep-alive: one client, many requests
            f.write(f"GET /p{i} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
            f.flush()
            status = f.readline()
            clen = 0
            while True:
                line = f.readline()
                if line in (b"\r\n", b""):
                    break
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":")[1])
            body = f.read(clen)
            ok = ok and status.split()[1:2] == [b"200"] and body == b"backend-ok:/p%d" % i
            if not ok:
                break
    check("kTLS upstream reused across a keep-alive client's 30 requests",
          ok and backend_conns <= 2, f"ok={ok} backend_conns={backend_conns}")

    st, body = get(LSTD, "/dribble")
    check("a TLS backend whose flight arrives 100 bytes at a time", st == 200 and body == b"backend-ok:/dribble",
          f"{st} {body!r}")

    # HTTPS in front on user-space records (http's default) and TLS behind:
    # the two handshakes and their buffers do not share space
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    oks = 0
    try:
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", LSTS), timeout=5)) as t:
            f = t.makefile("rwb")
            for i in range(10):
                f.write(f"GET /s{i} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
                f.flush()
                status, clen = f.readline(), 0
                while (line := f.readline()) not in (b"\r\n", b""):
                    if line.lower().startswith(b"content-length:"):
                        clen = int(line.split(b":")[1])
                oks += status.split()[1:2] == [b"200"] and f.read(clen) == b"backend-ok:/s%d" % i
    except (OSError, ssl.SSLError) as e:
        print("  https front:", repr(e))
    check("HTTPS front (user-space records) to a TLS backend: 10 requests", oks == 10, f"{oks}/10")

    check("wrong trust anchor: 502, not proxied", get(LST_BAD)[0] == 502, str(get(LST_BAD)))
    check("plaintext backend on a tls pool: 502", get(LST_HOST)[0] == 502, str(get(LST_HOST)))

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    if failures:
        log.seek(0)
        print(log.read()[-2000:])
    print(f"uptls {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
