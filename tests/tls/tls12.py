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
BACK, LST, SNIL, RLST, DLST = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
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


def get12(port, path="/hello", cipher="ECDHE-ECDSA-AES128-GCM-SHA256"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(cipher)
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


def early_close12(port):
    """A TLS 1.2 handshake whose last flight leaves together with a FIN."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="okena.test")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            while True:
                try:
                    obj.do_handshake()
                    done = True
                except ssl.SSLWantReadError:
                    done = False
                data = out.read()
                if done or b"\x14\x03\x03" in data:     # our ChangeCipherSpec: the last flight
                    s.sendall(data)
                    s.shutdown(socket.SHUT_WR)
                    s.recv(4096)
                    return
                s.sendall(data)
                chunk = s.recv(65536)
                if not chunk:
                    return
                inc.write(chunk)
    except (OSError, ssl.SSLError):
        pass


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
    # an RSA certificate, for a legacy TLS 1.2 client (ECDHE-RSA, rsa_pkcs1_sha256)
    sh("openssl", "genrsa", "-out", "rsa.key", "2048")
    sh("openssl", "req", "-new", "-x509", "-key", "rsa.key", "-subj", "/CN=okena.test",
       "-addext", "subjectAltName=DNS:okena.test", "-days", "2", "-out", "rsa.pem")
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
http 127.0.0.1:{RLST} {{
    tls {{ cert {tmp / 'rsa.pem'}; key {tmp / 'rsa.key'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{DLST} {{
    tls {{
        cert {tmp / 'leaf.pem'} key={tmp / 'leaf.key'}
        cert {tmp / 'rsa.pem'} key={tmp / 'rsa.key'}
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
    # an RSA certificate on a TLS 1.2 connection: ECDHE-RSA, rsa_pkcs1_sha256
    ver, data = get12(RLST, "/rsa12", cipher="ECDHE-RSA-AES128-GCM-SHA256")
    check("TLS 1.2 with an RSA certificate: 200 proxied from the backend",
          ver == "TLSv1.2" and data.startswith(b"HTTP/1.1 200") and b"backend:/rsa12" in data,
          f"{ver} {data[:80]}")

    # dual certificate on one host over TLS 1.2: a legacy client that offers
    # only rsa_pkcs1_sha256 (ECDHE-RSA) gets the RSA leaf; an ECDSA client the
    # EC leaf. openssl -sigalgs sets what the ClientHello offers.
    if shutil.which("openssl"):
        def served12(sigalgs, cipher):
            r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{DLST}",
                                "-servername", "okena.test", "-tls1_2", "-cipher", cipher,
                                "-sigalgs", sigalgs], input=b"", capture_output=True, timeout=10)
            import re
            m = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", r.stdout, re.S)
            if not m:
                return (r.stdout + r.stderr)[-120:]
            x = subprocess.run(["openssl", "x509", "-noout", "-text"], input=m.group(0), capture_output=True)
            return "EC" if b"id-ecPublicKey" in x.stdout else "RSA" if b"rsaEncryption" in x.stdout else x.stdout[:80]
        kt = served12("rsa_pkcs1_sha256", "ECDHE-RSA-AES128-GCM-SHA256")
        check("TLS 1.2 dual cert: an RSA-only client (rsa_pkcs1) gets the RSA certificate", kt == "RSA", kt)
        kt = served12("ecdsa_secp256r1_sha256", "ECDHE-ECDSA-AES128-GCM-SHA256")
        check("TLS 1.2 dual cert: an ECDSA client gets the ECDSA certificate", kt == "EC", kt)
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

    # clients that send their Finished with a FIN: the socket is in
    # CLOSE_WAIT when the keys go to the kernel, so the ULP fails with
    # ENOTCONN. That closes those connections only; the worker keeps kTLS
    # (it once took it for "no tls module" and refused every 1.2 client).
    for _ in range(12):
        early_close12(LST)
    oks = sum(get12(LST, f"/e{i}")[1].startswith(b"HTTP/1.1 200") for i in range(8))
    check("TLS 1.2 clients leaving at their Finished do not cost the worker kTLS", oks == 8, f"{oks}/8")

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    print(f"tls12 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
