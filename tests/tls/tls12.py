#!/usr/bin/env python3
"""TLS 1.2 for older clients: an http listener with tls { } accepts a TLS
1.2 client (ECDHE-ECDSA or ECDHE-RSA, AES-128-GCM or ChaCha20-Poly1305, x25519
or secp256r1, ECDSA, RSA-PSS or RSA PKCS #1, the extended master secret),
hands the connection to kTLS 1.2 and proxies the request to the backend;
nothing in common is a handshake_failure alert. Needs the kernel tls module (the 1.2
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
BASE = 33000 + os.getpid() % 40 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, SNIL, RLST, DLST, ULST = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5
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
        if self.path.startswith("/big"):
            body = bytes(range(256)) * 1024                 # 256 KiB: many records
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        got = self.rfile.read(n)
        body = b"posted:%d:%d" % (len(got), sum(got) % 65521)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def backend():
    http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Handler).serve_forever()


def get12(port, path="/hello", cipher="ECDHE-ECDSA-AES128-GCM-SHA256", post=None):
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
            if post is None:
                t.sendall(f"GET {path} HTTP/1.1\r\nHost: okena.test\r\nConnection: close\r\n\r\n".encode())
            else:
                t.sendall(f"POST {path} HTTP/1.1\r\nHost: okena.test\r\nContent-Length: {len(post)}\r\n"
                          "Connection: close\r\n\r\n".encode() + post)
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

    # negotiation: what the client offers decides (openssl s_client says what was chosen)
    def sclient(port, *opts):
        r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "okena.test",
                            "-tls1_2", *opts], input=b"", capture_output=True, timeout=10)
        return (r.stdout + r.stderr).decode(errors="replace")
    for port, cipher in ((LST, "ECDHE-ECDSA-CHACHA20-POLY1305"), (RLST, "ECDHE-RSA-CHACHA20-POLY1305")):
        ver, data = get12(port, "/cha", cipher=cipher)
        check(f"TLS 1.2 {cipher}: kTLS ChaCha20-Poly1305, 200 proxied",
              ver == "TLSv1.2" and data.startswith(b"HTTP/1.1 200") and b"backend:/cha" in data, f"{ver} {data[:80]}")
    o = sclient(LST, "-cipher", "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256")
    check("  the client's order kept (ChaCha20 first: ChaCha20)", "Cipher is ECDHE-ECDSA-CHACHA20-POLY1305" in o, o[-300:])
    o = sclient(LST)
    check("x25519 when offered; the extended master secret; secure renegotiation said",
          "X25519" in o and "TLSv1.2, Cipher is" in o and "Extended master secret: yes" in o
          and "Secure Renegotiation IS supported" in o, o[-500:])
    o = sclient(LST, "-curves", "P-256")
    check("  secp256r1 for a client without x25519", "prime256v1" in o and "TLSv1.2, Cipher is ECDHE-ECDSA" in o, o[-400:])
    o = sclient(RLST, "-curves", "X25519")
    check("  x25519 alone, an RSA certificate: x25519", "X25519" in o and "TLSv1.2, Cipher is ECDHE-RSA" in o, o[-400:])
    o = sclient(LST, "-curves", "X25519")
    check("  x25519 alone, an ECDSA (secp256r1) certificate: refused, as RFC 8422 has it",
          "alert handshake failure" in o, o[-300:])
    o = sclient(RLST, "-sigalgs", "RSA-PSS+SHA256:RSA+SHA256")
    check("RSA: rsa_pss_rsae_sha256 when offered", "Peer signature type: rsa_pss_rsae_sha256" in o
          and "TLSv1.2, Cipher is" in o, o[-400:])
    o = sclient(RLST, "-sigalgs", "RSA+SHA256")
    check("  else rsa_pkcs1_sha256", "Peer signature type: rsa_pkcs1_sha256" in o and "TLSv1.2, Cipher is ECDHE-RSA" in o, o[-400:])
    t0 = time.time()
    o = sclient(LST, "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384")
    check("nothing in common: a handshake_failure alert, at once",
          "alert handshake failure" in o and time.time() - t0 < 5, o[-300:])
    o = sclient(LST, "-curves", "P-384")
    check("  no group in common: the same", "alert handshake failure" in o, o[-300:])

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

    # no kTLS (OKENA_KTLS=off): the 1.2 records sealed and opened by okena itself
    uconf = tmp / "u.conf"
    uconf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{ULST} {{
    tls {{
        cert {tmp / 'leaf.pem'} key={tmp / 'leaf.key'}
        cert {tmp / 'rsa.pem'} key={tmp / 'rsa.key'}
    }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    ulog = open(tmp / "u.log", "w+")
    u = subprocess.Popen([str(BIN), "-c", str(uconf)], stderr=ulog, env=dict(os.environ, OKENA_KTLS="off"))
    atexit.register(u.kill)
    for _ in range(100):
        if get12(ULST)[0] is not None:
            break
        time.sleep(0.05)
    big = bytes(range(256)) * 1024
    for cipher in ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256",
                   "ECDHE-RSA-CHACHA20-POLY1305"):
        ver, data = get12(ULST, "/u", cipher=cipher)
        ok1 = ver == "TLSv1.2" and data.startswith(b"HTTP/1.1 200") and b"backend:/u" in data
        ver, data = get12(ULST, "/big", cipher=cipher)
        ok2 = data.startswith(b"HTTP/1.1 200") and data.endswith(big)
        payload = os.urandom(100000)
        ver, data = get12(ULST, "/up", cipher=cipher, post=payload)
        ok3 = b"posted:%d:%d" % (len(payload), sum(payload) % 65521) in data
        check(f"no kTLS, {cipher}: records here (a request, 256 KiB down, 100 KB up)", ok1 and ok2 and ok3,
              f"{ok1} {ok2} {ok3} {data[:80]}")
    u.terminate()
    u.wait(10)

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    print(f"tls12 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
