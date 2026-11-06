#!/usr/bin/env python3
"""A certificate chain towards a backend, on one engine (argument), over TLS 1.3
and 1.2: only an authority may sign, and every link must be in date. The holder of
any leaf of the pool's authority must not be able to pass for another name."""
import datetime
import http.client
import http.server
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip chain: no cryptography")
    sys.exit(0)

BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 29984 + (6 if ENGINE == "epoll" else 0) + os.getpid() % 2 * 3
BACK, LST = BASE, BASE + 1
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name_of(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(cn, issuer, sk, signer, ca, days=2, usage=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = x509.CertificateBuilder().subject_name(name_of(cn)).issuer_name(name_of(issuer)).public_key(sk.public_key()) \
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=3)) \
        .not_valid_after(now + datetime.timedelta(days=days))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if usage:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    return b.sign(signer, hashes.SHA256())


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")
        self.close_connection = True

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def serve(tmp, chain, sk, version):
    (tmp / "c.pem").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain))
    (tmp / "k.pem").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = version
    ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
    s = S(("127.0.0.1", BACK), H)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def status():
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    try:
        c.request("GET", "/", headers={"Connection": "close"})
        return c.getresponse().status
    except OSError as e:
        return str(e)
    finally:
        c.close()


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-chain."))
    cak, bob, fake, inter = key(), key(), key(), key()
    ca = make("ca", "ca", cak, cak, True)
    (tmp / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    target = lambda issuer, signer: make("backend.test", issuer, fake, signer, False)
    good = target("ca", cak)
    forged = [
        ("a leaf signing another leaf", [target("bob", bob), make("bob", "ca", bob, cak, False)]),
        ("a certificate that does not say it is a CA", [target("bob", bob), make("bob", "ca", bob, cak, None)]),
        ("a CA not allowed to sign", [target("bob", bob), make("bob", "ca", bob, cak, True, usage=True)]),
        ("an expired intermediate", [target("mid", inter), make("mid", "ca", inter, cak, True, days=-1)]),
        ("an expired leaf", [make("backend.test", "ca", fake, cak, False, days=-1)]),
    ]
    honest = [target("mid", inter), make("mid", "ca", inter, cak, True)]
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool b {{
    server 127.0.0.1:{BACK}
    tls {{ trust {tmp}/ca.pem; sni backend.test }}
}}
http 127.0.0.1:{LST} {{ route /* {{ to pool b }} }}
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
        for ver, tag in ((ssl.TLSVersion.TLSv1_3, "1.3"), (ssl.TLSVersion.TLSv1_2, "1.2")):
            for what, chain, want in [("the authority's own leaf", [good], 200), ("through a real intermediate", honest, 200)] + \
                    [(w, c, 502) for w, c in forged]:
                s = serve(tmp, chain, fake, ver)
                # (an ejected backend is 502 too: a good chain after each shows it is back)
                got = status()
                s.shutdown()
                s.server_close()
                check(f"TLS {tag}, {what}: {want}", got == want, got)
                time.sleep(0.05)
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    print(f"chain {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
