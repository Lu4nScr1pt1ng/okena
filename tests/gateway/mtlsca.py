#!/usr/bin/env python3
"""`client_ca` at scale, on one engine (argument): every certificate in the file
an anchor (a client of either CA gets in, one through an intermediate; one of a
CA not in the file does not); `crl=`: a revoked client, a revoked intermediate
(its clients all), a list past its nextUpdate (its CA's clients refused, the
other CA's not), a list no anchor signed (refused at load), `optional` with
crl= (no certificate: in, as before)."""
import datetime
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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 53400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, REQ, OLD, OPT = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
NOW = datetime.datetime.now(datetime.timezone.utc)


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(cn, key, issuer_name, issuer_key, ca=False, aki=None):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if aki is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki.public_key()), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def ca(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    return k, cert(cn, k, name(cn), k, ca=True)


def crl(issuer, ikey, revoked, next_update):
    b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
         .last_update(NOW - datetime.timedelta(days=1)).next_update(next_update))
    for c in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(c.serial_number)
                                      .revocation_date(NOW - datetime.timedelta(hours=1)).build())
    return b.sign(ikey, hashes.SHA256())


class Back(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (self.headers.get("x-user-id") or "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def pem(*objs):
    return b"".join(o.public_bytes(serialization.Encoding.PEM) for o in objs)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mtlsca-", dir="/tmp"))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    sk = ec.generate_private_key(ec.SECP256R1())
    srv = cert("okena.test", sk, name("okena.test"), sk)
    (tmp / "srv.pem").write_bytes(pem(srv))
    (tmp / "srv.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    k1, c1 = ca("okena client CA one")
    k2, c2 = ca("okena client CA two")
    k3, c3 = ca("okena client CA three")
    ki, ci = ec.generate_private_key(ec.SECP256R1()), None
    ci = cert("okena intermediate two-a", ki, c2.subject, k2, ca=True, aki=k2)
    kj = ec.generate_private_key(ec.SECP256R1())
    cj = cert("okena intermediate two-b", kj, c2.subject, k2, ca=True, aki=k2)
    clients = {}

    def client(tag, cn, issuer, ikey, chain=()):
        k = ec.generate_private_key(ec.SECP256R1())
        c = cert(cn, k, issuer.subject, ikey, aki=ikey)
        (tmp / f"{tag}.pem").write_bytes(pem(c, *chain))
        (tmp / f"{tag}.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        clients[tag] = c
        return c
    client("one", "alice", c1, k1)
    client("revoked", "mallory", c1, k1)
    client("two", "bob", ci, ki, (ci,))
    client("twob", "carol", cj, kj, (cj,))
    client("three", "eve", c3, k3)
    (tmp / "cas.pem").write_bytes(pem(c1, c2))
    later = NOW + datetime.timedelta(days=1)
    (tmp / "crl.pem").write_bytes(pem(crl(c1, k1, [clients["revoked"]], later), crl(c2, k2, [cj], later)))
    (tmp / "old.pem").write_bytes(pem(crl(c1, k1, [], NOW - datetime.timedelta(hours=1))))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{REQ} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/cas.pem crl={tmp}/crl.pem }}
    route /* {{ auth mtls; to pool b }}
}}
http 127.0.0.1:{OLD} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/cas.pem crl={tmp}/old.pem }}
    route /* {{ auth mtls; to pool b }}
}}
http 127.0.0.1:{OPT} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/cas.pem optional crl={tmp}/crl.pem }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))

    def get(port, tag=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if tag:
            ctx.load_cert_chain(tmp / f"{tag}.pem", tmp / f"{tag}.key")
        try:
            with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="okena.test") as t:
                t.sendall(b"GET / HTTP/1.1\r\nHost: okena.test\r\nConnection: close\r\n\r\n")
                data = b""
                while True:
                    b = t.recv(4096)
                    if not b:
                        break
                    data += b
            return data
        except (OSError, ssl.SSLError) as e:
            return repr(e).encode()
    try:
        for _ in range(100):
            if get(REQ, "one").startswith(b"HTTP/1.1"):
                break
            time.sleep(0.05)
        r = get(REQ, "one")
        check("a client of the first CA: in, its name to the backend", r.startswith(b"HTTP/1.1 200") and r.endswith(b"alice"), r[:120])
        r = get(REQ, "two")
        check("a client of the second CA, through an intermediate: in", r.startswith(b"HTTP/1.1 200") and r.endswith(b"bob"), r[:120])
        r = get(REQ, "three")
        check("a client of a CA not in the file: refused", not r.startswith(b"HTTP/1.1 200"), r[:120])
        r = get(REQ, "revoked")
        check("crl=: a revoked client: refused", not r.startswith(b"HTTP/1.1 200"), r[:120])
        r = get(REQ, "twob")
        check("  a revoked intermediate: its clients refused", not r.startswith(b"HTTP/1.1 200"), r[:120])
        r = get(OLD, "one")
        check("a list past its nextUpdate: its CA's clients refused", not r.startswith(b"HTTP/1.1 200"), r[:120])
        r = get(OLD, "two")
        check("  the other CA's still in", r.startswith(b"HTTP/1.1 200") and r.endswith(b"bob"), r[:120])
        check("  said at load", "past its nextUpdate" in log.read_text(), log.read_text()[-300:])
        r = get(OPT)
        check("optional with crl=: no certificate, in", r.startswith(b"HTTP/1.1 200"), r[:120])
        r = get(OPT, "revoked")
        check("  a revoked one sent: refused", not r.startswith(b"HTTP/1.1 200"), r[:120])
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    (tmp / "bad.pem").write_bytes(pem(crl(c3, k3, [], later)))
    bad = tmp / "bad.conf"
    bad.write_text(conf.read_text().replace(f"crl={tmp}/old.pem", f"crl={tmp}/bad.pem"))
    r = subprocess.run([str(BIN), "check", "-c", str(bad)], capture_output=True, text=True, timeout=20)
    check("a list no anchor signed: refused at load", r.returncode != 0 and "not signed by one of client_ca" in r.stderr,
          r.stderr[-300:])
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited with status" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"mtlsca {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
