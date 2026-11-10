#!/usr/bin/env python3
"""ACME with two CAs, ARI, and OCSP's word, on one engine (argument): the first refuses the order
(rateLimited), so okena asks the fallback at once, which wants an external account
binding (EAB, RFC 8555 7.3.4: an HS256 JWS over the account's key, as ZeroSSL asks)
and gets it; each CA's own anchor (trust=, fallback_trust=). A CA that wants EAB
with none given, or with the wrong key: refused, and said. (The CAs are the acme
suite's.)"""
import datetime
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
import http.server

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acme as A  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BIN = A.BIN
BASE = 47000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS, CA1, CA2, CA3, CA4, RESP = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5, BASE + 6, BASE + 7
A.PLAIN = PLAIN                         # (where the CAs prove HTTP-01)
KID = "kid-zerossl-0123"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def ca(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(A.name(cn)).issuer_name(A.name(cn)).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(k, hashes.SHA256()))
    return k, c


def serve(tmp, tag, port, k, c, st):
    """that CA's ACME server on HTTPS, its own certificate for localhost"""
    sk = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sc = A.issue(k, c, sk.public_key(), ["localhost"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=5))
    (tmp / f"{tag}.pem").write_bytes(sc.public_bytes(serialization.Encoding.PEM))
    (tmp / f"{tag}.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    (tmp / f"{tag}-ca.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), A.H)
    srv.st = st
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / f"{tag}.pem", tmp / f"{tag}.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def served(sni):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", TLS), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            return x509.load_der_x509_certificate(t.getpeercert(binary_form=True))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acmefb-", dir="/tmp"))
    k1, c1 = ca("okena test CA one")
    k2, c2 = ca("okena test CA two")
    st1 = A.CAState(k1, c1, CA1)
    st1.fail_orders = (429, "rateLimited")
    st1.bad_nonce_once = False
    st2 = A.CAState(k2, c2, CA2)
    st2.bad_nonce_once = False
    hkey = os.urandom(32)
    st2.eab = {KID: hkey}
    serve(tmp, "one", CA1, k1, c1, st1)
    serve(tmp, "two", CA2, k2, c2, st2)
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), A.Back).serve_forever, daemon=True).start()
    (tmp / "eab").write_text(f"{KID}:{A.b64u(hkey)}\n")

    def conf(name, acme):
        c = tmp / f"{name}.conf"
        c.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/{name} {acme} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{TLS} {{
    tls {{ acme f.example.test }}
    route /* {{ to pool b }}
}}
""")
        return c
    log = tmp / "log"
    procs = []

    def start(c):
        p = subprocess.Popen([str(BIN), "-c", str(c)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        return p

    def stop(p):
        p.terminate()
        p.wait(10)
    try:
        p = start(conf("a", f"ca=https://localhost:{CA1}/dir trust={tmp}/one-ca.pem fallback=https://localhost:{CA2}/dir "
                            f"fallback_trust={tmp}/two-ca.pem fallback_eab={tmp}/eab"))
        check("the first CA refuses the order: the fallback's certificate, served",
              A.until(lambda: served("f.example.test").issuer == c2.subject, 15),
              (st1.log[-4:], st2.log[-6:], log.read_text()[-500:]))
        check("  the first CA was asked (its own anchor), refused, and said so in the log",
              any(e[0] == "order refused" for e in st1.log) and "asking the fallback CA" in log.read_text(),
              (st1.log, log.read_text()[-400:]))
        check("  the fallback's account bound to the external account (HS256 over the key, right)",
              ("eab", (KID, True)) in st2.log and any(e[0] == "account" for e in st2.log), st2.log)
        ctx = ssl.create_default_context(cafile=str(tmp / "two-ca.pem"))
        with socket.create_connection(("127.0.0.1", TLS), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname="f.example.test") as t:
                t.sendall(b"GET / HTTP/1.1\r\nHost: f.example.test\r\nConnection: close\r\n\r\n")
                got = t.recv(100)
        check("  verified against the fallback's CA", got.startswith(b"HTTP/1.1 200"))
        stop(p)

        # the CA that wants EAB, as the only one: none given, then the wrong key
        p = start(conf("b", f"ca=https://localhost:{CA2}/dir trust={tmp}/two-ca.pem"))
        check("EAB required and none given: no account asked for, said",
              A.until(lambda: "asks for an external account binding (eab=)" in log.read_text(), 8), log.read_text()[-300:])
        stop(p)
        n = len(st2.log)
        (tmp / "bad.eab").write_text(f"{KID}:{A.b64u(os.urandom(32))}\n")
        p = start(conf("c", f"ca=https://localhost:{CA2}/dir trust={tmp}/two-ca.pem eab={tmp}/bad.eab"))
        check("  the wrong key: the binding refused by the CA",
              A.until(lambda: ("eab", (KID, False)) in st2.log[n:] and "the order failed (the account" in log.read_text(), 8),
              (st2.log[n:], log.read_text()[-300:]))
        stop(p)
        r = subprocess.run([str(BIN), "check", "-c", str(conf("d", f"ca=https://localhost:{CA2}/dir fallback_eab={tmp}/eab"))],
                           capture_output=True, text=True, timeout=10)
        check("fallback_eab= without fallback=: refused", r.returncode != 0 and "fallback" in r.stderr, r.stderr)

        # ARI (RFC 9773): two certificates far from 2/3 of their life; the CA's window
        # for one is past (renew now), for the other ahead
        k3, c3 = ca("okena test CA three")
        st3 = A.CAState(k3, c3, CA3)
        st3.bad_nonce_once = False
        st3.ari = {}
        serve(tmp, "three", CA3, k3, c3, st3)
        now = datetime.datetime.now(datetime.timezone.utc)
        olds = {}
        for nm in ("g.example.test", "h.example.test"):
            d = tmp / "e" / nm
            d.mkdir(parents=True)
            key = ec.generate_private_key(ec.SECP256R1())
            c = A.issue(k3, c3, key.public_key(), [nm], now - datetime.timedelta(days=1), now + datetime.timedelta(days=60))
            (d / "cert.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM) + c3.public_bytes(serialization.Encoding.PEM))
            (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                          serialization.NoEncryption()))
            olds[nm] = c
        st3.ari[A.certid(olds["g.example.test"])] = (now - datetime.timedelta(hours=2), now - datetime.timedelta(hours=1))
        st3.ari[A.certid(olds["h.example.test"])] = (now + datetime.timedelta(days=10), now + datetime.timedelta(days=11))
        c = tmp / "e.conf"
        c.write_text(conf("x", "").read_text().replace(f"acme {tmp}/x ", f"acme {tmp}/e ca=https://localhost:{CA3}/dir trust={tmp}/three-ca.pem ")
                     .replace("tls { acme f.example.test }", "tls { acme g.example.test; acme h.example.test }"))
        p = start(c)
        check("ari: the certificate the CA's window says is due: renewed at once (the other one is not)",
              A.until(lambda: served("g.example.test").serial_number != olds["g.example.test"].serial_number, 10)
              and served("h.example.test").serial_number == olds["h.example.test"].serial_number,
              (st3.log[-8:], log.read_text()[-400:]))
        check("  asked for by the CertID (the AKI and serial), the order saying what it replaces, the log why",
              ("ari", A.certid(olds["g.example.test"])) in st3.log and ("ari", A.certid(olds["h.example.test"])) in st3.log
              and [e[1] for e in st3.log if e[0] == "replaces"] == [A.certid(olds["g.example.test"])]
              and [e[1] for e in st3.log if e[0] == "order"] == [["g.example.test"]]
              and "asks for it to be renewed now (ARI)" in log.read_text(), (st3.log, log.read_text()[-300:]))
        new = served("g.example.test")
        check("  the new one's window asked for too (ahead: nothing more)",
              A.until(lambda: ("ari", A.certid(new)) in st3.log, 5)
              and not A.until(lambda: sum(1 for e in st3.log if e[0] == "order") > 1, 1), st3.log[-6:])
        stop(p)

        # OCSP says the certificate in the directory is revoked: renewed at once,
        # the new one stapled good
        k4, c4 = ca("okena test CA four")
        st4 = A.CAState(k4, c4, CA4)
        st4.bad_nonce_once = False
        st4.ocsp_url = f"http://127.0.0.1:{RESP}/"
        serve(tmp, "four", CA4, k4, c4, st4)
        revoked = set()

        class Resp(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = ocsp.load_der_ocsp_request(self.rfile.read(int(self.headers["Content-Length"])))
                n = datetime.datetime.now(datetime.timezone.utc)
                bad = req.serial_number in revoked
                rb = ocsp.OCSPResponseBuilder().add_response_by_hash(
                    issuer_name_hash=req.issuer_name_hash, issuer_key_hash=req.issuer_key_hash, serial_number=req.serial_number,
                    algorithm=req.hash_algorithm, cert_status=ocsp.OCSPCertStatus.REVOKED if bad else ocsp.OCSPCertStatus.GOOD,
                    this_update=n - datetime.timedelta(minutes=5), next_update=n + datetime.timedelta(days=1),
                    revocation_time=n - datetime.timedelta(hours=1) if bad else None,
                    revocation_reason=x509.ReasonFlags.key_compromise if bad else None)
                out = rb.responder_id(ocsp.OCSPResponderEncoding.NAME, c4).sign(k4, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
                self.send_response(200)
                self.send_header("Content-Type", "application/ocsp-response")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
        threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", RESP), Resp).serve_forever, daemon=True).start()
        d = tmp / "r" / "r.example.test"
        d.mkdir(parents=True)
        key = ec.generate_private_key(ec.SECP256R1())
        old = A.issue(k4, c4, key.public_key(), ["r.example.test"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=60),
                      st4.ocsp_url)
        revoked.add(old.serial_number)
        (d / "cert.pem").write_bytes(old.public_bytes(serialization.Encoding.PEM) + c4.public_bytes(serialization.Encoding.PEM))
        (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                      serialization.NoEncryption()))
        c = tmp / "r.conf"
        c.write_text(conf("y", "").read_text().replace(f"acme {tmp}/y ", f"acme {tmp}/r ca=https://localhost:{CA4}/dir trust={tmp}/four-ca.pem ")
                     .replace("tls { acme f.example.test }", "tls { acme r.example.test }"))
        t0 = time.time()
        p = start(c)
        check("ocsp: revoked: the acme process told (not waiting out its hour), a new certificate at once",
              A.until(lambda: served("r.example.test").serial_number != old.serial_number, 10)
              and "OCSP says its certificate is revoked: renewing it now" in log.read_text() and time.time() - t0 < 10,
              (st4.log[-6:], log.read_text()[-500:]))

        def stapled():
            r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{TLS}", "-servername", "r.example.test",
                                "-status"], input="", capture_output=True, text=True, timeout=10)
            return "Cert Status: good" in r.stdout
        check("  the new one stapled good", A.until(stapled, 8))
        stop(p)
    finally:
        for q in procs:
            if q.poll() is None:
                q.terminate()
        for q in procs:
            try:
                q.wait(10)
            except subprocess.TimeoutExpired:
                q.kill()
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"acmefb {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
