#!/usr/bin/env python3
"""OCSP stapling, on one engine (argument): okena asks each certificate's
responder (its AIA, http://) by a CertID of SHA-1 hashes (read back here by
`cryptography`'s own OCSP parser), takes the answer only when the issuer signed it
or a responder it delegated to (OCSPSigning), staples it in the TLS 1.3
Certificate for a client that asks (openssl s_client -status, both workers); a
forged answer, a revoked certificate (said in the log), `ocsp off` and a
certificate with no responder: nothing stapled."""
import datetime
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, AuthorityInformationAccessOID

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 45000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, TLS, TLS2, RESP = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def nm(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


NOW = datetime.datetime.now(datetime.timezone.utc)
CA_K = ec.generate_private_key(ec.SECP256R1())
CA_C = (x509.CertificateBuilder().subject_name(nm("okena test OCSP CA")).issuer_name(nm("okena test OCSP CA"))
        .public_key(CA_K.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(CA_K.public_key()), critical=False)
        .sign(CA_K, hashes.SHA256()))


def leaf(name, aia=True, eku=None, key=None):
    k = key or ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(nm(name)).issuer_name(CA_C.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=20))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(CA_K.public_key()), critical=False))
    if aia:
        b = b.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://127.0.0.1/ca.der")),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(f"http://127.0.0.1:{RESP}/ocsp"))]),
            critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return k, b.sign(CA_K, hashes.SHA256())


# the responder's own certificate, the CA's delegate
DELEG_K, DELEG_C = leaf("okena test OCSP responder", aia=False, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
# an impostor: the CA's name, another key
FORGER_K = ec.generate_private_key(ec.SECP256R1())
FORGER_C = (x509.CertificateBuilder().subject_name(CA_C.subject).issuer_name(CA_C.subject).public_key(FORGER_K.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(FORGER_K, hashes.SHA256()))
CERTS = {}                       # serial -> (name, cert)
SEEN = []                        # (name, hash algorithm, the issuer's hashes right)


class Responder(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        req = ocsp.load_der_ocsp_request(body)
        name, cert = CERTS[req.serial_number]
        b = ocsp.OCSPRequestBuilder().add_certificate(cert, CA_C, hashes.SHA1()).build()
        SEEN.append((name, req.hash_algorithm.name, req.issuer_key_hash == b.issuer_key_hash
                     and req.issuer_name_hash == b.issuer_name_hash, self.headers["Content-Type"]))
        status = ocsp.OCSPCertStatus.REVOKED if name == "revoked.test" else ocsp.OCSPCertStatus.GOOD
        rb = ocsp.OCSPResponseBuilder().add_response(
            cert=cert, issuer=CA_C, algorithm=hashes.SHA1(), cert_status=status,
            this_update=NOW - datetime.timedelta(minutes=5), next_update=NOW + datetime.timedelta(days=2),
            revocation_time=NOW - datetime.timedelta(days=1) if name == "revoked.test" else None,
            revocation_reason=x509.ReasonFlags.key_compromise if name == "revoked.test" else None)
        if name == "deleg.test":
            rb = rb.responder_id(ocsp.OCSPResponderEncoding.HASH, DELEG_C).certificates([DELEG_C])
            r = rb.sign(DELEG_K, hashes.SHA256())
        elif name == "forged.test":
            rb = rb.responder_id(ocsp.OCSPResponderEncoding.NAME, FORGER_C)
            r = rb.sign(FORGER_K, hashes.SHA256())
        else:
            rb = rb.responder_id(ocsp.OCSPResponderEncoding.NAME, CA_C)
            r = rb.sign(CA_K, hashes.SHA256())
        out = r.public_bytes(serialization.Encoding.DER)
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class Back(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def staple(port, name, version="-tls1_3"):
    """what openssl s_client says of the staple: its status line and the cert's"""
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", name, "-status",
                        version], input="", capture_output=True, text=True, timeout=10)
    out = r.stdout
    if "OCSP response: no response sent" in out:
        return "none"
    if "OCSP Response Status: successful" in out:
        for line in out.splitlines():
            if "Cert Status:" in line:
                return line.split(":", 1)[1].strip()
    return "?" + out[-300:]


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ocsp-", dir="/tmp"))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", RESP), Responder).serve_forever, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    lines = {}
    for name, aia in (("good.test", True), ("deleg.test", True), ("forged.test", True), ("revoked.test", True),
                      ("plain.test", False), ("off.test", True)):
        k, c = leaf(name, aia)
        CERTS[c.serial_number] = (name, c)
        (tmp / f"{name}.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM) + CA_C.public_bytes(serialization.Encoding.PEM))
        (tmp / f"{name}.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                          serialization.NoEncryption()))
        lines[name] = f"cert {tmp}/{name}.pem key={tmp}/{name}.key"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS} {{
    tls {{
        {lines["good.test"]}
        {lines["deleg.test"]}
        {lines["forged.test"]}
        {lines["revoked.test"]}
        {lines["plain.test"]}
    }}
    route /* {{ to pool b }}
}}
http 127.0.0.1:{TLS2} {{
    tls {{
        {lines["off.test"]}
        ocsp off
    }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("stapled: the issuer's answer, good", until(lambda: staple(TLS, "good.test") == "good", 10),
              (staple(TLS, "good.test"), SEEN, log.read_text()[-400:]))
        check("  in every worker (eight handshakes)", all(staple(TLS, "good.test") == "good" for _ in range(8)))
        check("  and over TLS 1.2 (CertificateStatus after Certificate)", staple(TLS, "good.test", "-tls1_2") == "good"
              and staple(TLS, "deleg.test", "-tls1_2") == "good" and staple(TLS, "revoked.test", "-tls1_2") == "none",
              staple(TLS, "good.test", "-tls1_2"))
        g = [s for s in SEEN if s[0] == "good.test"]
        check("  asked by a CertID of SHA-1 hashes of the issuer's name and key (cryptography reads it), POSTed",
              g and g[0][1] == "sha1" and g[0][2] and g[0][3] == "application/ocsp-request", g)
        check("a responder the issuer delegated to (OCSPSigning): stapled", until(lambda: staple(TLS, "deleg.test") == "good", 5),
              staple(TLS, "deleg.test"))
        check("an answer the issuer did not sign (an impostor of its name): not stapled, said",
              until(lambda: "no good answer for the certificate of forged.test" in log.read_text(), 5)
              and staple(TLS, "forged.test") == "none", log.read_text()[-300:])
        check("a revoked certificate: nothing stapled, said in the log",
              until(lambda: "REVOKED" in log.read_text(), 5) and staple(TLS, "revoked.test") == "none", log.read_text()[-300:])
        check("no responder in it, or `ocsp off`: not asked, nothing stapled",
              staple(TLS, "plain.test") == "none" and staple(TLS2, "off.test") == "none"
              and not any(s[0] in ("plain.test", "off.test") for s in SEEN), SEEN)
        r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{TLS}", "-servername", "good.test", "-tls1_3"],
                           input="", capture_output=True, text=True, timeout=10)
        check("a client that does not ask: none sent, the handshake as before",
              "OCSP response" not in r.stdout and "Verify return code" in r.stdout, r.stdout[-300:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"ocsp {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
