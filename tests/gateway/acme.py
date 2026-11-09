#!/usr/bin/env python3
"""Automatic HTTPS (ACME, RFC 8555), on one engine (argument), against a small CA
of the test's own over HTTPS (trust=): every request a JWS (ES256) it verifies, a
nonce each, the account by its key; HTTP-01 proven by fetching okena's port with
the name as Host; a certificate issued for the CSR's names. okena serves one it
signs itself until then, then the CA's (after a reload of its own); a restart
finds the files and asks nothing; a certificate past 2/3 of its life is renewed;
a badNonce is tried again; a token not asked for goes on to the routes."""
import base64
import datetime
import hashlib
import http.server
import json
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
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 56000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS, CA, TLS2 = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
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


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca():
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name("okena test ACME CA")).issuer_name(name("okena test ACME CA"))
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(k, hashes.SHA256()))
    return k, c


def issue(ca_k, ca_c, pub, names, before, after):
    b = (x509.CertificateBuilder().subject_name(name(names[0])).issuer_name(ca_c.subject).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_k.public_key()), critical=False))
    return b.sign(ca_k, hashes.SHA256())


class CAState:
    def __init__(self, ca_k, ca_c):
        self.ca_k, self.ca_c = ca_k, ca_c
        self.base = f"https://localhost:{CA}"
        self.nonces = set()
        self.accounts = {}            # thumbprint -> (id, key)
        self.by_kid = {}
        self.orders = {}
        self.authz = {}
        self.lock = threading.Lock()
        self.log = []                 # (what, detail)
        self.bad_nonce_once = True
        self.days = 30
        self.n = 0

    def nonce(self):
        n = b64u(os.urandom(16))
        self.nonces.add(n)
        return n

    def next(self):
        self.n += 1
        return self.n


ST = None


def jwk_key(jwk):
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    x = int.from_bytes(unb64u(jwk["x"]), "big")
    y = int.from_bytes(unb64u(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def thumbprint(jwk):
    j = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(j.encode()).digest())


def validate_tls(az):
    """TLS-ALPN-01 (RFC 8737): okena's TLS port, the name as SNI, ALPN acme-tls/1 only;
    a certificate for that name alone carrying the key authorization's hash"""
    want = hashlib.sha256((az["token"] + "." + az["thumb"]).encode()).digest()
    ok, got = False, None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["acme-tls/1"])
        with socket.create_connection(("127.0.0.1", TLS2), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=az["name"]) as t:
                c = x509.load_der_x509_certificate(t.getpeercert(binary_form=True))
                ext = c.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31"))
                san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                got = (t.selected_alpn_protocol(), ext.critical, ext.value.value.hex(), san)
        # meanwhile an ordinary client of that name: the ordinary certificate
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection(("127.0.0.1", TLS2), timeout=3) as s:
            with ctx2.wrap_socket(s, server_hostname=az["name"]) as t2:
                c2 = x509.load_der_x509_certificate(t2.getpeercert(binary_form=True))
                plain = not any(e.oid.dotted_string == "1.3.6.1.5.5.7.1.31" for e in c2.extensions)
        got = got + (plain,)
        ok = got == ("acme-tls/1", True, (b"\x04\x20" + want).hex(), [az["name"]], True)
    except Exception as e:
        got = repr(e)
    with ST.lock:
        az["status"] = "valid" if ok else "invalid"
        ST.log.append(("validated", (az["name"], ok, got)))


def validate(az):
    """HTTP-01: okena's port, the name as Host"""
    want = az["token"] + "." + az["thumb"]
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{PLAIN}/.well-known/acme-challenge/{az['token']}",
                                     headers={"Host": az["name"]})
        with urllib.request.urlopen(req, timeout=3) as r:
            got = r.read().decode()
            ok = r.status == 200 and got == want
    except Exception as e:
        got, ok = repr(e), False
    with ST.lock:
        az["status"] = "valid" if ok else "invalid"
        ST.log.append(("validated", (az["name"], ok, got)))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", ctype="application/json", headers=(), chunked=False):
        self.send_response(code)
        self.send_header("Replay-Nonce", ST.nonce())
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for k, v in headers:
            self.send_header(k, v)
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_header("Content-Type", ctype)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(body), 500):
                part = body[i:i + 500]
                self.wfile.write(b"%x;ext=1\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        self.close_connection = True

    def problem(self, code, kind, detail):
        self.send(code, {"type": "urn:ietf:params:acme:error:" + kind, "detail": detail}, "application/problem+json")

    def do_GET(self):
        if self.path == "/dir":
            b = ST.base
            self.send(200, {"newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order",
                            "revokeCert": b + "/revoke", "keyChange": b + "/kc", "meta": {"termsOfService": b + "/tos"}})
        elif self.path == "/nonce":
            self.send(204)
        else:
            self.send(404, b"", "text/plain")

    def do_HEAD(self):
        self.send(200 if self.path == "/nonce" else 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with ST.lock:
            try:
                self.post(body)
            except Exception as e:
                ST.log.append(("error", repr(e)))
                self.problem(400, "malformed", repr(e))

    def post(self, body):
        st = ST
        if self.headers.get("Content-Type") != "application/jose+json":
            return self.problem(415, "malformed", "content type")
        jws = json.loads(body)
        prot = json.loads(unb64u(jws["protected"]))
        payload_raw = unb64u(jws["payload"]) if jws["payload"] else b""
        url = st.base + self.path
        if prot.get("alg") != "ES256" or prot.get("url") != url:
            return self.problem(400, "malformed", "alg or url")
        if ("jwk" in prot) == ("kid" in prot):
            return self.problem(400, "malformed", "jwk xor kid")
        if "jwk" in prot:
            if self.path != "/acct":
                return self.problem(400, "malformed", "jwk only for newAccount")
            key = jwk_key(prot["jwk"])
            thumb = thumbprint(prot["jwk"])
        else:
            if prot["kid"] not in st.by_kid:
                return self.problem(400, "accountDoesNotExist", "kid")
            thumb = st.by_kid[prot["kid"]]
            key = st.accounts[thumb][1]
        sig = unb64u(jws["signature"])
        if len(sig) != 64:
            return self.problem(400, "malformed", "signature length")
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, (jws["protected"] + "." + jws["payload"]).encode(), ec.ECDSA(hashes.SHA256()))
        n = prot.get("nonce")
        if n not in st.nonces or st.bad_nonce_once:
            st.bad_nonce_once = False
            st.nonces.discard(n)
            st.log.append(("badNonce", self.path))
            return self.problem(400, "badNonce", "nonce")
        st.nonces.discard(n)
        p = json.loads(payload_raw) if payload_raw else None
        path = self.path
        st.log.append(("post", path))
        if path == "/acct":
            if thumb in st.accounts:
                aid = st.accounts[thumb][0]
                return self.send(200, {"status": "valid"}, headers=[("Location", f"{st.base}/acct/{aid}")])
            if not p.get("termsOfServiceAgreed"):
                return self.problem(400, "malformed", "terms")
            aid = st.next()
            st.accounts[thumb] = (aid, key)
            st.by_kid[f"{st.base}/acct/{aid}"] = thumb
            st.log.append(("account", (aid, p.get("contact"))))
            return self.send(201, {"status": "valid", "contact": p.get("contact", [])}, headers=[("Location", f"{st.base}/acct/{aid}")])
        if path == "/order":
            names = [i["value"] for i in p["identifiers"] if i["type"] == "dns"]
            oid = st.next()
            azs = []
            for nm in names:
                zid = st.next()
                st.authz[zid] = {"name": nm, "status": "pending", "token": b64u(os.urandom(24)), "thumb": thumb, "cid": st.next()}
                azs.append(zid)
            st.orders[oid] = {"names": names, "authz": azs, "status": "pending", "cert": None, "thumb": thumb, "polled": 0}
            st.log.append(("order", names))
            return self.send(201, self.order_json(oid), headers=[("Location", f"{st.base}/order/{oid}")])
        if path.startswith("/authz/"):
            zid = int(path.split("/")[2])
            az = st.authz[zid]
            return self.send(200, {"identifier": {"type": "dns", "value": az["name"]}, "status": az["status"],
                                   "challenges": [
                                       {"type": "dns-01", "url": f"{st.base}/chall/x{zid}", "token": "dnstoken", "status": "pending"},
                                       {"type": "http-01", "url": f"{st.base}/chall/{zid}", "token": az["token"], "status": az["status"]},
                                       {"type": "tls-alpn-01", "url": f"{st.base}/chall/t{zid}", "token": az["token"], "status": az["status"]}]})
        if path.startswith("/chall/"):
            ref = path.split("/")[2]
            zid = int(ref.lstrip("t"))
            az = st.authz[zid]
            if p != {}:
                return self.problem(400, "malformed", "challenge payload")
            az["status"] = "processing"
            st.log.append(("challenge", "tls-alpn-01" if ref.startswith("t") else "http-01"))
            threading.Thread(target=validate_tls if ref.startswith("t") else validate, args=(az,), daemon=True).start()
            return self.send(200, {"type": "http-01", "url": f"{st.base}/chall/{zid}", "token": az["token"], "status": "processing"})
        if path.startswith("/order/"):
            oid = int(path.split("/")[2])
            o = st.orders[oid]
            o["polled"] += 1
            if o["status"] == "processing" and o["polled"] > 1:
                o["status"] = "valid"
            return self.send(200, self.order_json(oid))
        if path.startswith("/finalize/"):
            oid = int(path.split("/")[2])
            o = st.orders[oid]
            if o["status"] != "ready":
                return self.problem(403, "orderNotReady", o["status"])
            csr = x509.load_der_x509_csr(unb64u(p["csr"]))
            assert csr.is_signature_valid
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            if sorted(san) != sorted(o["names"]):
                return self.problem(400, "badCSR", "names")
            now = datetime.datetime.now(datetime.timezone.utc)
            c = issue(st.ca_k, st.ca_c, csr.public_key(), o["names"], now - datetime.timedelta(minutes=1), now + datetime.timedelta(days=st.days))
            o["cert"] = c.public_bytes(serialization.Encoding.PEM) + st.ca_c.public_bytes(serialization.Encoding.PEM)
            o["status"] = "processing"
            o["polled"] = 0
            st.log.append(("issued", (o["names"], c.serial_number)))
            return self.send(200, self.order_json(oid))
        if path.startswith("/cert/"):
            oid = int(path.split("/")[2])
            return self.send(200, st.orders[oid]["cert"], "application/pem-certificate-chain", chunked=True)
        return self.problem(404, "malformed", path)

    def order_json(self, oid):
        st = ST
        o = st.orders[oid]
        if o["status"] == "pending" and all(st.authz[z]["status"] == "valid" for z in o["authz"]):
            o["status"] = "ready"
        if any(st.authz[z]["status"] == "invalid" for z in o["authz"]):
            o["status"] = "invalid"
        j = {"status": o["status"], "identifiers": [{"type": "dns", "value": n} for n in o["names"]],
             "authorizations": [f"{st.base}/authz/{z}" for z in o["authz"]], "finalize": f"{st.base}/finalize/{oid}"}
        if o["status"] == "valid":
            j["certificate"] = f"{st.base}/cert/{oid}"
        return j


class Back(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("backend " + self.path).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def served(sni, port=TLS, alpn=None):
    """the certificate okena shows for that name (not verified), DER"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            return x509.load_der_x509_certificate(t.getpeercert(binary_form=True))


def verified(sni, cafile):
    return verified_on(sni, cafile, TLS)


def verified_on(sni, cafile, port):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            t.sendall(f"GET /x HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            return t.recv(4096)


def main():
    global ST
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acme-", dir="/tmp"))
    ca_k, ca_c = make_ca()
    (tmp / "ca.pem").write_bytes(ca_c.public_bytes(serialization.Encoding.PEM))
    # the CA's own HTTPS: localhost, signed by its CA
    sk = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sc = issue(ca_k, ca_c, sk.public_key(), ["localhost"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=5))
    (tmp / "srv.pem").write_bytes(sc.public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ST = CAState(ca_k, ca_c)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", CA), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()

    adir = tmp / "acme"
    # c.example.test: a certificate there already, 2/3 of its life gone
    (adir / "c.example.test").mkdir(parents=True)
    ok_ = ec.generate_private_key(ec.SECP256R1())
    old = issue(ca_k, ca_c, ok_.public_key(), ["c.example.test"], now - datetime.timedelta(hours=3), now + datetime.timedelta(hours=1))
    (adir / "c.example.test" / "cert.pem").write_bytes(old.public_bytes(serialization.Encoding.PEM) + ca_c.public_bytes(serialization.Encoding.PEM))
    (adir / "c.example.test" / "key.pem").write_bytes(ok_.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {adir} ca=https://localhost:{CA}/dir email=ops@example.test trust={tmp}/ca.pem }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{TLS} {{
    tls {{ acme a.example.test b.example.test; acme c.example.test }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    procs = [p]
    cafile = str(tmp / "ca.pem")
    try:
        # at once: one okena signed itself for the names (the CA's not here yet)
        first = None

        def placeholder():
            nonlocal first
            first = served("a.example.test")
            return True
        until(placeholder, 5)
        check("before the CA answers: a certificate okena signed for the names", first is not None
              and first.issuer == first.subject and "b.example.test" in
              first.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),
              (first, log.read_text()[-300:]))
        check("c.example.test: the one in the directory, loaded", served("c.example.test").serial_number == old.serial_number)

        def issued_ab():
            c = served("a.example.test")
            return c.issuer == ca_c.subject
        check("the CA's certificate, after the order: served, verified for both names (a reload of its own)",
              until(issued_ab, 15) and verified("a.example.test", cafile).startswith(b"HTTP/1.1 200")
              and verified("b.example.test", cafile).startswith(b"HTTP/1.1 200"),
              (log.read_text()[-600:], [e for e in ST.log if e[0] != "post"][-8:]))
        v = [e[1] for e in ST.log if e[0] == "validated"]
        check("  each name proven over HTTP-01 on okena's port, the key authorization right",
              {x[0] for x in v if x[1]} >= {"a.example.test", "b.example.test"} and all(x[1] for x in v), v)
        check("  the account: one, made with its key, the contact given",
              len(ST.accounts) == 1 and any(e[0] == "account" and e[1][1] == ["mailto:ops@example.test"] for e in ST.log))
        check("  a badNonce: asked again with a fresh one", sum(1 for e in ST.log if e[0] == "badNonce") == 1)
        check("c.example.test, 2/3 of its life gone: renewed", until(lambda: served("c.example.test").serial_number != old.serial_number
                                                                   and served("c.example.test").issuer == ca_c.subject, 10))
        f = adir / "a.example.test"
        check("the files: cert.pem (the chain), key.pem 0600, the account key",
              (f / "cert.pem").read_bytes().count(b"BEGIN CERTIFICATE") == 2 and (os.stat(f / "key.pem").st_mode & 0o777) == 0o600
              and (adir / "account.key").exists() and not list(adir.rglob("*.new")))
        r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PLAIN}/.well-known/acme-challenge/nottoken"), timeout=3)
        check("a token not asked for: to the routes", r.read() == b"backend /.well-known/acme-challenge/nottoken")
        orders = sum(1 for e in ST.log if e[0] == "order")
        check("  two orders: a+b, and c", orders == 2, [e for e in ST.log if e[0] == "order"])

        # again, from the files: nothing asked
        serial = served("a.example.test").serial_number
        p.terminate()
        p.wait(10)
        n0 = len(ST.log)
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("a restart: the certificates from the directory at once", until(lambda: served("a.example.test").serial_number == serial, 5))
        check("  and nothing asked of the CA (none due)", not until(lambda: [e for e in ST.log[n0:] if e[0] in ("order", "post")], 1.5), ST.log[n0:])
        p.terminate()
        p.wait(10)

        # TLS-ALPN-01: only a TLS port, no http listener (no port 80 needed)
        n0 = len(ST.log)
        conf2 = tmp / "okena2.conf"
        conf2.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme2 ca=https://localhost:{CA}/dir trust={tmp}/ca.pem challenge=tls-alpn-01 }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS2} {{
    tls {{ acme d.example.test }}
    route /* {{ to pool b }}
}}
""")
        p = subprocess.Popen([str(BIN), "-c", str(conf2)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("tls-alpn-01: proven on the TLS port (ALPN acme-tls/1, the hash in a critical acmeIdentifier), issued",
              until(lambda: served("d.example.test", TLS2).issuer == ca_c.subject, 15),
              (ST.log[n0:][-8:], log.read_text()[-400:]))
        v = [e[1] for e in ST.log[n0:] if e[0] == "validated"]
        check("  the challenge chosen: tls-alpn-01, validated (an ordinary client meanwhile: the ordinary certificate)", [e[1] for e in ST.log[n0:] if e[0] == "challenge"] == ["tls-alpn-01"]
              and len(v) == 1 and v[0][1], v)
        try:
            c = served("d.example.test", TLS2, ["acme-tls/1"])
            refused = not any(e.oid.dotted_string == "1.3.6.1.5.5.7.1.31" for e in c.extensions)
        except (ssl.SSLError, OSError):
            refused = True
        check("  acme-tls/1 with no challenge pending: no challenge certificate", refused)
        check("  the CA's certificate, verified", verified_on("d.example.test", cafile, TLS2).startswith(b"HTTP/1.1 200"))
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
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-500:])
    shutil.rmtree(tmp, ignore_errors=True)
    srv.shutdown()
    print(f"acme {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
