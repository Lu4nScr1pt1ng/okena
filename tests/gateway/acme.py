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
import hmac
import socketserver
import struct
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
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 56000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS, CA, TLS2, CF, TLS3, DNS, TLS4, R53_PORT, TLS5 = (BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5,
                                                             BASE + 6, BASE + 7, BASE + 8, BASE + 9, BASE + 10)
CF_TOKEN = "cf-test-token_0123"
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


def issue(ca_k, ca_c, pub, names, before, after, ocsp_url=None):
    b = (x509.CertificateBuilder().subject_name(name(names[0])).issuer_name(ca_c.subject).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_k.public_key()), critical=False))
    if ocsp_url:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))]), critical=False)
    return b.sign(ca_k, hashes.SHA256())


def certid(c):
    """ARI's CertID: base64url(AKI keyIdentifier) "." base64url(the serial's DER bytes)"""
    aki = c.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    sn = c.serial_number
    return b64u(aki) + "." + b64u(sn.to_bytes((sn.bit_length() + 8) // 8, "big"))


def rfc3339(t, frac=False):
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (".123456Z" if frac else "Z")


class CAState:
    def __init__(self, ca_k, ca_c, port=None):
        self.ca_k, self.ca_c = ca_k, ca_c
        self.base = f"https://localhost:{port or CA}"
        self.eab = {}                 # kid -> HMAC key: external accounts required
        self.fail_orders = None       # (status, error) every newOrder gets
        self.garbage = False          # every answer HTML, not ACME (make chaos)
        self.ari = None               # ARI (RFC 9773): CertID -> (start, end), when served
        self.ocsp_url = None          # put in the certificates it issues (AIA)
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


CFS = {"records": {}, "log": [], "n": 0, "lock": threading.Lock()}


def sigv4(secret, method, path, query, headers, signed, payload, amzdate, region, service):
    """AWS Signature Version 4 (checked below against AWS's own get-vanilla vector)"""
    def h(k, m):
        return hmac.new(k, m.encode(), hashlib.sha256).digest()
    creq = "\n".join([method, path, query] + [f"{n}:{headers[n]}" for n in signed.split(";")] + ["", signed,
                      hashlib.sha256(payload).hexdigest()])
    scope = f"{amzdate[:8]}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = h(h(h(h(("AWS4" + secret).encode(), amzdate[:8]), region), service), "aws4_request")
    return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest(), scope


R53 = {"akid": "AKIDOKENATEST", "secret": "okena/Test+Secret0123456789abcdefghijKLMN", "token": "sess-tok/en+" + "x" * 300,
       "rrsets": {}, "log": [], "changes": {}, "n": 0, "lock": threading.Lock()}
NS = "https://route53.amazonaws.com/doc/2013-04-01/"


class R53Api(http.server.BaseHTTPRequestHandler):
    """Route 53's API, as much as DNS-01 uses: zones by name (the first from that
    name on, as Route 53 lists them), record sets changed (DELETE only of what is
    there), changes PENDING then INSYNC; every request's SigV4 checked"""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def answer(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)
        self.close_connection = True

    def handle_any(self, method):
        n = int(self.headers.get("Content-Length", "0") or 0)
        payload = self.rfile.read(n) if n else b""
        path, _, query = self.path.partition("?")
        auth = self.headers.get("Authorization", "")
        amz = self.headers.get("X-Amz-Date", "")
        ok = False
        try:
            parts = dict(x.strip().split("=", 1) for x in auth[len("AWS4-HMAC-SHA256 "):].split(","))
            signed = parts["SignedHeaders"]
            hdrs = {"host": self.headers["Host"], "x-amz-date": amz,
                    "x-amz-security-token": self.headers.get("X-Amz-Security-Token", "")}
            want, scope = sigv4(R53["secret"], method, path, query, hdrs, signed, payload, amz, "us-east-1", "route53")
            ok = (auth.startswith("AWS4-HMAC-SHA256 ") and parts["Credential"] == f"{R53['akid']}/{scope}"
                  and signed == "host;x-amz-date;x-amz-security-token" and hdrs["x-amz-security-token"] == R53["token"]
                  and hmac.compare_digest(parts["Signature"], want)
                  and abs(datetime.datetime.strptime(amz, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc).timestamp() - time.time()) < 300)
        except Exception as e:
            R53["log"].append(("bad auth", repr(e)))
        with R53["lock"]:
            R53["log"].append((method, self.path, ok, self.headers.get("Content-Type")))
            if not ok:
                return self.answer(403, "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>")
            if method == "GET" and path == "/2013-04-01/hostedzonesbyname":
                q = urllib.parse.parse_qs(query)
                # (the zones listed from that name on: example.test whatever is asked, here)
                return self.answer(200, f'<?xml version="1.0"?><ListHostedZonesByNameResponse xmlns="{NS}"><HostedZones>'
                                        f'<HostedZone><Id>/hostedzone/Z0EXAMPLE123</Id><Name>example.test.</Name></HostedZone>'
                                        f'</HostedZones><DNSName>{q["dnsname"][0]}</DNSName><MaxItems>{q["maxitems"][0]}</MaxItems>'
                                        f'</ListHostedZonesByNameResponse>')
            if method == "POST" and path == "/2013-04-01/hostedzone/Z0EXAMPLE123/rrset":
                x = ET.fromstring(payload)
                c = x.find(f"{{{NS}}}ChangeBatch/{{{NS}}}Changes/{{{NS}}}Change")
                action = c.find(f"{{{NS}}}Action").text
                rr = c.find(f"{{{NS}}}ResourceRecordSet")
                name = rr.find(f"{{{NS}}}Name").text.rstrip(".")
                key = (name, rr.find(f"{{{NS}}}Type").text)
                vals = sorted(v.text for v in rr.iter(f"{{{NS}}}Value"))
                ttl = int(rr.find(f"{{{NS}}}TTL").text)
                if action == "DELETE":
                    if R53["rrsets"].get(key) != (ttl, vals):
                        return self.answer(400, "<ErrorResponse><Error><Code>InvalidChangeBatch</Code></Error></ErrorResponse>")
                    del R53["rrsets"][key]
                elif action in ("UPSERT", "CREATE"):
                    R53["rrsets"][key] = (ttl, vals)
                R53["n"] += 1
                cid = f"C{R53['n']:06d}XYZ"
                R53["changes"][cid] = 0
                R53["log"].append(("change", action, key, vals))
                return self.answer(200, f'<?xml version="1.0"?><ChangeResourceRecordSetsResponse xmlns="{NS}"><ChangeInfo>'
                                        f'<Id>/change/{cid}</Id><Status>PENDING</Status><SubmittedAt>2026-11-09T00:00:00Z</SubmittedAt>'
                                        f'</ChangeInfo></ChangeResourceRecordSetsResponse>')
            if method == "GET" and path.startswith("/2013-04-01/change/"):
                cid = path.rsplit("/", 1)[1]
                if cid not in R53["changes"]:
                    return self.answer(404, "<ErrorResponse/>")
                R53["changes"][cid] += 1
                st = "INSYNC" if R53["changes"][cid] > 1 else "PENDING"
                return self.answer(200, f'<?xml version="1.0"?><GetChangeResponse xmlns="{NS}"><ChangeInfo><Id>/change/{cid}</Id>'
                                        f'<Status>{st}</Status></ChangeInfo></GetChangeResponse>')
            return self.answer(404, "<ErrorResponse/>")

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def txt_of(name):
    with CFS["lock"]:
        got = [r["content"] for r in CFS["records"].values() if r["type"] == "TXT" and r["name"] == name]
    with R53["lock"]:
        got += [v.strip('"') for v in R53["rrsets"].get((name, "TXT"), (0, []))[1]]
    return got


def validate_dns(az):
    """DNS-01: a TXT record _acme-challenge.NAME, base64url(SHA-256(key authorization))
    (the DNS here: what the provider's API holds)"""
    want = b64u(hashlib.sha256((az["token"] + "." + az["thumb"]).encode()).digest())
    got = txt_of("_acme-challenge." + az["name"])
    ok = want in got
    with az["st"].lock:
        az["status"] = "valid" if ok else "invalid"
        az["st"].log.append(("validated", (az["name"], ok, got)))


class CFApi(http.server.BaseHTTPRequestHandler):
    """Cloudflare's API, as much as DNS-01 uses: zones by name, TXT records made and removed"""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def answer(self, code, j):
        b = json.dumps(j).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b)
        self.close_connection = True

    def handle_any(self, method):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = json.loads(self.rfile.read(n)) if n else None
        with CFS["lock"]:
            CFS["log"].append((method, self.path, self.headers.get("Authorization"), self.headers.get("Content-Type")))
            if self.headers.get("Authorization") != "Bearer " + CF_TOKEN:
                return self.answer(403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})
            parts = self.path.split("?")[0].split("/")
            if method == "GET" and self.path.startswith("/client/v4/zones?name="):
                name = self.path.split("=", 1)[1]
                res = [{"id": "zone1example", "name": name}] if name == "example.test" else []
                return self.answer(200, {"success": True, "result": res})
            if method == "POST" and parts[-1] == "dns_records" and parts[-2] == "zone1example":
                CFS["n"] += 1
                rid = f"rec{CFS['n']:04d}abc"
                CFS["records"][rid] = dict(body, id=rid)
                return self.answer(200, {"success": True, "result": dict(body, id=rid)})
            if method == "DELETE" and parts[-2] == "dns_records" and parts[-1] in CFS["records"]:
                del CFS["records"][parts[-1]]
                return self.answer(200, {"success": True, "result": {"id": parts[-1]}})
            return self.answer(404, {"success": False})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_DELETE(self):
        self.handle_any("DELETE")


def wire(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.lower().rstrip(".").split(".")) + b"\0"


def read_name(m, i):
    """a name at m[i], compression pointers followed: its text, the index past it"""
    labels, end = [], None
    while m[i]:
        if m[i] >= 0xC0:
            if end is None:
                end = i + 2
            i = (m[i] & 0x3F) << 8 | m[i + 1]
            continue
        labels.append(m[i + 1:i + 1 + m[i]].decode())
        i += 1 + m[i]
    return ".".join(labels), (end if end is not None else i + 1)


DNSS = {"key": "acme-key.example.test", "secret": os.urandom(32), "log": [], "zone": "example.test"}


class DNSUpdate(socketserver.BaseRequestHandler):
    """RFC 2136 UPDATE over TCP, TSIG HMAC-SHA256 (RFC 8945) checked and signed; one
    zone, example.test: any other is NOTAUTH"""

    def handle(self):
        def recv(n):
            b = b""
            while len(b) < n:
                c = self.request.recv(n - len(b))
                if not c:
                    raise EOFError
                b += c
            return b
        try:
            n = struct.unpack("!H", recv(2))[0]
            m = recv(n)
        except EOFError:
            return
        mid, flags, zo, pr, up, ar = struct.unpack("!6H", m[:12])
        i = 12
        zone, i = read_name(m, i)
        zt, zc = struct.unpack("!HH", m[i:i + 4])
        i += 4
        rrs = []
        for _ in range(pr + up):
            nm, i = read_name(m, i)
            t, c, ttl, rl = struct.unpack("!HHIH", m[i:i + 10])
            rrs.append((nm, t, c, ttl, m[i + 10:i + 10 + rl]))
            i += 10 + rl
        # the TSIG: the last additional record
        tstart = i
        kname, i = read_name(m, i)
        t, c, ttl, rl = struct.unpack("!HHIH", m[i:i + 10])
        rd = m[i + 10:i + 10 + rl]
        alg, j = read_name(rd, 0)
        tsigned = int.from_bytes(rd[j:j + 6], "big")
        fudge, msize = struct.unpack("!HH", rd[j + 6:j + 10])
        mac = rd[j + 10:j + 10 + msize]
        oid, err, olen = struct.unpack("!HHH", rd[j + 10 + msize:j + 16 + msize])
        other = rd[j + 16 + msize:j + 16 + msize + olen]
        head = bytearray(m[:tstart])
        head[10:12] = struct.pack("!H", ar - 1)
        tvars = wire(kname) + struct.pack("!HI", 255, 0) + wire(alg) + rd[j:j + 8] + struct.pack("!HH", err, olen) + other
        want = hmac.new(DNSS["secret"], bytes(head) + tvars, hashlib.sha256).digest()
        good = (t == 250 and kname == DNSS["key"] and alg == "hmac-sha256" and hmac.compare_digest(mac, want)
                and abs(tsigned - time.time()) <= fudge and (flags >> 11) & 15 == 5 and zt == 6)
        DNSS["log"].append((zone, good, [(r[0], r[1], r[2], r[3]) for r in rrs]))
        if not good:
            # BADSIG: NOTAUTH, unsigned (RFC 8945 5.3.2)
            self.reply(struct.pack("!6H", mid, 0x8000 | 5 << 11 | 9, 0, 0, 0, 0))
            return
        rcode = 0
        if zone != DNSS["zone"]:
            rcode = 9
        else:
            with CFS["lock"]:
                for nm, t, c, ttl, rdata in rrs:
                    txt = rdata[1:1 + rdata[0]].decode()
                    if c == 1 and t == 16:
                        CFS["n"] += 1
                        CFS["records"][f"dns{CFS['n']}"] = {"type": "TXT", "name": nm, "content": txt, "via": "rfc2136"}
                    elif c == 254 and t == 16:
                        for k in [k for k, r in CFS["records"].items() if r["name"] == nm and r["content"] == txt]:
                            del CFS["records"][k]
        body = struct.pack("!6H", mid, 0x8000 | 5 << 11 | rcode, 1, 0, 0, 0) + wire(zone) + struct.pack("!HH", 6, 1)
        now = int(time.time())
        rvars = wire(DNSS["key"]) + struct.pack("!HI", 255, 0) + wire("hmac-sha256") + now.to_bytes(6, "big") + struct.pack("!HHH", 300, 0, 0)
        rmac = hmac.new(DNSS["secret"], struct.pack("!H", len(mac)) + mac + body + rvars, hashlib.sha256).digest()
        rdata = wire("hmac-sha256") + now.to_bytes(6, "big") + struct.pack("!HH", 300, 32) + rmac + struct.pack("!HHH", mid, 0, 0)
        tsig = wire(DNSS["key"]) + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata
        signed = bytearray(body + tsig)
        signed[10:12] = struct.pack("!H", 1)
        self.reply(bytes(signed))

    def reply(self, msg):
        self.request.sendall(struct.pack("!H", len(msg)) + msg)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


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
    with az["st"].lock:
        az["status"] = "valid" if ok else "invalid"
        az["st"].log.append(("validated", (az["name"], ok, got)))


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
    with az["st"].lock:
        az["status"] = "valid" if ok else "invalid"
        az["st"].log.append(("validated", (az["name"], ok, got)))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", ctype="application/json", headers=(), chunked=False):
        if self.server.st.garbage:
            code, body, ctype, headers, chunked = 200, b"<html>a proxy's error page</html>", "text/html", (), False
        self.send_response(code)
        self.send_header("Replay-Nonce", self.server.st.nonce())
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
            b = self.server.st.base
            meta = {"termsOfService": b + "/tos"}
            if self.server.st.eab:
                meta["externalAccountRequired"] = True
            d = {"newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order",
                 "revokeCert": b + "/revoke", "keyChange": b + "/kc", "meta": meta}
            if self.server.st.ari is not None:
                d["renewalInfo"] = b + "/renewal-info"
            self.send(200, d)
        elif self.path.startswith("/renewal-info/") and self.server.st.ari is not None:
            st = self.server.st
            cid = self.path[len("/renewal-info/"):]
            with st.lock:
                st.log.append(("ari", cid))
                w = st.ari.get(cid)
            if not w:
                return self.send(404, b"", "text/plain")
            self.send(200, {"suggestedWindow": {"start": rfc3339(w[0], True), "end": rfc3339(w[1])}},
                      headers=[("Retry-After", "21600")])
        elif self.path == "/nonce":
            self.send(204)
        else:
            self.send(404, b"", "text/plain")

    def do_HEAD(self):
        self.send(200 if self.path == "/nonce" else 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        st = self.server.st
        with st.lock:
            try:
                self.post(body)
            except Exception as e:
                st.log.append(("error", repr(e)))
                self.problem(400, "malformed", repr(e))

    def post(self, body):
        st = self.server.st
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
            if st.eab:
                # RFC 8555 7.3.4: a JWS over the account's key, HS256 with the external account's
                eb = p.get("externalAccountBinding")
                if not eb:
                    return self.problem(400, "externalAccountRequired", "an external account binding is required")
                ep = json.loads(unb64u(eb["protected"]))
                ek = st.eab.get(ep.get("kid"))
                good = (ek is not None and ep.get("alg") == "HS256" and ep.get("url") == url and "nonce" not in ep
                        and json.loads(unb64u(eb["payload"])) == prot["jwk"]
                        and hmac.compare_digest(unb64u(eb["signature"]),
                                                hmac.new(ek, (eb["protected"] + "." + eb["payload"]).encode(), hashlib.sha256).digest()))
                st.log.append(("eab", (ep.get("kid"), good)))
                if not good:
                    return self.problem(400, "unauthorized", "external account binding")
            aid = st.next()
            st.accounts[thumb] = (aid, key)
            st.by_kid[f"{st.base}/acct/{aid}"] = thumb
            st.log.append(("account", (aid, p.get("contact"))))
            return self.send(201, {"status": "valid", "contact": p.get("contact", [])}, headers=[("Location", f"{st.base}/acct/{aid}")])
        if path == "/order":
            if st.fail_orders:
                st.log.append(("order refused", st.fail_orders))
                return self.problem(*st.fail_orders, "no")
            names = [i["value"] for i in p["identifiers"] if i["type"] == "dns"]
            if "replaces" in p:
                st.log.append(("replaces", p["replaces"]))
            oid = st.next()
            azs = []
            for nm in names:
                zid = st.next()
                wild = nm.startswith("*.")
                st.authz[zid] = {"name": nm[2:] if wild else nm, "wildcard": wild, "status": "pending", "st": st,
                                 "token": b64u(os.urandom(24)), "thumb": thumb, "cid": st.next()}
                azs.append(zid)
            st.orders[oid] = {"names": names, "authz": azs, "status": "pending", "cert": None, "thumb": thumb, "polled": 0}
            st.log.append(("order", names))
            return self.send(201, self.order_json(oid), headers=[("Location", f"{st.base}/order/{oid}")])
        if path.startswith("/authz/"):
            zid = int(path.split("/")[2])
            az = st.authz[zid]
            ch = [{"type": "dns-01", "url": f"{st.base}/chall/d{zid}", "token": az["token"], "status": az["status"]}]
            if not az["wildcard"]:          # (a wildcard: DNS-01 only, RFC 8555 7.1.3)
                ch += [{"type": "http-01", "url": f"{st.base}/chall/{zid}", "token": az["token"], "status": az["status"]},
                       {"type": "tls-alpn-01", "url": f"{st.base}/chall/t{zid}", "token": az["token"], "status": az["status"]}]
            j = {"identifier": {"type": "dns", "value": az["name"]}, "status": az["status"], "challenges": ch}
            if az["wildcard"]:
                j["wildcard"] = True
            return self.send(200, j)
        if path.startswith("/chall/"):
            ref = path.split("/")[2]
            zid = int(ref.lstrip("td"))
            az = st.authz[zid]
            if p != {}:
                return self.problem(400, "malformed", "challenge payload")
            az["status"] = "processing"
            kind = {"t": "tls-alpn-01", "d": "dns-01"}.get(ref[0], "http-01")
            st.log.append(("challenge", kind))
            fn = {"tls-alpn-01": validate_tls, "dns-01": validate_dns}.get(kind, validate)
            threading.Thread(target=fn, args=(az,), daemon=True).start()
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
            c = issue(st.ca_k, st.ca_c, csr.public_key(), o["names"], now - datetime.timedelta(minutes=1),
                      now + datetime.timedelta(days=st.days), st.ocsp_url)
            o["cert"] = c.public_bytes(serialization.Encoding.PEM) + st.ca_c.public_bytes(serialization.Encoding.PEM)
            if st.ari is not None:
                st.ari[certid(c)] = (now + datetime.timedelta(days=20), now + datetime.timedelta(days=21))
            o["status"] = "processing"
            o["polled"] = 0
            st.log.append(("issued", (o["names"], c.serial_number)))
            return self.send(200, self.order_json(oid))
        if path.startswith("/cert/"):
            oid = int(path.split("/")[2])
            return self.send(200, st.orders[oid]["cert"], "application/pem-certificate-chain", chunked=True)
        return self.problem(404, "malformed", path)

    def order_json(self, oid):
        st = self.server.st
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
    # the test's SigV4 against AWS's own vector (aws-sig-v4-test-suite, get-vanilla)
    v, _ = sigv4("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "GET", "/", "",
                 {"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"}, "host;x-amz-date", b"",
                 "20150830T123600Z", "us-east-1", "service")
    check("(the test's SigV4 gives AWS's get-vanilla signature)", v == "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", v)
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
    srv.st = ST
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    threading.Thread(target=TCPServer(("127.0.0.1", DNS), DNSUpdate).serve_forever, daemon=True).start()
    r53 = http.server.ThreadingHTTPServer(("127.0.0.1", R53_PORT), R53Api)
    r53.socket = sctx.wrap_socket(r53.socket, server_side=True)
    threading.Thread(target=r53.serve_forever, daemon=True).start()
    cf = http.server.ThreadingHTTPServer(("127.0.0.1", CF), CFApi)
    cf.socket = sctx.wrap_socket(cf.socket, server_side=True)
    threading.Thread(target=cf.serve_forever, daemon=True).start()

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
        r = subprocess.run([str(BIN), "certs", "-c", str(conf)], capture_output=True, text=True, timeout=20)
        lines = [l for l in r.stdout.splitlines() if "example.test" in l]
        ab = [l for l in lines if l.startswith("a.example.test b.example.test")]
        check("okena certs: each certificate, its names, the CA, the days left, what acme last did",
              r.returncode == 0 and r.stdout.startswith("NAMES") and len(lines) == 2 and ab
              and "okena test ACME CA" in ab[0] and (" 29d " in ab[0] or " 30d " in ab[0])
              and "acme: " in ab[0] and "got from the CA; renewal on" in ab[0], r.stdout + r.stderr)

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
        p.terminate()
        p.wait(10)

        # DNS-01 through Cloudflare's API: a wildcard and its parent
        n0 = len(ST.log)
        (tmp / "cf.token").write_text(CF_TOKEN + "\n")
        conf3 = tmp / "okena3.conf"
        conf3.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme3 ca=https://localhost:{CA}/dir trust={tmp}/ca.pem challenge=dns-01 dns=cloudflare dns_token={tmp}/cf.token dns_api=https://localhost:{CF}/client/v4 dns_wait=100ms dns_trust={tmp}/ca.pem }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS3} {{
    tls {{ acme *.w.example.test w.example.test }}
    route /* {{ to pool b }}
}}
""")
        p = subprocess.Popen([str(BIN), "-c", str(conf3)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("dns-01: a wildcard issued, served for a name under it and for its parent",
              until(lambda: served("x.w.example.test", TLS3).issuer == ca_c.subject, 15)
              and verified_on("x.w.example.test", cafile, TLS3).startswith(b"HTTP/1.1 200")
              and verified_on("w.example.test", cafile, TLS3).startswith(b"HTTP/1.1 200"),
              (ST.log[n0:][-8:], CFS["log"][-6:], log.read_text()[-400:]))
        v = [e[1] for e in ST.log[n0:] if e[0] == "validated"]
        check("  both names proven over dns-01 (the wildcard's offered nothing else)",
              [e[1] for e in ST.log[n0:] if e[0] == "challenge"] == ["dns-01", "dns-01"] and len(v) == 2 and all(x[1] for x in v), v)
        calls = [(m, path) for m, path, *_ in CFS["log"]]
        check("  the zone found from the name up, the records made in it with the token",
              ("GET", "/client/v4/zones?name=w.example.test") in calls and ("GET", "/client/v4/zones?name=example.test") in calls
              and sum(1 for m, path in calls if m == "POST" and path == "/client/v4/zones/zone1example/dns_records") == 2
              and all(a == "Bearer " + CF_TOKEN for _, _, a, _ in CFS["log"])
              and all(c == "application/json" for m, _, _, c in CFS["log"] if m == "POST"), CFS["log"])
        check("  and removed after", until(lambda: not CFS["records"], 3)
              and sum(1 for m, _ in calls if m == "DELETE") == 2, CFS["records"])
        bad = tmp / "bad.conf"
        bad.write_text(f"okena {{ acme {tmp}/x ca=https://localhost:{CA}/dir }}\npool b {{ server 127.0.0.1:{BACK} }}\n"
                       f"http 127.0.0.1:{TLS3} {{\n    tls {{ acme *.w.example.test }}\n    route /* {{ to pool b }}\n}}\n")
        r = subprocess.run([str(BIN), "check", "-c", str(bad)], capture_output=True, text=True, timeout=10)
        check("a wildcard without dns-01: refused", r.returncode != 0 and "wildcard" in r.stderr, r.stderr)
        p.terminate()
        p.wait(10)

        # DNS-01 by RFC 2136: an UPDATE signed with TSIG, to the server itself. The
        # test's server first checked against BIND's nsupdate (when it is here)
        if shutil.which("nsupdate"):
            nk = f"hmac-sha256:{DNSS['key']}:{base64.b64encode(DNSS['secret']).decode()}"
            r = subprocess.run(["nsupdate", "-v", "-y", nk], capture_output=True, text=True, timeout=10,
                               input=f"server 127.0.0.1 {DNS}\nzone example.test\n"
                                     "update add _acme-challenge.ref.example.test 60 TXT ref\nsend\n"
                                     "update delete _acme-challenge.ref.example.test TXT ref\nsend\n")
            check("  (the test's DNS server and BIND's nsupdate agree on TSIG, both ways)",
                  r.returncode == 0 and len(DNSS["log"]) == 2 and all(g for _, g, _ in DNSS["log"]), (r.stdout, r.stderr, DNSS["log"]))
            DNSS["log"].clear()
        n0 = len(ST.log)
        (tmp / "tsig.key").write_text(f"hmac-sha256:{DNSS['key']}:{base64.b64encode(DNSS['secret']).decode()}\n")
        conf4 = tmp / "okena4.conf"
        conf4.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme4 ca=https://localhost:{CA}/dir trust={tmp}/ca.pem challenge=dns-01 dns=rfc2136 dns_server=127.0.0.1:{DNS} dns_key={tmp}/tsig.key dns_wait=100ms }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS4} {{
    tls {{ acme *.r.example.test r.example.test }}
    route /* {{ to pool b }}
}}
""")
        p = subprocess.Popen([str(BIN), "-c", str(conf4)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("rfc2136: a wildcard issued through UPDATE (TSIG HMAC-SHA256)",
              until(lambda: served("y.r.example.test", TLS4).issuer == ca_c.subject, 15)
              and verified_on("y.r.example.test", cafile, TLS4).startswith(b"HTTP/1.1 200"),
              (ST.log[n0:][-6:], DNSS["log"][-4:], log.read_text()[-400:]))
        v = [e[1] for e in ST.log[n0:] if e[0] == "validated"]
        lg = DNSS["log"]
        check("  each UPDATE signed right; the zone found from the name up (NOTAUTH, then example.test)",
              lg and all(g for _, g, _ in lg) and lg[0][0] == "r.example.test" and lg[1][0] == "example.test"
              and len(v) == 2 and all(x[1] for x in v), (lg, v))
        check("  the records added (IN, TTL 60), then removed (NONE)",
              until(lambda: not [r for r in CFS["records"].values() if r.get("via") == "rfc2136"], 3)
              and sum(1 for z, _, rr in lg if z == "example.test" and rr and rr[0][2] == 1 and rr[0][3] == 60) == 2
              and sum(1 for z, _, rr in lg if z == "example.test" and rr and rr[0][2] == 254) == 2, lg)
        p.terminate()
        p.wait(10)
        # the wrong key: the server's unsigned BADSIG is not taken
        (tmp / "bad.key").write_text(f"{DNSS['key']}:{base64.b64encode(os.urandom(32)).decode()}\n")
        conf5 = tmp / "okena5.conf"
        conf5.write_text(conf4.read_text().replace(f"{tmp}/tsig.key", f"{tmp}/bad.key").replace(f"{tmp}/acme4", f"{tmp}/acme5"))
        n1 = len(DNSS["log"])
        p = subprocess.Popen([str(BIN), "-c", str(conf5)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("  the wrong key: refused by the server, its unsigned answer not taken, said",
              until(lambda: "not signed with the key" in log.read_text(), 8) and DNSS["log"][n1:]
              and not any(g for _, g, _ in DNSS["log"][n1:]), (DNSS["log"][n1:], log.read_text()[-300:]))
        p.terminate()
        p.wait(10)

        # DNS-01 through Route 53: SigV4 (with a session token), the zone by name,
        # the wildcard's and its parent's values in one record set, INSYNC waited for
        n0 = len(ST.log)
        (tmp / "aws.key").write_text(f"{R53['akid']}:{R53['secret']}:{R53['token']}\n")
        conf6 = tmp / "okena6.conf"
        conf6.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme6 ca=https://localhost:{CA}/dir trust={tmp}/ca.pem challenge=dns-01 dns=route53 dns_key={tmp}/aws.key dns_api=https://localhost:{R53_PORT} dns_wait=100ms dns_trust={tmp}/ca.pem }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS5} {{
    tls {{ acme *.q.example.test q.example.test }}
    route /* {{ to pool b }}
}}
""")
        p = subprocess.Popen([str(BIN), "-c", str(conf6)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        check("route53: a wildcard issued (SigV4, a session token)",
              until(lambda: served("z.q.example.test", TLS5).issuer == ca_c.subject, 20)
              and verified_on("q.example.test", cafile, TLS5).startswith(b"HTTP/1.1 200"),
              (ST.log[n0:][-6:], R53["log"][-6:], log.read_text()[-400:]))
        lg = R53["log"]
        calls = [(e[0], e[1]) for e in lg if e[0] in ("GET", "POST")]
        check("  every request signed right; the zone by name: q.example.test's answer not taken (another zone's), example.test's",
              lg and all(e[2] for e in lg if e[0] in ("GET", "POST"))
              and ("GET", "/2013-04-01/hostedzonesbyname?dnsname=q.example.test&maxitems=1") in calls
              and ("GET", "/2013-04-01/hostedzonesbyname?dnsname=example.test&maxitems=1") in calls
              and all(e[3] == "text/xml" for e in lg if e[0] == "POST"), lg)
        ch = [e for e in lg if e[0] == "change"]
        check("  one record set, its values added up (UPSERT 1, then 2), INSYNC waited for, then DELETE exactly",
              [c[1] for c in ch] == ["UPSERT", "UPSERT", "DELETE"] and len(ch[0][3]) == 1 and len(ch[1][3]) == 2
              and ch[2][3] == ch[1][3] and not R53["rrsets"]
              and sum(1 for e in calls if e[1].startswith("/2013-04-01/change/")) >= 4, ch)
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


if __name__ == "__main__":
    main()
