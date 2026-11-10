#!/usr/bin/env python3
"""`client_ca` and `auth mtls`, on one engine (argument): who gets in on a required
listener and on an optional one, what the backend is told, and each way to pass
for someone else: a forged chain, a key that is not the certificate's, a ticket
from another listener, a name made to break a header."""
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import os
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    from cryptography import x509
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip mtls: no cryptography")
    sys.exit(0)

BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 15000 + os.getpid() % 50 * 12 + (6 if ENGINE == "epoll" else 0)	# ports 15000-15599: this suite's own
BACK, SHADOW, REQ, OPT, KT, OPEN = (BASE + i for i in range(6))
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name_of(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn, _validate=False)])


def make(cn, issuer, sk, signer, ca=False, days=2, eku=None, subject=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    pub = sk if not hasattr(sk, "public_key") else sk.public_key()
    b = x509.CertificateBuilder().subject_name(subject or name_of(cn)).issuer_name(name_of(issuer)).public_key(pub) \
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=3)) \
        .not_valid_after(now + datetime.timedelta(days=days)) \
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return b.sign(signer, hashes.SHA256())


seen = []


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        who = self.headers.get("x-user-id") or self.headers.get("x-who", "-")
        seen.append((self.server.server_address[1], self.path, who))
        b = who.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Client:
    def __init__(self, tmp):
        self.tmp, self.n = tmp, 0

    def ctx(self, chain=None, sk=None, version=ssl.TLSVersion.TLSv1_3):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        c.minimum_version = c.maximum_version = version
        if chain:
            self.n += 1
            f = self.tmp / f"cl{self.n}.pem"
            f.write_bytes(b"".join(x.public_bytes(serialization.Encoding.PEM) for x in chain) +
                          sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
            c.load_cert_chain(f)
        return c


def req(port, ctx, path="/", headers=None, session=None):
    """(status, body), or the error. TLS 1.3 hides a refused certificate until the
    first read: the server's answer is what tells."""
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.settimeout(3)
    try:
        t = ctx.wrap_socket(s, session=session)
        h = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        t.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{h}\r\n".encode())
        d = b""
        while True:
            try:
                x = t.recv(65536)
            except ssl.SSLZeroReturnError:
                break
            if not x:
                break
            d += x
        if not d:
            return "closed"
        return int(d.split()[1]), d.split(b"\r\n\r\n", 1)[1].decode(errors="replace"), getattr(t, "session", None)
    except (OSError, ssl.SSLError) as e:
        return "refused"
    finally:
        s.close()


def body(r):
    return r[:2] if isinstance(r, tuple) else r


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def label(secret, name, ctx, n):
    full = b"tls13 " + name
    info = struct.pack(">HB", n, len(full)) + full + bytes([len(ctx)]) + ctx
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


class Liar:
    """TLS 1.3 by hand, because a TLS library will not send what a liar sends: a
    certificate it has no key for, a signature over something else."""

    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), 3)
        self.s.settimeout(3)
        self.buf = b""
        self.tr = hashlib.sha256()
        self.seq = 0

    def rec(self):
        while len(self.buf) < 5 or len(self.buf) < 5 + int.from_bytes(self.buf[3:5], "big"):
            d = self.s.recv(65536)
            if not d:
                raise ConnectionError
            self.buf += d
        n = 5 + int.from_bytes(self.buf[3:5], "big")
        r, self.buf = self.buf[:n], self.buf[n:]
        return r

    def seal(self, key, iv, seq, data, kind):
        n = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        head = bytes([23, 3, 3]) + (len(data) + 17).to_bytes(2, "big")
        return head + AESGCM(key).encrypt(n, data + bytes([kind]), head)

    def hello(self):
        self.sk = x25519.X25519PrivateKey.generate()
        pub = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ext = b""
        for t, v in ((43, b"\x02\x03\x04"), (10, b"\x00\x02\x00\x1d"), (13, b"\x00\x02\x04\x03"),
                     (51, struct.pack(">HHH", 36, 29, 32) + pub)):
            ext += struct.pack(">HH", t, len(v)) + v
        ch = hs(1, b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01\x01\x00" +
                struct.pack(">H", len(ext)) + ext)
        self.s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch)
        self.tr.update(ch)
        r = self.rec()
        assert r[0] == 22
        sh = r[5:]
        self.tr.update(sh)
        i = sh.find(b"\x00\x33\x00\x24\x00\x1d\x00\x20")
        shared = self.sk.exchange(x25519.X25519PublicKey.from_public_bytes(sh[i + 8:i + 40]))
        zero = bytes(32)
        early = hkdf_extract(zero, zero)
        derived = label(early, b"derived", hashlib.sha256().digest(), 32)
        hsec = hkdf_extract(derived, shared)
        th = self.tr.digest()
        self.cht, sht = label(hsec, b"c hs traffic", th, 32), label(hsec, b"s hs traffic", th, 32)
        self.ms = hkdf_extract(label(hsec, b"derived", hashlib.sha256().digest(), 32), zero)
        k, iv = label(sht, b"key", b"", 16), label(sht, b"iv", b"", 12)
        msgs, seq = b"", 0
        while True:
            r = self.rec()
            if r[0] == 20:
                continue
            n = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
            p = AESGCM(k).decrypt(n, r[5:], r[:5]).rstrip(b"\x00")[:-1]
            seq += 1
            msgs += p
            if b"\x14\x00\x00\x20" in msgs[-36:-30] or msgs[-36:-32] == b"\x14\x00\x00\x20":
                break
        self.tr.update(msgs)
        return b"\x0d" == msgs[6:7] or b"\x0d\x00\x00\x0f" in msgs

    def flight(self, certs, sign=None, content=None, finished=None, scheme=b"\x04\x03", cv=True):
        """certs: DERs (none: an empty list). sign(content) makes the signature."""
        lst = b"".join(len(c).to_bytes(3, "big") + c + b"\x00\x00" for c in certs)
        ce = hs(11, b"\x00" + len(lst).to_bytes(3, "big") + lst)
        self.tr.update(ce)
        out = [ce]
        if cv:
            th = self.tr.digest()
            c = content or (b" " * 64 + b"TLS 1.3, client CertificateVerify\x00" + th)
            sig = sign(c)
            m = hs(15, scheme + struct.pack(">H", len(sig)) + sig)
            self.tr.update(m)
            out.append(m)
        fk = label(self.cht, b"finished", b"", 32)
        vd = hmac.new(fk, self.tr.digest(), hashlib.sha256).digest()
        out.append(hs(20, finished or vd))
        k, iv = label(self.cht, b"key", b"", 16), label(self.cht, b"iv", b"", 12)
        wire = b"\x14\x03\x03\x00\x01\x01"
        for i, m in enumerate(out):
            wire += self.seal(k, iv, i, m, 22)
        self.s.sendall(wire)
        # the keys come from the transcript through the server's Finished, which
        # is what was hashed before our flight: kept by the caller
        return self

    def app(self, th):
        cap, sap = label(self.ms, b"c ap traffic", th, 32), label(self.ms, b"s ap traffic", th, 32)
        k, iv = label(cap, b"key", b"", 16), label(cap, b"iv", b"", 12)
        self.s.sendall(self.seal(k, iv, 0, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 23))
        k, iv = label(sap, b"key", b"", 16), label(sap, b"iv", b"", 12)
        seq, data = 0, b""
        while True:
            try:
                r = self.rec()
            except (ConnectionError, OSError):
                if data:
                    return data
                raise
            n = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
            p = AESGCM(k).decrypt(n, r[5:], r[:5]).rstrip(b"\x00")
            seq += 1
            if p[-1] == 23:
                data += p[:-1]
            elif p[-1] == 21 and data:
                return data


def lie(port, certs, sign=None, **kw):
    """what a lying client gets: the response, or `refused`"""
    c = Liar(port)
    try:
        c.hello()
        th = c.tr.digest()
        c.flight(certs, sign, **kw)
        d = c.app(th)
        return int(d.split()[1]), d.split(b"\r\n\r\n", 1)[1].decode()
    except (OSError, ConnectionError, InvalidTag, AssertionError):
        return "refused"
    finally:
        c.s.close()


def ecdsa(sk):
    return lambda c: sk.sign(c, ec.ECDSA(hashes.SHA256()))


CONF = """okena {{ drain delay=0s timeout=1s; workers 2; io_engine {engine} }}
pool b {{ server 127.0.0.1:{back} }}
pool s {{ server 127.0.0.1:{shadow} }}
http 127.0.0.1:{req} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/ca.pem }}
    http2 on
    route /plain {{ to pool b }}
    route /*  {{ auth mtls; to pool b }}
}}
http 127.0.0.1:{opt} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/ca.pem optional }}
    route /need {{ auth mtls identity=x-who; to pool b }}
    route /copied {{ auth mtls; to pool b; mirror pool s }}
    route /lim {{ auth mtls; limit 2/s burst=1 key=auth.user; to pool b }}
    route /anyone {{ to pool b }}
}}
http 127.0.0.1:{kt} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/ca.pem; ktls on }}
    route /* {{ auth mtls; to pool b }}
}}
http 127.0.0.1:{open} {{
    tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key }}
    route /* {{ to pool b }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mtls."))
    cak, ak, bk, mk, srv = key(), key(), key(), key(), key()
    ca = make("ca", "ca", cak, cak, ca=True)
    (tmp / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.pem").write_bytes(make("server", "ca", srv, cak).public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.key").write_bytes(srv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    alice = make("alice", "ca", ak, cak, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    bob = make("bob", "ca", bk, cak)
    other = key()
    strangers = make("alice", "other", ak, other)
    for port, n in ((BACK, "b"), (SHADOW, "s")):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", port), Back)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    cl = Client(tmp)
    a = cl.ctx([alice], ak)
    none = cl.ctx()
    conf = tmp / "okena.conf"
    conf.write_text(CONF.format(engine=ENGINE, tmp=tmp, back=BACK, shadow=SHADOW, req=REQ, opt=OPT, kt=KT, open=OPEN))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", REQ), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        check("required: a good certificate, and who it is", body(req(REQ, a)) == (200, "alice"), req(REQ, a))
        check("  another one", body(req(REQ, cl.ctx([bob], bk))) == (200, "bob"))
        r = req(REQ, none)
        check("  no certificate: not in", not isinstance(r, tuple), r)
        check("  no route is reached without one", not isinstance(req(REQ, none, "/plain"), tuple))
        check("  a route with no auth is behind it", req(REQ, a, "/plain")[0] == 200)
        check("  the client's own x-user-id is dropped",
              body(req(REQ, cl.ctx([bob], bk), headers={"x-user-id": "root"})) == (200, "bob"))
        r = req(REQ, cl.ctx(version=ssl.TLSVersion.TLSv1_2, chain=[alice], sk=ak))
        check("TLS 1.2 too, the same checks (a certificate, who it is)", body(r) == (200, "alice"), r)

        for what, ctx in [
                ("another authority's certificate", cl.ctx([strangers], ak)),
                ("a leaf signing another leaf", cl.ctx([make("root", "alice", mk, ak), alice], mk)),
                ("a server certificate", cl.ctx([make("svc", "ca", mk, cak, eku=[ExtendedKeyUsageOID.SERVER_AUTH])], mk)),
                ("an expired certificate", cl.ctx([make("old", "ca", mk, cak, days=-1)], mk)),
                ("a name that would break a header", cl.ctx([make("x\r\nx-user-id: root", "ca", mk, cak)], mk)),
                ("a name too long to be kept", cl.ctx([make("n" * 65, "ca", mk, cak)], mk)),
                ("no name", cl.ctx([make("", "ca", mk, cak, subject=x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "o")]))], mk))]:
            if ctx:
                r = req(REQ, ctx)
                check(f"{what}: not in", not isinstance(r, tuple), r)
        der = lambda c: c.public_bytes(serialization.Encoding.DER)
        check("a hand-made client, honest, is let in", lie(REQ, [der(alice)], ecdsa(ak)) == (200, "alice"),
              lie(REQ, [der(alice)], ecdsa(ak)))
        for what, kw in (
                ("someone else's certificate, signed with another key", dict(sign=ecdsa(mk))),
                ("a signature over something else", dict(sign=ecdsa(ak), content=b" " * 64 + b"TLS 1.3, client CertificateVerify\x00" + bytes(32))),
                ("the server's label on the signature", dict(sign=ecdsa(ak), content="server")),
                ("a scheme not the key's", dict(sign=ecdsa(ak), scheme=b"\x08\x07")),
                ("no CertificateVerify", dict(cv=False)),
                ("a wrong Finished", dict(sign=ecdsa(ak), finished=bytes(32)))):
            if kw.get("content") == "server":
                kw = dict(sign=lambda c: ak.sign(c.replace(b"client Cert", b"server Cert"), ec.ECDSA(hashes.SHA256())))
            r = lie(REQ, [der(alice)], **kw)
            check(f"{what}: not in", r == "refused", r)
        check("an empty certificate list: not in", lie(REQ, [], cv=False) == "refused")
        check("  optional: in, as nobody", lie(OPT, [], cv=False)[0] in (401, 404), lie(OPT, [], cv=False))
        long = "n" * 64
        check("a name of 64 is whole, for the backend",
              body(req(REQ, cl.ctx([make(long, "ca", mk, cak)], mk))) == (200, long))

        rk, ed = rsa.generate_private_key(public_exponent=65537, key_size=2048), ed25519.Ed25519PrivateKey.generate()
        check("an RSA client", body(req(REQ, cl.ctx([make("rsa", "ca", rk, cak)], rk))) == (200, "rsa"))
        check("an Ed25519 client", body(req(REQ, cl.ctx([make("ed", "ca", ed, cak)], ed))) == (200, "ed"))
        inter = key()
        chain = [make("mid-client", "mid", mk, inter), make("mid", "ca", inter, cak, ca=True)]
        check("through an intermediate", body(req(REQ, cl.ctx(chain, mk))) == (200, "mid-client"))
        (tmp / "split.pem").write_bytes(alice.public_bytes(serialization.Encoding.PEM) +
                                        ak.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        q = subprocess.run(["timeout", "5", "openssl", "s_client", "-connect", f"127.0.0.1:{REQ}", "-tls1_3", "-quiet",
                            "-cert", str(tmp / "split.pem"), "-key", str(tmp / "split.pem"), "-max_send_frag", "512",
                            "-ign_eof"], input=b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                           capture_output=True)
        check("a message in many records", q.stdout.endswith(b"alice"), q.stdout[-80:] + q.stderr[-160:])
        r = req(KT, a)
        check("kTLS: the same", body(r) == (200, "alice"), r)

        # the ticket: a session of a listener that asks nothing must not open one
        # that does
        o = cl.ctx()
        s1 = socket.create_connection(("127.0.0.1", OPEN), 3)
        t = o.wrap_socket(s1)
        t.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        while t.recv(4096):
            pass
        ticket = t.session
        s1.close()
        check("  (a ticket came from the open listener)", ticket is not None and ticket.has_ticket)
        r = req(REQ, o, session=ticket)
        check("a ticket from another listener: not in", not isinstance(r, tuple), r)
        r = req(OPT, o, "/need", session=ticket)
        check("  nor as anyone, on an optional one", isinstance(r, tuple) and r[0] == 401, r)
        # its own tickets: after the client's flight, with who it is; a resumption
        # is that client again without a certificate, here only
        r = req(REQ, a)
        sess = r[2] if isinstance(r, tuple) else None
        check("this listener's ticket comes after the client's certificate", sess is not None and sess.has_ticket, r)
        s2 = socket.create_connection(("127.0.0.1", REQ), 3)
        t = a.wrap_socket(s2, session=sess)                # (a resumption: no certificate asked, none sent)
        reused = t.session_reused
        t.close()
        r2 = req(REQ, a, session=sess)
        check("  it resumes, as the same client", reused and body(r2) == (200, "alice"), (reused, r2))
        n = cl.ctx()
        r3 = req(OPT, n, "/need")
        r4 = req(REQ, n, session=r3[2] if isinstance(r3, tuple) else None)
        check("  an optional listener's ticket, no one in it: not in on a required one",
              isinstance(r3, tuple) and r3[0] == 401 and not isinstance(r4, tuple), (r3, r4))
        s1.close()

        check("optional: no certificate is fine for what asks none", req(OPT, none, "/anyone")[0] == 200)
        check("  a route that asks for one refuses", req(OPT, none, "/need")[0] == 401)
        check("  with one, under the name it was told", body(req(OPT, a, "/need")) == (200, "alice"))
        seen.clear()
        req(OPT, a, "/copied")
        for i in range(20):
            if len(seen) >= 2:
                break
            time.sleep(0.05)
        check("a mirror's copy says who, too", sorted(x[2] for x in seen) == ["alice", "alice"], seen)
        time.sleep(1.1)
        for who, c in (("alice", a), ("bob", cl.ctx([bob], bk))):
            codes = [req(OPT, c, "/lim")[0] for i in range(6)]
            check(f"limit by who, {who} has their own", codes[0] == 200 and 429 in codes, codes)

        q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "--cert", str(tmp / "cl1.pem"),
                            "-o", "-", "-w", " %{http_version}", f"https://127.0.0.1:{REQ}/"],
                           capture_output=True, text=True)
        check("over HTTP/2, each stream knows who", q.stdout == "alice 2", q.stdout + q.stderr[-100:])
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-300:])
    text = CONF.format(engine=ENGINE, tmp=tmp, back=BACK, shadow=SHADOW, req=REQ, opt=OPT, kt=KT, open=OPEN)
    for what, bad in (
            ("auth mtls with no client_ca", text.replace("tls {{ cert".replace("{{", "{"), "tls { cert", 1).replace(f"; client_ca {tmp}/ca.pem }}", " }", 1)),
            ("client_ca and http3", text.replace("http2 on", "http3 on")),
            ("a client_ca that is not there", text.replace(f"client_ca {tmp}/ca.pem }}", "client_ca /nosuch }", 1)),
            ("client_ca on tcp", f"pool b {{ server 127.0.0.1:1 }}\ntcp 127.0.0.1:{KT} {{ tls {{ cert {tmp}/srv.pem; key {tmp}/srv.key; client_ca {tmp}/ca.pem }}; to pool b }}\n")):
        c = tmp / "bad.conf"
        c.write_text(bad)
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-160:]}")
    print(f"mtls {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
