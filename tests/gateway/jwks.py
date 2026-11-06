#!/usr/bin/env python3
"""`jwks URL` on `auth jwt`, on one engine (argument). Keys that rotate, and each
way a provider can fail or lie: down, slow to come up, a bad body, the wrong
certificate. Keys already here must outlive what can be survived, and no more."""
import base64
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
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.x509.oid import NameOID
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip jwks: no cryptography")
    sys.exit(0)

ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 29900 + os.getpid() % 3 * 16 + (8 if ENGINE == "epoll" else 0)	# (above what the mirror suite's BASE reaches)
BACK, LST, GOOD, EVIL, LATER = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
fails = 0
SECRET = {"kty": "oct", "kid": "s", "alg": "HS256", "k": base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode()}


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, "" if ok else detail, flush=True)
    fails += 0 if ok else 1


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Key:
    def __init__(self, kid):
        self.kid, self.sk = kid, ec.generate_private_key(ec.SECP256R1())

    def jwk(self):
        n = self.sk.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "kid": self.kid, "alg": "ES256", "use": "sig",
                "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}

    def token(self, sub="alice"):
        m = b64(json.dumps({"alg": "ES256", "kid": self.kid}).encode()) + "." + \
            b64(json.dumps({"sub": sub, "exp": int(time.time()) + 3600}).encode())
        r, s = utils.decode_dss_signature(self.sk.sign(m.encode(), ec.ECDSA(hashes.SHA256())))
        return m + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def jset(*keys):
    return json.dumps({"keys": [k.jwk() for k in keys]}).encode()


class Provider:
    """path -> what it answers: bytes, or (status, body), or a function of the handler"""

    def __init__(self, port, ctx=None):
        self.port, self.ctx, self.paths, self.hits = port, ctx, {}, {}
        self.srv = None

    def start(self):
        p = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                p.hits[self.path] = p.hits.get(self.path, 0) + 1
                a = p.paths.get(self.path, (404, b"no"))
                if callable(a):
                    a(self)
                    return
                st, body = a if isinstance(a, tuple) else (200, a)
                self.send_response(st)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, *a):
                pass

        class S(http.server.ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, *a):
                pass

        self.srv = S(("127.0.0.1", self.port), H)
        if self.ctx:
            self.srv.socket = self.ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def chunked(body):
    def go(h):
        h.send_response(200)
        h.send_header("Transfer-Encoding", "chunked")
        h.send_header("Connection", "close")
        h.end_headers()
        m = len(body) // 2
        for part in (body[:m], body[m:]):
            h.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
        h.wfile.write(b"0\r\n\r\n")
        h.close_connection = True
    return go


def cut_short(body):
    def go(h):
        h.send_response(200)
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Connection", "close")
        h.end_headers()
        h.wfile.write(body[:len(body) // 2])
        h.close_connection = True
    return go


def name_of(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(cn, issuer, sk, signer, ca, days=2, usage=None):
    """a certificate for `cn` and sk, by `signer`; ca as said, valid for days from now"""
    now = datetime.datetime.now(datetime.timezone.utc)
    b = x509.CertificateBuilder().subject_name(name_of(cn)).issuer_name(name_of(issuer)).public_key(sk.public_key()) \
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=3)) \
        .not_valid_after(now + datetime.timedelta(days=days))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if usage == "no-sign":
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    return b.sign(signer, hashes.SHA256())


def serving(tmp, name, chain, sk):
    """a server context that presents this chain, leaf first"""
    (tmp / f"{name}.leaf").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain))
    (tmp / f"{name}.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / f"{name}.leaf", tmp / f"{name}.key")
    return ctx


def certs(tmp, name, cn):
    cak, leafk = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = make(name, name, cak, cak, True)
    (tmp / f"{name}.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return serving(tmp, name, [make(cn, name, leafk, cak, False)], leafk), cak


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def status(path, token):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    try:
        c.request("GET", path, headers={"Authorization": "Bearer " + token, "Connection": "close"})
        return c.getresponse().status
    except OSError as e:
        return str(e)
    finally:
        c.close()


def until(f, secs):
    end = time.time() + secs
    while time.time() < end:
        if f():
            return True
        time.sleep(0.1)
    return f()


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-jwks."))
    (good_ctx, cak), (evil_ctx, _) = certs(tmp, "ca", "localhost"), certs(tmp, "evil", "localhost")
    k = lambda: ec.generate_private_key(ec.SECP256R1())
    # chains the authority never signed the end of. A holder of any leaf of it:
    bob, fake, inter = k(), k(), k()
    bobc = make("bob.example", "ca", bob, cak, False)
    bobnone = make("bob.example", "ca", bob, cak, None)
    bobca = make("bob.example", "ca", bob, cak, True, usage="no-sign")
    forged = [("a leaf signing another leaf", [make("localhost", "bob.example", fake, bob, False), bobc], fake),
              ("a certificate that says nothing of being a CA", [make("localhost", "bob.example", fake, bob, False), bobnone], fake),
              ("a CA not allowed to sign certificates", [make("localhost", "bob.example", fake, bob, False), bobca], fake),
              ("an intermediate that has expired", [make("localhost", "old", fake, inter, False),
                                                    make("old", "ca", inter, cak, True, days=-1)], fake)]
    honest = serving(tmp, "honest", [make("localhost", "mid", fake, inter, False), make("mid", "ca", inter, cak, True)], fake)
    b = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back)
    threading.Thread(target=b.serve_forever, daemon=True).start()
    k1, k2, k3, stranger = Key("one"), Key("two"), Key("three"), Key("two")
    good, evil, later = Provider(GOOD, good_ctx), Provider(EVIL, evil_ctx), Provider(LATER, good_ctx)
    for p in ("/fast", "/bad", "/name"):
        good.paths[p] = jset(k1)
    good.paths["/slow"] = jset(k1)
    good.paths["/short"] = jset(k1)
    good.paths["/chunk"] = chunked(jset(k1))
    evil.paths["/x"] = jset(k1)
    later.paths["/x"] = jset(k1)
    good.start()
    evil.start()
    tr = f'trust={tmp}/ca.pem'
    routes = {
        "fast": f"https://localhost:{GOOD}/fast {tr} refresh=1s",
        "slow": f"https://localhost:{GOOD}/slow {tr} refresh=1h",
        "short": f"https://localhost:{GOOD}/short {tr} refresh=1s stale=4s",
        "chunk": f"https://localhost:{GOOD}/chunk {tr}",
        "bad": f"https://localhost:{GOOD}/bad {tr} refresh=1s",
        "evil": f"https://localhost:{EVIL}/x {tr} refresh=1s",
        "name": f"https://127.0.0.1:{GOOD}/name {tr}",
        "later": f"https://localhost:{LATER}/x {tr} refresh=1s",
    }
    text = f"okena {{ workers 2; io_engine {ENGINE} }}\npool b {{ server 127.0.0.1:{BACK} }}\n" \
           f"http 127.0.0.1:{LST} {{\n"
    for r, u in routes.items():
        text += f"    route /{r} {{ to pool b; auth jwt {{ jwks {u} }} }}\n"
    text += "}\n"
    conf = tmp / "okena.conf"
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen(["timeout", "--foreground", "70", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("at start, the keys are there before the first request", until(lambda: status("/fast", k1.token()) == 200, 5),
              log.read_text()[-400:])
        t = k1.token()
        check("  a token of that key, on each worker", all(status("/fast", t) == 200 for i in range(32)))
        check("  one signed by someone else with the same name for a key: no",
              status("/fast", stranger.token()) == 401 and status("/slow", stranger.token()) == 401)
        check("  a body in chunks", status("/chunk", k1.token()) == 200)
        check("the wrong authority: no keys", status("/evil", k1.token()) == 401, log.read_text()[-300:])
        check("  and the log says why", "not trusted" in log.read_text(), log.read_text()[-300:])
        evil.stop()
        for i, (what, chain, sk) in enumerate(forged):
            f = Provider(EVIL, serving(tmp, f"forged{i}", chain, sk))
            f.paths["/x"] = jset(k1)
            f.start()
            time.sleep(1.6)
            check(f"{what}: no keys", status("/evil", k1.token()) == 401, log.read_text()[-200:])
            f.stop()
        f = Provider(EVIL, honest)
        f.paths["/x"] = jset(k1)
        f.start()
        check("  a real intermediate is fine", until(lambda: status("/evil", k1.token()) == 200, 4), log.read_text()[-200:])
        check("a certificate for another name: no keys", status("/name", k1.token()) == 401)
        check("a provider not up yet: refused meanwhile", status("/later", k1.token()) == 401)

        # rotation: the new key works, and the old one stops even for a token seen
        good.paths["/fast"] = jset(k2)
        check("rotation: the new key is taken up", until(lambda: status("/fast", k2.token()) == 200, 4))
        time.sleep(1.2)				# (each worker takes a new set on its tick)
        check("  the old key's token, verified before, is forgotten", all(status("/fast", t) == 401 for i in range(32)))

        # a key not here yet asks for a fetch, and that cannot be used for a flood
        good.paths["/slow"] = jset(k1, k3)
        time.sleep(0.5)
        before = good.hits["/slow"]
        for i in range(40):
            status("/slow", k3.token())
        check("a new kid: taken up long before refresh", until(lambda: status("/slow", k3.token()) == 200, 14))
        check("  forty tokens asked for few fetches", good.hits["/slow"] - before <= 2, good.hits["/slow"] - before)
        check("  the key it had goes on working", status("/slow", k1.token()) == 200)

        # nothing a provider answers can take the keys away
        for name, a in (("a 500", (500, jset())), ("a redirect", (302, b"")), ("not JSON", b"<html>"),
                        ("JSON, no keys", b'{"keys":[]}'), ("not a set", b'{"a":1}'),
                        ("a set cut short", jset(k3)[:20]), ("a body cut short", cut_short(jset(k3))),
                        ("only shared secrets", json.dumps({"keys": [SECRET]}).encode())):
            good.paths["/bad"] = a
            hits = good.hits["/bad"]
            until(lambda: good.hits["/bad"] > hits, 34)
            time.sleep(0.3)
            check(f"{name}: the keys stay", good.hits["/bad"] > hits and status("/bad", k1.token()) == 200
                  and status("/bad", k3.token()) == 401, str(good.hits["/bad"] - hits))
        good.paths["/bad"] = json.dumps({"keys": [k1.jwk(), SECRET]}).encode()
        hits = good.hits["/bad"]
        until(lambda: good.hits["/bad"] > hits, 34)
        time.sleep(1.5)
        m = b64(json.dumps({"alg": "HS256", "kid": "s"}).encode()) + "." + \
            b64(json.dumps({"sub": "eve", "exp": int(time.time()) + 3600}).encode())
        forged = m + "." + b64(hmac.new(b"s" * 32, m.encode(), hashlib.sha256).digest())
        check("a shared secret in a public set signs nothing", status("/bad", forged) == 401 and status("/bad", k1.token()) == 200)
        check("  the failures are logged, once each", "not a JWK set" in log.read_text() and
              log.read_text().count("not a 200") <= 4, log.read_text()[-500:])

        # a provider that comes up
        later.start()
        check("the provider comes up: keys", until(lambda: status("/later", k1.token()) == 200, 34))

        # down: the keys stay, across a reload too, until `stale`
        tok = k1.token("reload")
        good.stop()
        fresh = time.time()
        check("the provider down: tokens go on", status("/slow", k1.token()) == 200)
        p_sup = [int(x) for x in subprocess.run(["pgrep", "-P", str(p.pid), "okena"], capture_output=True, text=True).stdout.split()]
        os.kill(p_sup[0] if p_sup else p.pid, signal.SIGHUP)
        until(lambda: "configuration reloaded" in log.read_text(), 6)
        time.sleep(0.5)
        check("  a reload while it is down keeps them", "configuration reloaded" in log.read_text() and
              status("/slow", tok) == 200, log.read_text()[-300:])
        check("  past `stale` they are gone", until(lambda: status("/short", k1.token()) == 401, 8), time.time() - fresh)
        check("  and not before it, on the others", status("/slow", k1.token()) == 200)
        check("  the fast set had its 24 h too", status("/fast", k2.token()) == 200)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    for bad in (f"https://localhost:{GOOD}/x", "http://example.com/jwks", f"https://localhost:{GOOD} {tr}",
                f"https://:1/x {tr}", f"https://localhost:0/x {tr}", f"https://localhost:{GOOD}/x {tr} refresh=0s",
                f"ftp://localhost/x {tr}", f"https://localhost:{GOOD}/x trust={tmp}/nosuch"):
        c = tmp / "bad.conf"
        c.write_text(text.replace(routes["evil"], bad))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"refused: {bad[:44]}", q.returncode not in (0, 124) and "auth jwt" in q.stderr, f"{q.returncode} {q.stderr[-200:]}")
    print(f"jwks {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
