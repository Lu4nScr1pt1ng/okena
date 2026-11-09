#!/usr/bin/env python3
"""`auth jwt` on a route, on one engine (argument): real tokens of each algorithm,
and every known way around them: alg none, an RSA public key used as an HMAC
secret, a changed claim, a late token, the wrong issuer or audience, a forged
header, a line break hidden in a claim, a name given twice."""
import base64
import http.client
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    from cryptography.hazmat.primitives import hashes, hmac, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip jwt: no cryptography")
    sys.exit(0)

ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 33000 - 8000 + os.getpid() % 70 * 10 + (5 if ENGINE == "epoll" else 0) + 300
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
failures = 0
seen = []


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def be(n, size=None):
    size = size or (n.bit_length() + 7) // 8
    return n.to_bytes(size, "big")


EC = ec.generate_private_key(ec.SECP256R1())
RS = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ED = ed25519.Ed25519PrivateKey.generate()
OTHER = ec.generate_private_key(ec.SECP256R1())
SECRET = os.urandom(32)


def jwks():
    e = EC.public_key().public_numbers()
    r = RS.public_key().public_numbers()
    ed_pub = ED.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"keys": [
        {"kty": "EC", "crv": "P-256", "kid": "ec1", "use": "sig", "x": b64(be(e.x, 32)), "y": b64(be(e.y, 32))},
        {"kty": "RSA", "kid": "rs1", "n": b64(be(r.n)), "e": b64(be(r.e))},
        {"kty": "OKP", "crv": "Ed25519", "kid": "ed1", "x": b64(ed_pub)},
        {"kty": "oct", "kid": "hs1", "alg": "HS256", "k": b64(SECRET)},
        {"kty": "EC", "crv": "P-384", "kid": "unknown-curve", "x": "AA", "y": "AA"},
        {"kty": "RSA", "kid": "encryption", "use": "enc", "n": "AQAB", "e": "AQAB"},
    ]}


def sign(alg, msg, key=None):
    if alg == "ES256":
        r, s = utils.decode_dss_signature((key or EC).sign(msg, ec.ECDSA(hashes.SHA256())))
        return be(r, 32) + be(s, 32)
    if alg == "RS256":
        return (key or RS).sign(msg, padding.PKCS1v15(), hashes.SHA256())
    if alg == "PS256":
        return (key or RS).sign(msg, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
    if alg == "EdDSA":
        return (key or ED).sign(msg)
    if alg == "HS256":
        h = hmac.HMAC(key or SECRET, hashes.SHA256())
        h.update(msg)
        return h.finalize()
    return b""


NOW = int(time.time())
GOOD = {"iss": "https://auth.test", "aud": "api", "sub": "alice", "scope": "read write", "exp": NOW + 600}


def token(alg="ES256", kid="ec1", claims=None, head=None, key=None, raw_claims=None):
    c = dict(GOOD)
    c.update(claims or {})
    c = {k: v for k, v in c.items() if v is not None}
    h = {"alg": alg, "typ": "JWT"}
    if kid:
        h["kid"] = kid
    h.update(head or {})
    msg = b64(json.dumps(h).encode()) + "." + b64(raw_claims or json.dumps(c).encode())
    return msg + "." + b64(sign(alg, msg.encode(), key))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen.append(1)
        d = {k.lower(): v for k, v in self.headers.items()}
        d["all-sub"] = [v for k, v in self.headers.items() if k.lower() == "x-user-id"]
        b = json.dumps(d).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def get(path, tok=None, headers=None):
    h = dict(headers or {})
    if tok is not None:
        h["Authorization"] = "Bearer " + tok
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers=h)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r, b


CONF = """okena {{ drain delay=0s timeout=1s; workers 2; io_engine {engine} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{
        to 127.0.0.1:{back}
        auth jwt {{ jwks {tmp}/jwks.json; issuer https://auth.test; audience api; claims sub -> x-user-id }}
    }}
}}
http 127.0.0.1:{lst} {{
    route /api {{
        to 127.0.0.1:{back}
        auth jwt {{
            jwks {tmp}/jwks.json
            issuer https://auth.test
            audience api
            leeway 2s
            claims sub -> x-user-id, scope -> x-user-scope
        }}
    }}
    route /noclaims {{ to 127.0.0.1:{back}; auth jwt {{ jwks {tmp}/jwks.json }} }}
    route /lim {{
        to 127.0.0.1:{back}
        auth jwt {{ jwks {tmp}/jwks.json; claims sub -> x-user-id }}
        limit 1/h burst=2 key=jwt.sub
    }}
    route /open {{ to 127.0.0.1:{back} }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-jwt-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=j.test",
                    "-addext", "subjectAltName=DNS:j.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    (tmp / "jwks.json").write_text(json.dumps(jwks()))
    http.server.ThreadingHTTPServer.request_queue_size = 64
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    text = CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp)
    conf.write_text(text)
    p = subprocess.Popen(["timeout", "--foreground", "40", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        for alg, kid in (("ES256", "ec1"), ("RS256", "rs1"), ("PS256", "rs1"), ("EdDSA", "ed1"), ("HS256", "hs1")):
            r, b = get("/api", token(alg, kid))
            check(f"{alg}: through", r.status == 200 and json.loads(b).get("x-user-id") == "alice", f"{r.status} {b[:90]}")
        r, b = get("/api", token())
        h = json.loads(b)
        check("the claims told, the token not passed on", h.get("x-user-scope") == "read write" and "authorization" not in h, str(h))
        r, b = get("/api", token(kid=None))
        check("no kid: a key of its kind", r.status == 200, str(r.status))
        r, b = get("/api", token(claims={"exp": NOW + 600.5}))
        check("exp with a fraction", r.status == 200, str(r.status))
        r, b = get("/api", token(claims={"aud": ["other", "api"]}))
        check("aud a list holding ours", r.status == 200, str(r.status))
        r, b = get("/api", token(claims={"iss": "https:\\/\\/auth.test".replace("\\/", "/")}))
        check("iss as it should be", r.status == 200, str(r.status))
        raw = json.dumps(GOOD).replace("https://auth.test", "https:\\/\\/auth.test").encode()
        r, b = get("/api", token(raw_claims=raw))
        check("iss with its slashes escaped", r.status == 200, str(r.status))
        r, b = get("/api", token(claims={"exp": int(time.time()) - 1}))
        check("late by less than the leeway: through", r.status == 200, str(r.status))
        n = len(seen)
        tamper = token()
        head, claims, sig = tamper.split(".")
        rsa_pem = RS.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        none_h = b64(json.dumps({"alg": "none", "kid": "ec1"}).encode())
        bad = {
            "no token": None,
            "empty": "",
            "not three parts": "abc.def",
            "alg none": none_h + "." + claims + ".",
            "alg none with a signature": none_h + "." + claims + "." + sig,
            "alg None": b64(json.dumps({"alg": "None"}).encode()) + "." + claims + ".",
            "alg an RSA key as an HMAC secret": token("HS256", "rs1", key=rsa_pem),
            "HS256 by an RSA key's bytes": token("HS256", "rs1", key=be(RS.public_key().public_numbers().n)),
            "HS256 by an EC key's bytes": token("HS256", "ec1", key=b"\x04" + be(EC.public_key().public_numbers().x, 32)
                                                + be(EC.public_key().public_numbers().y, 32)),
            "HS256 by an Ed25519 key's bytes": token("HS256", "ed1", key=ED.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "HS256 with the EC key's name": token("HS256", "ec1"),
            "ES256 by the wrong key": token(key=OTHER),
            "RS256 by a key named ES": token("RS256", "ec1"),
            "another key id": token(kid="nope"),
            "an algorithm not here": token("ES256", head={"alg": "ES512"}),
            "a claim changed": head + "." + b64(json.dumps(dict(GOOD, sub="root")).encode()) + "." + sig,
            "a signature changed": head + "." + claims + "." + sig[:-3] + ("AAA" if sig[-3:] != "AAA" else "BBB"),
            "a signature cut": head + "." + claims + "." + sig[:40],
            "a signature gone": head + "." + claims + ".",
            "expired": token(claims={"exp": NOW - 60}),
            "no exp": token(claims={"exp": None}),
            "exp not a number": token(claims={"exp": "soon"}),
            "not yet": token(claims={"nbf": NOW + 60}),
            "another issuer": token(claims={"iss": "https://evil.test"}),
            "no issuer": token(claims={"iss": None}),
            "another audience": token(claims={"aud": "other"}),
            "an audience list without ours": token(claims={"aud": ["a", "b"]}),
            "crit": token(head={"crit": ["exp"]}),
            "a line break in a claim": token(claims={"sub": "alice\r\nx-admin: 1"}),
            "a NUL in a claim": token(claims={"scope": "a\u0000b"}),
            "exp twice": token(raw_claims=json.dumps(GOOD)[:-1].encode() + b', "exp": 99999999999}'),
            "broken JSON": token(raw_claims=b'{"exp": '),
            "claims not an object": token(raw_claims=b'[1,2]'),
            "deep JSON": token(raw_claims=b'{"exp":' + b"[" * 100 + b"]" * 100 + b"}"),
            "a huge token": "a" * 13000,
            "a bad base64": "!!!." + claims + "." + sig,
        }
        for name, t in bad.items():
            r, _ = get("/api", t)
            check(f"{name}: 401", r.status == 401 and r.getheader("www-authenticate") == "Bearer", f"{r.status} {r.getheaders()}")
        check("the backend heard of none of them", len(seen) == n, str(len(seen) - n))
        r, _ = get("/api", headers={"Authorization": "Basic " + tamper})
        check("another scheme: 401", r.status == 401, str(r.status))
        t = token()
        a = time.time()
        for _ in range(200):
            get("/api", t)
        r, b = get("/api", t, {"x-user-id": "root", "x-user-scope": "admin"})
        h = json.loads(b)
        check("a forged x-user-id: gone, the claim alone in its place", h["all-sub"] == ["alice"] and h.get("x-user-scope") == "read write", str(h))
        r, _ = get("/noclaims", token(claims={"iss": "anyone", "aud": "any"}))
        check("no issuer or audience asked: not looked at", r.status == 200, str(r.status))
        rs = [get("/lim", token(claims={"sub": "bob"}))[0].status for _ in range(3)]
        q = get("/lim", token(claims={"sub": "carol"}))[0].status
        check("limit key=jwt.sub: each their own, whatever the token", rs == [200, 200, 429] and q == 200, f"{rs} {q}")
        short = token(claims={"exp": int(time.time()) + 2})
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=12)	# (one connection: one worker, its cache)
        def again():
            c.request("GET", "/api", headers={"Authorization": "Bearer " + short})
            r = c.getresponse()
            r.read()
            return r.status
        a = again()
        time.sleep(7)					# (2 s of it, 2 of leeway, a tick or two)
        b = again()
        c.close()
        check("a token kept by the cache still ends", (a, b) == (200, 401), str((a, b)))
        for proto, flag in (("h1", "--http1.1"), ("h2", "--http2"), ("h3", "--http3-only")):
            q = subprocess.run(["timeout", "6", "curl", "-sk", flag, "--resolve", f"j.test:{TLS}:127.0.0.1",
                                f"https://j.test:{TLS}/x", "-w", "\n%{http_code}", "-H", "Authorization: Bearer " + token()],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if q.returncode in (1, 2):
                print(f"skip {proto}")
                continue
            check(f"over {proto}", q.stdout.endswith("200") and json.loads(q.stdout.rsplit("\n", 1)[0])["all-sub"] == ["alice"], q.stdout[-120:])
        check("the worker lives", get("/open")[0].status == 200)
    finally:
        p.terminate()
        p.wait(10)
    t = (tmp / "log").read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    (tmp / "empty.json").write_text('{"keys": []}')
    (tmp / "broken.json").write_text('{"keys": [')
    (tmp / "short.json").write_text(json.dumps({"keys": [{"kty": "oct", "alg": "HS256", "k": b64(b"short")}]}))
    (tmp / "noalg.json").write_text(json.dumps({"keys": [{"kty": "oct", "k": b64(SECRET)}]}))
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
    (tmp / "small.json").write_text(json.dumps({"keys": [{"kty": "RSA", "n": b64(be(small.n)), "e": b64(be(small.e))}]}))
    for bad in ("empty.json", "broken.json", "short.json", "noalg.json", "small.json", "nosuch.json"):
        c = tmp / "bad.conf"
        c.write_text(text.replace(f"auth jwt {{ jwks {tmp}/jwks.json }}", f"auth jwt {{ jwks {tmp}/{bad} }}", 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"jwks {bad}: refused", q.returncode not in (0, 124) and "jwt" in q.stderr, f"{q.returncode} {q.stderr[:90]}")
    print(f"jwt {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
