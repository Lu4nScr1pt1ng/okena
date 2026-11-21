#!/usr/bin/env python3
"""addons/oidc (oidc-okena), on one engine (argument), against a provider of
the test's own (discovery, authorization with PKCE, the code's exchange, an
RS256 ID token, its keys): a page without a session goes to the provider; the
callback sets a sealed session cookie and sends the browser back; with it the
backend gets the e-mail (a client's own field replaced) and not the cookie;
an API call without a session gets 401; a tampered cookie is no session; a
wrong state, a wrong nonce, a token signed by another key, an e-mail not
allowed, an unverified one are refused; the PKCE verifier is checked by the
provider; logout ends the session. Refresh (-refresh-every): the session
checked again with the provider, its tokens renewed and the new cookie on the
response (the response_headers phase); requests at once with one stale
cookie make one refresh (the provider rotates refresh tokens); a refresh
refused ends the session; without the response phase a page load is sent to
itself with the new cookie and API calls use the renewal kept by the addon.
Logout revokes the refresh token and goes to the provider's
end_session_endpoint with id_token_hint and post_logout_redirect_uri."""
import base64
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ADDON = ROOT / "build" / "oidc-okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    print("skip oidc: no cryptography package")
    sys.exit(0)
if not ADDON.exists():
    print("skip oidc: no build/oidc-okena (Go missing)")
    sys.exit(0)
BASE = 27600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
IDP, BACK, L, L2 = BASE, BASE + 1, BASE + 2, BASE + 3
ISS = f"http://127.0.0.1:{IDP}"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key().public_numbers()
CODES = {}            # code -> what the authorization said
NEXT = {"email": "alice@example.com", "verified": True, "nonce": None, "key": KEY}
RTS = {}              # refresh token -> e-mail (those not rotated or revoked)
STATS = {"refreshes": 0, "seq": 0, "revoked": [], "logouts": []}
LOCK = threading.Lock()


def id_token(claims, key=KEY, kid="k1"):
    h = b64(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    p = b64(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64(sig)}"


class IdP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            self.send(200, json.dumps({"issuer": ISS, "authorization_endpoint": ISS + "/authorize",
                                       "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/jwks",
                                       "end_session_endpoint": ISS + "/logout", "revocation_endpoint": ISS + "/revoke"}).encode())
        elif u.path == "/logout":
            STATS["logouts"].append(q)
            self.send(302, headers=[("Location", q.get("post_logout_redirect_uri", "/"))])
        elif u.path == "/jwks":
            n = PUB.n.to_bytes((PUB.n.bit_length() + 7) // 8, "big")
            self.send(200, json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "n": b64(n), "e": b64(b"\x01\x00\x01")}]}).encode())
        elif u.path == "/authorize":
            assert q["client_id"] == "app" and q["response_type"] == "code" and q["code_challenge_method"] == "S256"
            code = os.urandom(8).hex()
            CODES[code] = dict(q)
            loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
            self.send(302, headers=[("Location", loc)])
        else:
            self.send(404)

    def tokens(self, email, nonce=None):
        with LOCK:
            STATS["seq"] += 1
            n = STATS["seq"]
            RTS[f"rt-{n}"] = email
        now = int(time.time())
        claims = {"iss": ISS, "aud": "app", "sub": "u-" + email, "email": email, "email_verified": NEXT["verified"],
                  "name": "Alice A.", "iat": now, "exp": now + 300}
        if nonce:
            claims["nonce"] = nonce
        return {"id_token": id_token(claims, NEXT["key"]), "token_type": "Bearer", "access_token": f"at-{n}",
                "refresh_token": f"rt-{n}"}

    def do_POST(self):
        f = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        if self.path == "/revoke":
            STATS["revoked"].append(f.get("token"))
            RTS.pop(f.get("token"), None)
            self.send(200)
            return
        if f.get("grant_type") == "refresh_token":
            time.sleep(0.1)          # (so requests at once meet here)
            with LOCK:
                STATS["refreshes"] += 1
                email = RTS.pop(f.get("refresh_token"), None) if f.get("client_secret") == "s3cret" else None
            if email is None:
                self.send(400, json.dumps({"error": "invalid_grant"}).encode())
                return
            self.send(200, json.dumps(self.tokens(email)).encode(), [("Content-Type", "application/json")])
            return
        a = CODES.pop(f.get("code"), None)
        ok = (a and f.get("client_secret") == "s3cret" and f.get("redirect_uri") == a["redirect_uri"]
              and b64(hashlib.sha256(f.get("code_verifier", "").encode()).digest()) == a["code_challenge"])
        if not ok:
            self.send(400, json.dumps({"error": "invalid_grant"}).encode())
            return
        self.send(200, json.dumps(self.tokens(NEXT["email"], NEXT["nonce"] or a["nonce"])).encode(),
                  [("Content-Type", "application/json")])

    def log_message(self, *a):
        pass


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = json.dumps({"email": self.headers.get("x-user-email"), "sub": self.headers.get("x-user-sub"),
                        "cookie": self.headers.get("cookie"), "at": self.headers.get("x-access-token")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Srv(http.server.ThreadingHTTPServer):
    request_queue_size = 128          # (requests at once: the default backlog of 5 drops some)
    daemon_threads = True


for port, h in ((IDP, IdP), (BACK, Back)):
    srv = Srv(("127.0.0.1", port), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def req(port, path, cookies=None, headers=None, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": f"127.0.0.1:{port}", "Accept": "text/html"}
    h.update(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    out = {k.lower(): v for k, v in r.getheaders() if k.lower() != "set-cookie"}
    sc = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
    c.close()
    return r.status, out, sc, body


def jar_add(jar, set_cookies):
    for s in set_cookies:
        nv = s.split(";")[0]
        k, _, v = nv.partition("=")
        if "Max-Age=0" in s:
            jar.pop(k, None)
        else:
            jar[k] = v


def sign_in(path="/app", port=L):
    """the browser's way: okena -> provider -> callback -> back"""
    jar = {}
    st, h, sc, _ = req(port, path)
    jar_add(jar, sc)
    if st != 302 or not h.get("location", "").startswith(ISS + "/authorize"):
        return None, (st, h)
    u = urllib.parse.urlparse(h["location"])
    st2, h2, _, _ = req(IDP, u.path + "?" + u.query)
    cb = urllib.parse.urlparse(h2["location"])
    st3, h3, sc3, body = req(port, cb.path + "?" + cb.query, jar)
    jar_add(jar, sc3)
    return jar, (st3, h3, body)


tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "secret").write_text("s3cret\n")
(tmp / "key").write_text(os.urandom(32).hex() + "\n")
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
addon oidc {{
    run {ADDON} -issuer {ISS} -client-id app -client-secret-file {tmp}/secret -cookie-key-file {tmp}/key -redirect-url http://127.0.0.1:{L}/oauth2/callback -allow-domain example.com -insecure-cookie -refresh-every 400ms -access-token-header x-access-token
    phases request_headers response_headers
    timeout 5s
}}
addon oidc2 {{
    run {ADDON} -issuer {ISS} -client-id app -client-secret-file {tmp}/secret -cookie-key-file {tmp}/key -redirect-url http://127.0.0.1:{L2}/oauth2/callback -allow-domain example.com -insecure-cookie -refresh-every 400ms -access-token-header x-access-token
    timeout 5s
}}
http 127.0.0.1:{L} {{
    route /* {{ addon oidc; to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{L2} {{
    route /* {{ addon oidc2; to 127.0.0.1:{BACK} }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(200):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    st, h, sc, _ = req(L, "/app?x=1")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(h.get("location", "")).query))
    check("a page without a session: to the provider, with PKCE (S256), state and nonce",
          st == 302 and q.get("code_challenge_method") == "S256" and q.get("state") and q.get("nonce")
          and q.get("redirect_uri") == f"http://127.0.0.1:{L}/oauth2/callback" and any("okena_session_state=" in s for s in sc), (st, h, sc))
    jar, (st, h, body) = sign_in("/app?x=1")
    check("the callback: a session cookie, and back where it was", st == 302 and h.get("location") == "/app?x=1"
          and "okena_session" in jar and "okena_session_state" not in jar, (st, h, jar))
    st, h, sc, body = req(L, "/app", dict(jar, other="1"), {"x-user-email": "mallory@evil.test"})
    j = json.loads(body) if st == 200 else {}
    check("with the session: the backend gets the e-mail (not the client's), not the cookie",
          j.get("email") == "alice@example.com" and j.get("sub") == "u-alice@example.com" and j.get("cookie") == "other=1", (st, body))
    st, h, sc, body = req(L, "/api/x", headers={"Accept": "application/json"})
    check("an API call without a session: 401", st == 401, (st, h))
    bad = dict(jar)
    v = bad["okena_session"]
    bad["okena_session"] = v[:-3] + ("A" if v[-3] != "A" else "B") + v[-2:]
    st, h, sc, body = req(L, "/app", bad)
    check("a tampered cookie: no session", st == 302, (st, h))
    # a wrong state
    st, h, sc, _ = req(L, "/app")
    jar2 = {}
    jar_add(jar2, sc)
    u = urllib.parse.urlparse(h["location"])
    _, h2, _, _ = req(IDP, u.path + "?" + u.query)
    cb = urllib.parse.urlparse(h2["location"])
    qq = dict(urllib.parse.parse_qsl(cb.query))
    qq["state"] = "x" + qq["state"]
    st, h, sc, body = req(L, cb.path + "?" + urllib.parse.urlencode(qq), jar2)
    check("a state that does not match: 400", st == 400, (st, body))
    for what, change, want in (("another nonce", {"nonce": "zzz"}, 401), ("a token signed by another key", {"key": OTHER}, 401),
                               ("an e-mail not allowed", {"email": "eve@elsewhere.test"}, 403),
                               ("an unverified e-mail", {"verified": False}, 403)):
        NEXT.update(change)
        jar3, (st, h, body) = sign_in()
        NEXT.update({"email": "alice@example.com", "verified": True, "nonce": None, "key": KEY})
        check(f"{what}: {want}, no session", st == want and "okena_session" not in (jar3 or {}), (st, body))
    # refresh, with the response phase
    jar, _ = sign_in()
    st, h, sc, body = req(L, "/app", jar)
    at0 = json.loads(body).get("at") if st == 200 else None
    check("the access token to the backend (-access-token-header)", at0 and at0.startswith("at-"), (st, body))
    time.sleep(0.45)                                           # (the session due for its check)
    n0 = STATS["refreshes"]
    st, h, sc, body = req(L, "/api/x", jar, {"Accept": "application/json"})
    at1 = json.loads(body).get("at") if st == 200 else None
    check("due: refreshed, the backend gets the new access token, the cookie renewed on the response",
          st == 200 and STATS["refreshes"] == n0 + 1 and at1 and at1 != at0 and any(c.startswith("okena_session=") for c in sc), (st, body, sc))
    old = dict(jar)
    jar_add(jar, sc)
    st, h, sc, body = req(L, "/app", jar)
    check("  the renewed cookie: not refreshed again yet", st == 200 and STATS["refreshes"] == n0 + 1 and json.loads(body).get("at") == at1,
          (st, body))
    st, h, sc, body = req(L, "/app", old)
    check("  the old one, still sent by another tab: the renewal, no refresh with a spent token",
          st == 200 and STATS["refreshes"] == n0 + 1 and json.loads(body).get("at") == at1, (st, body))
    time.sleep(0.45)
    n0 = STATS["refreshes"]
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        rs = list(ex.map(lambda _: req(L, "/api/y", jar, {"Accept": "application/json"}), range(8)))
    ats = {json.loads(b).get("at") for st_, _, _, b in rs if st_ == 200}
    check("eight requests at once with a stale cookie: one refresh, all served with its tokens",
          all(x[0] == 200 for x in rs) and STATS["refreshes"] == n0 + 1 and len(ats) == 1,
          ([x[0] for x in rs], STATS["refreshes"] - n0, ats, [(x[1], x[3][:200]) for x in rs if x[0] != 200]))
    for x in rs:
        jar_add(jar, x[2])
    # the provider refuses: signed out
    RTS.clear()
    time.sleep(0.45)
    st, h, sc, body = req(L, "/api/z", jar, {"Accept": "application/json"})
    check("a refresh refused: the session ends (401, the cookie cleared)", st == 401
          and any(c.startswith("okena_session=;") and "Max-Age=0" in c for c in sc), (st, sc))
    jar_add(jar, sc)
    check("  a page then goes to the provider", req(L, "/app", jar)[0] == 302)
    # without the response phase
    jar, _ = sign_in(port=L2)
    time.sleep(0.45)
    n0 = STATS["refreshes"]
    st, h, sc, body = req(L2, "/api/x", jar, {"Accept": "application/json"})
    at2 = json.loads(body).get("at") if st == 200 else None
    check("no response phase: an API call refreshed and served, no cookie to set", st == 200 and STATS["refreshes"] == n0 + 1
          and not sc, (st, body, sc))
    st, h, sc, body = req(L2, "/api/x", jar, {"Accept": "application/json"})
    check("  again with the old cookie: the kept renewal, no new refresh", st == 200 and STATS["refreshes"] == n0 + 1
          and json.loads(body).get("at") == at2, (st, body))
    time.sleep(0.45)
    st, h, sc, body = req(L2, "/app?y=2", jar)
    check("  a page load once due: to itself, with the new cookie", st == 302 and h.get("location") == "/app?y=2"
          and any(c.startswith("okena_session=") for c in sc), (st, h, sc))
    jar_add(jar, sc)
    st, h, sc, body = req(L2, "/app?y=2", jar)
    check("  and then served", st == 200, (st, body))
    # logout
    jar, _ = sign_in()
    rt = max(RTS, key=lambda k: int(k[3:]))
    st, h, sc, body = req(L, "/oauth2/logout", jar)
    jar_add(jar, sc)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(h.get("location", "")).query))
    hint = q.get("id_token_hint", "")
    claims = json.loads(base64.urlsafe_b64decode(hint.split(".")[1] + "==")) if hint.count(".") == 2 else {}
    check("logout: the cookie cleared, to the provider's end_session_endpoint (id_token_hint, client_id, post_logout_redirect_uri)",
          st == 302 and "okena_session" not in jar and h.get("location", "").startswith(ISS + "/logout?") and q.get("client_id") == "app"
          and q.get("post_logout_redirect_uri") == f"http://127.0.0.1:{L}/" and claims.get("sub") == "u-alice@example.com", (st, h, sc))
    t = time.time()
    while rt not in STATS["revoked"] and time.time() - t < 5:
        time.sleep(0.02)
    check("  its refresh token revoked at the provider (RFC 7009)", rt in STATS["revoked"], (rt, STATS["revoked"]))
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read()[-2000:])
print(f"oidc ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
