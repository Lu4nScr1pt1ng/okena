#!/usr/bin/env python3
"""`require` in `auth jwt`, on one engine (argument): a valid token without what
a route requires gets 403 (no token or a bad one still 401), and the backend
never hears of it. Scopes as space-separated words, several lines all held,
values in one line any of them, arrays, nested claims by a dotted path, a
name with dots of its own, numbers and booleans as written; the decision is
kept with the token."""
import base64
import http.client
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip jwtreq: no cryptography")
    sys.exit(0)

ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 14400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
failures = 0
hits = []


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


EC = ec.generate_private_key(ec.SECP256R1())
NOW = int(time.time())


def token(**claims):
    c = {"sub": "alice", "exp": NOW + 600}
    c.update(claims)
    h = {"alg": "ES256", "kid": "k"}
    msg = b64(json.dumps(h).encode()) + "." + b64(json.dumps(c).encode())
    r, s = utils.decode_dss_signature(EC.sign(msg.encode(), ec.ECDSA(hashes.SHA256())))
    return msg + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(path, tok=None):
    h = {"Authorization": "Bearer " + tok} if tok else {}
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers=h)
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
n = EC.public_key().public_numbers()
(tmp / "jwks.json").write_text(json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k",
    "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}]}))
J = f"jwks {tmp}/jwks.json"
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{LST} {{
    route /admin {{ auth jwt {{ {J}; require scope admin }}; to 127.0.0.1:{BACK} }}
    route /rw {{ auth jwt {{ {J}; require scope read; require scope write }}; to 127.0.0.1:{BACK} }}
    route /any {{ auth jwt {{ {J}; require scope admin,ops support }}; to 127.0.0.1:{BACK} }}
    route /roles {{ auth jwt {{ {J}; require realm_access.roles editor }}; to 127.0.0.1:{BACK} }}
    route /ns {{ auth jwt {{ {J}; require https://example.com/roles ops }}; to 127.0.0.1:{BACK} }}
    route /num {{ auth jwt {{ {J}; require tier 2 }}; to 127.0.0.1:{BACK} }}
    route /bool {{ auth jwt {{ {J}; require email_verified true }}; to 127.0.0.1:{BACK} }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())

    check("no token: 401", get("/admin") == 401)
    check("a broken token: 401", get("/admin", "a.b.c") == 401)
    t = token(scope="read write")
    hits.clear()
    check("scope without admin: 403", get("/admin", t) == 403)
    check("  and again, from the token kept: 403", get("/admin", t) == 403)
    check("  the backend never asked", not hits, str(hits))
    check("scope with admin among its words: through", get("/admin", token(scope="read admin")) == 200)
    check("two lines, both held: through", get("/rw", t) == 200)
    check("two lines, one missing: 403", get("/rw", token(scope="read")) == 403)
    check("one line's values: any of them", get("/any", token(scope="support")) == 200
          and get("/any", token(scope="ops")) == 200 and get("/any", token(scope="read")) == 403)
    check("no such claim: 403", get("/admin", token()) == 403)
    check("a nested array (realm_access.roles): through",
          get("/roles", token(realm_access={"roles": ["viewer", "editor"]})) == 200)
    check("  without the role: 403", get("/roles", token(realm_access={"roles": ["viewer"]})) == 403)
    check("  not an object on the way: 403", get("/roles", token(realm_access="editor")) == 403)
    check("a name with dots of its own (Auth0's namespaced claims)",
          get("/ns", token(**{"https://example.com/roles": ["ops", "dev"]})) == 200)
    check("a number as written", get("/num", token(tier=2)) == 200 and get("/num", token(tier=3)) == 403)
    check("a boolean as written", get("/bool", token(email_verified=True)) == 200
          and get("/bool", token(email_verified=False)) == 403)
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.terminate()
    p.wait(10)
    if failures:
        log.seek(0)
        print(log.read())
print(f"jwt require ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
