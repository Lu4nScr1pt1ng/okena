#!/usr/bin/env python3
"""`tls { auto }` and plain http to https, on one engine (argument), with the acme
suite's CA: a certificate for each name of the listener's host blocks (a
wildcard's skipped with HTTP-01), one order each, verified; a plain http request
for such a name answered 308 to https://NAME:PORT/the-target (no port for 443,
case and the Host's port ignored, an `acme NAME` line's names too); other names
and `redirect off` blocks' go on to the routes; the challenges still answered.
Without okena { acme }: Let's Encrypt and /var/lib/okena/acme, as okena certs
and okena check say."""
import datetime
import http.client
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

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acme as A  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BIN = A.BIN
BASE = 49400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS, CA, TLS3 = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
A.PLAIN = PLAIN
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def plain(host, target="/x?y=1"):
    c = http.client.HTTPConnection("127.0.0.1", PLAIN, timeout=5)
    c.request("GET", target, headers={"Host": host})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, r.getheader("Location"), body


def verified(name, port, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=name) as t:
            t.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
            return t.recv(100).startswith(b"HTTP/1.1 200")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acmeauto-", dir="/tmp"))
    k, c = A.make_ca()
    st = A.CAState(k, c, CA)
    st.bad_nonce_once = False
    sk = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sc = A.issue(k, c, sk.public_key(), ["localhost"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=5))
    (tmp / "srv.pem").write_bytes(sc.public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    (tmp / "ca.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", CA), A.H)
    srv.st = st
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), A.Back).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme ca=https://localhost:{CA}/dir trust={tmp}/ca.pem }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{TLS} {{
    tls {{ auto }}
    host a.auto.test b.auto.test {{ route /* {{ to pool b }} }}
    host *.w.auto.test {{ route /* {{ to pool b }} }}
}}
http 127.0.0.1:443 {{
    tls {{ acme d.auto.test }}
    route /* {{ to pool b }}
}}
http 127.0.0.1:{TLS3} {{
    tls {{ acme c.auto.test; redirect off }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    cafile = str(tmp / "ca.pem")
    try:
        ok = A.until(lambda: all(verified(n, TLS, cafile) for n in ("a.auto.test", "b.auto.test")), 20)
        orders = [e[1] for e in st.log if e[0] == "order"]
        check("auto: a certificate for each host name, verified", ok, (log.read_text()[-500:], orders))
        check("  one order each; the wildcard not asked for (HTTP-01)",
              orders.count(["a.auto.test"]) == 1 and orders.count(["b.auto.test"]) == 1
              and not [o for o in orders if any("w.auto.test" in n for n in o)], orders)
        A.until(lambda: verified("d.auto.test", 443, cafile) and verified("c.auto.test", TLS3, cafile), 20)
        s, loc, _ = plain("a.auto.test")
        check("plain http, a name of auto's: 308 to https, its port, the target",
              s == 308 and loc == f"https://a.auto.test:{TLS}/x?y=1", (s, loc))
        s, loc, _ = plain(f"B.Auto.Test:{PLAIN}", "/")
        check("  case and the Host's port ignored", s == 308 and loc == f"https://B.Auto.Test:{TLS}/", (s, loc))
        s, loc, _ = plain("d.auto.test", "/p")
        check("  an acme line's name, on 443: no port", s == 308 and loc == "https://d.auto.test/p", (s, loc))
        s, loc, body = plain("c.auto.test")
        check("  redirect off: on to the routes", s == 200 and loc is None, (s, loc, body))
        s, loc, body = plain("other.test")
        check("  a name okena has no certificate for: on to the routes", s == 200 and loc is None, (s, loc, body))
        s, _, _ = plain("a.auto.test", "/.well-known/acme-challenge/nottoken")
        check("  a path under the challenges' but no token: redirected too", s == 308, s)
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    # no okena { acme }: Let's Encrypt, /var/lib/okena/acme (compiled only)
    conf2 = tmp / "le.conf"
    conf2.write_text(f"""pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS} {{
    tls {{ auto }}
    host le.auto.test {{ route /* {{ to pool b }} }}
}}
""")
    r = subprocess.run([str(BIN), "certs", "-c", str(conf2)], capture_output=True, text=True, timeout=20)
    check("no okena { acme }: auto all the same (okena certs)",
          r.returncode == 0 and any(l.startswith("le.auto.test") and "acme" in l for l in r.stdout.splitlines()),
          r.stdout + r.stderr)
    r = subprocess.run([str(BIN), "check", "-c", str(conf2)], capture_output=True, text=True, timeout=20)
    check("  okena check takes it", r.returncode == 0, r.stdout + r.stderr)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"acmeauto {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
