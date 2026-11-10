#!/usr/bin/env python3
"""On-demand certificates, on one engine (argument): a ClientHello for a name no
certificate has, that `on_demand *.od.example.test ask=...` allows and the ask
service says yes to, waits while okena gets one from the CA (the acme suite's),
then goes on with it; two clients for the same name, one order; ask saying no, a
name no pattern allows, and one past max=: on at once with the listener's own (a
placeholder okena signs), the CA not asked; a restart serves the ones it got
(DIR/on_demand.list) without asking again."""
import datetime
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
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acme as A  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BIN = A.BIN
BASE = 43500 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS, CA, ASK = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
A.PLAIN = PLAIN
fails = 0
ASKED = []


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Ask(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        d = self.path.split("domain=", 1)[1] if "domain=" in self.path else ""
        ASKED.append((self.path, d))
        ok = d.startswith("yes")
        self.send_response(200 if ok else 403)
        self.send_header("Content-Length", "0")
        self.end_headers()


def hello(name, cafile=None, timeout=20):
    """the certificate the TLS listener shows for that name, and how long it took"""
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    if not cafile:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t = time.time()
    with socket.create_connection(("127.0.0.1", TLS), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=name) as c:
            der = c.getpeercert(binary_form=True)
            c.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
            first = c.recv(100)
    return x509.load_der_x509_certificate(der), time.time() - t, first


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acmeod-", dir="/tmp"))
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
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", ASK), Ask).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {tmp}/acme ca=https://localhost:{CA}/dir trust={tmp}/ca.pem }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{TLS} {{
    tls {{ on_demand *.od.example.test ask=http://127.0.0.1:{ASK}/check?v=1 max=2 }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    procs = []

    def start():
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        return p
    cafile = str(tmp / "ca.pem")
    p = start()
    try:
        A.until(lambda: hello("other.example.test")[0] is not None, 5)
        cert, took, first = hello("yes1.od.example.test", cafile)
        check("a name allowed and said yes to: the handshake waits, then the CA's certificate (verified), the request answered",
              cert.issuer == c.subject and first.startswith(b"HTTP/1.1 200"), (took, log.read_text()[-400:]))
        check("  ask= asked: GET URL&domain=NAME", ("/check?v=1&domain=yes1.od.example.test", "yes1.od.example.test") in ASKED, ASKED)
        cert2, took2, _ = hello("yes1.od.example.test", cafile)
        check("  then at once from the store (no reload)", cert2.serial_number == cert.serial_number and took2 < 1, took2)

        res = []

        def two():
            res.append(hello("yes2.od.example.test", cafile))
        ts = [threading.Thread(target=two) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        check("two clients for one name: both served, one order",
              len(res) == 2 and all(r[0].issuer == c.subject for r in res) and res[0][0].serial_number == res[1][0].serial_number
              and [e[1] for e in st.log if e[0] == "order"].count(["yes2.od.example.test"]) == 1,
              [e for e in st.log if e[0] == "order"])
        n = len([e for e in st.log if e[0] == "order"])
        cert3, took3, _ = hello("no1.od.example.test")
        check("ask says no: on at once with the listener's own, the CA not asked",
              cert3.issuer == cert3.subject and took3 < 3 and "not asked for" in log.read_text()
              and len([e for e in st.log if e[0] == "order"]) == n, (took3, cert3.subject))
        k0 = len(ASKED)
        cert4, took4, _ = hello("www.other.test")
        check("a name no pattern allows: on at once, not even ask= asked",
              cert4.issuer == cert4.subject and took4 < 1 and len(ASKED) == k0, (took4, ASKED[k0:]))
        cert5, took5, _ = hello("yes3.od.example.test")
        check("past max=2: on with the listener's own",
              cert5.issuer == cert5.subject and len([e for e in st.log if e[0] == "order"]) == n, (took5, log.read_text()[-300:]))
        lst = (tmp / "acme" / "on_demand.list").read_text().split()
        check("  DIR/on_demand.list: the two names", sorted(lst) == ["yes1.od.example.test", "yes2.od.example.test"], lst)

        p.terminate()
        p.wait(10)
        n = len([e for e in st.log if e[0] == "order"])
        p = start()
        check("a restart: the names it got served at once, the CA not asked",
              A.until(lambda: hello("yes2.od.example.test", cafile, 3)[0].serial_number == res[0][0].serial_number, 5)
              and not A.until(lambda: len([e for e in st.log if e[0] == "order"]) > n, 1), log.read_text()[-300:])
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
    print(f"acmeod {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
