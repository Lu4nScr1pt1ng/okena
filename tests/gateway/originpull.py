#!/usr/bin/env python3
"""Authenticated origin pulls, on one engine (argument): a pool's `tls { cert; key }`
is the certificate okena shows a backend that asks for one (TLS 1.3, RFC 8446
4.4.2): EC P-256, RSA and Ed25519 keys; without one, a backend that requires it
refuses (502) and one that only asks gets an empty Certificate; a certificate of
another authority is refused; a backend that asks nothing is not bothered."""
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
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 54000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
REQ, OPT, NONE_, LST = BASE, BASE + 1, BASE + 2, BASE + 3
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


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def ca(d, name):
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
       "-keyout", d / f"{name}.key", "-out", d / f"{name}.pem", "-subj", f"/CN={name}", "-days", "2")


def leaf(d, name, cn, by, kind, client):
    key = d / f"{name}.key"
    if kind == "ec":
        sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key)
        sh("openssl", "ec", "-in", key, "-out", key)                   # SEC1, as okena reads it
    elif kind == "rsa":
        sh("openssl", "genrsa", "-traditional", "-out", key, "2048")
    else:
        sh("openssl", "genpkey", "-algorithm", "ED25519", "-out", key)
    sh("openssl", "req", "-new", "-key", key, "-out", d / f"{name}.csr", "-subj", f"/CN={cn}")
    ext = d / f"{name}.ext"
    ext.write_text(("extendedKeyUsage=clientAuth\n" if client else "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"))
    sh("openssl", "x509", "-req", "-in", d / f"{name}.csr", "-CA", d / f"{by}.pem", "-CAkey", d / f"{by}.key",
       "-CAcreateserial", "-out", d / f"{name}.pem", "-days", "2", "-extfile", ext)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        cert = self.connection.getpeercert()
        who = "none"
        if cert:
            who = dict(x[0] for x in cert["subject"])["commonName"]
        b = f"client={who}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, ctx):
        super().__init__(addr, H)
        self.ctx = ctx

    def get_request(self):
        s, a = super().get_request()
        return self.ctx.wrap_socket(s, server_side=True), a

    def handle_error(self, *a):
        pass


def serve(port, d, mode):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(d / "srv.pem", d / "srv.key")
    ctx.load_verify_locations(d / "clientca.pem")
    ctx.verify_mode = mode
    threading.Thread(target=TLSServer(("127.0.0.1", port), ctx).serve_forever, daemon=True).start()


def get(path):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=8)
    c.request("GET", path, headers={"Host": "t"})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b


def main():
    d = pathlib.Path(tempfile.mkdtemp(prefix="okena-pull-", dir="/tmp"))
    ca(d, "srvca")
    ca(d, "clientca")
    ca(d, "otherca")
    leaf(d, "srv", "localhost", "srvca", "ec", False)
    leaf(d, "cl_ec", "edge-ec", "clientca", "ec", True)
    leaf(d, "cl_rsa", "edge-rsa", "clientca", "rsa", True)
    leaf(d, "cl_ed", "edge-ed", "clientca", "ed", True)
    leaf(d, "cl_other", "edge-other", "otherca", "ec", True)
    serve(REQ, d, ssl.CERT_REQUIRED)
    serve(OPT, d, ssl.CERT_OPTIONAL)
    serve(NONE_, d, ssl.CERT_NONE)

    def pool(name, port, cert=None):
        c = f"; cert {d}/{cert}.pem; key {d}/{cert}.key" if cert else ""
        return f"pool {name} {{ server 127.0.0.1:{port}; tls {{ trust {d}/srvca.pem; sni localhost{c} }} }}\n"
    conf = d / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
{pool("ec", REQ, "cl_ec")}{pool("rsa", REQ, "cl_rsa")}{pool("ed", REQ, "cl_ed")}{pool("anon", REQ)}
{pool("other", REQ, "cl_other")}{pool("opt", OPT)}{pool("none", NONE_, "cl_ec")}
http 127.0.0.1:{LST} {{
    route /ec/* {{ to pool ec }}
    route /rsa/* {{ to pool rsa }}
    route /ed/* {{ to pool ed }}
    route /anon/* {{ to pool anon }}
    route /other/* {{ to pool other }}
    route /opt/* {{ to pool opt }}
    route /none/* {{ to pool none }}
}}
""")
    log = d / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get("/none/x")[0] == 200), log.read_text()[-400:])
        for kind, cn in (("ec", "edge-ec"), ("rsa", "edge-rsa"), ("ed", "edge-ed")):
            r = get(f"/{kind}/x")
            check(f"a backend that requires a certificate: okena's ({kind}) is taken", r == (200, f"client={cn}".encode()), r)
        out = [get("/ec/again") for _ in range(10)]
        check("  again and again", all(o == (200, b"client=edge-ec") for o in out), out[:2])
        check("without one: refused (502)", get("/anon/x")[0] == 502)
        check("one of another authority: refused (502)", get("/other/x")[0] == 502)
        check("a backend that only asks: an empty Certificate, served as nobody", get("/opt/x") == (200, b"client=none"), get("/opt/x"))
        check("a backend that asks nothing: not bothered", get("/none/x") == (200, b"client=none"))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(d, ignore_errors=True)
    print(f"originpull {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
