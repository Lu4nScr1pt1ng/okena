#!/usr/bin/env python3
"""Keys and certificates okena makes itself (ECDSA P-256, DER in its shortest
form), on one engine (argument): `okena cert selfsigned` and `okena cert csr` read
and checked by OpenSSL, the key the certificate's, a new key and serial each time,
many names (lengths of two bytes) and a long one, and okena serving what it made."""
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
BASE = 58000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, TLS = BASE, BASE + 1
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


def run(*a):
    return subprocess.run([str(BIN), *a], capture_output=True, text=True, timeout=20)


def ossl(*a):
    return subprocess.run(["openssl", *a], capture_output=True, text=True, timeout=20)


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-certgen-", dir="/tmp"))
    r = run("cert", "selfsigned", str(tmp / "a"), "a.example.test", "b.example.test", "days=30")
    t = ossl("x509", "-in", str(tmp / "a" / "cert.pem"), "-noout", "-text")
    check("selfsigned: OpenSSL reads it: v3, ECDSA SHA-256, the names, server auth",
          r.returncode == 0 and "Version: 3" in t.stdout and "ecdsa-with-SHA256" in t.stdout
          and "DNS:a.example.test, DNS:b.example.test" in t.stdout and "TLS Web Server Authentication" in t.stdout
          and "CA:FALSE" in t.stdout, (r.stderr, t.stdout[:300], t.stderr))
    v = ossl("verify", "-CAfile", str(tmp / "a" / "cert.pem"), str(tmp / "a" / "cert.pem"))
    check("  its signature verifies", v.returncode == 0 and ": OK" in v.stdout, v.stdout + v.stderr)
    end = ossl("x509", "-in", str(tmp / "a" / "cert.pem"), "-noout", "-checkend", str(29 * 86400))
    end2 = ossl("x509", "-in", str(tmp / "a" / "cert.pem"), "-noout", "-checkend", str(31 * 86400))
    check("  good for the days asked (30)", end.returncode == 0 and end2.returncode != 0)
    k = ossl("pkey", "-in", str(tmp / "a" / "key.pem"), "-pubout")
    c = ossl("x509", "-in", str(tmp / "a" / "cert.pem"), "-noout", "-pubkey")
    check("  the key is the certificate's (SEC1, and only its owner reads it)", k.stdout == c.stdout and k.stdout
          and (os.stat(tmp / "a" / "key.pem").st_mode & 0o777) == 0o600, (k.stderr, oct(os.stat(tmp / "a" / "key.pem").st_mode)))
    run("cert", "selfsigned", str(tmp / "a2"), "a.example.test")
    s1 = ossl("x509", "-in", str(tmp / "a" / "cert.pem"), "-noout", "-serial").stdout
    s2 = ossl("x509", "-in", str(tmp / "a2" / "cert.pem"), "-noout", "-serial").stdout
    check("  a new key and serial each time", s1 != s2 and (tmp / "a" / "key.pem").read_bytes() != (tmp / "a2" / "key.pem").read_bytes())

    names = [f"host{i}.many-names.example.test" for i in range(60)]
    r = run("cert", "selfsigned", str(tmp / "m"), *names)
    t = ossl("x509", "-in", str(tmp / "m" / "cert.pem"), "-noout", "-ext", "subjectAltName")
    check("60 names (lengths of two bytes): all there, in order", r.returncode == 0 and all(f"DNS:{n}" in t.stdout for n in names)
          and ossl("verify", "-CAfile", str(tmp / "m" / "cert.pem"), str(tmp / "m" / "cert.pem")).returncode == 0, t.stderr)
    long = "x" * 60 + ".example.test"
    r = run("cert", "selfsigned", str(tmp / "l"), long)
    t = ossl("x509", "-in", str(tmp / "l" / "cert.pem"), "-noout", "-subject", "-ext", "subjectAltName")
    check("a name past 64 bytes: the CN cut, the SAN whole", r.returncode == 0 and f"DNS:{long}" in t.stdout
          and f"CN={long[:64]}\n" in t.stdout, t.stdout + t.stderr)

    r = run("cert", "csr", str(tmp / "c"), "x.example.test", "y.example.test")
    q = ossl("req", "-in", str(tmp / "c" / "csr.pem"), "-noout", "-verify", "-text")
    check("csr: its signature verifies, the names in an extension request", r.returncode == 0
          and "verify OK" in (q.stdout + q.stderr) and "DNS:x.example.test, DNS:y.example.test" in q.stdout, (q.stdout[:300], q.stderr))
    check("bad arguments: said", run("cert", "selfsigned", str(tmp / "z")).returncode != 0
          and run("cert", "selfsigned", str(tmp / "z"), "a.test", "days=0").returncode != 0
          and run("cert", "nothing", str(tmp / "z"), "a.test").returncode != 0)

    # okena serving what okena made
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/a/cert.pem; key {tmp}/a/key.pem }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        ctx = ssl.create_default_context(cafile=str(tmp / "a" / "cert.pem"))

        def fetch():
            with socket.create_connection(("127.0.0.1", TLS), timeout=3) as s:
                with ctx.wrap_socket(s, server_hostname="b.example.test") as t:
                    t.sendall(b"GET / HTTP/1.1\r\nHost: b.example.test\r\nConnection: close\r\n\r\n")
                    return t.recv(4096)
        check("okena serves it, verified for its second name", until(lambda: fetch().startswith(b"HTTP/1.1 200"), 6), log.read_text()[-300:])
    finally:
        p.terminate()
        p.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"certgen {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
