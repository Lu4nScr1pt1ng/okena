#!/usr/bin/env python3
"""Certificates near their end, on one engine (argument): /metrics has
okena_tls_certificate_not_after_seconds for each certificate served (its first
name, where it comes from); one with less than 14 days left is said in the log
and to `alerts { on certificate }` (one ending in 3 days, one already past),
one with months left is not."""
import datetime
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parent.parent / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 51400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
TLS, MET, HOOK = BASE, BASE + 1, BASE + 2
fails = 0
got = {}


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    import time
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        got.setdefault(self.server.name, []).append(json.loads(body))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def hook(name, port):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), Hook)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


def cert(tmp, name, after):
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=30))
         .not_valid_after(now + after)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .sign(k, hashes.SHA256()))
    (tmp / f"{name}.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (tmp / f"{name}.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    return c


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-certexpiry-", dir="/tmp"))
    hook("hook", HOOK)
    near = cert(tmp, "near.test", datetime.timedelta(days=3, hours=1))
    gone = cert(tmp, "gone.test", -datetime.timedelta(days=1))
    far = cert(tmp, "far.test", datetime.timedelta(days=200))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s; metrics 127.0.0.1:{MET} }}
alerts {{
    webhook http://127.0.0.1:{HOOK}/
    on certificate
    every 1s
}}
pool b {{ server 127.0.0.1:1 }}
http 127.0.0.1:{TLS} {{
    tls {{
        cert {tmp}/far.test.pem key={tmp}/far.test.key
        cert {tmp}/near.test.pem key={tmp}/near.test.key
        cert {tmp}/gone.test.pem key={tmp}/gone.test.key
    }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        def metrics():
            return urllib.request.urlopen(f"http://127.0.0.1:{MET}/metrics", timeout=3).read().decode()
        until(lambda: "okena_tls_certificate" in metrics(), 5)
        m = metrics()
        lines = [l for l in m.splitlines() if l.startswith("okena_tls_certificate_not_after_seconds{")]
        want = {n: int(c.not_valid_after_utc.timestamp()) for n, c in (("far.test", far), ("near.test", near), ("gone.test", gone))}
        seen = {}
        for l in lines:
            lab, v = l.rsplit(" ", 1)
            nm = lab.split('name="', 1)[1].split('"', 1)[0]
            seen[nm] = (int(v), 'source="file"' in lab)
        check("/metrics: each certificate's end, its name, from a file",
              all(seen.get(n) == (t, True) for n, t in want.items()) and "# TYPE okena_tls_certificate_not_after_seconds gauge" in m,
              (lines, want))

        def told():
            texts = [e["text"] for d in got.get("hook", []) for e in d["events"]]
            return texts if any("near.test" in t for t in texts) and any("gone.test" in t for t in texts) else None
        check("near its end and past it: said to `on certificate`", until(told, 8), got)
        texts = told() or []
        kinds = [e["kind"] for d in got.get("hook", []) for e in d["events"]]
        check("  as kind certificate, days left and the date",
              any("near.test (a file) ends in 3 days, on " in t for t in texts)
              and any("gone.test (a file) has ended, on " in t for t in texts) and set(kinds) == {"certificate"},
              (texts, kinds))
        check("  one with months left: not", not any("far.test" in t for t in texts), texts)
        t = log.read_text()
        check("  and in the log, once", t.count("certificate near.test (a file) ends in") == 1, t[-400:])
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"certexpiry {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
