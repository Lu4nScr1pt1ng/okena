#!/usr/bin/env python3
"""The local CA, on one engine (argument): `tls { local NAME... }` with
`local_ca DIR`: the CA made at the first start (DIR 0700, root.key 0600), its
certificates verified by clients trusting root.pem alone (Python's strict
checks, openssl verify -x509_strict) for a name, a wildcard's and addresses;
7 days, its key identifier named; a reload and a restart sign again with the
same CA; okena certs says where they come from; `okena trust` puts root.pem in
the system's store (bound over in a mount namespace) and runs its update
command, `okena trust remove` takes it out."""
import datetime
import http.server
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 47400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, TLS = BASE, BASE + 1
fails = 0
STORES = [("/usr/local/share/ca-certificates", "okena-local-ca.crt", "update-ca-certificates", []),
          ("/etc/pki/ca-trust/source/anchors", "okena-local-ca.pem", "update-ca-trust", ["extract"]),
          ("/etc/pki/trust/anchors", "okena-local-ca.pem", "update-ca-certificates", []),
          ("/etc/ca-certificates/trust-source/anchors", "okena-local-ca.crt", "trust", ["extract-compat"])]


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
        except (OSError, ssl.SSLError):
            pass
        time.sleep(0.05)
    return False


class Back(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def fetch(sni, cafile):
    """verified against root.pem alone (strict, as Python 3.13 does by default)"""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0)
    with socket.create_connection(("127.0.0.1", TLS), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            der = t.getpeercert(binary_form=True)
            t.sendall(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            return x509.load_der_x509_certificate(der), t.recv(100)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-localca-", dir="/tmp"))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    ca = tmp / "var" / "ca"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s; local_ca {ca} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS} {{
    tls {{ local localhost app.test *.app.test 127.0.0.1 }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    procs = []

    def start():
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
        procs.append(p)
        return p
    rootf = str(ca / "root.pem")
    p = start()
    try:
        check("the CA made at the first start", until(lambda: fetch("localhost", rootf), 5), log.read_text()[-400:])
        check("  DIR 0700, root.key 0600", (ca.stat().st_mode & 0o777) == 0o700
              and ((ca / "root.key").stat().st_mode & 0o777) == 0o600 and "local CA: made" in log.read_text(),
              (oct(ca.stat().st_mode), log.read_text()[-300:]))
        root = x509.load_pem_x509_certificate((ca / "root.pem").read_bytes())
        bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
        check("  a CA: basicConstraints cA (critical), keyCertSign, 10 years",
              bc.critical and bc.value.ca and root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
              and (root.not_valid_after_utc - root.not_valid_before_utc).days >= 3649, root)
        for name in ("localhost", "app.test", "x.app.test", "127.0.0.1"):
            try:
                cert, first = fetch(name, rootf)
                ok = first.startswith(b"HTTP/1.1 200") and cert.issuer == root.subject
            except Exception as e:
                ok, first = False, repr(e)
            check(f"  {name}: verified against root.pem alone (strict), answered", ok, first)
        cert, _ = fetch("localhost", rootf)
        life = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        check("  7 days, the CA's key identifier named", datetime.timedelta(days=6, hours=23) < life <= datetime.timedelta(days=7)
              and aki == ski, (life, aki, ski))
        leaf = tmp / "leaf.pem"
        from cryptography.hazmat.primitives import serialization
        leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        r = subprocess.run(["openssl", "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", rootf, str(leaf)],
                           capture_output=True, text=True, timeout=10)
        check("  openssl verify -x509_strict -purpose sslserver", r.returncode == 0, r.stdout + r.stderr)

        p.send_signal(signal.SIGHUP)
        ok = until(lambda: fetch("app.test", rootf)[0].serial_number != cert.serial_number, 5)
        check("a reload: signed again, by the same CA", ok and (ca / "root.pem").read_bytes() == root.public_bytes(serialization.Encoding.PEM),
              log.read_text()[-400:])
        r = subprocess.run([str(BIN), "certs", "-c", str(conf)], capture_output=True, text=True, timeout=20)
        check("okena certs: the local CA's", r.returncode == 0 and any(l.startswith("localhost") and "okena local CA" in l
                                                                        and l.rstrip().endswith("the local CA")
                                                                        for l in r.stdout.splitlines()), r.stdout + r.stderr)
        p.terminate()
        p.wait(10)
        p = start()
        check("a restart: the same CA, not made again",
              until(lambda: fetch("localhost", rootf)[0].issuer == root.subject, 5)
              and log.read_text().count("local CA: made") == 1, log.read_text()[-300:])

        # okena trust: the first store this system has, bound over; its update command a fake
        store = next((s for s in STORES if os.path.isdir(s[0])), None)
        if store is None:
            print("ok   okena trust: (no trust store here: not tried)")
        else:
            d, fname, cmd, args = store
            sdir, fake = tmp / "store", tmp / "bin"
            sdir.mkdir()
            fake.mkdir()
            ran = tmp / "ran"
            (fake / cmd).write_text(f"#!/bin/sh\necho \"$@\" >> {ran}\n")
            (fake / cmd).chmod(0o755)

            def trust(*extra):
                return subprocess.run(["unshare", "-m", "sh", "-c", f'mount --bind {sdir} {d} && PATH={fake}:$PATH exec "$@"', "-",
                                       str(BIN), "trust", *extra, "-c", str(conf)], capture_output=True, text=True, timeout=20)
            r = trust()
            put = sdir / fname
            check(f"okena trust: root.pem in {d}/{fname}, {cmd} run",
                  r.returncode == 0 and put.exists() and put.read_bytes() == (ca / "root.pem").read_bytes()
                  and ran.read_text().split("\n")[0] == " ".join(args), r.stdout + r.stderr)
            r = trust("remove")
            check("okena trust remove: taken out, run again", r.returncode == 0 and not put.exists()
                  and len(ran.read_text().splitlines()) == 2, r.stdout + r.stderr)
            (fake / cmd).write_text("#!/bin/sh\nexit 3\n")
            r = trust()
            check("  its command failing: said, exit 1", r.returncode == 1 and "exit 3" in r.stderr, r.stdout + r.stderr)
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
    print(f"localca {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
