#!/usr/bin/env python3
"""Ed25519 server certificates: an http listener whose tls { } holds an
Ed25519 certificate and its PKCS #8 key signs CertificateVerify with
ed25519 (0x0807) for a client that offers it, and refuses one that does
not; beside an EC certificate for the same host, each client gets the one
it can verify, and the request goes through (no 421 for the sibling).
TLS 1.2 has no Ed25519 here: such a client is refused. okena check takes
the pair and refuses a key that is not the certificate's."""
import atexit
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 36000 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
ED, DUAL = BASE, BASE + 1
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*a):
    subprocess.run(a, check=True, capture_output=True, cwd=tmp)


def client(port, ca, *extra):
    """(signature type, HTTP status line) as s_client saw them."""
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "okena.test",
                        "-CAfile", str(tmp / ca), "-verify_return_error", "-ign_eof", *extra],
                       input=b"GET / HTTP/1.1\r\nHost: okena.test\r\nConnection: close\r\n\r\n",
                       capture_output=True, timeout=10)
    sig = status = None
    for line in r.stdout.decode(errors="replace").splitlines():
        if line.startswith("Peer signature type:"):
            sig = line.split(":", 1)[1].strip()
        if line.startswith("HTTP/1.1"):
            status = line.split()[1]
    return sig, status, (r.stdout + r.stderr).decode(errors="replace")[-300:]


def main():
    if not shutil.which("openssl"):
        print("skip ed25519: openssl not found")
        return 0
    sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", "ed.key")
    sh("openssl", "req", "-new", "-x509", "-key", "ed.key", "-subj", "/CN=okena.test",
       "-addext", "subjectAltName=DNS:okena.test", "-days", "2", "-out", "ed.pem")
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ec.key")
    sh("openssl", "req", "-new", "-x509", "-key", "ec.key", "-subj", "/CN=okena.test",
       "-addext", "subjectAltName=DNS:okena.test", "-days", "2", "-out", "ec.pem")
    sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", "other.key")
    route = "route /* { redirect 302 https://okena.test/x }"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{ED} {{
    tls {{ cert {tmp}/ed.pem; key {tmp}/ed.key }}
    {route}
}}
http 127.0.0.1:{DUAL} {{
    tls {{
        cert {tmp}/ec.pem key={tmp}/ec.key
        cert {tmp}/ed.pem key={tmp}/ed.key
    }}
    {route}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    check("okena check: an Ed25519 certificate and key", r.returncode == 0, r.stderr[-300:])
    bad = tmp / "bad.conf"
    bad.write_text(f"""http 127.0.0.1:{ED} {{
    tls {{ cert {tmp}/ed.pem; key {tmp}/other.key }}
    {route}
}}
""")
    r = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    check("okena check: an Ed25519 key that is not the certificate's is refused",
          r.returncode != 0 and "key" in r.stderr, r.stderr[-300:])

    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)

    sig, status, out = client(ED, "ed.pem")
    check("Ed25519 certificate: CertificateVerify ed25519, verified, 302", sig == "ed25519" and status == "302", out)
    sig, status, out = client(ED, "ed.pem", "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256")
    check("a client without ed25519: refused (handshake_failure)", sig is None and "alert" in out, out)
    sig, status, out = client(ED, "ed.pem", "-tls1_2")
    check("TLS 1.2 with only an Ed25519 certificate: refused", status is None, out)
    sig, status, out = client(DUAL, "ec.pem")
    check("dual EC + Ed25519, a default client: ECDSA", sig == "ecdsa_secp256r1_sha256" and status == "302", out)
    sig, status, out = client(DUAL, "ed.pem", "-sigalgs", "ed25519")
    check("dual EC + Ed25519, a client with ed25519 only: the Ed25519 sibling, and no 421",
          sig == "ed25519" and status == "302", out)
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{ED}", "-servername", "okena.test",
                        "-CAfile", str(tmp / "ed.pem"), "-sess_out", str(tmp / "s.pem")], input=b"",
                       capture_output=True, timeout=10)
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{ED}", "-servername", "okena.test",
                        "-CAfile", str(tmp / "ed.pem"), "-sess_in", str(tmp / "s.pem")], input=b"",
                       capture_output=True, timeout=10)
    check("a session resumed on the Ed25519 listener", b"Reused, TLSv1.3" in r.stdout, r.stdout[-200:])

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    print(f"ed25519 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
