#!/usr/bin/env python3
"""The TLS 1.2 server handshake (src/tls/tls12_server.inc) through the
harness in tests/tls/server12.asm: openssl s_client -tls1_2 connects with
ECDHE-ECDSA/AES-128-GCM and x25519; the harness completes the handshake
and sends one application record. The test checks openssl saw it, i.e. the
whole 1.2 flow (ServerHello, Certificate, a signed ServerKeyExchange,
ServerHelloDone, ClientKeyExchange, the Finished exchange) worked."""
import atexit
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "build" / "tlsserver12"
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def main():
    if not shutil.which("openssl"):
        print("skip tls12 server: openssl not found")
        return 0
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print("skip tls12 server: cryptography not available")
        return 0

    key = ec.generate_private_key(ec.SECP256R1())
    import datetime
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    scalar = key.private_numbers().private_value.to_bytes(32, "big")
    clist = len(der).to_bytes(3, "big") + der + b"\x00\x00"       # 1.3 certificate_list framing

    def run_once(port):
        stdin = struct.pack(">H", port) + scalar + struct.pack("<H", len(clist)) + clist
        hp = subprocess.Popen([str(SERVER)], stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hp.stdin.write(stdin)
        hp.stdin.close()
        time.sleep(0.4)                 # let it bind and accept
        try:
            r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
                                "-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256",
                                "-curves", "P-256", "-quiet"],
                               input=b"", capture_output=True, timeout=10)
        finally:
            hp.kill()
        return r.stdout + r.stderr

    out = run_once(34520)
    check("tls1.2 handshake completes and an application record arrives",
          b"okena12" in out, out[-300:])
    print(f"tls12 server: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
