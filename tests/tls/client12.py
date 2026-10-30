#!/usr/bin/env python3
"""The TLS 1.2 client handshake (src/tls/client.inc, tlsc12_*) through the
harness in tests/tls/client12.asm: it connects to openssl s_server running
TLS 1.2, completes a full ECDHE handshake (ServerHello..ServerHelloDone,
then ClientKeyExchange + ChangeCipherSpec + Finished, then the server's
ChangeCipherSpec + Finished), and exchanges a GET whose HTTP response is
decrypted. This exercises the ClientHello's 1.2 offer, the ServerKeyExchange
signature verification (ECDSA and RSA), the ECDHE key exchange and the 1.2
PRF key schedule, over user-space records and kTLS."""
import atexit
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT = ROOT / "build" / "tlsclient12"
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "s.key")
sh("openssl", "req", "-new", "-x509", "-key", "s.key", "-subj", "/CN=localhost", "-days", "2", "-out", "s.pem")
sh("openssl", "genrsa", "-out", "rsa.key", "2048")
sh("openssl", "req", "-new", "-x509", "-key", "rsa.key", "-sha256", "-subj", "/CN=localhost",
   "-days", "2", "-out", "rsa.pem")


def run_against(port, cipher, cert="s.pem", key="s.key", ktls=False, tickets=True):
    cmd = ["openssl", "s_server", "-accept", str(port), "-cert", str(tmp / cert),
           "-key", str(tmp / key), "-tls1_2", "-cipher", cipher, "-naccept", "1", "-www"]
    if not tickets:
        cmd += ["-no_ticket"]
    sp = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.7)
        r = subprocess.run([str(CLIENT)], input=struct.pack(">H", port) + bytes([1 if ktls else 0]),
                           capture_output=True, timeout=10)
    finally:
        sp.kill()
    return r.stdout.decode().strip()


def main():
    if not shutil.which("openssl"):
        print("skip tls 1.2 client: openssl not found")
        return 0
    check("ECDHE-ECDSA: handshake and HTTP response decrypted",
          run_against(34560, "ECDHE-ECDSA-AES128-GCM-SHA256") == "1")
    check("ECDHE-RSA: the ServerKeyExchange signature (rsa_pkcs1_sha256) verifies",
          run_against(34561, "ECDHE-RSA-AES128-GCM-SHA256", cert="rsa.pem", key="rsa.key") == "1")
    # kTLS 1.2: the keys go to the kernel; falls back to user-space records
    # (still "1") when the tls module is absent
    check("kTLS 1.2: ECDHE-ECDSA over the kernel's TLS",
          run_against(34562, "ECDHE-ECDSA-AES128-GCM-SHA256", ktls=True) == "1")
    check("kTLS 1.2: ECDHE-RSA over the kernel's TLS",
          run_against(34563, "ECDHE-RSA-AES128-GCM-SHA256", cert="rsa.pem", key="rsa.key", ktls=True) == "1")
    # a server that sends no NewSessionTicket (the Finished transcript differs)
    check("ECDHE-ECDSA without a session ticket",
          run_against(34564, "ECDHE-ECDSA-AES128-GCM-SHA256", tickets=False) == "1")
    print(f"tls 1.2 client: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
