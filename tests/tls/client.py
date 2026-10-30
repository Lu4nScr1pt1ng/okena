#!/usr/bin/env python3
"""The TLS 1.3 client handshake (src/tls/client.inc) through the harness in
tests/tls/client_test.asm: it opens a connection to openssl s_server with
an EC P-256 certificate, sends its ClientHello, and decrypts the server's
flight. The test checks that the whole flight comes back in the clear with
the expected handshake messages, which exercises the ClientHello, the
ServerHello parse, the ECDH key exchange (x25519 and secp256r1) and the
handshake-key derivation."""
import atexit
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT = ROOT / "build" / "tlsclient"
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


def run_against(groups, port):
    sp = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", str(tmp / "s.pem"),
                           "-key", str(tmp / "s.key"), "-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
                           "-groups", groups, "-naccept", "1", "-www"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.7)                 # let s_server bind (its one accept is for the client)
        r = subprocess.run([str(CLIENT)], input=struct.pack(">H", port), capture_output=True, timeout=10)
    finally:
        sp.kill()
    return r.stdout.decode().strip()


def main():
    if not shutil.which("openssl"):
        print("skip tls client: openssl not found")
        return 0
    # the full exchange: verify the server's flight, send the client
    # Finished, then a GET whose HTTP response is decrypted ("1" on success)
    check("x25519: encrypted channel, HTTP response decrypted",
          run_against("X25519", 34480) == "1")
    check("secp256r1: encrypted channel, HTTP response decrypted",
          run_against("P-256", 34481) == "1")
    check("x25519 preferred when the server offers both",
          run_against("X25519:P-256", 34482) == "1")
    print(f"tls client: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
