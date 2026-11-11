#!/usr/bin/env python3
"""The TLS 1.3 client handshake (src/tls/client.inc) through the harness in
tests/tls/client_test.asm: it opens a connection to openssl s_server with
an EC P-256 certificate, sends its ClientHello, and decrypts the server's
flight. The test checks that the whole flight comes back in the clear with
the expected handshake messages, which exercises the ClientHello, the
ServerHello parse, the ECDH key exchange (x25519 and secp256r1) and the
handshake-key derivation."""
import atexit
import os
import pathlib
import select
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


last = [""]                         # what the client said last: a failure shows it


def check(name, ok, detail=""):
    global failures
    detail = detail or (f"the client said {last[0]!r}" if not ok else "")
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "s.key")
sh("openssl", "req", "-new", "-x509", "-key", "s.key", "-subj", "/CN=localhost", "-days", "2", "-out", "s.pem")
sh("openssl", "genrsa", "-out", "rsa.key", "2048")
sh("openssl", "req", "-new", "-x509", "-key", "rsa.key", "-sha256", "-subj", "/CN=localhost", "-days", "2", "-out", "rsa.pem")
sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", "ed.key")
sh("openssl", "req", "-new", "-x509", "-key", "ed.key", "-subj", "/CN=localhost", "-days", "2", "-out", "ed.pem")


def run_against(groups, port, ktls=False, cert="s.pem", key="s.key"):
    cmd = ["openssl", "s_server", "-accept", str(port), "-cert", str(tmp / cert),
           "-key", str(tmp / key), "-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256",
           "-groups", groups, "-naccept", "1", "-www"]
    if ktls:
        cmd += ["-num_tickets", "0"]    # a plain read() can't drain post-handshake records
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        # it says ACCEPT once it listens (a fixed sleep lost the race under
        # load; a probe connection would take its one accept)
        end, said = time.time() + 15, b""
        while b"ACCEPT" not in said and select.select([sp.stdout], [], [], max(end - time.time(), 0))[0]:
            more = os.read(sp.stdout.fileno(), 4096)    # (not readline: its buffer hides lines from select)
            if not more:
                break
            said += more
        if b"ACCEPT" not in said:
            last[0] = "s_server did not start: " + said.decode(errors="replace")[-300:]
            return "s_server did not start"
        r = subprocess.run([str(CLIENT)], input=struct.pack(">H", port) + bytes([1 if ktls else 0]),
                           capture_output=True, timeout=10)
    finally:
        sp.kill()
    last[0] = r.stdout.decode().strip() + (" / " + r.stderr.decode()[-200:] if r.stderr else "")
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
    # the same exchange, but the application keys go to the kernel (kTLS):
    # the client writes/reads plaintext and the kernel seals/opens records.
    # Falls back to user-space records (still "1") when the tls module is absent.
    check("kTLS: application keys handed to the kernel, HTTP response read",
          run_against("X25519", 34483, ktls=True) == "1")
    check("kTLS: secp256r1 over the kernel's TLS",
          run_against("P-256", 34484, ktls=True) == "1")
    # an RSA server certificate: the CertificateVerify is rsa_pss_rsae_sha256,
    # which the client verifies with rsa_pss_verify over the leaf's RSA key
    check("RSA server leaf: handshake verifies (rsa_pss_rsae_sha256)",
          run_against("X25519", 34485, cert="rsa.pem", key="rsa.key") == "1")
    check("RSA server leaf over kTLS", run_against("P-256", 34486, ktls=True, cert="rsa.pem", key="rsa.key") == "1")
    # an Ed25519 server certificate: CertificateVerify with ed25519 (0x0807)
    check("Ed25519 server leaf: CertificateVerify verified (ed25519)",
          run_against("X25519", 34490, cert="ed.pem", key="ed.key") == "1")
    # the post-quantum hybrid: a server that takes nothing else proves the
    # share is right (ML-KEM-768 key, decapsulation, the 64-byte secret)
    if b"X25519MLKEM768" in subprocess.run(["openssl", "list", "-kem-algorithms"], capture_output=True).stdout:
        check("X25519MLKEM768: encrypted channel, HTTP response decrypted",
              run_against("X25519MLKEM768", 34487) == "1")
        check("X25519MLKEM768 over kTLS", run_against("X25519MLKEM768", 34488, ktls=True) == "1")
        check("X25519MLKEM768 chosen when the server prefers it",
              run_against("X25519MLKEM768:X25519:P-256", 34489) == "1")
    print(f"tls client: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
