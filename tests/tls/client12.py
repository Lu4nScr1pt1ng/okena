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
import os
import pathlib
import select
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
            return "s_server did not start: " + said.decode(errors="replace")[-200:]
        r = subprocess.run([str(CLIENT)], input=struct.pack(">H", port) + bytes([1 if ktls else 0]),
                           capture_output=True, timeout=10)
    finally:
        sp.kill()
    out = r.stdout.decode().strip()
    return out if out == "1" else f"{out!r} (exit {r.returncode}) {r.stderr.decode(errors='replace')[-200:]}"


def main():
    if not shutil.which("openssl"):
        print("skip tls 1.2 client: openssl not found")
        return 0
    res = run_against(34560, "ECDHE-ECDSA-AES128-GCM-SHA256")
    check("ECDHE-ECDSA: handshake and HTTP response decrypted", res == "1", res)
    res = run_against(34561, "ECDHE-RSA-AES128-GCM-SHA256", cert="rsa.pem", key="rsa.key")
    check("ECDHE-RSA: the ServerKeyExchange signature (rsa_pkcs1_sha256) verifies", res == "1", res)
    # kTLS 1.2: the keys go to the kernel; falls back to user-space records
    # (still "1") when the tls module is absent
    res = run_against(34562, "ECDHE-ECDSA-AES128-GCM-SHA256", ktls=True)
    check("kTLS 1.2: ECDHE-ECDSA over the kernel's TLS", res == "1", res)
    res = run_against(34563, "ECDHE-RSA-AES128-GCM-SHA256", cert="rsa.pem", key="rsa.key", ktls=True)
    check("kTLS 1.2: ECDHE-RSA over the kernel's TLS", res == "1", res)
    # a server that sends no NewSessionTicket (the Finished transcript differs)
    res = run_against(34564, "ECDHE-ECDSA-AES128-GCM-SHA256", tickets=False)
    check("ECDHE-ECDSA without a session ticket", res == "1", res)
    print(f"tls 1.2 client: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
