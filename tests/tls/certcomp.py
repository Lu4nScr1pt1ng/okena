#!/usr/bin/env python3
"""Certificate compression (RFC 8879) on one engine (argument): a TLS 1.3 client
of its own (x25519, AES-128-GCM) offers compress_certificate and reads okena's
flight: brotli gets CompressedCertificate with brotli, zlib with zlib, both
brotli, none the plain Certificate; what each decompresses to is that very
Certificate, byte for byte, for a chain of one and of two; asked again, the same
bytes (kept per worker). OpenSSL's s_client, which offers zlib, completes."""
import hashlib
import hmac
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib

try:
    import brotli
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("skip certcomp: no brotli or cryptography package")
    sys.exit(0)

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ONE, TWO = 18970 + (5 if ENGINE == "epoll" else 0), 18971 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""), flush=True)
    fails += not ok


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret, label, context, length):
    info = struct.pack(">H", length) + bytes([len(b"tls13 " + label)]) + b"tls13 " + label + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def ext(kind, body):
    return struct.pack(">HH", kind, len(body)) + body


def hello(algs, priv):
    pub = priv.public_key().public_bytes_raw()
    exts = (ext(0, struct.pack(">HBH", 1 + 2 + 9, 0, 9) + b"cert.test")
            + ext(10, struct.pack(">HH", 2, 0x001d))
            + ext(13, struct.pack(">HHH", 4, 0x0403, 0x0804))
            + ext(43, b"\x02\x03\x04")
            + ext(51, struct.pack(">HHH", 36, 0x001d, 32) + pub))
    if algs:
        exts += ext(27, bytes([2 * len(algs)]) + b"".join(struct.pack(">H", a) for a in algs))
    body = b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + struct.pack(">HH", 2, 0x1301) + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


def recv_exact(s, n):
    d = b""
    while len(d) < n:
        x = s.recv(n - len(d))
        if not x:
            raise EOFError(len(d))
        d += x
    return d


def record(s):
    h = recv_exact(s, 5)
    return h[0], h, recv_exact(s, struct.unpack(">H", h[3:5])[0])


def flight(port, algs):
    """the server's handshake messages, decrypted: [(type, body)]"""
    priv = X25519PrivateKey.generate()
    ch = hello(algs, priv)
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch)
    kind, _, sh = record(s)
    assert kind == 22 and sh[0] == 2, (kind, sh[:8])
    # the server's key share
    i = 4 + 2 + 32
    i += 1 + sh[i]
    i += 2 + 1
    exts_end = i + 2 + struct.unpack(">H", sh[i:i + 2])[0]
    i += 2
    spub = None
    while i < exts_end:
        k, n = struct.unpack(">HH", sh[i:i + 4])
        if k == 51:
            spub = sh[i + 8:i + 8 + 32]
        i += 4 + n
    shared = priv.exchange(X25519PublicKey.from_public_bytes(spub))
    th = hashlib.sha256(ch + sh).digest()
    early = hkdf_extract(b"\0" * 32, b"\0" * 32)
    derived = hkdf_expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    hs = hkdf_extract(derived, shared)
    shs = hkdf_expand_label(hs, b"s hs traffic", th, 32)
    key, iv = hkdf_expand_label(shs, b"key", b"", 16), hkdf_expand_label(shs, b"iv", b"", 12)
    aead, seq, data, msgs = AESGCM(key), 0, b"", []
    while True:
        kind, head, body = record(s)
        if kind == 20:
            continue
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        seq += 1
        plain = aead.decrypt(nonce, body, head).rstrip(b"\0")
        data += plain[:-1]
        while len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big"):
            n = int.from_bytes(data[1:4], "big")
            msgs.append((data[0], data[4:4 + n]))
            data = data[4 + n:]
            if msgs[-1][0] == 20:                   # Finished: the flight is whole
                s.close()
                return msgs


def cert_of(msgs):
    """(the type it came as, the algorithm, the Certificate body it is)"""
    for t, b in msgs:
        if t == 11:
            return 11, 0, b, len(b)
        if t == 25:
            alg, ulen, clen = struct.unpack(">H", b[:2])[0], int.from_bytes(b[2:5], "big"), int.from_bytes(b[5:8], "big")
            data = b[8:8 + clen]
            plain = brotli.decompress(data) if alg == 2 else zlib.decompress(data) if alg == 1 else None
            assert len(plain) == ulen and clen == len(b) - 8, (len(plain), ulen, clen)
            return 25, alg, plain, len(b)
    return None, 0, b"", 0


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-certcomp-"))
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=tmp)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
        "-subj", "/C=BR/O=Okena Test Authority/CN=Okena Test Intermediate CA R1", "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
        "-subj", "/CN=cert.test")
    (tmp / "ext").write_text("subjectAltName=DNS:cert.test,DNS:www.cert.test,DNS:api.cert.test\nbasicConstraints=CA:FALSE\n"
                             "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.crt", "-days", "1", "-extfile", "ext")
    (tmp / "chain.crt").write_text((tmp / "leaf.crt").read_text() + (tmp / "ca.crt").read_text())
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{ONE} {{
    tls {{ cert {tmp}/leaf.crt; key {tmp}/leaf.key }}
    route /* {{ respond 404 }}
}}
http 127.0.0.1:{TWO} {{
    tls {{ cert {tmp}/chain.crt; key {tmp}/leaf.key }}
    route /* {{ respond 404 }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", TWO), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        for port, what in ((ONE, "a chain of one"), (TWO, "a chain of two")):
            plain = cert_of(flight(port, []))
            check(f"{what}, nothing offered: Certificate", plain[0] == 11, plain[:2])
            for algs, want in (([2], 2), ([1], 1), ([1, 2], 2), ([3], 0)):
                got = cert_of(flight(port, algs))
                if want:
                    check(f"  offered {algs}: CompressedCertificate, algorithm {want}, the very same Certificate"
                          f" ({got[3]} bytes for {plain[3]})",
                          got[0] == 25 and got[1] == want and got[2] == plain[2] and got[3] < plain[3], got[:2])
                else:
                    check(f"  offered only zstd: Certificate", got[0] == 11, got[:2])
        a = [m for m in flight(TWO, [2]) if m[0] == 25]
        b = [m for m in flight(TWO, [2]) if m[0] == 25]
        check("asked again: the same bytes", a == b and a)
        q = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{TWO}", "-servername", "cert.test", "-tls1_3",
                            "-CAfile", str(tmp / "ca.crt"), "-msg"], input=b"", capture_output=True, timeout=10)
        out = q.stdout.decode(errors="replace")
        check("OpenSSL (zlib): CompressedCertificate, verified", "CompressedCertificate" in out and "Verify return code: 0" in out,
              out[-400:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t and "exited" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"certcomp {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
