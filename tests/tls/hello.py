#!/usr/bin/env python3
"""ClientHellos that are odd, on one engine (argument), against a TLS 1.3 listener
with an EC P-256 certificate: split across records (three, or one byte each) or
sent a byte per segment (taken); TLS 1.0 and 1.1, CBC and RSA key exchange only
(handshake_failure); a TLS 1.2 client whose groups leave out the certificate's
curve (handshake_failure, RFC 8422 5.1) and one that has it (taken); application
data, a ChangeCipherSpec or an empty record before the hello, an SSLv2 hello
(unexpected_message); a record past 2^14+256 (record_overflow); a hello larger
than okena reads (16 KiB) closes the connection; okena still serves after all."""
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError:
    print("skip hello: no cryptography package")
    sys.exit(0)

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 31000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def ext(k, b):
    return struct.pack(">HH", k, len(b)) + b


def hello(versions=(0x0304,), suites=(0x1301,), legacy=0x0303, pad=0, groups=(0x001d,), sv=True):
    pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
    e = ext(0, struct.pack(">HBH", 9, 0, 6) + b"a.test")
    e += ext(10, struct.pack(">H", 2 * len(groups)) + b"".join(struct.pack(">H", g) for g in groups))
    e += ext(13, struct.pack(">HHH", 4, 0x0403, 0x0804)) + ext(11, b"\x01\x00")
    if sv:
        e += ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack(">H", v) for v in versions))
    e += ext(51, struct.pack(">HHH", 36, 0x001d, 32) + pub)
    if pad:
        e += ext(21, b"\0" * pad)
    body = (struct.pack(">H", legacy) + os.urandom(32) + b"\x20" + os.urandom(32) + struct.pack(">H", 2 * len(suites))
            + b"".join(struct.pack(">H", s) for s in suites) + b"\x01\x00" + struct.pack(">H", len(e)) + e)
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


def recs(msg, size=16384, typ=22):
    return b"".join(struct.pack(">BHH", typ, 0x0301, len(msg[i:i + size])) + msg[i:i + size] for i in range(0, len(msg), size))


def talk(data, seg=None):
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(3)
    try:
        if seg:
            for i in range(0, len(data), seg):
                k.send(data[i:i + seg])
                time.sleep(0.001)
        else:
            k.sendall(data)
    except OSError:
        pass
    out, end = b"", "open"
    try:
        while len(out) < 7:
            x = k.recv(65536)
            if not x:
                end = "closed"
                break
            out += x
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "reset"
    k.close()
    if out[:1] == b"\x16" and len(out) > 5:
        return "ServerHello" if out[5] == 2 else f"handshake {out[5]}"
    if out[:1] == b"\x15" and len(out) >= 7:
        return f"alert {out[6]}"
    return end


H = hello()
CASES = [
    ("one record", recs(H), None, "ServerHello"),
    ("split across 3 records", recs(H, len(H) // 3 + 1), None, "ServerHello"),
    ("split into 1-byte records", recs(H, 1), None, "ServerHello"),
    ("one record, a byte per segment", recs(H), 1, "ServerHello"),
    ("TLS 1.1 only: handshake_failure", recs(hello(versions=(0x0302,), suites=(0xc02b,))), None, "alert 40"),
    ("TLS 1.0, no supported_versions: handshake_failure", recs(hello(sv=False, legacy=0x0301, suites=(0xc013, 0x002f))), None, "alert 40"),
    ("TLS 1.2, CBC and RSA key exchange only: handshake_failure", recs(hello(sv=False, suites=(0x002f, 0x0035, 0x003c))), None, "alert 40"),
    ("TLS 1.2 without the certificate's curve in its groups: handshake_failure", recs(hello(sv=False, suites=(0xc02b,))), None, "alert 40"),
    ("TLS 1.2 with it: taken", recs(hello(sv=False, suites=(0xc02b,), groups=(0x001d, 0x0017))), None, "ServerHello"),
    ("application data first: unexpected_message", recs(b"hello", typ=23), None, "alert 10"),
    ("ChangeCipherSpec first: unexpected_message", struct.pack(">BHHB", 20, 0x0303, 1, 1) + recs(H), None, "alert 10"),
    ("an empty record first: unexpected_message", struct.pack(">BHH", 22, 0x0301, 0) + recs(H), None, "alert 10"),
    ("an SSLv2 hello: unexpected_message", bytes.fromhex("802e0103010015000000100100800300800700c006004000040000ff") + os.urandom(16), None, "alert 10"),
    ("a record past 2^14+256: record_overflow", struct.pack(">BHH", 22, 0x0301, 18000) + b"\0" * 18000, None, "alert 22"),
]


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-hello-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=a.test",
                    "-addext", "subjectAltName=DNS:a.test", "-days", "2"], check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\n"
                    f"http 127.0.0.1:{L} {{ tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}; route /* {{ respond 404 }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        for name, data, seg, want in CASES:
            got = talk(data, seg)
            check(name, got == want, got)
        got = talk(recs(hello(pad=20000)))
        check("a hello past 16 KiB: the connection closed", got in ("closed", "reset") or got.startswith("alert"), got)
        check("still serving after all that", talk(recs(hello())) == "ServerHello")
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"hello {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
