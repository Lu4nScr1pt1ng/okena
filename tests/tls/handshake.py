#!/usr/bin/env python3
"""The TLS 1.3 handshake (src/tls/handshake.inc) through the echo server in
tests/tls/server.asm, against OpenSSL (Python's ssl, s_client) and curl:
interop, records split and dribbled, refusals with the right alert, a
forged Finished, and kTLS when the kernel has it."""
import atexit
import os
import pathlib
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key

ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "build" / "tlsserver"
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0
procs = []


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key")
sh("openssl", "req", "-new", "-x509", "-key", "ca.key", "-subj", "/CN=okena test ca", "-days", "2",
   "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=okena.test", "-out", "leaf.csr")
(tmp / "ext").write_text("subjectAltName=DNS:okena.test\nkeyUsage=critical,digitalSignature\n"
                         "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n")
sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
   "-days", "2", "-extfile", "ext", "-out", "leaf.pem")


def blob(mode, alpn):
    d = load_pem_private_key((tmp / "leaf.key").read_bytes(), None).private_numbers().private_value
    lst = b""
    for c in [x509.load_pem_x509_certificate((tmp / f).read_bytes()) for f in ("leaf.pem", "ca.pem")]:
        der = c.public_bytes(Encoding.DER)
        lst += len(der).to_bytes(3, "big") + der + b"\0\0"
    return mode + alpn + d.to_bytes(32, "big") + struct.pack("<I", len(lst)) + lst


def start(mode=b"U", alpn=b"H"):
    p = subprocess.Popen([str(SERVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write(blob(mode, alpn))
    p.stdin.close()
    procs.append(p)
    return p, int(p.stdout.readline())


@atexit.register
def stop():
    for p in procs:
        p.kill()


def context(alpn=("h2", "http/1.1"), **kw):
    ctx = ssl.create_default_context(cafile=str(tmp / "ca.pem"))
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    for k, v in kw.items():
        setattr(ctx, k, v)
    return ctx


def ecdh_ctx(curve):
    c = context()
    c.set_ecdh_curve(curve)
    return c


def roundtrip(port, ctx, payloads=(b"hello",)):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        with ctx.wrap_socket(s, server_hostname="okena.test") as t:
            info = (t.version(), t.cipher()[0], t.selected_alpn_protocol())
            for data in payloads:
                t.sendall(data)
                got = b""
                while len(got) < len(data):
                    chunk = t.recv(1 << 16)
                    if not chunk:
                        break
                    got += chunk
                if got != data:
                    return info, False
            return info, True


def refused(port, ctx):
    """The ssl error a client gets, or None when the handshake went through."""
    try:
        roundtrip(port, ctx)
        return None
    except ssl.SSLError as e:
        return str(e)
    except (ConnectionError, OSError) as e:
        return f"closed: {e}"


def session_of(port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        with TICKET_CTX.wrap_socket(s, server_hostname="okena.test") as t:
            t.sendall(b"t")
            t.recv(10)                      # the ticket arrives with the flight
            return t.session


def resume(port, sess):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        with TICKET_CTX.wrap_socket(s, server_hostname="okena.test", session=sess) as t:
            t.sendall(b"again")
            return t.session_reused, t.recv(10) == b"again"


def check_resumption(port, how):
    sess = session_of(port)
    check(f"{how}: a ticket comes with the handshake", sess is not None and sess.has_ticket)
    results = [resume(port, sess) for _ in range(5)]
    check(f"{how}: resumed with it, 5 times", all(r and ok for r, ok in results), str(results))


TICKET_CTX = None


class Wire:
    """A client on memory BIOs: what goes on the wire, and how, is ours."""

    def __init__(self, port, ctx=None):
        self.ctx = ctx or context()
        self.inc, self.outg = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = self.ctx.wrap_bio(self.inc, self.outg, server_hostname="okena.test")
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def step(self):
        try:
            self.obj.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False

    def pending(self):
        return self.outg.read()

    def feed_until_done(self):
        while not self.step():
            if self.outg.pending:
                self.sock.sendall(self.pending())
            data = self.sock.recv(1 << 16)
            if not data:
                raise ConnectionError("closed during the handshake")
            self.inc.write(data)
        if self.outg.pending:
            self.sock.sendall(self.pending())

    def echo(self, data):
        self.obj.write(data)
        self.sock.sendall(self.pending())
        got = b""
        while len(got) < len(data):
            raw = self.sock.recv(1 << 16)
            if not raw:
                break
            self.inc.write(raw)
            try:
                while True:             # one record per read
                    got += self.obj.read(1 << 16)
            except ssl.SSLWantReadError:
                pass
        return got


def records(data):
    out = []
    while data:
        n = int.from_bytes(data[3:5], "big")
        out.append(data[:5 + n])
        data = data[5 + n:]
    return out


def main():
    global TICKET_CTX
    TICKET_CTX = context()
    proc, port = start()

    # interop: Python's ssl is OpenSSL 3.x
    (version, cipher, alpn), ok = roundtrip(port, context(), [b"hello", bytes(range(256)) * 800])
    check("OpenSSL client: TLS 1.3, AES-128-GCM, ALPN http/1.1, the chain verified",
          (version, cipher, alpn) == ("TLSv1.3", "TLS_AES_128_GCM_SHA256", "http/1.1"), f"{version} {cipher} {alpn}")
    check("echo of a 5-byte and a 200 KiB message (13 records)", ok)
    info, ok = roundtrip(port, context(alpn=None))
    check("a client without ALPN", ok and info[2] is None, str(info))
    good = sum(roundtrip(port, context())[1] for _ in range(40))
    check("40 handshakes in a row", good == 40, f"{good}/40")

    # the ClientHello split over records, and dribbled a few bytes at a time
    w = Wire(port)
    w.step()
    hello = w.pending()
    body = hello[5:]
    split = b"".join(b"\x16\x03\x01" + len(body[i:i + 100]).to_bytes(2, "big") + body[i:i + 100]
                     for i in range(0, len(body), 100))
    w.sock.sendall(split)
    try:
        w.feed_until_done()
        check(f"a ClientHello in {len(records(split))} records", w.echo(b"split") == b"split")
    except (ConnectionError, ssl.SSLError) as e:
        check("a ClientHello in several records", False, str(e))
    w = Wire(port)
    w.step()
    hello = w.pending()
    for i in range(0, len(hello), 7):
        w.sock.sendall(hello[i:i + 7])
        time.sleep(0.0005)
    try:
        w.feed_until_done()
        check("a ClientHello 7 bytes at a time", w.echo(b"dribble") == b"dribble")
    except (ConnectionError, ssl.SSLError) as e:
        check("a ClientHello 7 bytes at a time", False, str(e))

    # the client's ChangeCipherSpec and Finished in separate segments
    w = Wire(port)
    w.step()
    w.sock.sendall(w.pending())
    while True:
        w.inc.write(w.sock.recv(1 << 16))
        if w.step():
            break
    flight = w.pending()
    for r in records(flight):
        w.sock.sendall(r)
        time.sleep(0.01)
    check("ChangeCipherSpec and Finished apart", w.echo(b"apart") == b"apart")

    # a forged Finished: one bit of its ciphertext flipped
    w = Wire(port)
    w.step()
    w.sock.sendall(w.pending())
    while True:
        w.inc.write(w.sock.recv(1 << 16))
        if w.step():
            break
    flight = bytearray(w.pending())
    flight[-3] ^= 1
    w.sock.sendall(bytes(flight))
    w.sock.settimeout(3)
    try:
        closed = w.sock.recv(100) == b""
    except ConnectionResetError:
        closed = True
    check("a forged client Finished: the connection is closed", closed)

    # refusals, each with its alert
    ctx = context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    err = refused(port, ctx)
    check("a TLS 1.2-only client: protocol_version", err is not None and "PROTOCOL_VERSION" in err.upper(), err)
    err = refused(port, context(alpn=("h2",)))
    check("ALPN h2 only: no_application_protocol", err is not None and "NO_APPLICATION_PROTOCOL" in err.upper(), err)
    ctx = context()
    ctx.set_ecdh_curve("secp384r1")                 # a group okena offers neither of
    err = refused(port, ctx)
    check("no group in common (P-384 only): handshake_failure",
          err is not None and "HANDSHAKE_FAILURE" in err.upper(), err)
    check("x25519 and P-256 both work (ECDHE)",
          roundtrip(port, context())[1] and roundtrip(port, ecdh_ctx("prime256v1"))[1])
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        reply = s.recv(100)
    check("plain HTTP on the TLS port: an unexpected_message alert", reply == b"\x15\x03\x03\x00\x02\x02\x0a", reply.hex())
    good = roundtrip(port, context())[1]
    check("the server still serves after all that", good)

    # session tickets: issued with the flight, taken back for resumption
    check_resumption(port, "user-space records")
    proc2, port2 = start()
    sess = session_of(port)
    reused, ok = resume(port2, sess)
    check("a ticket from another server (another key): a full handshake instead", ok and not reused)
    proc2.kill()

    # s_client without middlebox compatibility (no session id, no CCS),
    # and curl
    if shutil.which("openssl"):
        sc = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-CAfile", str(tmp / "ca.pem"),
                               "-servername", "okena.test", "-no_middlebox", "-verify_return_error", "-quiet"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sc.stdin.write(b"s_client\n")
        sc.stdin.flush()
        line = b""
        try:
            if select.select([sc.stdout], [], [], 5)[0]:
                line = sc.stdout.readline()
        finally:
            sc.kill()
        check("openssl s_client -no_middlebox", line == b"s_client\n", sc.stderr.read().decode()[-200:])
        for extra, name in [([], "with"), (["-no_middlebox"], "without")]:
            # P-256 first: its share only, x25519 offered: a HelloRetryRequest
            sc = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-CAfile",
                                   str(tmp / "ca.pem"), "-servername", "okena.test", "-groups", "P-384:X25519",
                                   "-verify_return_error", "-msg", *extra],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            sc.stdin.write(b"retried\n")
            sc.stdin.flush()
            out = b""
            deadline = time.time() + 5
            while b"\nretried" not in out and time.time() < deadline:
                if not select.select([sc.stdout], [], [], 0.5)[0]:
                    continue
                chunk = os.read(sc.stdout.fileno(), 65536)
                if not chunk:
                    break
                out += chunk
            sc.kill()
            hellos = out.count(b"ServerHello")
            check(f"HelloRetryRequest ({name} middlebox compatibility): two ClientHellos, then the echo",
                  out.count(b"ClientHello") == 2 and hellos == 2 and b"\nretried" in out, out[-300:].decode(errors="replace"))
        # a session saved, then resumed through a HelloRetryRequest
        sess = tmp / "sess.pem"
        common = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-CAfile", str(tmp / "ca.pem"),
                  "-servername", "okena.test"]
        subprocess.run(common + ["-sess_out", str(sess)], input=b"", capture_output=True, timeout=10)
        r = subprocess.run(common + ["-sess_in", str(sess), "-groups", "P-384:X25519"], input=b"",
                           capture_output=True, timeout=10)
        check("s_client: a saved session resumed through a HelloRetryRequest",
              b"Reused, TLSv1.3" in r.stdout, r.stdout.decode(errors="replace")[-300:])
    if shutil.which("curl"):
        r = subprocess.run(["curl", "-sv", "--cacert", str(tmp / "ca.pem"), "--resolve", f"okena.test:{port}:127.0.0.1",
                            f"https://okena.test:{port}/", "--max-time", "3"], capture_output=True, timeout=10)
        log = r.stderr.decode()
        check("curl: TLS 1.3, ALPN http/1.1, the certificate verified",
              "SSL connection using TLSv1.3" in log and "ALPN: server accepted http/1.1" in log, log[-300:])
    proc.kill()

    # kTLS: the kernel's TLS takes over after the handshake
    try:
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        probe.listen()
        c = socket.create_connection(probe.getsockname())
        a, _ = probe.accept()
        a.setsockopt(socket.IPPROTO_TCP, 31, b"tls")
        have_ktls = True
    except OSError:
        have_ktls = False
    finally:
        for s in ("a", "c", "probe"):
            if s in locals():
                locals()[s].close()
    if not have_ktls:
        print("skip kTLS: the tls module is not loaded (sudo modprobe tls)")
    else:
        proc, port = start(b"K")
        info, ok = roundtrip(port, context(), [b"kernel", os.urandom(300000)])
        check("kTLS: the kernel seals and opens the records (300 KB echo)", ok, str(info))
        good = sum(roundtrip(port, context())[1] for _ in range(20))
        check("kTLS: 20 handshakes in a row", good == 20, f"{good}/20")
        check_resumption(port, "kTLS (sending starts at record 1, after the ticket)")
        proc.kill()

    print(f"tls handshake: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
