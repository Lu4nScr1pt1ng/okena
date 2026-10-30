#!/usr/bin/env python3
"""tls passthrough on one engine (argument): okena reads the ClientHello's
server_name, picks the pool, and moves the bytes untouched; TLS ends at the
backends, which hold the certificates. Routing by name and wildcard,
default reject and default to pool, a ClientHello in pieces, plaintext
refused, PROXY v2 ahead of the ClientHello, and many clients at once."""
import atexit
import os
import pathlib
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 28000 + os.getpid() % 99 * 10 + (5 if ENGINE == "epoll" else 0)
A, B, C, LST, LST2 = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


for n, cn, san in (("a", "backend-a", "DNS:a.test"), ("b", "backend-b", "DNS:*.b.test"),
                   ("c", "backend-c", "DNS:c.test")):
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", f"{n}.key")
    sh("openssl", "req", "-new", "-x509", "-key", f"{n}.key", "-subj", f"/CN={cn}", "-addext",
       f"subjectAltName={san}", "-days", "2", "-out", f"{n}.pem")

PP_SEEN = []


def backend(port, name, proxy=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / f"{name}.pem", tmp / f"{name}.key")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)

    def serve(c):
        try:
            if proxy:                       # PROXY v2: 16 bytes, then its addresses
                head = b""
                while len(head) < 16:
                    head += c.recv(16 - len(head))
                rest = struct.unpack("!H", head[14:16])[0]
                body = b""
                while len(body) < rest:
                    body += c.recv(rest - len(body))
                PP_SEEN.append(head[:12] == b"\r\n\r\n\x00\r\nQUIT\n")
            with ctx.wrap_socket(c, server_side=True) as t:
                while True:
                    d = t.recv(1 << 16)
                    if not d:
                        break
                    t.sendall(name.encode() + b":" + d)
        except (OSError, ssl.SSLError):
            pass
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def client(port, sni, data=b"ping"):
    """(the certificate's CN, the echo) or the error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            from cryptography import x509
            cn = x509.load_der_x509_certificate(t.getpeercert(binary_form=True)).subject.rfc4514_string()
            t.sendall(data)
            return cn, t.recv(100)
    except (OSError, ssl.SSLError) as e:
        return None, type(e).__name__


def main():
    for port, name, pp in ((A, "a", False), (B, "b", False), (C, "c", True)):
        threading.Thread(target=backend, args=(port, name, pp), daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
tcp 127.0.0.1:{LST} {{
    tls passthrough {{
        sni a.test to pool pa
        sni *.b.test x.test to pool pb
        default reject
    }}
}}
tcp 127.0.0.1:{LST2} {{
    tls passthrough {{
        sni a.test to pool pa
        default to pool pc
    }}
    proxy_protocol send v2
}}
pool pa {{ server 127.0.0.1:{A} }}
pool pb {{ server 127.0.0.1:{B} }}
pool pc {{ server 127.0.0.1:{C} }}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    check("okena check: tls passthrough", r.returncode == 0 and "warning" not in r.stderr, r.stderr[-300:])
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)

    check("a.test: to pool pa, its backend's certificate, bytes both ways",
          client(LST, "a.test") == ("CN=backend-a", b"a:ping"), str(client(LST, "a.test")))
    check("*.b.test and x.test: to pool pb", client(LST, "y.b.test") == ("CN=backend-b", b"b:ping")
          and client(LST, "X.TEST") == ("CN=backend-b", b"b:ping"), str(client(LST, "X.TEST")))
    check("another name: refused (default reject)", client(LST, "other.test")[0] is None)
    check("no server_name: refused", client(LST, None)[0] is None)
    check("default to pool: another name goes there (with PROXY v2 first)",
          client(LST2, "other.test") == ("CN=backend-c", b"c:ping") and PP_SEEN and all(PP_SEEN), str(PP_SEEN))

    # the ClientHello a few bytes at a time
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, outg, server_hostname="a.test")
    s = socket.create_connection(("127.0.0.1", LST), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outg.read()
    for i in range(0, len(hello), 7):
        s.sendall(hello[i:i + 7])
        time.sleep(0.0005)
    ok = False
    try:
        while True:
            data = s.recv(1 << 16)
            if not data:
                break
            inc.write(data)
            try:
                obj.do_handshake()
                ok = True
                break
            except ssl.SSLWantReadError:
                if outg.pending:
                    s.sendall(outg.read())
        if outg.pending:
            s.sendall(outg.read())
    except OSError:
        pass
    s.close()
    check("a ClientHello 7 bytes at a time: routed, the handshake ends at the backend", ok)

    with socket.create_connection(("127.0.0.1", LST), timeout=3) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        try:
            got = s.recv(100)
        except ConnectionResetError:
            got = b""
    check("plaintext on a passthrough port: closed", got == b"", got[:40])

    res = []
    ths = [threading.Thread(target=lambda i=i: res.append(client(LST, "a.test", b"n%d" % i)
                                                          == ("CN=backend-a", b"a:n%d" % i))) for i in range(32)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    check("32 clients at once", sum(res) == 32, f"{sum(res)}/32")

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text, text[-300:])
    print(f"passthrough {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
