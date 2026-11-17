#!/usr/bin/env python3
"""TLS to a pool's servers from a `tcp` listener, on one engine (argument):
the client speaks plaintext, okena runs the TLS client handshake (the
server's certificate verified against the pool's trust, its name), then
relays over kTLS: bytes both ways intact (2 MB each way, eight connections
at once), the SNI the pool names; a server okena does not trust, or of
another name, gets no byte of the client; `proxy_protocol send` goes first,
in the clear, then the handshake."""
import os
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 30600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
TB, L, LBAD, LNAME, LPP, TBPP = (BASE + i for i in range(6))
fails = 0
SEEN = {"sni": [], "plain": [], "pp": [], "hs": [], "data": []}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


def openssl(*a, cwd):
    subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=cwd)


tmp = pathlib.Path(tempfile.mkdtemp())
openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key", cwd=tmp)
openssl("req", "-new", "-x509", "-key", "ca.key", "-subj", "/CN=test ca", "-days", "2", "-out", "ca.pem", cwd=tmp)
openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "b.key", cwd=tmp)
openssl("req", "-new", "-key", "b.key", "-subj", "/CN=b.test", "-out", "b.csr", cwd=tmp)
(tmp / "ext").write_text("subjectAltName=DNS:b.test\n")
openssl("x509", "-req", "-in", "b.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
        "-extfile", "ext", "-out", "b.pem", cwd=tmp)
openssl("ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "o.key", cwd=tmp)
openssl("req", "-new", "-x509", "-key", "o.key", "-subj", "/CN=other ca", "-days", "2", "-out", "other.pem", cwd=tmp)


def tls_backend(port, pp=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "b.pem", tmp / "b.key")
    ctx.sni_callback = lambda s, name, c: SEEN["sni"].append(name)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)

    def one(c):
        try:
            if pp:          # the PROXY header, in the clear, before the handshake
                line = b""
                while not line.endswith(b"\r\n"):
                    line += c.recv(1)
                SEEN["pp"].append(line)
            first = c.recv(1, socket.MSG_PEEK)
            if first and first[0] != 0x16:
                SEEN["plain"].append(c.recv(4096))
                return
            s = ctx.wrap_socket(c, server_side=True)
            SEEN["hs"].append(s.version())
            while (d := s.recv(65536)):
                SEEN["data"].append(len(d))
                s.sendall(d)
            s.close()
        except (OSError, ssl.SSLError):
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


tls_backend(TB)
tls_backend(TBPP, pp=True)
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool sec {{ server 127.0.0.1:{TB}; tls {{ trust {tmp}/ca.pem; sni b.test }} }}
pool untrusted {{ server 127.0.0.1:{TB}; tls {{ trust {tmp}/other.pem; sni b.test }} }}
pool wrongname {{ server 127.0.0.1:{TB}; tls {{ trust {tmp}/ca.pem; sni c.test }} }}
pool secpp {{ server 127.0.0.1:{TBPP}; tls {{ trust {tmp}/ca.pem; sni b.test }} }}
tcp 127.0.0.1:{L} {{ to pool sec }}
tcp 127.0.0.1:{LBAD} {{ to pool untrusted }}
tcp 127.0.0.1:{LNAME} {{ to pool wrongname }}
tcp 127.0.0.1:{LPP} {{ proxy_protocol send v1; to pool secpp }}
""")


def echo(port, data, timeout=10):
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    got = bytearray()
    def reader():
        try:
            while len(got) < len(data):
                d = c.recv(1 << 20)
                if not d:
                    break
                got.extend(d)
        except OSError:
            pass
    t = threading.Thread(target=reader)
    t.start()
    try:
        c.sendall(data)
    except OSError:
        pass
    t.join(timeout)
    c.close()
    return bytes(got)


log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    r = echo(L, b"hello over tls")
    check("plaintext in, TLS to the server, the bytes back", r == b"hello over tls", (r, SEEN["hs"], SEEN["data"]))
    check("  the SNI the pool names", "b.test" in SEEN["sni"], SEEN["sni"])
    big = os.urandom(2 << 20)
    check("2 MB each way, intact", echo(L, big, 30) == big)
    with ThreadPoolExecutor(8) as ex:
        datas = [os.urandom(200000 + i) for i in range(8)]
        res = list(ex.map(lambda d: echo(L, d, 30), datas))
    check("eight connections at once", res == datas, [len(r) for r in res])
    check("a server of a CA okena does not trust: nothing through", echo(LBAD, b"secret", 3) == b"")
    check("a server of another name: nothing through", echo(LNAME, b"secret", 3) == b"")
    check("  and never a byte in the clear", not SEEN["plain"], SEEN["plain"][:2])
    check("proxy_protocol send: first, in the clear, then TLS", echo(LPP, b"after the header") == b"after the header"
          and SEEN["pp"] and SEEN["pp"][0].startswith(b"PROXY TCP4 127.0.0.1 127.0.0.1 "), SEEN["pp"][:1])
    log.seek(0)
    t = log.read()
    check("the failures said", "upstream TLS handshake failed" in t, t[-300:])
    check("no crash", "killed by signal" not in t)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read()[-2000:])
print(f"tcp upstream TLS ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
