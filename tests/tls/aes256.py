#!/usr/bin/env python3
"""AES-256-GCM with SHA-384, through OpenSSL's s_client: TLS_AES_256_GCM_SHA384
for a TLS 1.3 client that offers only it (EC, RSA and Ed25519 certificates, its
records here and on kTLS, after a HelloRetryRequest too); a client that also
offers AES-128 keeps AES-128; no session resumed with it (its hash is not the
tickets'); and TLS 1.2's ECDHE-ECDSA-AES256-GCM-SHA384, resumed by its ticket,
the request sent with the client's Finished (an abbreviated handshake's last
word) taken as the request, not lost with the handshake."""
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import socket
import ssl

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 35000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, LE, LR, LD, LU = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = b"x" * 200000
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):                 # (clients that read the head only)
        pass


def sclient(port, *opts, tls="-tls1_3"):
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "a.test", tls, "-ign_eof", *opts],
                       input=b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", capture_output=True, timeout=10)
    o = (r.stdout + r.stderr).decode(errors="replace")
    cipher = next((x.split("Cipher is ")[1].strip() for x in o.splitlines() if "Cipher is " in x), "")
    return cipher, o.count("HTTP/1.1 200"), len(r.stdout) > 200000, o


CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname, CTX.verify_mode = False, ssl.CERT_NONE
CTX.maximum_version = ssl.TLSVersion.TLSv1_2
CTX.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")


def one_write(port, session=None):
    try:
        return one_write_(port, session)
    except OSError as e:                        # (a request lost: the wait runs out)
        return repr(e), False, None


def one_write_(port, session=None):
    """TLS 1.2 through a memory BIO: the client's last flight and the request
    leave in one write. (status, resumed, session)"""
    i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
    t = CTX.wrap_bio(i, o, server_hostname="a.test", session=session)
    k = socket.create_connection(("127.0.0.1", port), 5)
    while True:
        try:
            t.do_handshake()
            break
        except ssl.SSLWantReadError:
            if o.pending:
                k.sendall(o.read())
            d = k.recv(65536)
            if not d:
                return 0, False, None
            i.write(d)
    t.write(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    k.sendall(o.read())                         # Finished (when resumed) and the request
    got = b""
    while b"\r\n\r\n" not in got:
        try:
            got += t.read(65536)
        except ssl.SSLWantReadError:
            d = k.recv(65536)
            if not d:
                break
            i.write(d)
        except ssl.SSLError:
            break
    if o.pending:
        k.sendall(o.read())
    k.close()
    return int(got[9:12] or 0), t.session_reused, t.session


def main():
    if not shutil.which("openssl"):
        print("skip aes256: no openssl")
        return
    threading.Thread(target=S(("127.0.0.1", B), H).serve_forever, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-aes256-"))
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=tmp)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ek.pem", "-out", "ec.pem", "-subj", "/CN=a.test", "-days", "2")
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rk.pem", "-out", "rc.pem", "-subj", "/CN=a.test", "-days", "2")
    run("req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", "dk.pem", "-out", "dc.pem", "-subj", "/CN=a.test", "-days", "2")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{LE} {{ tls {{ cert {tmp}/ec.pem; key {tmp}/ek.pem; ktls on }}; route /* {{ to pool b }} }}
http 127.0.0.1:{LR} {{ tls {{ cert {tmp}/rc.pem; key {tmp}/rk.pem; ktls on }}; route /* {{ to pool b }} }}
http 127.0.0.1:{LD} {{ tls {{ cert {tmp}/dc.pem; key {tmp}/dk.pem }}; route /* {{ to pool b }} }}
http 127.0.0.1:{LU} {{ tls {{ cert {tmp}/ec.pem; key {tmp}/ek.pem }}; route /* {{ to pool b }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LU), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        for port, what, extra in ((LE, "EC, kTLS", ()), (LR, "RSA, kTLS", ()), (LD, "Ed25519", ("-sigalgs", "ed25519")),
                                  (LU, "EC, records here", ())):
            c, n, whole, o = sclient(port, "-ciphersuites", "TLS_AES_256_GCM_SHA384", *extra)
            check(f"TLS 1.3, AES-256 only offered ({what}): TLS_AES_256_GCM_SHA384, 200 KB whole",
                  c == "TLS_AES_256_GCM_SHA384" and n == 1 and whole, (c, n, o[-300:]))
        c, n, whole, o = sclient(LU, "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-groups", "P-384:X25519")
        check("  after a HelloRetryRequest (a P-384 share first)", c == "TLS_AES_256_GCM_SHA384" and n == 1, (c, o[-300:]))
        c, n, whole, o = sclient(LU, "-ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")
        check("AES-256 and AES-128 offered: AES-128", c == "TLS_AES_128_GCM_SHA256" and n == 1, c)
        sess = tmp / "sess"
        sclient(LU, "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-sess_out", str(sess))
        if sess.exists():
            c, n, whole, o = sclient(LU, "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-sess_in", str(sess))
            check("  AES-256: a full handshake each time (no ticket of SHA-384)", "Reused" not in o and n == 1, o[-300:])
        else:
            check("  AES-256: no ticket issued (its hash is not the tickets')", True)
        c, n, whole, o = sclient(LE, "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384", "-sess_out", str(sess), tls="-tls1_2")
        check("TLS 1.2 ECDHE-ECDSA-AES256-GCM-SHA384", c == "ECDHE-ECDSA-AES256-GCM-SHA384" and n == 1 and whole, (c, o[-300:]))
        c, n, whole, o = sclient(LE, "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384", "-sess_in", str(sess), tls="-tls1_2")
        check("  resumed by its ticket", "Reused, TLSv1.2" in o and n == 1, o[-300:])
        for port, what in ((LE, "kTLS"), (LU, "records here")):
            st, re1, ses = one_write(port)
            for x in range(5):
                st2, re2, _ = one_write(port, ses)
                if not (st2 == 200 and re2):
                    break
            check(f"  resumed, its Finished and request in one write ({what}): answered",
                  st == 200 and st2 == 200 and re2, (st, st2, re2))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"aes256 {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
