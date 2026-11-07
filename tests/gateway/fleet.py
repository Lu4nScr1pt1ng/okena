#!/usr/bin/env python3
"""A fleet's two needs, on one engine (argument): `okena drain` and `resume`
take an instance out of rotation and back without cutting anything, and the
ticket keys file is followed when it changes, with no reload."""
import base64
import http.client
import http.server
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, MET, TLS = 18740, 18741, 18742
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        if "s=" in self.path:
            time.sleep(float(self.path.split("s=")[1]))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def ready():
    c = http.client.HTTPConnection("127.0.0.1", MET, timeout=3)
    c.request("GET", "/ready")
    st = c.getresponse().status
    c.close()
    return st


def key():
    return base64.b64encode(os.urandom(32)).decode()


def resumed(ctx, sess):
    s = socket.create_connection(("127.0.0.1", TLS), 3)
    t = ctx.wrap_socket(s, server_hostname="localhost", session=sess)
    t.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    d = b""
    while not d.endswith(b"ok"):              # (an EOF with no close_notify makes OpenSSL drop the session)
        x = t.recv(4096)
        if not x:
            break
        d += x
    r, ns = t.session_reused, t.session
    t.close()
    return r, ns


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-fleet-", dir="/tmp"))
    b = S(("127.0.0.1", 0), H)
    threading.Thread(target=b.serve_forever, daemon=True).start()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    keys = tmp / "tickets"
    k1, k2 = key(), key()
    keys.write_text(k1 + "\n")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; admin unix:{tmp}/a.sock; metrics 127.0.0.1:{MET}; ticket_keys {keys} }}
pool p {{ server 127.0.0.1:{b.server_address[1]} }}
http 127.0.0.1:{LST} {{ route /* {{ to pool p }} }}
http 127.0.0.1:{TLS} {{ tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}; route /* {{ to pool p }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))

    def ctl(*a):
        return subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=90)
    try:
        for i in range(100):
            try:
                if ready() == 200:
                    break
            except OSError:
                time.sleep(0.05)
        check("in rotation: /ready 200", ready() == 200)
        keep = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        keep.request("GET", "/")
        r = keep.getresponse()
        r.read()
        check("  a kept-alive connection", r.getheader("connection") != "close")

        # a request in flight when the drain comes
        slow = {}

        def run():
            c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
            c.request("GET", "/?s=1.5")
            rr = c.getresponse()
            slow["r"] = (rr.status, rr.read(), rr.getheader("connection"))
        th = threading.Thread(target=run)
        th.start()
        time.sleep(0.3)
        r = ctl("drain")
        check("okena drain: says so", r.returncode == 0 and "503" in r.stdout, r)
        check("  /ready 503 for the balancer in front", ready() == 503)
        keep.request("GET", "/")
        r = keep.getresponse()
        r.read()
        check("  a kept-alive connection gets its answer, and Connection: close", r.status == 200 and r.getheader("connection") == "close", r.getheaders())
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.request("GET", "/")
        r = c.getresponse()
        check("  a new one is still served", r.status == 200 and r.read() == b"ok")
        c.close()
        th.join()
        check("  the one in flight finishes whole", slow.get("r", (0,))[0] == 200 and slow["r"][1] == b"ok", slow)
        t = time.time()
        r = ctl("drain", "wait")
        check("okena drain wait: back once nothing is open", r.returncode == 0 and "nothing left open" in r.stdout and time.time() - t < 10, r)
        r = ctl("reload")
        check("  a reload keeps it", r.returncode == 0 and ready() == 503, (r, ready()))
        r = ctl("resume")
        check("okena resume: in rotation again", r.returncode == 0 and ready() == 200, r)
        keep = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        keep.request("GET", "/")
        r = keep.getresponse()
        r.read()
        check("  connections kept alive again", r.getheader("connection") != "close")
        keep.close()

        # ticket keys: a session resumes; a new key and the old as the second
        # line: still resumes, with no reload
        ctx = ssl.create_default_context(cafile=str(tmp / "c.pem"))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        _, sess = resumed(ctx, None)
        reused, sess2 = resumed(ctx, sess)
        check("a ticket resumes", reused)
        keys.write_text(f"{k2}\n{k1}\n")
        time.sleep(2.2)
        check("  the file followed, and said", "ticket keys taken again" in log.read_text(), log.read_text()[-300:])
        reused, sess3 = resumed(ctx, sess2)
        check("  a new key first, the old second: the old ticket still resumes", reused)
        keys.write_text(f"{k2}\n")
        time.sleep(2.2)
        reused, _ = resumed(ctx, sess2)
        check("  the old key gone: its ticket does not", not reused)
        reused, _ = resumed(ctx, sess3)
        check("  one sealed with the new key does", reused)
        keys.write_text("this is not a key\n")
        time.sleep(2.2)
        reused, _ = resumed(ctx, sess3)
        check("a file that is not keys: the keys stay, and it is said", reused and "does not hold keys" in log.read_text(), (reused, log.read_text()[-600:]))
    finally:
        p.terminate()
        p.wait(10)
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text, text[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"fleet {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
