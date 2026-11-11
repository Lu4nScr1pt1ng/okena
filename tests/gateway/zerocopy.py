#!/usr/bin/env python3
"""Zero copy, on one engine (argument): a body from a file (`files`) or from the disk
cache goes from the page cache to the socket without passing through okena (splice
through a pipe with io_uring, sendfile with epoll), in the clear and with kTLS. Every
byte right: whole, from an offset (a range), to a slow client, again and again on one
connection; clients that leave mid-body give their pipes (or descriptors) back; small bodies and
HTTP/2 are copied, as before, and right too."""
import hashlib
import http.client
import http.server
import os
import pathlib
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 46000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, TLS, MET, UTLS = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
BIG = random.Random(1).randbytes(3 << 20)
OBJ = random.Random(2).randbytes(400000)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(OBJ)))
        self.end_headers()
        self.wfile.write(OBJ)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


CTX = ssl.create_default_context()
CTX.check_hostname, CTX.verify_mode = False, ssl.CERT_NONE


def get(path, port=LST, headers=None, method="GET"):
    c = (http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=CTX) if port in (TLS, UTLS)
         else http.client.HTTPConnection("127.0.0.1", port, timeout=10))
    c.request(method, path, headers=headers or {})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, r


def zc():
    t = urllib.request.urlopen(f"http://127.0.0.1:{MET}/metrics", timeout=5).read().decode()
    return int(re.search(r"^okena_zero_copy_bytes_total (\d+)", t, re.M).group(1))


def settled():
    """the counter, once it has not moved for a publication period (a second)"""
    last = [zc(), time.time()]

    def still():
        v = zc()
        if v != last[0]:
            last[:] = [v, time.time()]
            return False
        return time.time() - last[1] > 1.1
    until(still, 6)
    return last[0]


def grew(before, by):
    """the counter (published once a second) shows at least this much more"""
    return until(lambda: zc() >= before + by, 4)


def worker_fds(master):
    """descriptors open in okena's workers"""
    n = 0
    for d in pathlib.Path("/proc").iterdir():
        try:
            if d.name.isdigit() and (d / "comm").read_text().strip() == "okena-worker" \
                    and (d / "stat").read_text().rsplit(")", 1)[1].split()[1] == str(master):
                n += len(list((d / "fd").iterdir()))
        except OSError:
            pass
    return n


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-zc-", dir="/tmp"))
    site = tmp / "site"
    (site / "f").mkdir(parents=True)
    (site / "f" / "big.bin").write_bytes(BIG)
    (site / "f" / "small.txt").write_bytes(b"s" * 1000)
    (tmp / "store").mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"], check=True, capture_output=True)
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    routes = f"""route /f/* {{ files {site} }}
    route /c/* {{ cache 1h max=1MiB; to pool b }}"""
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s; metrics 127.0.0.1:{MET}
    cache_memory 1MiB; cache_disk {tmp}/store size=16MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    http2 on
    {routes}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem; ktls on }}
    {routes}
}}
http 127.0.0.1:{UTLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    {routes}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get("/f/small.txt")[0] == 200) and until(lambda: zc() >= 0), log.read_text()[-300:])
        fds0 = worker_fds(p.pid)
        z0 = zc()
        s, b, _ = get("/f/big.bin")
        check("a file, whole: every byte", s == 200 and b == BIG, (s, len(b)))
        check("  and without copies", grew(z0, len(BIG)), (z0, zc()))

        z0 = zc()
        s, b, r = get("/f/big.bin", headers={"Range": "bytes=1000000-2999999"})
        check("a range of it: from its offset", s == 206 and b == BIG[1000000:3000000], (s, len(b)))
        check("  without copies", grew(z0, 2000000), (z0, zc()))

        z0 = zc()
        s, b, _ = get("/f/big.bin", port=TLS)
        check("over TLS (kTLS): every byte", s == 200 and b == BIG, (s, len(b)))
        check("  without copies", grew(z0, len(BIG)), (z0, zc()))

        # one connection, again and again: the pipe goes back and comes again
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
        same = []
        for _ in range(5):
            c.request("GET", "/f/big.bin")
            r = c.getresponse()
            same.append(r.read() == BIG)
        c.close()
        check("one connection, five times: all right", all(same), same)

        # a slow client: the socket fills, and the rest goes when there is room
        sk = socket.socket()
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sk.connect(("127.0.0.1", LST))
        sk.sendall(b"GET /f/big.bin HTTP/1.1\r\nHost: t\r\n\r\n")
        raw = b""
        sk.settimeout(10)
        time.sleep(0.3)
        while b"\r\n\r\n" not in raw or len(raw.split(b"\r\n\r\n", 1)[1]) < len(BIG):
            d = sk.recv(65536)
            if not d:
                break
            raw += d
        sk.close()
        check("a slow client: every byte", raw.split(b"\r\n\r\n", 1)[1] == BIG, len(raw))

        # from the disk cache: filled once, then hits, on both workers
        get("/c/obj")
        z0 = zc()
        out = [get("/c/obj") for _ in range(12)]
        disk = [o for o in out if "detail=disk" in o[2].getheader("cache-status", "")]
        check("a hit from disk: every byte, without copies", disk and all(o[1] == OBJ for o in out)
              and grew(z0, len(OBJ) * len(disk)), (len(disk), z0, zc()))

        # clients that leave mid-body: more than all the pipes there are
        def leave():
            k = socket.create_connection(("127.0.0.1", LST), timeout=5)
            k.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            k.sendall(b"GET /f/big.bin HTTP/1.1\r\nHost: t\r\n\r\n")
            k.recv(1000)
            k.close()
        ts = [threading.Thread(target=leave) for _ in range(200)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        z0 = zc()
        out = [get("/f/big.bin")[1] == BIG for _ in range(6)]
        check("after 200 clients left mid-body: still right, still without copies (the pipes came back)",
              all(out) and grew(z0, 6 * len(BIG)), (out, z0, zc()))
        if ENGINE == "io_uring":                # (epoll's clients are descriptors themselves)
            check("  and the descriptors the ring made for them closed (sendfile on them)",
                  until(lambda: worker_fds(p.pid) == fds0, 5), (fds0, worker_fds(p.pid)))

        # copied as before: a small body, HTTP/2, HEAD
        z0 = settled()                  # (what the clients that left still had: counted)
        s, b, _ = get("/f/small.txt")
        check("a small body: right (copied: cheaper)", s == 200 and b == b"s" * 1000)
        import h2.config
        import h2.connection
        import h2.events
        k = socket.create_connection(("127.0.0.1", LST), timeout=5)
        hc = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        hc.initiate_connection()
        hc.send_headers(1, [(":method", "GET"), (":path", "/f/big.bin"), (":scheme", "http"), (":authority", "t")], end_stream=True)
        k.sendall(hc.data_to_send())
        data, ended = b"", False
        while not ended:
            for e in hc.receive_data(k.recv(65536)):
                if isinstance(e, h2.events.DataReceived):
                    data += e.data
                    hc.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, h2.events.StreamEnded):
                    ended = True
            k.sendall(hc.data_to_send())
        k.close()
        check("HTTP/2: right (copied, in frames)", data == BIG, len(data))
        s, b, _ = get("/f/big.bin", port=UTLS)
        check("TLS sealed by okena (no kTLS): right (copied)", s == 200 and b == BIG, (s, len(b)))
        s, b, r = get("/f/big.bin", method="HEAD")
        check("HEAD: its length, no body", s == 200 and b == b"" and r.getheader("content-length") == str(len(BIG)))
        check("  and none of those went without copies", not until(lambda: zc() != z0, 1.3), (z0, zc()))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"zerocopy {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
