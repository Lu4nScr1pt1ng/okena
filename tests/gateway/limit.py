#!/usr/bin/env python3
"""`limit` on a route, on one engine (argument). The point of it: with 4 workers
the limit is the instance's, not 4 times that. Also the keys (each its own
bucket, the empty one shared), 429 with Retry-After on a connection that stays,
recovery at the rate, a flood of new keys, reloads, and bad lines refused."""
import http.client
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 26000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
failures = 0
seen = [0]


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen[0] += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.do_GET()

    def log_message(self, *a):
        pass


def get(path, headers={}, conn=None):
    c = conn or http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers=headers)
    r = c.getresponse()
    r.read()
    if conn is None:
        c.close()
    return r


CONF = """okena {{ drain delay=0s timeout=1s; workers 4; io_engine {engine} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /h1 {{ to 127.0.0.1:{back}; limit 1/h burst=20 }}
    route /h2 {{ to 127.0.0.1:{back}; limit 1/h burst=20 }}
    route /h3 {{ to 127.0.0.1:{back}; limit 1/h burst=20 }}
}}
http 127.0.0.1:{lst} {{
    route /all {{ to 127.0.0.1:{back}; limit 100/s burst=100 }}
    route /ip {{ to 127.0.0.1:{back}; limit 5/m burst=5 key=client.ip }}
    route /hdr {{ to 127.0.0.1:{back}; limit 1/h burst=3 key=header:x-api-key }}
    route /q {{ to 127.0.0.1:{back}; limit 1/h burst=2 key=query:u }}
    route /c {{ to 127.0.0.1:{back}; limit 1/h burst=2 key=cookie:sid }}
    route /m {{ to 127.0.0.1:{back}; limit 1/h burst=2 key=method }}
    route /two {{ to 127.0.0.1:{back}; limit 1/h burst=4; limit 1/h burst=2 key=header:x-a }}
    route /slow {{ to 127.0.0.1:{back}; limit 1/s burst=1 }}
    route /share {{ to 127.0.0.1:{back}; limit 400/s burst=100 instances=4 }}
    route /flood {{ redirect 302 /z; limit 1/h burst=1 key=header:x-k }}
    route /fine {{ to 127.0.0.1:{back} }}
}}
"""


def hammer(path, secs, threads=16):
    """fresh connections, so they land on all the workers: (ok, refused)"""
    end = time.time() + secs
    def one(_):
        a = b = 0
        while time.time() < end:
            s = get(path).status
            a += s == 200
            b += s == 429
        return a, b
    with ThreadPoolExecutor(threads) as ex:
        r = list(ex.map(one, range(threads)))
    return sum(x[0] for x in r), sum(x[1] for x in r)


def flood(i, n=100000, batch=200):
    """pipelined requests, each its own key: (let through, refused)"""
    c = socket.create_connection(("127.0.0.1", LST), timeout=20)
    a = b = 0
    tail = b""
    for j in range(0, n, batch):
        c.sendall(b"".join(b"GET /flood HTTP/1.1\r\nHost: x\r\nx-k: f%d-%d\r\n\r\n" % (i, k)
                           for k in range(j, j + batch)))
        got = 0
        while got < batch:
            data = tail + c.recv(1 << 20)
            cut = data.rfind(b"\r\n\r\n")
            if cut < 0:
                tail = data
                continue
            tail = data[cut + 4:]
            head = data[:cut + 4]
            x, y = head.count(b"HTTP/1.1 302"), head.count(b"HTTP/1.1 429")
            a, b, got = a + x, b + y, got + x + y
    c.close()
    return a, b


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-limit-"))
    http.server.ThreadingHTTPServer.request_queue_size = 256
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=l.test",
                    "-addext", "subjectAltName=DNS:l.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    text = CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp)
    conf.write_text(text)
    p = subprocess.Popen(["timeout", "--foreground", "60", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        t0 = time.time()
        ok, no = hammer("/all", 3)
        dt = time.time() - t0
        want = 100 + 100 * dt
        check(f"100/s burst=100, 4 workers, {dt:.1f} s: the instance's limit ({ok} of about {want:.0f})",
              want * 0.85 <= ok <= want * 1.05 and no > 0, f"{ok} ok {no} refused")
        ok, no = hammer("/share", 2)
        check(f"instances=4: a quarter of 400/s ({ok} in 2 s)", 200 <= ok <= 340 and no > 0, f"{ok} {no}")
        r = [get("/ip").status for _ in range(8)]
        check("client.ip: burst, then 429", r[:5] == [200] * 5 and r[5:] == [429] * 3, str(r))
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        rs = [get("/hdr", {"x-api-key": "a"}, c) for _ in range(4)]
        s4 = c.sock
        r5 = get("/hdr", {"x-api-key": "a"}, c)
        check("429 keeps the connection, says when", rs[3].status == 429 and c.sock is s4 and r5.status == 429
              and int(rs[3].getheader("retry-after")) > 3000, f"{[x.status for x in rs]} {rs[3].getheaders()}")
        check("  a request id with it", bool(rs[3].getheader("x-request-id")), str(rs[3].getheaders()))
        c.close()
        before = seen[0]
        check("  another key its own bucket", get("/hdr", {"x-api-key": "b"}).status == 200, "")
        check("  the backend was not asked for what was refused", seen[0] == before + 1, str(seen[0] - before))
        r = [get("/hdr").status for _ in range(5)]
        check("no such header: one shared bucket, no way around", r == [200] * 3 + [429] * 2, str(r))
        r = [get("/q?x=1&u=a").status for _ in range(3)]
        r2 = get("/q?u=b").status
        check("query:u", r == [200, 200, 429] and r2 == 200, f"{r} {r2}")
        r = [get("/c", {"cookie": "a=1; sid=x; b=2"}).status for _ in range(3)]
        r2 = get("/c", {"cookie": "sid=y"}).status
        check("cookie:sid", r == [200, 200, 429] and r2 == 200, f"{r} {r2}")
        r = [get("/m").status for _ in range(3)]
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.request("POST", "/m", body=b"x")
        q = c.getresponse()
        q.read()
        c.close()
        check("method", r == [200, 200, 429] and q.status == 200, f"{r} {q.status}")
        r = [get("/two", {"x-a": "1"}).status for _ in range(3)]
        check("two limits: the tighter refuses", r == [200, 200, 429], str(r))
        a = get("/slow").status
        b = get("/slow").status
        time.sleep(1.1)
        d = get("/slow").status
        check("1/s: refused, then back after a second", (a, b, d) == (200, 429, 200), str((a, b, d)))
        check("a route without one untouched", all(get("/fine").status == 200 for _ in range(50)), "")
        for proto in ("h1", "h2", "h3"):			# each way a request comes
            q = subprocess.run(["timeout", "10", str(BIN), "bench", f"https://127.0.0.1:{TLS}/{proto}", f"proto={proto}",
                                "conns=4", "duration=1s", "warmup=0s", "workers=2", "format=kv"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
            refused = int(kv.get("other", 0))
            check(f"over {proto}: 20 through, then 429, on the same connections", kv.get("ok") == "20" and refused > 10
                  and kv.get("errors") == "0" and kv.get("reconnects") == "0", q.stdout[:120])
        # a reload starts new workers: what the keys have used stays
        before = get("/hdr", {"x-api-key": "kept"}).status, get("/hdr", {"x-api-key": "kept"}).status
        master = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()[0]
        os.kill(int(master), signal.SIGHUP)
        time.sleep(1)
        r = [get("/hdr", {"x-api-key": "kept"}).status for _ in range(3)]
        check("a reload: keys keep what they used", before == (200, 200) and r == [200, 429, 429], f"{before} {r}")
        # a flood of new keys, past what the table holds, answered without a
        # backend so that many can go: it stays up, and no key gets more
        v = {"x-k": "victim"}
        s = [get("/flood", v).status for _ in range(2)]
        with ThreadPoolExecutor(4) as ex:
            r = list(ex.map(flood, range(4)))
        through, refused = sum(x[0] for x in r), sum(x[1] for x in r)
        total = through + refused
        check(f"{total} new keys, past the table of 262144: at most that many through ({through})",
              total == 400000 and 0 < through <= 262144 + 2048, f"{through} {refused}")
        check("  the key limited before it still is", s == [302, 429] and get("/flood", v).status == 429, str(s))
        check("  and the workers live, routes as before", get("/fine").status == 200, "")
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("limit 0/s", "limit 10", "limit 10/x", "limit abc/s", "limit 10/s key=nope",
                "limit 10/s key=header:", "limit 10/s key=client.ip extra=1"):
        c = tmp / "bad.conf"
        c.write_text(text.replace("limit 100/s burst=100", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{bad}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[:90]}")
    if failures:
        print((tmp / "log").read_text()[-600:])
    print(f"limit {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
