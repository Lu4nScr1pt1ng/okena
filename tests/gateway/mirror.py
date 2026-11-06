#!/usr/bin/env python3
"""`mirror` on a route, on one engine (argument). What it promises is that the
client never notices: not when the shadow is slow, nor down, nor when it answers
something else. Also that the copy is the request (head and body), that the
share holds, and each protocol."""
import http.client
import http.server
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 29000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
MAIN, SHADOW, SLOW, LST, TLS = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
FAST = 29950 + (5 if ENGINE == "epoll" else 0)		# (above what BASE reaches)
FEW = FAST + 1
failures = 0
got = []
lock = threading.Lock()


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


def backend(port, status, delay=0, keep=False):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def answer(self):
            body = b""
            if self.headers.get("Transfer-Encoding"):
                while True:
                    n = int(self.rfile.readline().strip(), 16)
                    if n == 0:
                        self.rfile.readline()
                        break
                    body += self.rfile.read(n)
                    self.rfile.readline()
            else:
                n = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(n) if n else b""
            if keep:
                with lock:
                    got.append((self.command, self.path, dict(self.headers.items()), body))
            time.sleep(delay)
            out = b"from %d" % port
            self.send_response(status)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST = answer

        def log_message(self, *a):
            pass
    http.server.ThreadingHTTPServer.request_queue_size = 256
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def call(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b


def wait(n, secs=2):
    end = time.time() + secs
    while time.time() < end:
        with lock:
            if len(got) >= n:
                return True
        time.sleep(0.01)
    return False


CONF = """okena {{ workers 2; io_engine {engine}; {metrics} }}
pool main {{ server 127.0.0.1:{main} }}
pool shadow {{ server 127.0.0.1:{shadow} }}
pool slow {{ server 127.0.0.1:{slow} }}
pool nobody {{ server 127.0.0.1:1 }}
pool deaf {{ server 127.0.0.1:{deaf} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ to pool main; mirror pool shadow }}
}}
http 127.0.0.1:{lst} {{
    access_log {tmp}/access.log
    route /all {{ to pool main; mirror pool shadow }}
    route /tenth {{ to pool main; mirror pool shadow 10% }}
    route /slow {{ to pool main; mirror pool slow }}
    route /down {{ to pool main; mirror pool nobody }}
    route /re/* {{ to pool main; mirror pool shadow; rewrite path /re/{{*}} -> /new/{{*}}; header set x-env prod }}
    route /deaf {{ to pool main; mirror pool deaf }}
    route /stuck {{ to pool main; mirror pool deaf }}
    route /plain {{ to pool main }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mirror-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=m.test",
                    "-addext", "subjectAltName=DNS:m.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    backend(MAIN, 200)
    backend(SHADOW, 500, keep=True)
    backend(SLOW, 200, delay=1.5)
    deaf = socket.socket()			# accepts, and never reads
    deaf.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    deaf.bind(("127.0.0.1", 0))
    deaf.listen(64)
    conf = tmp / "okena.conf"
    args = dict(deaf=deaf.getsockname()[1], engine=ENGINE, main=MAIN, shadow=SHADOW, slow=SLOW, lst=LST, tls=TLS, tmp=tmp, metrics="watchdog 5s")
    text = CONF.format(**args)
    conf.write_text(text)
    p = subprocess.Popen(["timeout", "--foreground", "40", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        s = call("GET", "/all?x=1", headers={"x-a": "b"})
        check("the client gets the main answer, a shadow's 500 is nothing to it", s == (200, b"from %d" % MAIN), str(s))
        check("  the copy arrives, whole", wait(1) and got[0][0] == "GET" and got[0][1] == "/all?x=1"
              and got[0][2].get("x-a") == "b", str(got[:1]))
        got.clear()
        s = call("POST", "/all", b"hello body")
        check("POST: its body too", wait(1) and got[0][3] == b"hello body" and s[0] == 200, str(got[:1]))
        got.clear()
        mid = bytes(range(256)) * 160
        s = call("POST", "/all", mid)
        check("40 KB coming after the head: teed, every byte", s[0] == 200 and wait(1) and got[0][3] == mid,
              f"{s[0]} {[len(g[3]) for g in got]}")
        got.clear()
        def chunks():
            for i in range(5):
                yield b"part%d" % i
                time.sleep(0.02)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
        c.request("POST", "/all", chunks(), encode_chunked=True, headers={"Transfer-Encoding": "chunked"})
        q = c.getresponse()
        q.read()
        c.close()
        check("a chunked body too", q.status == 200 and wait(1) and got[0][3] == b"part0part1part2part3part4",
              f"{q.status} {got[:1]}")
        got.clear()
        s = call("POST", "/deaf", b"z" * 2000000)
        check("a shadow that stops reading a big body: the client never knows", s[0] == 200, str(s[0]))
        s = call("GET", "/re/x")
        check("rewrites and headers as the request's", wait(1) and got[0][1] == "/new/x" and got[0][2].get("x-env") == "prod",
              str(got[:1]))
        got.clear()
        for _ in range(500):
            call("GET", "/tenth")
        time.sleep(0.3)
        check(f"10% of 500: {len(got)}", 20 <= len(got) <= 85, str(len(got)))
        t0 = time.time()
        r = [call("GET", "/slow") for _ in range(30)]
        dt = time.time() - t0
        check(f"a shadow of 1.5 s: 30 answers in {dt:.2f} s", dt < 1.0 and all(x[0] == 200 for x in r), str(dt))
        t0 = time.time()
        r = [call("GET", "/down") for _ in range(30)]
        dt = time.time() - t0
        check(f"a shadow that refuses: 30 answers in {dt:.2f} s", dt < 1.0 and all(x[0] == 200 for x in r), str(dt))
        with ThreadPoolExecutor(16) as ex:
            r = list(ex.map(lambda i: call("GET", "/slow")[0], range(1200)))
        check("1200 at once with the shadow slow, past the copies' cap: all served", r.count(200) == 1200, str(set(r)))
        time.sleep(1.8)
        check("  the worker lives, and its copies are gone", call("GET", "/plain")[0] == 200)
        log = (tmp / "access.log").read_text() if (tmp / "access.log").exists() else ""
        check("copies are not in the access log", log.count("/all?x=1") == 1, str(log.count("/all?x=1")))
        got.clear()
        for proto, flag in (("h2", "--http2"), ("h3", "--http3-only")):
            before = len(got)
            q = subprocess.run(["timeout", "8", "curl", "-sk", flag, "-o", "/dev/null", "-w", "%{http_code}",
                                "--resolve", f"m.test:{TLS}:127.0.0.1", f"https://m.test:{TLS}/x/{proto}"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if q.returncode in (1, 2):
                print(f"skip {proto}: this curl does not speak it")
                continue
            check(f"over {proto}: the client answered, the copy arrives", q.stdout == "200" and wait(before + 1)
                  and got[-1][1] == f"/x/{proto}", f"{q.stdout} {got[-1:]}")
        # a copy stuck on a shadow that does not answer must not hold up a drain
        threading.Thread(target=lambda: call("GET", "/stuck"), daemon=True).start()
        time.sleep(0.2)
        t0 = time.time()
        p.terminate()
        p.wait(10)
        check(f"a drain does not wait for a copy ({time.time() - t0:.1f} s)", time.time() - t0 < 2, "")
    finally:
        p.terminate()
        p.wait(10)
    # a copy whose upstream goes back to its pool has nothing left to close: its
    # session must still come free. With few sessions, a leak refuses real clients
    subprocess.run(["gcc", "-O2", "-pthread", "-o", tmp / "l4bench", ROOT / "tests/bench/l4bench.c"], check=True)
    fast = subprocess.Popen(["timeout", "--foreground", "20", str(tmp / "l4bench"), "http", str(FAST), "2"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    few = tmp / "few.conf"
    few.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
pool fast {{ server 127.0.0.1:{FAST} }}
http 127.0.0.1:{FEW} {{
    route /copied {{ to pool fast; mirror pool fast }}
    route /plain {{ to pool fast }}
}}
""")
    q = subprocess.Popen(["prlimit", "--nofile=1024:1024", "timeout", "--foreground", "15", str(BIN), "-c", str(few)],
                         stderr=open(tmp / "few.log", "w"))
    try:
        time.sleep(0.5)
        def load(path, rate):
            r = subprocess.run(["timeout", "8", str(BIN), "bench", f"http://127.0.0.1:{FEW}{path}", "conns=16",
                                "workers=2", f"rate={rate}", "duration=1s", "warmup=0s", "format=kv"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            return dict(x.split("=", 1) for x in r.stdout.split() if "=" in x)
        kv = load("/copied", 4000)
        check("thousands of copies, on a few hundred sessions", kv.get("ok") == "4000" and kv.get("errors") == "0", str(kv)[:100])
        kv = load("/copied", 4000)
        check("  and as many again", kv.get("ok") == "4000" and kv.get("errors") == "0", str(kv)[:100])
        kv = load("/plain", 1000)
        check("  real clients still get sessions", kv.get("ok") == "1000" and kv.get("errors") == "0", str(kv)[:100])
    finally:
        q.terminate()
        q.wait(10)
        fast.terminate()
    t = (tmp / "log").read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    for bad in ("mirror pool nosuch", "mirror pool shadow 0%", "mirror pool shadow 101%", "mirror pool shadow x", "mirror shadow"):
        c = tmp / "bad.conf"
        c.write_text(text.replace("mirror pool shadow 10%", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{bad}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[:90]}")
    print(f"mirror {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
