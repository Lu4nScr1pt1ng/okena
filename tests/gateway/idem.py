#!/usr/bin/env python3
"""`idempotency` on one engine (argument), with two workers: what it is for is that a
request sent twice runs once, whichever worker each one lands on, and that nobody gets
someone else's answer."""
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

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 6000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
fails = 0
runs = {}
lock = threading.Lock()


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n) if n else b""
        p = self.path
        with lock:
            runs[p] = runs.get(p, 0) + 1
            k = runs[p]
        if "slow" in p:
            time.sleep(0.5)
        if p.endswith("/drop"):
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        st = 201
        for c in ("500", "503", "404"):
            if p.endswith("/" + c):
                st = int(c)
        b = f"run {k} of {p} for {self.headers.get('x-user-id', '-')}".encode()
        if p.endswith("/big"):
            b = b"x" * 100000
        if p.endswith("/chunked"):
            self.send_response(st)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("X-Mine", "kept")
            self.end_headers()
            self.wfile.write(b"%x\r\n" % len(b) + b + b"\r\n0\r\n\r\n")
            return
        self.send_response(st)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Mine", "kept")
        self.send_header("Set-Cookie", "a=1")
        self.end_headers()
        self.wfile.write(b)

    do_PUT = do_POST

    def do_GET(self):
        self.do_POST()

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def handle_error(self, *a):
        pass


def post(path, key=None, method="POST", body=b"x", **hdr):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=8)
    h = {k.replace("_", "-"): v for k, v in hdr.items()}
    if key:
        h["Idempotency-Key"] = key
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


CONF = """okena {{ workers 2; io_engine {engine} }}
pool b {{ server 127.0.0.1:{back} }}
pool gone {{ server 127.0.0.1:1 }}
http 127.0.0.1:{lst} {{
    route /nope/* {{ idempotency header=idempotency-key; to pool gone }}
    route /short/* {{ idempotency header=idempotency-key ttl=1s lock=1s; to pool b }}
    route /auth/* {{ auth api_key header=x-k keys={tmp}/keys; idempotency header=idempotency-key; to pool b }}
    route /other/* {{ idempotency header=idempotency-key; to pool b }}
    route /plain/* {{ to pool b }}
    route /quota/* {{ limit 40/d burst=40 key=header:x-who; to pool b }}
    route /* {{ idempotency header=idempotency-key; to pool b }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-idem."))
    (tmp / "keys").write_text("alice:ka\nbob:kb\n")
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(CONF.format(engine=ENGINE, back=BACK, lst=LST, tmp=tmp))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        a = post("/pay", "k1")
        rs = [post("/pay", "k1") for i in range(12)]
        check("twice: it runs once", runs["/pay"] == 1, runs["/pay"])
        check("  the same answer, on any worker", all(r[:2] == a[:2] for r in rs), [r[:2] for r in rs[:3]])
        r = rs[0]
        check("  its head too, and it says so", r[2].get("x-mine") == "kept" and r[2].get("idempotency-replayed") == "true" and r[2].get("set-cookie") == "a=1", r[2])
        check("  the first does not say so", "idempotency-replayed" not in a[2])
        check("another key: it runs", post("/pay", "k2")[0] == 201 and runs["/pay"] == 2)
        n = runs["/pay"]
        post("/pay")
        post("/pay")
        check("no key: as ever", runs["/pay"] == n + 2)
        check("a GET is left alone", post("/pay", "k1", method="GET", body=None)[1] != a[1])
        check("the key of another path: 422", post("/payx", "k1")[0] == 422, post("/payx", "k1")[:2])
        check("  of another method", post("/pay", "k1", method="PUT")[0] == 422)
        check("  of another length", post("/pay", "k1", body=b"xy")[0] == 422)
        check("  of another type", post("/pay", "k1", Content_Type="text/plain")[0] == 422)
        check("  of another route, its own", post("/other/pay", "k1")[0] == 201)
        check("a key too long", post("/pay", "x" * 300)[0] == 400)

        # a quota: 40 a day, with two workers taking from it
        ok = [post("/quota/x", x_who="q1")[0] for i in range(60)]
        check("limit N/d: as many as it says, across workers", ok.count(201) in (40, 41) and ok.count(429) in (19, 20), (ok.count(201), ok.count(429)))
        r = post("/quota/x", x_who="q1")
        check("  it says for how long", int(r[2].get("retry-after", 0)) > 1000, r[2])
        check("  each key its own", post("/quota/x", x_who="q2")[0] == 201)

        # at once, both workers
        res = []
        def one():
            res.append(post("/slow", "k3"))
        th = [threading.Thread(target=one) for i in range(24)]
        [t.start() for t in th]
        [t.join() for t in th]
        codes = sorted(r[0] for r in res)
        check("24 at once: it ran once", runs["/slow"] == 1, runs["/slow"])
        check("  one answer, the rest told to wait or replayed", codes.count(409) + codes.count(201) == 24 and 201 in codes, codes)
        r = post("/slow", "k3")
        check("  then the answer for anyone", r[0] == 201 and r[2].get("idempotency-replayed") == "true", r[0::2])
        # many keys at once, each once
        def many(i):
            post(f"/m{i}", f"many{i}")
            post(f"/m{i}", f"many{i}")
        th = [threading.Thread(target=many, args=(i,)) for i in range(60)]
        [t.start() for t in th]
        [t.join() for t in th]
        check("60 keys, each sent twice: each ran once", all(runs.get(f"/m{i}") == 1 for i in range(60)), [runs.get(f"/m{i}") for i in range(60)][:10])

        a = post("/auth/x", "same", x_k="ka")
        b = post("/auth/x", "same", x_k="kb")
        check("one key, two people: each their own", runs["/auth/x"] == 2 and "idempotency-replayed" not in b[2], (runs["/auth/x"], b[2]))
        r = post("/auth/x", "same", x_k="ka")
        check("  each their replay", r[1] == a[1] and r[2].get("idempotency-replayed") == "true", r[:2])
        check("  no key, no way in", post("/auth/x", "same")[0] == 401)

        r = post("/a/chunked", "c1")
        q = post("/a/chunked", "c1")
        check("a chunked answer", q[1] == r[1] and q[0] == 201 and runs["/a/chunked"] == 1, (q[:2], r[:2]))
        check("its status: a 404 is an answer", post("/a/404", "s1")[0] == 404 and post("/a/404", "s1")[0] == 404 and runs["/a/404"] == 1)
        check("  a 500 too: it may have done it", post("/a/500", "s2")[0] == 500 and post("/a/500", "s2")[0] == 500 and runs["/a/500"] == 1)
        check("  a 503 did not: tried again", post("/a/503", "s3")[0] == 503 and post("/a/503", "s3")[0] == 503 and runs["/a/503"] == 2, runs["/a/503"])
        check("no connection: the key is free", post("/nope/x", "n1")[0] == 502 and post("/nope/x", "n1")[0] == 502)
        r = post("/a/big", "b1")
        q = post("/a/big", "b1")
        check("too big to keep: not run again", len(r[1]) == 100000 and q[0] == 409 and runs["/a/big"] == 1, (q[:2], runs["/a/big"]))
        try:
            post("/short/drop", "d1")
        except (http.client.HTTPException, OSError):
            pass
        check("sent, and no answer: locked", post("/short/drop", "d1")[0] in (409, 502), post("/short/drop", "d1")[:2])
        n = runs["/short/drop"]
        check("  it did not run again", n == 1, n)
        time.sleep(1.2)
        try:
            post("/short/drop", "d1")
        except (http.client.HTTPException, OSError):
            pass
        check("  past `lock`, it may", runs["/short/drop"] == 2, runs["/short/drop"])
        a = post("/short/x", "t1")
        time.sleep(1.3)
        r = post("/short/x", "t1")
        check("past `ttl` the key is new", runs["/short/x"] == 2 and "idempotency-replayed" not in r[2], (runs["/short/x"], r[2]))

        # a worker that dies holding a key
        s = socket.create_connection(("127.0.0.1", LST))
        s.sendall(b"POST /short/slow HTTP/1.1\r\nHost: x\r\nIdempotency-Key: w1\r\nContent-Length: 1\r\n\r\nx")
        time.sleep(0.15)
        for w in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split():
            if open(f"/proc/{w}/comm").read().strip() == "okena-worker":
                os.kill(int(w), signal.SIGKILL)
        s.close()
        time.sleep(0.5)
        for i in range(50):
            try:
                c = post("/alive", "w2")
                if c[0] == 201:
                    break
            except (http.client.HTTPException, OSError):
                time.sleep(0.1)
        time.sleep(1.2)
        r = post("/short/slow", "w1")
        check("a worker dies holding a key: it comes free", r[0] == 201, r[:2])

        # a reload
        a = post("/keep", "r1")
        os.kill(p.pid, signal.SIGHUP)
        for i in range(50):
            if "configuration reloaded" in log.read_text():
                break
            time.sleep(0.1)
        time.sleep(0.3)
        r = post("/keep", "r1")
        check("a reload keeps them", r[1] == a[1] and runs["/keep"] == 1, (r[:2], runs["/keep"]))
    finally:
        p.terminate()
        p.wait(10)
    c = tmp / "bad.conf"
    for what, line in (("no header", "idempotency ttl=1s"), ("no time", "idempotency header=x ttl=0s")):
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ {line}; to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"idem {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
