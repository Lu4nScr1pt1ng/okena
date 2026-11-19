#!/usr/bin/env python3
"""Handler modules (make MODULES=...), on one engine (argument), with
build/okena-modtest (tests/modules/test.inc assembled in): what a handler is
given (method, target, the route's ARG, the body by Content-Length or chunked,
in pieces too), what its init read, its status and Content-Type, a status that
is none (500); keep-alive and pipelined requests after a body; HTTP/2 and
HTTP/3; and `handler` refused by a binary without that module."""
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena-modtest"
PLAIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 17900 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
LST, TLS = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


def exchange(parts, port=LST, n=1, pause=0.0, is_head=False):
    """Send parts (with a pause between), read n answers: [(status, headers, body)]"""
    s = socket.create_connection(("127.0.0.1", port), 5)
    for i, p in enumerate(parts):
        s.sendall(p)
        if pause and i + 1 < len(parts):
            time.sleep(pause)
    got = b""
    out = []
    s.settimeout(5)
    while len(out) < n:
        while b"\r\n\r\n" not in got:
            d = s.recv(65536)
            if not d:
                s.close()
                return out
            got += d
        head, _, rest = got.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        h = {k.lower(): v.strip() for k, _, v in (x.partition(":") for x in lines[1:])}
        ln = 0 if is_head else int(h.get("content-length", 0))
        while len(rest) < ln:
            d = s.recv(65536)
            if not d:
                break
            rest += d
        out.append((int(lines[0].split()[1]), h, rest[:ln].decode()))
        got = rest[ln:]
    s.close()
    return out


def req(method, target, body=None, chunked=False, close=False):
    h = f"{method} {target} HTTP/1.1\r\nHost: t\r\n"
    if close:
        h += "Connection: close\r\n"
    if body is None:
        return (h + "\r\n").encode()
    if chunked:
        b = body.encode()
        mid = len(b) // 2
        parts = [x for x in (b[:mid], b[mid:]) if x]          # (an empty chunk would be the last)
        enc = b"".join(b"%x;ext=1\r\n%s\r\n" % (len(x), x) for x in parts) + b"0\r\nX-Trailer: t\r\n\r\n"
        return (h + "Transfer-Encoding: chunked\r\n\r\n").encode() + enc
    return (h + f"Content-Length: {len(body)}\r\n\r\n").encode() + body.encode()


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mod."))
    (tmp / "word").write_text("hello world\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"],
                   check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; overload off }}
http 127.0.0.1:{LST} {{
    route /e/* {{ handler echo the-arg }}
    route /j {{ handler json }}
    route /b {{ handler broken }}
    route /raw {{ handler raw }}
    route /w/* {{ handler wait }}
    route /z/* {{ handler echo; compress br gzip min=10B }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    route /e/* {{ handler echo }}
}}
""")
    env = dict(os.environ, OKENA_MODTEST_FILE=str(tmp / "word"))
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"), env=env)
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        r = exchange([req("GET", "/e/x?q=1")])
        check("GET: method, target, ARG, no body, what init read", r and r[0][:1] == (200,)
              and r[0][2] == "GET /e/x?q=1|the-arg||hello" and r[0][1].get("content-type") == "text/plain; charset=utf-8", r)
        r = exchange([req("POST", "/e/p", "payload")])
        check("POST, Content-Length: its body", r and r[0][2] == "POST /e/p|the-arg|payload|hello", r)
        r = exchange([req("POST", "/e/c", "chunked-body", chunked=True)])
        check("POST, chunked: its body undone (extension, trailer)", r and r[0][2] == "POST /e/c|the-arg|chunked-body|hello", r)
        whole = req("POST", "/e/f", "fragmented", chunked=True)
        ok = True
        for cut in range(1, len(whole), 3):
            r = exchange([whole[:cut], whole[cut:]], pause=0.01)
            if not r or r[0][2] != "POST /e/f|the-arg|fragmented|hello":
                ok = False
                break
        check("a body in pieces, cut anywhere: whole", ok, (cut, r))
        r = exchange([req("POST", "/e/1", "one"), req("GET", "/e/2"), req("POST", "/e/3", "three", chunked=True)], n=3)
        check("pipelined after bodies: each its own, the connection kept", [x[2] for x in r] ==
              ["POST /e/1|the-arg|one|hello", "GET /e/2|the-arg||hello", "POST /e/3|the-arg|three|hello"], r)
        r = exchange([req("GET", "/j")])
        check("its status and Content-Type", r and r[0][0] == 201 and r[0][1].get("content-type") == "application/json"
              and r[0][2] == '{"ok":true}', r)
        r = exchange([req("GET", "/b")])
        check("a status that is none: 500", r and r[0][0] == 500, r)
        r = exchange([req("HEAD", "/e/h")], is_head=True)
        check("HEAD: its length, no body", r and r[0][0] == 200 and int(r[0][1].get("content-length", 0)) > 0, r)
        import random
        rnd = random.Random(7)
        ok = True
        for size in (0, 1, 1024, 10240, 102400, 1000000):
            body = "".join(rnd.choice("abcdefgh0123") for i in range(size))
            for chunked in (False, True):
                r = exchange([req("POST", "/raw", body, chunked=chunked)])
                if not r or r[0][0] != 200 or r[0][2] != body:
                    ok = False
                    detail = (size, chunked, r[0][:2] if r else None, len(r[0][2]) if r else None)
                    break
            if not ok:
                break
        check("bodies of 0 B to 1 MB, both framings, answered from where they are", ok, None if ok else detail)
        r = exchange([req("POST", "/raw", "x" * 300000), req("GET", "/e/after")], n=2)
        check("  and a pipelined request after a large one", len(r) == 2 and len(r[0][2]) == 300000
              and r[1][2] == "GET /e/after|the-arg||hello", [(x[0], len(x[2])) for x in r])
        r = exchange([req("POST", "/raw", "9" * 1100000, close=True)])
        check("a body past MOD_BODY_MAX: 413", r and r[0][0] == 413, r and r[0][:2])
        t = time.time()
        r = exchange([req("GET", "/w/150")])
        dt = time.time() - t
        check("held: answered after its time, not before", r and r[0][2] == "waited 150" and 0.15 <= dt < 1.0, (r, dt))
        import concurrent.futures as cf
        def one(ms):
            t = time.time()
            r = exchange([req("GET", f"/w/{ms}")])
            return ms, r and r[0][2], time.time() - t
        with cf.ThreadPoolExecutor(20) as ex:
            res = list(ex.map(one, [50 + 10 * i for i in range(20)]))
        check("  twenty at once, each its own time (the loop never waited)",
              all(b == f"waited {ms}" and ms / 1000 <= dt < ms / 1000 + 0.5 for ms, b, dt in res), res[:3])
        import gzip
        long = "/z/" + "abc" * 600
        s2 = socket.create_connection(("127.0.0.1", LST), 5)
        s2.sendall(f"GET {long} HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n".encode())
        raw = b""
        while True:
            d = s2.recv(65536)
            if not d:
                break
            raw += d
        head, _, body = raw.partition(b"\r\n\r\n")
        if b"chunked" in head.lower():
            out, rest = b"", body
            while True:
                n, _, rest = rest.partition(b"\r\n")
                n = int(n, 16)
                if n == 0:
                    break
                out += rest[:n]
                rest = rest[n + 2:]
            body = out
        try:
            plain = gzip.decompress(body).decode()
        except Exception as e:
            plain = repr(e)
        check("a route with compress: the handler's answer compressed by okena", b"content-encoding: gzip" in head.lower()
              and plain == f"GET {long}|||hello", head[:200])
        r = exchange([req("GET", "/w/0")])
        check("  0 ms: at once", r and r[0][2] == "waited 0", r)
        q = subprocess.run(["curl", "-q", "-sk", "--http2", f"https://localhost:{TLS}/e/h2"], capture_output=True, text=True)
        check("HTTP/2", q.stdout == "GET /e/h2|||hello", q.stdout)
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{TLS}/e/h3", "proto=h3", "conns=1", "workers=1",
                            "rate=50", "duration=500ms", "warmup=0s", "format=kv"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
        check("HTTP/3", kv.get("ok", "0") != "0" and kv.get("errors") == "0", q.stdout[:120])
    finally:
        p.terminate()
        p.wait(10)
    t = (tmp / "log").read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])
    # a binary without the module: refused, its modules named
    q = subprocess.run([str(PLAIN), "check", str(conf)], capture_output=True, text=True)
    check("`handler` in a binary without it: refused", q.returncode != 0 and "make MODULES" in q.stderr, q.stderr[-200:])
    bad = tmp / "bad.conf"
    bad.write_text(f"http 127.0.0.1:{LST} {{ route /* {{ handler nosuch }} }}\n")
    q = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    check("  a name no module has: refused, those it has listed", q.returncode != 0 and "echo" in q.stderr, q.stderr[-200:])
    # an init that fails stops the start
    env["OKENA_MODTEST_FILE"] = "/no/such/file"
    q = subprocess.run(["timeout", "5", str(BIN), "-c", str(conf)], capture_output=True, text=True, env=env)
    check("an init that fails: okena does not start, and says why", q.returncode not in (0, 124) and "modtest" in q.stderr, q.stderr[-200:])
    print(f"modules {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
