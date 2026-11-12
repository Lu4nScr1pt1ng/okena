#!/usr/bin/env python3
"""`respond CODE [BODY] [type=]`, on one engine (argument): a 200 with its
body as text/plain (a health endpoint), HEAD with its length and no body, a
201 with type=application/json, a 204 empty, an error as before; over HTTP/1.1
and HTTP/2 (prior knowledge, through curl); codes outside 2xx, 4xx, 5xx and a
204 with a body refused by the checker; a client still sending a body
okena does not read gets the answer, not a reset (the connection lingers)."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 43000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def raw(req, answers=1):
    k = socket.create_connection(("127.0.0.1", L), 5)
    k.sendall(req)
    d = b""
    k.settimeout(3)
    try:
        while True:
            x = k.recv(4096)
            if not x:
                break
            d += x
            if b"\r\n\r\n" in d:
                h, _, b = d.partition(b"\r\n\r\n")
                n = next((int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length:")), 0)
                if (req.startswith(b"HEAD") or len(b) >= n) and d.count(b"HTTP/1.1 ") >= answers:
                    break
    except OSError:
        pass
    k.close()
    return d


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-respond-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{L} {{
    http2 on
    route /healthz {{ respond 200 "ok" }}
    route /json {{ respond 201 "{{\\"made\\":true}}" type=application/json }}
    route /empty {{ respond 204 }}
    route /gone {{ respond 410 }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = raw(b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\n")
        check("respond 200 \"ok\": 200 OK, text/plain, its body", r.startswith(b"HTTP/1.1 200 OK\r\n") and b"Content-Type: text/plain; charset=utf-8" in r
              and b"Content-Length: 2\r\n" in r and r.endswith(b"\r\n\r\nok"), r)
        r = raw(b"HEAD /healthz HTTP/1.1\r\nHost: a\r\n\r\n")
        check("  HEAD: its length, no body", b"Content-Length: 2\r\n" in r and r.endswith(b"\r\n\r\n"), r)
        r = raw(b"GET /json HTTP/1.1\r\nHost: a\r\n\r\n")
        check("respond 201 with type=application/json", r.startswith(b"HTTP/1.1 201 Created") and b"Content-Type: application/json" in r
              and r.endswith(b'{"made":true}'), r)
        r = raw(b"GET /empty HTTP/1.1\r\nHost: a\r\n\r\n")
        check("respond 204: no body, no Content-Length", r.startswith(b"HTTP/1.1 204 No Content") and r.endswith(b"\r\n\r\n")
              and b"Content-Length" not in r, r)
        r = raw(b"GET /gone HTTP/1.1\r\nHost: a\r\n\r\n")
        check("respond 410: as before", r.startswith(b"HTTP/1.1 410 Gone") and b"Content-Length: 0" in r, r)
        r = raw(b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\nGET /json HTTP/1.1\r\nHost: a\r\n\r\n", 2)
        check("  kept alive: the next request answered on the same connection", r.count(b"HTTP/1.1 20") == 2, r)
        # a body okena does not read, still coming after the answer: the
        # connection is shut for writing and lingers, reading it away; closed
        # at once with bytes unread, the socket would send a reset, and the
        # client lose the answer
        k = socket.create_connection(("127.0.0.1", L), 5)
        k.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        k.sendall(b"POST /healthz HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n" + b"x" * 65536)
        time.sleep(0.1)				# answered, and (before) closed
        d, err = b"", ""
        try:
            k.settimeout(3)
            for _ in range(16):
                k.sendall(b"x" * 65536)
            while not d.endswith(b"ok"):
                x = k.recv(4096)
                if not x:
                    break
                d += x
        except OSError as e:
            err = repr(e)
        k.close()
        check("a body still coming after the answer: answered, no reset", d.startswith(b"HTTP/1.1 200 OK") and d.endswith(b"ok")
              and b"Connection: close" in d and not err, (d[:80], err))
        if shutil.which("curl"):
            c = subprocess.run(["curl", "-s", "--http2-prior-knowledge", "-D", "-", f"http://127.0.0.1:{L}/healthz", f"http://127.0.0.1:{L}/json"],
                               capture_output=True, timeout=10)
            o = c.stdout
            check("HTTP/2: both answered, bodies and types", o.count(b"HTTP/2 20") == 2 and b"ok" in o and b'{"made":true}' in o
                  and b"application/json" in o, o)
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("respond 302", "respond 204 \"x\"", "respond 100", "respond 600"):
        b = tmp / "bad.conf"
        b.write_text(f"http 127.0.0.1:{L} {{ route /* {{ {bad} }} }}\n")
        r = subprocess.run([str(BIN), "check", str(b)], capture_output=True, text=True)
        check(f"`{bad}` refused", r.returncode == 2 and "respond" in r.stderr, r.stderr)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"respond {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
