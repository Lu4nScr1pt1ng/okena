#!/usr/bin/env python3
"""The HTTP reverse proxy, end to end, on one engine (argument).

A raw-socket backend shows what reached it (method, target, fields,
body) and answers with each framing on request: Content-Length,
chunked, until close, HEAD, 204, a malformed head. Clients are raw
sockets too, so every byte okena sends is checked."""
import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
# ports 26000-26999: this suite's own range
BASE = 26000 + os.getpid() % 99 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, DEAD = BASE, BASE + 1, BASE + 2


def read_message(f, head_only=False):
    """Read one HTTP/1.1 message from a file object: (start line, fields, body)."""
    start = f.readline()
    if not start:
        return None
    fields = []
    while True:
        line = f.readline()
        if line in (b"\r\n", b""):
            break
        name, _, value = line.decode("latin1").partition(":")
        fields.append((name, value.strip()))
    lower = {n.lower(): v for n, v in fields}
    body = b""
    if head_only:
        return start, fields, body
    if lower.get("transfer-encoding", "").lower() == "chunked":
        while True:
            size = int(f.readline().split(b";")[0], 16)
            if size == 0:
                while f.readline() not in (b"\r\n", b""):
                    pass
                break
            body += f.read(size)
            f.read(2)
    elif "content-length" in lower:
        body = f.read(int(lower["content-length"]))
    return start, fields, body


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(512)

    def handle(c):
        f = c.makefile("rb")
        try:
            while True:
                m = read_message(f)
                if m is None:
                    return
                start, fields, body = m
                method, target, _ = start.decode().split(" ")
                echo = json.dumps({"method": method, "target": target, "fields": fields,
                                   "body_len": len(body),
                                   "body_sha": hashlib.sha256(body).hexdigest()}).encode()
                if target.startswith("/chunked"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    for i in range(0, len(echo), 7):
                        piece = echo[i:i + 7]
                        c.sendall(b"%x;ext=1\r\n%s\r\n" % (len(piece), piece))
                    c.sendall(b"0\r\nX-Trailer: 1\r\n\r\n")
                elif target.startswith("/close"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + echo)
                    return
                elif target.startswith("/big"):
                    data = (b"0123456789abcdef" * 65536 * 8)[:int(target.split("/")[2])]
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(data) + data)
                elif target.startswith("/nocontent"):
                    c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                elif target.startswith("/broken"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello")
                    return
                elif method == "HEAD":
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
                else:
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Back: yes\r\n"
                              b"Connection: keep-alive, x-secret\r\nX-Secret: hop\r\n\r\n%s" % (len(echo), echo))
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


class Client:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", LST), timeout=5)
        self.f = self.s.makefile("rb")

    def send(self, raw):
        self.s.sendall(raw)

    def response(self, head=False):
        m = read_message(self.f, head_only=head)
        if m is None:
            return None
        start, fields, body = m
        return int(start.split()[1]), dict((n.lower(), v) for n, v in fields), body

    def closed(self):
        self.s.settimeout(2)
        try:
            return self.s.recv(1) == b""
        except OSError:
            return True


def req(method, target, extra=b"", body=None, host=b"t"):
    head = b"%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, target, host) + extra
    if body is not None:
        head += b"Content-Length: %d\r\n" % len(body)
    return head + b"\r\n" + (body or b"")


def echo_of(r):
    return json.loads(r[2])


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


backend()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{
    workers 2
    io_engine {ENGINE}
}}
http 127.0.0.1:{LST} {{
    route /api/* {{ to 127.0.0.1:{BACK} }}
    route /api/exact {{ to 127.0.0.1:{BACK} }}
    route /only-get GET {{ to 127.0.0.1:{BACK} }}
    route /down/* {{ to 127.0.0.1:{DEAD} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
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

    c = Client()
    c.send(req(b"GET", b"/api/users?x=1", b"X-Forwarded-For: 6.6.6.6\r\nConnection: x-drop\r\nX-Drop: 1\r\n"
               b"Keep-Alive: 5\r\nTE: trailers\r\nAccept: */*\r\n"))
    r = c.response()
    e = echo_of(r)
    names = {n.lower(): v for n, v in e["fields"]}
    check("request reaches the backend with its target", r[0] == 200 and e["target"] == "/api/users?x=1")
    check("X-Forwarded-For is okena's, not the client's", names.get("x-forwarded-for") == "127.0.0.1", names.get("x-forwarded-for"))
    check("X-Forwarded-Proto set", names.get("x-forwarded-proto") == "http")
    check("hop-by-hop fields dropped (Connection, the fields it names, Keep-Alive, TE)",
          not ({"x-drop", "keep-alive", "te"} & set(names)) and names.get("connection") == "close")
    check("end-to-end fields kept (Host, Accept)", names.get("host") == "t" and names.get("accept") == "*/*")
    check("response hop-by-hop fields dropped, others kept",
          "x-secret" not in r[1] and r[1].get("x-back") == "yes" and "keep-alive" not in r[1].get("connection", ""))

    # keep-alive and pipelining on the same connection
    c.send(req(b"GET", b"/a") + req(b"GET", b"/api/b") + req(b"GET", b"/c"))
    got = [echo_of(c.response())["target"] for _ in range(3)]
    check("three pipelined requests, answered in order", got == ["/a", "/api/b", "/c"], str(got))

    # bodies
    body = os.urandom(3_000_000)
    c.send(req(b"POST", b"/api/upload", body=body))
    e = echo_of(c.response())
    check("3 MB Content-Length body intact", e["body_len"] == len(body) and e["body_sha"] == hashlib.sha256(body).hexdigest())
    chunks = b"".join(b"%x\r\n%s\r\n" % (n, body[i:i + n]) for i, n in [(0, 1), (1, 70000), (70001, 5)]) + b"0\r\n\r\n"
    c.send(b"POST /api/chunked-up HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks)
    e = echo_of(c.response())
    check("chunked request body decoded and framed again", e["body_len"] == 70006
          and e["body_sha"] == hashlib.sha256(body[:70006]).hexdigest())

    # response framings
    c.send(req(b"GET", b"/chunked"))
    r = c.response()
    check("chunked response re-framed for the client", r[1].get("transfer-encoding") == "chunked"
          and echo_of(r)["target"] == "/chunked")
    c.send(req(b"HEAD", b"/api/head"))
    r = c.response(head=True)
    check("HEAD: no body, length kept", r[0] == 200 and r[1].get("content-length") == "1234")
    c.send(req(b"GET", b"/nocontent"))
    r = c.response()
    check("204 without body", r[0] == 204 and r[2] == b"")
    c.send(req(b"GET", b"/big/5000000"))
    r = c.response()
    check("5 MB response intact", len(r[2]) == 5000000 and r[2][:16] == b"0123456789abcdef")
    c.send(req(b"GET", b"/close"))
    r = c.response()
    check("body until the backend closes, chunked to the client, connection kept",
          r[1].get("transfer-encoding") == "chunked" and echo_of(r)["target"] == "/close")
    c.send(req(b"GET", b"/api/after"))
    check("the connection still works after it", echo_of(c.response())["target"] == "/api/after")

    # routing
    c.send(req(b"GET", b"/api/exact"))
    check("exact route", echo_of(c.response())["target"] == "/api/exact")
    c.send(req(b"POST", b"/only-get", body=b"x"))
    r = c.response()
    check("method filter: POST /only-get falls back to /*", r[0] == 200)
    c.send(req(b"GET", b"/down/x"))
    r = c.response()
    check("backend down: 502", r[0] == 502 and c.closed())

    # Expect: 100-continue
    c = Client()
    c.send(b"POST /api/x HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
    c.s.settimeout(3)
    first = c.f.readline()
    c.f.readline()
    c.send(b"data")
    e = echo_of(c.response())
    check("Expect: 100-continue answered, then the body flows", first.startswith(b"HTTP/1.1 100") and e["body_len"] == 4)

    # refused requests
    for name, raw, code in [
        ("CL and TE together (smuggling)", b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
        ("no Host", b"GET / HTTP/1.1\r\n\r\n", 400),
        ("bare LF", b"GET / HTTP/1.1\nHost: t\r\n\r\n", 400),
        ("HTTP/2.0 request line", b"GET / HTTP/2.0\r\nHost: t\r\n\r\n", 505),
    ]:
        c = Client()
        c.send(raw)
        r = c.response()
        check(f"refused: {name} -> {code}", r is not None and r[0] == code and c.closed(), str(r and r[0]))
    c = Client()
    c.send(b"GET / HTTP/1.1\r\nHost: t\r\nX: " + b"a" * 20000 + b"\r\n\r\n")
    r = c.response()
    check("head too large -> 431", r is not None and r[0] == 431)
    c = Client()
    c.send(req(b"GET", b"/broken"))
    r = c.response()
    check("malformed response -> 502", r is not None and r[0] == 502)
    c = Client()
    c.send(b"GET /api/v10 HTTP/1.0\r\n\r\n")
    r = c.response()
    check("HTTP/1.0 client: answered, then closed", r[0] == 200 and r[1].get("connection") == "close" and c.closed())

    log.seek(0)
    check("no crash", "killed by signal" not in log.read() and p.poll() is None)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"httpproxy ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
