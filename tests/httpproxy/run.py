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
BASE = 26000 + os.getpid() % 99 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, DEAD, QUICK, MET, BAD, BAD2, TRUST = (BASE + i for i in range(8))


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


BACKEND_CONNS = []


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(512)

    def handle(c):
        f = c.makefile("rb")
        BACKEND_CONNS.append(1)
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
                lower = {n.lower(): v for n, v in fields}
                if target.startswith("/ws") and lower.get("upgrade") == "websocket":
                    hdr = json.dumps({"upgrade": lower.get("upgrade"),
                                      "connection": lower.get("connection")}).encode()
                    # 101, then bytes of the new protocol right behind it
                    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                              b"Connection: Upgrade\r\nX-Seen: %s\r\n\r\nHELLO" % hdr.hex().encode())
                    while True:
                        data = f.read1(65536)
                        if not data:
                            return
                        c.sendall(data.upper())
                if target.startswith("/slow"):
                    time.sleep(3)
                if target.startswith("/hints"):
                    c.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n"
                              b"Link: </app.css>; rel=preload\r\nConnection: x-hop\r\nX-Hop: 1\r\n\r\n")
                    time.sleep(0.05)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    continue
                if target.startswith("/surprise101"):
                    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                    return
                if target.startswith("/chunked"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    for i in range(0, len(echo), 7):
                        piece = echo[i:i + 7]
                        c.sendall(b"%x;ext=1\r\n%s\r\n" % (len(piece), piece))
                    c.sendall(b"0\r\nX-Trailer: 1\r\n\r\n")
                elif target.startswith("/drop-after"):
                    # keep-alive claimed, then the connection is dropped: the
                    # next request on it must be sent again on a new one
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(echo) + echo)
                    time.sleep(0.05)
                    return
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


BAD_HITS = {BAD: 0, BAD2: 0}


def failing_backend(port):
    """Answers every request with 503, keep-alive; counts them."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)

    def handle(c):
        f = c.makefile("rb")
        try:
            while read_message(f) is not None:
                BAD_HITS[port] += 1
                c.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy")
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
    def __init__(self, port=None):
        try:
            self.s = socket.create_connection(("127.0.0.1", port or LST), timeout=5)
        except OSError:
            # what the kernel holds for that port when a connect fails
            port = port or LST
            print(subprocess.run(["ss", "-tanoi", f"( sport = :{port} or dport = :{port} )"],
                                 capture_output=True, text=True).stdout)
            print(subprocess.run(["ss", "-ltn", f"sport = :{port}"], capture_output=True, text=True).stdout)
            raise
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


check_lock = threading.Lock()


def check(name, ok, detail=""):
    global failures
    with check_lock:
        print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
        failures += not ok


def background(fn):
    """Run a group of checks in a thread; an exception in it is a failure."""
    def run():
        try:
            fn()
        except Exception as e:
            check(f"{fn.__name__} raised", False, repr(e))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


backend()
failing_backend(BAD)
failing_backend(BAD2)
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{
    workers 2
    io_engine {ENGINE}
    metrics 127.0.0.1:{MET}
    drain delay=0s timeout=1s
}}
http 127.0.0.1:{LST} {{
    access_log {tmp}/access.log
    route /api/* {{ to 127.0.0.1:{BACK} }}
    route /api/exact {{ to 127.0.0.1:{BACK} }}
    route /only-get GET {{ to 127.0.0.1:{BACK} }}
    route /down/* {{ to 127.0.0.1:{DEAD} }}
    route /bad/* {{ to 127.0.0.1:{BAD} }}
    route /deep/* {{ to 127.0.0.1:{BACK} }}
    route /old/* {{ redirect 301 /new/{{*}} }}
    route /v1/* {{
        rewrite path /v1/{{*}} -> /api/v2/{{*}}
        to 127.0.0.1:{BACK}
    }}
    route /exact-old {{ redirect 308 https://example.com/x }}
    route /hdr/* {{
        header set x-env prod
        header add x-added yes
        header drop x-secret-*
        response header set cache-control no-store
        response header drop x-back
        to 127.0.0.1:{BACK}
    }}
    route /deep/a/b/* {{ to 127.0.0.1:{BACK} }}
    route /deep/a/* {{ to 127.0.0.1:{DEAD} }}
    route /deep/a/b/c GET {{ to 127.0.0.1:{DEAD} }}
    route /retry/* {{ to pool flaky }}
    route /* {{ to 127.0.0.1:{BACK} }}
    host api.t {{ route /* {{ to 127.0.0.1:{DEAD} }} }}
    host *.w.t {{ route /only-wild {{ to 127.0.0.1:{BACK} }} }}
}}
pool flaky {{
    server 127.0.0.1:{BAD2}
    server 127.0.0.1:{BACK}
}}
http 127.0.0.1:{TRUST} {{
    trusted_proxies 127.0.0.0/8 10.0.0.0/8
    access_log {tmp}/access.log
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{QUICK} {{
    timeout {{ header 1s; response 1s; body_idle 1s }}
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
          not ({"x-drop", "keep-alive", "te", "connection"} & set(names)))
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

    # upstream keep-alive: many requests, few backend connections
    before = len(BACKEND_CONNS)
    for i in range(50):
        c.send(req(b"GET", b"/api/reuse/%d" % i))
        assert echo_of(c.response())["target"] == "/api/reuse/%d" % i
    check("upstream connections reused (pool)", len(BACKEND_CONNS) - before <= 4, f"{len(BACKEND_CONNS) - before} new for 50 requests")
    # the backend drops an idle pooled connection: the next request is sent again
    c.send(req(b"GET", b"/drop-after"))
    c.response()
    time.sleep(0.2)
    ok = True
    for i in range(6):
        c.send(req(b"GET", b"/api/after-drop/%d" % i))
        r = c.response()
        ok = ok and r[0] == 200 and echo_of(r)["target"] == "/api/after-drop/%d" % i
    check("a pooled connection the backend closed: request resent, no error", ok)
    # watched while idle: once the backend closes it, it leaves the pool, so
    # even a request with a body (never sent twice) does not meet it
    for i in range(4):
        c2 = Client()
        c2.send(req(b"GET", b"/drop-after"))
        c2.response()
        c2.s.close()
    time.sleep(0.3)
    bodies_ok = 0
    for i in range(8):
        c2 = Client()
        c2.send(req(b"POST", b"/api/with-body", body=b"payload"))
        r = c2.response()
        bodies_ok += r is not None and r[0] == 200
        c2.s.close()
    check("idle pooled connections closed by the backend are dropped before reuse", bodies_ok == 8, f"{bodies_ok}/8")

    # routing
    c.send(req(b"GET", b"/api/exact"))
    check("exact route", echo_of(c.response())["target"] == "/api/exact")
    c.send(req(b"POST", b"/only-get", body=b"x"))
    r = c.response()
    check("method filter: POST /only-get falls back to /*", r is not None and r[0] == 200, str(r and r[:2]))
    c.send(req(b"GET", b"/down/x"))
    r = c.response()
    check("backend down: 502", r[0] == 502 and c.closed())

    # host blocks
    def status(host, target):
        c3 = Client()
        c3.send(req(b"GET", target, host=host))
        r3 = c3.response()
        c3.s.close()
        return r3 and r3[0]
    check("host block chosen by exact name", status(b"api.t", b"/x") == 502)
    check("host match ignores case, port and a trailing dot", status(b"API.T.:8080", b"/x") == 502)
    check("wildcard host, one and several labels", status(b"a.w.t", b"/only-wild") == 200
          and status(b"b.a.w.t", b"/only-wild") == 200)
    check("a host block does not fall back to the listener's routes", status(b"a.w.t", b"/other") == 404)
    check("the wildcard does not match the bare domain", status(b"w.t", b"/other") == 200)
    check("other hosts use the listener's routes", status(b"elsewhere", b"/x") == 200)

    # paths are matched normalized: /down/* goes to the dead backend (502)
    for target, code, why in [
        (b"/%64own/x", 502, "an encoded unreserved character is decoded for matching"),
        (b"//down/x", 502, "a doubled slash is one"),
        (b"/api/../down/x", 400, "a dot-dot segment is refused"),
        (b"/api/%2e%2E/down/x", 400, "an encoded dot-dot segment is refused"),
        (b"/api/x/.", 400, "a trailing dot segment is refused"),
        (b"/api/%2Fdown", 400, "an encoded slash is refused"),
        (b"/api/%5Cdown", 400, "an encoded backslash is refused"),
        (b"/api/.well-known", 200, "a dot in a name is fine"),
    ]:
        c = Client()
        c.send(req(b"GET", target))
        r = c.response()
        check(f"path {target.decode()}: {why} -> {code}", r is not None and r[0] == code, str(r and r[0]))
    # route lookup: exact first (with its methods), then the longest prefix
    for method, target, code, why in [
        (b"GET", b"/deep/a/b/c", 502, "an exact route beats every prefix"),
        (b"POST", b"/deep/a/b/c", 200, "another method falls to the longest prefix"),
        (b"GET", b"/deep/a/b/c/d", 200, "the longest of nested prefixes"),
        (b"GET", b"/deep/a/x", 502, "a middle prefix"),
        (b"GET", b"/deep/a", 200, "no trailing slash: not /deep/a/*"),
        (b"GET", b"/deep/zz", 200, "the shortest prefix"),
    ]:
        c = Client()
        c.send(req(method, target, body=b"" if method == b"POST" else None))
        r = c.response()
        check(f"route {method.decode()} {target.decode()}: {why}", r is not None and r[0] == code, str(r and r[0]))
    # rewrite path: the backend gets the new path, the query kept
    c = Client()
    c.send(req(b"GET", b"/v1/users/42?full=1"))
    e = echo_of(c.response())
    check("rewrite path: /v1/{*} -> /api/v2/{*}, query kept", e["target"] == "/api/v2/users/42?full=1", e["target"])
    c.send(req(b"GET", b"/v1//users"))
    e = echo_of(c.response())
    check("rewrite applies to the normalized path", e["target"] == "/api/v2/users", e["target"])

    # route actions: redirects answered by okena, header changes
    c = Client()
    c.send(req(b"GET", b"/old/a/b?q=1&r=2"))
    r = c.response()
    check("redirect: {*} and the query carried into Location", r is not None and r[0] == 301
          and r[1].get("location") == "/new/a/b?q=1&r=2" and r[1].get("content-length") == "0"
          and "connection" not in r[1], str(r and r[:2]))
    c.send(req(b"GET", b"/api/after-redirect"))
    r = c.response()
    check("and the connection goes on", r is not None and r[0] == 200)
    c.send(req(b"GET", b"/exact-old?z=1"))
    r = c.response()
    check("redirect of an exact route to a URL", r is not None and r[0] == 308
          and r[1].get("location") == "https://example.com/x?z=1", str(r and r[:2]))
    c = Client()
    c.send(req(b"POST", b"/old/x", body=b"unread"))
    r = c.response()
    check("a redirected request with a body: answered, then closed", r is not None and r[0] == 301
          and r[1].get("connection") == "close" and c.closed(), str(r and r[:2]))
    c = Client()
    c.send(req(b"GET", b"/hdr/x", b"X-Env: dev\r\nX-Added: client\r\nX-Secret-Token: s\r\nX-Secret-Other: t\r\nX-Kept: k\r\n"))
    r = c.response()
    e = echo_of(r)
    sent = [(n.lower(), v) for n, v in e["fields"]]
    check("header set replaces the client's value", [v for n, v in sent if n == "x-env"] == ["prod"], str(sent))
    check("header add keeps it and adds", sorted(v for n, v in sent if n == "x-added") == ["client", "yes"], str(sent))
    check("header drop with a prefix removes every match", not any(n.startswith("x-secret-") for n, _ in sent)
          and ("x-kept", "k") in sent, str(sent))
    check("response header set and drop", r[1].get("cache-control") == "no-store" and "x-back" not in r[1], str(r[1]))

    c = Client()
    c.send(req(b"TRACE", b"/api/x"))
    r = c.response()
    check("TRACE -> 405", r is not None and r[0] == 405)
    c = Client()
    c.send(req(b"GET", b"/ws", b"Upgrade: websocket\r\nConnection: Upgrade\r\n", body=b"xx"))
    r = c.response()
    check("an upgrade with a body -> 400", r is not None and r[0] == 400, str(r and r[0]))

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

    # upgrades: after the 101 the connection is a byte tunnel
    c = Client()
    c.send(req(b"GET", b"/ws", b"Upgrade: websocket\r\nConnection: Upgrade\r\n") + b"early")
    r = c.response(head=True)
    seen = json.loads(bytes.fromhex(r[1].get("x-seen", "")))
    check("101 forwarded with Upgrade and Connection", r[0] == 101 and r[1].get("upgrade") == "websocket"
          and r[1].get("connection", "").lower() == "upgrade", str(r[:2]))
    check("backend saw Upgrade: websocket and Connection: upgrade",
          seen == {"upgrade": "websocket", "connection": "upgrade"}, str(seen))
    got = b""
    c.s.settimeout(3)
    while len(got) < 10:
        got += c.f.read1(100)
    check("bytes sent with the 101 and with the request both cross", got == b"HELLOEARLY", repr(got))
    big = os.urandom(3 << 20).hex().encode()[:3 << 20].lower()
    threading.Thread(target=c.s.sendall, args=(big,), daemon=True).start()
    got = b""
    while len(got) < len(big):
        piece = c.f.read1(1 << 20)
        if not piece:
            break
        got += piece
    check("3 MB both ways through the tunnel", got == big.upper())
    c.s.shutdown(socket.SHUT_WR)
    check("client end closes the tunnel", c.f.read1(10) == b"")
    c = Client()
    c.send(req(b"GET", b"/ws", b"Upgrade: h2c\r\nConnection: Upgrade\r\n"))
    r = c.response()
    check("upgrade refused by the backend: a normal response", r is not None and r[0] == 200, str(r and r[0]))
    c.send(req(b"GET", b"/api/after"))
    r = c.response()
    check("and the connection keeps serving requests", r is not None and echo_of(r)["target"] == "/api/after")
    c = Client()
    c.send(req(b"GET", b"/surprise101"))
    r = c.response()
    check("101 nobody asked for -> 502", r is not None and r[0] == 502, str(r and r[0]))

    # phase timeouts (the QUICK listener: header 1s, response 1s, body_idle
    # 1s). Each waits on its own clock, on its own connection: they run in
    # threads, alongside the rest of the suite, and are joined before the
    # metrics that count their answers. Same assertions, same bounds.
    def slow_head():
        c = Client(QUICK)
        t0 = time.time()
        c.send(b"GET /api/x HTTP/1.1\r\nHost: t\r\n")        # and never the end of it
        r = c.response()
        check("slow request head -> 408 and close", r is not None and r[0] == 408 and c.closed()
              and time.time() - t0 < 4, str(r and r[0]))

    def silent():
        c = Client(QUICK)
        t0 = time.time()
        c.s.settimeout(4)
        try:
            quiet = c.s.recv(1) == b""
        except OSError:
            quiet = False
        check("connected and silent: closed without a word", quiet and time.time() - t0 < 3.5, f"{time.time() - t0:.1f}s")

    def keepalive_then_504():
        c = Client(QUICK)
        c.send(b"GET /api/x HTTP/1.1\r\nHo")
        time.sleep(0.5)
        c.send(b"st: t\r\n\r\n")
        r = c.response()
        check("a head that arrives in pieces in time is served", r is not None and r[0] == 200)
        time.sleep(2.5)                     # idle keep-alive: not the header clock
        c.send(req(b"GET", b"/api/again"))
        r = c.response()
        check("an idle keep-alive connection is not cut by the header clock",
              r is not None and r[0] == 200, str(r and r[0]))
        t0 = time.time()
        c.send(req(b"GET", b"/slow"))
        r = c.response()
        check("slow backend -> 504 and close", r is not None and r[0] == 504 and c.closed()
              and time.time() - t0 < 3, str(r and r[0]))
        c = Client(QUICK)
        c.send(req(b"GET", b"/api/after-504"))
        r = c.response()
        check("then the listener keeps serving", r is not None and r[0] == 200)

    def body_stops():
        c = Client(QUICK)
        t0 = time.time()
        c.send(b"POST /api/up HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nabc")   # and then nothing
        r = c.response()
        check("a request body that stops coming -> 408", r is not None and r[0] == 408 and time.time() - t0 < 4,
              f"{r and r[0]} {time.time() - t0:.1f}s")

    def body_slow():
        c = Client(QUICK)
        c.send(b"POST /api/up HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\n\r\n")
        for ch in b"slowly":
            time.sleep(0.5)
            c.send(bytes([ch]))
        r = c.response()
        check("a slow body that keeps coming is fine (each byte restarts the clock)",
              r is not None and r[0] == 200 and echo_of(r)["body_len"] == 6, str(r and r[0]))

    def default_clock():
        c = Client()
        c.send(req(b"GET", b"/slow"))
        r = c.response()
        check("the default response clock (30 s) lets a 3 s backend answer", r is not None and r[0] == 200)

    timed = [background(f) for f in (slow_head, silent, keepalive_then_504, body_stops, body_slow, default_clock)]

    # trusted_proxies (the peer, 127.0.0.1, is trusted on TRUST)
    def via_trust(target, extra):
        c3 = Client(TRUST)
        c3.send(req(b"GET", target, extra))
        r3 = c3.response()
        c3.s.close()
        e3 = echo_of(r3)
        return {n.lower(): v for n, v in e3["fields"]}, [v for n, v in e3["fields"] if n.lower() == "x-forwarded-for"]
    names, xff = via_trust(b"/t/chain", b"X-Forwarded-For: 203.0.113.7, 10.1.2.3\r\nX-Forwarded-Proto: https\r\n")
    check("trusted peer: X-Forwarded-For extended, not replaced",
          xff == ["203.0.113.7, 10.1.2.3, 127.0.0.1"], str(xff))
    check("trusted peer: its X-Forwarded-Proto stands", names.get("x-forwarded-proto") == "https")
    names, xff = via_trust(b"/t/two", b"X-Forwarded-For: 192.0.2.1\r\nAccept: */*\r\nX-Forwarded-For: 10.0.0.9\r\n")
    check("several X-Forwarded-For lines merge in order", xff == ["192.0.2.1, 10.0.0.9, 127.0.0.1"], str(xff))
    names, xff = via_trust(b"/t/none", b"")
    check("trusted peer without X-Forwarded-For: just the peer, proto http",
          xff == ["127.0.0.1"] and names.get("x-forwarded-proto") == "http", f"{xff} {names.get('x-forwarded-proto')}")
    via_trust(b"/t/spoof", b"X-Forwarded-For: 1.1.1.1, 198.51.100.9\r\n")
    via_trust(b"/t/garbage", b"X-Forwarded-For: 198.51.100.1, unknown\r\n")
    via_trust(b"/t/v6", b"X-Forwarded-For: [2001:db8::5]:443, 10.0.0.1:8080\r\n")
    c = Client()
    c.send(req(b"GET", b"/api/spoofed", b"X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-Proto: https\r\n"))
    e = echo_of(c.response())
    names = {n.lower(): v for n, v in e["fields"]}
    check("without trusted_proxies the client's claims are dropped",
          names.get("x-forwarded-for") == "127.0.0.1" and names.get("x-forwarded-proto") == "http", str(names))

    # 1xx: 103 Early Hints passed on, 100 from the backend dropped
    c = Client()
    c.send(req(b"GET", b"/hints"))
    first = c.response(head=True)
    final = c.response()
    check("103 Early Hints forwarded before the final response", first is not None and first[0] == 103
          and first[1].get("link") == "</app.css>; rel=preload" and "x-hop" not in first[1]
          and final is not None and final[0] == 200 and final[2] == b"ok", f"{first} {final}")
    c.send(req(b"GET", b"/api/after-hints"))
    r = c.response()
    check("and the connection goes on", r is not None and r[0] == 200)
    c = Client()
    c.send(b"GET /hints HTTP/1.0\r\n\r\n")
    r = c.response()
    check("an HTTP/1.0 client gets no 1xx", r is not None and r[0] == 200 and r[2] == b"ok", str(r))

    # request ids
    import re
    c = Client()
    c.send(req(b"GET", b"/api/rid", b"X-Request-Id: spoofed-by-client\r\n"))
    e = echo_of(c.response())
    rid = [v for n, v in e["fields"] if n.lower() == "x-request-id"]
    check("a request id is added (the client's is not believed)", len(rid) == 1 and re.fullmatch(r"[0-9a-f]{16}", rid[0]) is not None, str(rid))
    RID = rid[0] if rid else ""
    c.send(req(b"GET", b"/api/rid2"))
    rid2 = [v for n, v in echo_of(c.response())["fields"] if n.lower() == "x-request-id"]
    check("each request gets its own id", rid2 and rid2[0] != RID)
    names, _ = via_trust(b"/t/rid", b"X-Request-Id: edge-42.a:b_c\r\n")
    check("a trusted proxy's request id is kept", names.get("x-request-id") == "edge-42.a:b_c", str(names.get("x-request-id")))
    names, _ = via_trust(b"/t/rid-bad", b"X-Request-Id: has space\r\n")
    check("an invalid one is replaced", re.fullmatch(r"[0-9a-f]{16}", names.get("x-request-id", "")) is not None)
    c = Client()
    c.send(req(b"GET", b"/nothing-here", host=b"api.t"))
    r = c.response()
    check("okena's errors carry the request id", r is not None and re.fullmatch(r"[0-9a-f]{16}", r[1].get("x-request-id", "")) is not None
          and b"request id: " + r[1].get("x-request-id", "").encode() in r[2], str(r and (r[1], r[2])))

    # retries and outliers
    c = Client()
    c.send(req(b"GET", b"/bad/x"))
    r = c.response()
    check("GET to a failing backend: retried once, then its 503", r is not None and r[0] == 503
          and BAD_HITS[BAD] == 2, f"{r and r[0]} hits={BAD_HITS[BAD]}")
    c.send(req(b"POST", b"/bad/x", body=b"once"))
    r = c.response()
    check("a request with a body is never sent twice", r is not None and r[0] == 503
          and BAD_HITS[BAD] == 3, f"{r and r[0]} hits={BAD_HITS[BAD]}")
    # every worker ejects on its own (per-worker outlier detection), after
    # 5 failing answers in a row from what it sends there: GETs until both
    # have, each of them still answered 200 (retried elsewhere)
    codes = []
    ejected = lambda: all(f"worker {w}: backend 127.0.0.1:{BAD2} ejected for 10 s after 5 failing answers"
                          in (log.seek(0) or log.read()) for w in (0, 1))
    t0 = time.time()
    while not ejected() and time.time() - t0 < 10:
        for i in range(10):
            c = Client()
            c.send(req(b"GET", b"/retry/%d" % i))
            r = c.response()
            codes.append(r and r[0])
            c.s.close()
    check("GETs to a pool with a failing server all succeed (retried elsewhere)",
          codes and all(x == 200 for x in codes) and BAD_HITS[BAD2] > 0,
          f"{len(codes)} requests, {sorted(set(codes), key=str)} hits={BAD_HITS[BAD2]}")
    check("the failing server is ejected after 5 failing answers (by every worker)", ejected())
    before = BAD_HITS[BAD2]
    codes = []
    for i in range(10):
        c = Client()
        c.send(req(b"POST", b"/retry/p", body=b"x"))
        r = c.response()
        codes.append(r and r[0])
        c.s.close()
    check("while ejected it gets no traffic (POSTs, not retried, all succeed)",
          codes == [200] * 10 and BAD_HITS[BAD2] == before, f"{codes} {before}->{BAD_HITS[BAD2]}")

    for t in timed:
        t.join()

    # metrics: what the QUICK listener answered above, by class and source
    time.sleep(1.2)                     # workers publish once a second
    m = socket.create_connection(("127.0.0.1", MET), timeout=5)
    m.sendall(b"GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
    text = b""
    while chunk := m.recv(65536):
        text += chunk
    vals = {}
    for line in text.decode().splitlines():
        if line.startswith("okena_http_responses_total{") and f':{QUICK}"' in line:
            k, v = line.rsplit(" ", 1)
            vals[k.split(",", 1)[1]] = int(v)
    check("metrics: backend 2xx counted", vals.get('code="2xx",source="backend"}') == 4, str(vals))
    check("metrics: okena's 408s and 504 counted as its own 4xx and 5xx",
          vals.get('code="4xx",source="okena"}') == 2 and vals.get('code="5xx",source="okena"}') == 1)
    check("metrics: no backend 5xx", vals.get('code="5xx",source="backend"}') == 0)
    trimmed = [int(l.rsplit(" ", 1)[1]) for l in text.decode().splitlines()
               if l.startswith("okena_http_idle_trimmed_total ")]
    check("idle keep-alive connections give their buffers back (and keep working)",
          trimmed and trimmed[0] >= 1, str(trimmed))
    retries = [int(l.rsplit(" ", 1)[1]) for l in text.decode().splitlines()
               if l.startswith("okena_http_retries_total{") and f':{LST}"' in l]
    check("metrics: retries counted", retries and retries[0] >= 1, str(retries))

    log.seek(0)
    check("no crash", "killed by signal" not in log.read() and p.poll() is None)

    # access log: rotation (SIGUSR1 reopens), then a last request just
    # before shutdown must still be written
    time.sleep(1.2)
    os.rename(tmp / "access.log", tmp / "access.log.1")
    p.send_signal(signal.SIGUSR1)
    time.sleep(0.5)
    c = Client()
    c.send(req(b"GET", b"/api/last-words"))
    r = c.response()
    p.send_signal(signal.SIGTERM)
    p.wait(10)
    old = (tmp / "access.log.1").read_text().splitlines()
    new = (tmp / "access.log").read_text().splitlines() if (tmp / "access.log").exists() else []
    try:
        lines = [json.loads(l) for l in old + new]
        parsed = True
    except ValueError as e:
        lines, parsed = [], False
    check("access log: every line is JSON", parsed and len(lines) > 20, f"{len(old)}+{len(new)} lines")
    by_target = {l["target"]: l for l in lines}
    first = by_target.get("/api/users?x=1", {})
    check("access log: an exchange with its fields", first.get("method") == "GET" and first.get("status") == 200
          and first.get("host") == "t" and first.get("client") == "127.0.0.1"
          and first.get("upstream") == f"127.0.0.1:{BACK}" and first.get("source") == "backend"
          and first.get("bytes", 0) > 100 and first.get("time", "").endswith("Z"), str(first))
    down = by_target.get("/down/x", {})
    check("access log: okena's own answer", down.get("status") == 502 and down.get("source") == "okena"
          and down.get("upstream") is None, str(down))
    bad = next((l for l in lines if l["target"] == "/bad/x" and l["method"] == "GET"), {})
    check("access log: a retried request is marked", bad.get("retried") is True, str(bad))
    red = by_target.get("/old/a/b?q=1&r=2", {})
    check("access log: a redirect is okena's own answer", red.get("status") == 301 and red.get("source") == "okena"
          and red.get("upstream") is None, str(red))
    check("access log: the request id the backend saw", by_target.get("/api/rid", {}).get("request_id") == RID,
          str(by_target.get("/api/rid", {}).get("request_id")))
    check("access log: SIGUSR1 reopens the file (logrotate)",
          any(json.loads(l)["target"] == "/api/last-words" for l in new), f"{len(new)} new lines")
    check("access log: the last request before shutdown is written",
          "/api/last-words" in by_target)
    import ipaddress
    def client_of(t):
        line = by_target.get(t, {})
        return line.get("client") and str(ipaddress.ip_address(line["client"])), line.get("peer")
    check("access log: client = rightmost untrusted hop", client_of("/t/chain") == ("203.0.113.7", "127.0.0.1"),
          str(client_of("/t/chain")))
    check("access log: a spoofed leftmost entry is not the client", client_of("/t/spoof")[0] == "198.51.100.9")
    check("access log: a non-address entry stops at the last trusted hop",
          client_of("/t/garbage")[0] == "127.0.0.1", str(client_of("/t/garbage")))
    check("access log: [v6]:port and v4:port entries", client_of("/t/v6")[0] == "2001:db8::5",
          str(client_of("/t/v6")))
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
