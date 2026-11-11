#!/usr/bin/env python3
"""What backends send that they should not, through okena, on one engine
(argument): malformed status lines and fields (502, the connection to the backend
closed), framing that disagrees (Content-Length and Transfer-Encoding, repeated
lengths, a body past its length, a 204 or 304 with one), bodies cut short (the
client sees them cut), a close-delimited body (chunked to the client), 1xx before
the answer, a 101 nobody asked for, hop-by-hop fields, Set-Cookie never folded, a
backend that never answers (504). And bytes a backend sends after its answer, late:
the connection is never used again for another request."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 28000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, B2, L = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


R = {
 "ok": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
 "bad status line": b"HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\nok",
 "garbage": b"hello world\r\n\r\n",
 "bad header name": b"HTTP/1.1 200 OK\r\nX Y: 1\r\nContent-Length: 2\r\n\r\nok",
 "obs-fold": b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 2\r\n\r\nok",
 "obs-text value": b"HTTP/1.1 200 OK\r\nX: caf\xe9\r\nContent-Length: 2\r\n\r\nok",
 "no reason": b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok",
 "empty reason": b"HTTP/1.1 200 \r\nContent-Length: 2\r\n\r\nok",
 "HTTP/1.0 close": b"HTTP/1.0 200 OK\r\n\r\nclose-delimited",
 "no length close": b"HTTP/1.1 200 OK\r\n\r\nuntil close",
 "TE+CL": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
 "dup CL differ": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
 "CL short (extra)": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA",
 "CL long (cut)": b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nok",
 "bad chunk": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n",
 "chunk cut": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nok",
 "TE gzip,chunked": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
 "204 with body": b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\nok",
 "304 with CL": b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n",
 "1xx x3": b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
 "101 unasked": b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
 "status 999": b"HTTP/1.1 999 Odd\r\nContent-Length: 2\r\n\r\nok",
 "status 099": b"HTTP/1.1 099 Odd\r\nContent-Length: 2\r\n\r\nok",
 "hop headers": b"HTTP/1.1 200 OK\r\nConnection: X-Secret, keep-alive\r\nX-Secret: s\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: x\r\nUpgrade: h2c\r\nTrailer: X\r\nContent-Length: 2\r\n\r\nok",
 "set-cookie x2": b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok",
 "huge headers": b"HTTP/1.1 200 OK\r\nX: " + b"a" * 70000 + b"\r\nContent-Length: 2\r\n\r\nok",
 "close no bytes": b"",
 "bare LF": b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
 "HTTP/2.0 status": b"HTTP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
 "trailers": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n\r\n",
 "space before colon": b"HTTP/1.1 200 OK\r\nX : 1\r\nContent-Length: 2\r\n\r\nok",
 "CL + spaces": b"HTTP/1.1 200 OK\r\nContent-Length:  2 \r\n\r\nok",
 "slow (timeout)": None,
}
CLOSING = ("HTTP/1.0 close", "no length close", "CL long (cut)", "chunk cut", "close no bytes", "101 unasked")


def serve(c):
    c.settimeout(5)
    d = b""
    try:
        while b"\r\n\r\n" not in d:
            x = c.recv(65536)
            if not x:
                return
            d += x
        name = urllib.parse.unquote(d.split(b" ")[1].decode()[3:])
        r = R.get(name)
        if r is None:
            time.sleep(4)
            return
        c.sendall(r)
        if name in CLOSING:
            c.shutdown(socket.SHUT_WR)
        time.sleep(0.2)
    except OSError:
        pass
    finally:
        c.close()


def listen(port, fn):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=fn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


# a backend that keeps its connections, and writes a little more after some answers
LATE = {
    "/extra": (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nEVIL!!"),
    "/204body": (b"HTTP/1.1 204 No Content\r\nContent-Length: 6\r\n\r\n", b"EVIL!!"),
    "/304body": (b"HTTP/1.1 304 Not Modified\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nEVIL!!"),
    "/headbody": (b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", b"EVIL!!"),
    "/ok": (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood", b""),
}


def keep(c):
    d = b""
    try:
        while True:
            x = c.recv(65536)
            if not x:
                return
            d += x
            while b"\r\n\r\n" in d:
                h, _, d = d.partition(b"\r\n\r\n")
                first, late = LATE[h.split(b" ")[1].decode()]
                c.sendall(first)
                if late:
                    time.sleep(0.05)
                    c.sendall(late)
    except OSError:
        pass


def fetch(port, raw, wait=3):
    k = socket.create_connection(("127.0.0.1", port))
    k.settimeout(wait)
    k.sendall(raw)
    out, end = b"", "open"
    try:
        while True:
            x = k.recv(65536)
            if not x:
                end = "closed"
                break
            out += x
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "reset"
    k.close()
    return out, end


def heads(out):
    """[(status, {name: [values]}, rest)] for each response head in out"""
    res = []
    while out.startswith(b"HTTP/1."):
        head, _, out = out.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        f = {}
        for x in lines[1:]:
            n, _, v = x.partition(b":")
            f.setdefault(n.strip().lower().decode(), []).append(v.strip())
        res.append((int(lines[0].split(b" ")[1]), f))
        if res[-1][0] >= 200:
            break
    return res, out


def main():
    listen(B, serve)
    listen(B2, keep)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-upstream-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{B} }}
pool k {{ server 127.0.0.1:{B2} }}
http 127.0.0.1:{L} {{
    timeout {{ response 1s }}
    route /c/* {{ to pool b }}
    route /* {{ to pool k }}
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
        got = {}

        def one(name):
            got[name] = fetch(L, b"GET /c/" + urllib.parse.quote(name).encode() + b" HTTP/1.1\r\nHost: a\r\n\r\n",
                              wait=0.6 if name not in ("slow (timeout)",) else 3)
        ts = [threading.Thread(target=one, args=(n,)) for n in R]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        def res(name):
            out, end = got[name]
            hs, body = heads(out)
            return [h[0] for h in hs], (hs[-1][1] if hs else {}), body, end

        for name in ("bad status line", "garbage", "bad header name", "obs-fold", "TE+CL", "dup CL differ",
                     "TE gzip,chunked", "101 unasked", "status 099", "huge headers", "close no bytes", "bare LF",
                     "HTTP/2.0 status", "space before colon"):
            st, f, body, end = res(name)
            check(f"{name}: 502, closed", st == [502] and end == "closed", (st, end, body[:40]))
        st, f, body, end = res("slow (timeout)")
        check("a backend that never answers: 504", st == [504], (st, end))
        for name in ("ok", "no reason", "empty reason", "CL + spaces", "status 999"):
            st, f, body, end = res(name)
            check(f"{name}: forwarded", st and st[-1] in (200, 999) and body == b"ok" and end == "open", (st, body, end))
        st, f, body, end = res("obs-text value")
        check("obs-text in a value: kept as it came", st == [200] and f.get("x") == [b"caf\xe9"], (st, f))
        for name, text in (("HTTP/1.0 close", b"close-delimited"), ("no length close", b"until close")):
            st, f, body, end = res(name)
            check(f"{name}: delimited by the close, chunked to the client (kept)",
                  st == [200] and f.get("transfer-encoding") == [b"chunked"] and body == b"%x\r\n%s\r\n0\r\n\r\n" % (len(text), text)
                  and end == "open", (st, f, body, end))
        st, f, body, end = res("CL short (extra)")
        check("a body past its length: the length's worth only", st == [200] and body == b"ok", (st, body))
        for name in ("CL long (cut)", "bad chunk", "chunk cut"):
            st, f, body, end = res(name)
            cut = (len(body) < int(f["content-length"][0]) if "content-length" in f else not body.endswith(b"0\r\n\r\n"))
            check(f"{name}: the client sees it cut (closed before its end)", st == [200] and end in ("closed", "reset") and cut,
                  (st, f, body, end))
        for name in ("204 with body", "304 with CL"):
            st, f, body, end = res(name)
            check(f"{name}: no body to the client", st and st[-1] in (204, 304) and body == b"", (st, body))
        st, f, body, end = res("1xx x3")
        check("several 1xx: 102 and 103 (its Link) go on, 100 not asked for does not, then the answer",
              st == [102, 103, 200] and body == b"ok", (st, body))
        st, f, body, end = res("hop headers")
        check("hop-by-hop fields from the backend, and those its Connection names, dropped",
              st == [200] and not {"connection", "x-secret", "keep-alive", "proxy-authenticate", "upgrade", "trailer"} & set(f), f)
        st, f, body, end = res("set-cookie x2")
        check("two Set-Cookie: two fields, never folded",
              f.get("set-cookie") == [b"a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", b"b=2"], f.get("set-cookie"))
        st, f, body, end = res("trailers")
        check("trailers to an HTTP/1.1 client: carried", body == b"2\r\nok\r\n0\r\nX-T: 1\r\n\r\n", body)

        # bytes after an answer, a little late: never read as the next request's
        for first, method in (("/extra", "GET"), ("/204body", "GET"), ("/304body", "GET"), ("/headbody", "HEAD")):
            a, _ = fetch(L, f"{method} {first} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n".encode(), wait=1)
            time.sleep(0.12)
            b, _ = fetch(L, b"GET /ok HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", wait=1)
            check(f"{first} with bytes after it: the next request gets its own answer", b.endswith(b"\r\n\r\ngood")
                  and b"EVIL" not in a + b, (a[-30:], b[-30:]))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"upstream {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
