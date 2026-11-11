#!/usr/bin/env python3
"""HTTP/1.x edge cases through okena, on one engine (argument): each line of
docs/EDGE_CASES.md's parsing table sent to a running okena, with the status it
answers, whether it keeps the connection, and what reaches the backend (nothing,
for what is refused before routing; for a refused body, at most its head). An error
answered with bytes unread must not cost the client its answer (no reset: the
writing side is shut and the rest read and dropped)."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 27000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, L = BASE, BASE + 1
seen = []
lock = threading.Lock()
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


busy = [0]


def serve(c):
    c.settimeout(5)
    data = b""
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            data += d
            if b"\r\n\r\n" in data:
                with lock:
                    busy[0] += 1                # (a request being noted: send() waits)
                time.sleep(0.02)                # (the body that follows)
                try:
                    c.settimeout(0.05)
                    data += c.recv(65536)
                except OSError:
                    pass
                c.settimeout(5)
                with lock:
                    seen.append(data)
                    busy[0] -= 1
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                data = b""
    except OSError:
        pass
    c.close()


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", B))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


HIDE = (b"X-Request-Id", b"X-Forwarded-For", b"X-Forwarded-Proto")


def send(raw):
    t0 = time.time()                            # the last case's backend done with it
    while busy[0] and time.time() - t0 < 6:
        time.sleep(0.01)
    with lock:
        seen.clear()
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(0.5)
    k.sendall(raw)
    out, end = b"", "open"
    try:
        while True:
            d = k.recv(65536)
            if not d:
                end = "closed"
                break
            out += d
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "reset"
    k.close()
    time.sleep(0.05)
    st = ",".join(x.split(b" ")[1].decode() for x in out.split(b"\r\n") if x.startswith(b"HTTP/1."))
    with lock:
        bk = [b"|".join(x for x in s.split(b"\r\n") if x and not x.startswith(HIDE)) for s in seen]
    return st, end, bk


G = b"GET / HTTP/1.1\r\nHost: a\r\n"
CASES = {
 "CL+TE": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
 "dup CL differ": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
 "CL comma differ": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 2\r\n\r\nab",
 "CL same twice": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nab",
 "CL 2,2": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2, 2\r\n\r\nab",
 "CL +2": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +2\r\n\r\nab",
 "TE gzip,chunked": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
 "TE chunked,chunked": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
 "TE Chunked case": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n",
 "TE xchunked": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
 "TE in http/1.0": b"POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
 "TE tab value": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n",
 "chunk size overflow": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF1\r\nx\r\n0\r\n\r\n",
 "chunk ext": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1;a=b\r\nx\r\n0\r\n\r\n",
 "chunk LF only": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\nx\n0\n\n",
 "chunk size space": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1 \r\nx\r\n0\r\n\r\n",
 "chunk 0x prefix": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0x1\r\nx\r\n0\r\n\r\n",
 "obs-fold": b"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n",
 "bare CR": b"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n",
 "bare LF line": b"GET / HTTP/1.1\nHost: a\n\n",
 "NUL in value": b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
 "space before colon": b"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n",
 "bad token name": b"GET / HTTP/1.1\r\nHost: a\r\nX(y): b\r\n\r\n",
 "1.0 no host": b"GET / HTTP/1.0\r\n\r\n",
 "0.9": b"GET /\r\n",
 "abs-form agree": b"GET http://a/x HTTP/1.1\r\nHost: a\r\n\r\n",
 "abs-form disagree": b"GET http://evil/x HTTP/1.1\r\nHost: a\r\n\r\n",
 "CONNECT": b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
 "TRACE": b"TRACE / HTTP/1.1\r\nHost: a\r\n\r\n",
 "two Host": b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
 "no Host 1.1": b"GET / HTTP/1.1\r\n\r\n",
 "upgrade w/ body": b"POST / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 2\r\n\r\nab",
 "connection names hdr": b"GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Secret\r\nX-Secret: 1\r\n\r\n",
 "pipelined bad 2nd": G + b"\r\n" + b"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n",
 "GET with body": b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nab",
 "expect 100": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n",
 "huge header": b"GET / HTTP/1.1\r\nHost: a\r\nX: " + b"a"*70000 + b"\r\n\r\n",
 "many headers": b"GET / HTTP/1.1\r\nHost: a\r\n" + b"".join(b"X%d: 1\r\n" % i for i in range(300)) + b"\r\n",
 "long URI": b"GET /" + b"a"*70000 + b" HTTP/1.1\r\nHost: a\r\n\r\n",
 "method lowercase": b"get / HTTP/1.1\r\nHost: a\r\n\r\n",
 "version HTTP/1.2": b"GET / HTTP/1.2\r\nHost: a\r\n\r\n",
 "version HTTP/2.0": b"GET / HTTP/2.0\r\nHost: a\r\n\r\n",
 "target ../": b"GET /a/../../etc HTTP/1.1\r\nHost: a\r\n\r\n",
 "target %2e%2e": b"GET /a/%2e%2e/%2e%2e/etc HTTP/1.1\r\nHost: a\r\n\r\n",
 "target backslash": b"GET /a\\..\\b HTTP/1.1\r\nHost: a\r\n\r\n",
 "target fragment": b"GET /a#x HTTP/1.1\r\nHost: a\r\n\r\n",
 "target asterisk GET": b"GET * HTTP/1.1\r\nHost: a\r\n\r\n",
 "host with userinfo": b"GET / HTTP/1.1\r\nHost: u@a\r\n\r\n",
 "host bad chars": b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
 "host empty": b"GET / HTTP/1.1\r\nHost:\r\n\r\n",
 "leading CRLF": b"\r\n" + G + b"\r\n",
 "space in reqline x2": b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
 "header leading space line1": b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
 "CL negative": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
 "CL huge": b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999\r\n\r\n",
 "TE + CL0 on GET": b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
 "trailer smuggle": b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\n",
 "Proxy-Connection": b"GET / HTTP/1.1\r\nHost: a\r\nProxy-Connection: keep-alive\r\n\r\n",
 "TE: trailers h1": b"GET / HTTP/1.1\r\nHost: a\r\nTE: trailers\r\n\r\n",
}

# (status, connection after, what the backend saw: None nothing, "" a head at
# most (a body refused on its way), bytes a part of it)
EXPECT = {
    'CL+TE': ('400', 'closed', None),
    'dup CL differ': ('400', 'closed', None),
    'CL comma differ': ('400', 'closed', None),
    'CL same twice': ('200', 'open', b'Content-Length: 2|ab'),
    'CL 2,2': ('200', 'open', b'Content-Length: 2|ab'),
    'CL +2': ('400', 'closed', None),
    'TE gzip,chunked': ('501', 'closed', None),
    'TE chunked,chunked': ('501', 'closed', None),
    'TE Chunked case': ('200', 'open', b'Transfer-Encoding: chunked|0'),
    'TE xchunked': ('501', 'closed', None),
    'TE in http/1.0': ('400', 'closed', None),
    'TE tab value': ('200', 'open', b'Transfer-Encoding: chunked|0'),
    'chunk size overflow': ('400', 'closed', ''),
    'chunk ext': ('200', 'open', b'|1|x|0'),
    'chunk LF only': ('400', 'closed', ''),
    'chunk size space': ('400', 'closed', ''),
    'chunk 0x prefix': ('400', 'closed', ''),
    'obs-fold': ('400', 'closed', None),
    'bare CR': ('400', 'closed', None),
    'bare LF line': ('400', 'closed', None),
    'NUL in value': ('400', 'closed', None),
    'space before colon': ('400', 'closed', None),
    'bad token name': ('400', 'closed', None),
    '1.0 no host': ('200', 'closed', b'GET / HTTP/1.1|Host: 127.0.0.1:'),
    '0.9': ('400', 'closed', None),
    'abs-form agree': ('200', 'open', b'GET /x HTTP/1.1|Host: a'),
    'abs-form disagree': ('400', 'closed', None),
    'CONNECT': ('405', 'closed', None),
    'TRACE': ('405', 'closed', None),
    'two Host': ('400', 'closed', None),
    'no Host 1.1': ('400', 'closed', None),
    'upgrade w/ body': ('400', 'closed', None),
    'connection names hdr': ('200', 'open', b'GET / HTTP/1.1|Host: a'),
    'pipelined bad 2nd': ('200', 'closed', b'GET / HTTP/1.1|Host: a'),
    'GET with body': ('200', 'open', b'Content-Length: 2|ab'),
    'expect 100': ('100', 'open', b'Content-Length: 2'),
    'huge header': ('431', 'closed', None),
    'many headers': ('431', 'closed', None),
    'long URI': ('414', 'closed', None),
    'method lowercase': ('200', 'open', b'get / HTTP/1.1'),
    'version HTTP/1.2': ('505', 'closed', None),
    'version HTTP/2.0': ('505', 'closed', None),
    'target ../': ('400', 'closed', None),
    'target %2e%2e': ('400', 'closed', None),
    'target backslash': ('400', 'closed', None),
    'target fragment': ('400', 'closed', None),
    'target asterisk GET': ('400', 'closed', None),
    'host with userinfo': ('400', 'closed', None),
    'host bad chars': ('400', 'closed', None),
    'host empty': ('400', 'closed', None),
    'leading CRLF': ('200', 'open', b'GET / HTTP/1.1|Host: a'),
    'space in reqline x2': ('400', 'closed', None),
    'header leading space line1': ('400', 'closed', None),
    'CL negative': ('400', 'closed', None),
    'CL huge': ('400', 'closed', None),
    'TE + CL0 on GET': ('400', 'closed', None),
    'trailer smuggle': ('200', 'open', b'Transfer-Encoding: chunked|0'),
    'Proxy-Connection': ('200', 'open', b'GET / HTTP/1.1|Host: a'),
    'TE: trailers h1': ('200', 'open', b'GET / HTTP/1.1|Host: a'),
}


def main():
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-edge-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{ route /* {{ to pool b }} }}
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
        for name, raw in CASES.items():
            st, end, bk = send(raw)
            want_st, want_end, want_bk = EXPECT[name]
            if want_bk is None:
                bk_ok = not bk
            elif want_bk == "":
                bk_ok = len(bk) <= 1
            else:
                bk_ok = len(bk) == 1 and want_bk in bk[0]
            check(f"{name}: {want_st}, {want_end}", st == want_st and end == want_end and bk_ok, (st, end, bk))
        # errors on connections the client drops at once, new connections
        # right behind them: each answered whole (a lingering close's shutdown
        # once landed on the next connection given the same slot)
        bad = []

        def churn():
            for _ in range(60):
                try:
                    k = socket.create_connection(("127.0.0.1", L), timeout=3)
                    k.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nX : b\r\n\r\n")
                    k.recv(100)
                    k.close()
                    k = socket.create_connection(("127.0.0.1", L), timeout=3)
                    k.sendall(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
                    got = b""
                    while True:
                        d = k.recv(4096)
                        if not d:
                            break
                        got += d
                    k.close()
                    if not got.endswith(b"\r\n\r\nok"):
                        bad.append(got[:60])
                except OSError as e:
                    bad.append(repr(e))
        ts = [threading.Thread(target=churn) for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check("after errors dropped at once, new connections answered whole", not bad, (len(bad), bad[:3]))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"edge {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
