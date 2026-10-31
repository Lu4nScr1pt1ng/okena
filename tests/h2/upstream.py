#!/usr/bin/env python3
"""HTTP/2 towards backends (src/http/h2u.inc, `protocol h2`), on one
engine (argument): okena in front of an HTTP/2 server written with the h2
package, and in front of another okena (`http2 on`). HTTP/1.1 and HTTP/2
clients; trailers (gRPC's status) reach both; request bodies with and
without content-length go out as DATA, unframed; streams share upstream
connections; a server's RST_STREAM and GOAWAY, a backend down; over TLS
(ALPN h2, the chain verified) when the tls module is loaded."""
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 26000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
H2B, FRONT, CHAIN, MID, DOWN, H1B = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, 26990 - (5 if ENGINE == "epoll" else 0)
TCHAIN, TMID = BASE + 5, BASE + 6
KTLS = pathlib.Path("/sys/module/tls").exists()
tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h2u-"))
failures = 0
conns = {"n": 0}

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    h2 = None


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


def h2_backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", H2B))
    s.listen(64)

    def handle(c):
        conns["n"] += 1
        cfg = h2.config.H2Configuration(client_side=False, header_encoding=None)
        conn = h2.connection.H2Connection(cfg)
        conn.initiate_connection()
        c.sendall(conn.data_to_send())
        bodies, heads = {}, {}
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    return
                for e in conn.receive_data(d):
                    if isinstance(e, h2.events.RequestReceived):
                        heads[e.stream_id] = {k.decode(): v.decode() for k, v in e.headers}
                        bodies[e.stream_id] = b""
                    elif isinstance(e, h2.events.DataReceived):
                        bodies[e.stream_id] = bodies.get(e.stream_id, b"") + e.data
                        conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                    elif isinstance(e, h2.events.StreamEnded):
                        sid, h, b = e.stream_id, heads[e.stream_id], bodies[e.stream_id]
                        path = h.get(":path", "")
                        if path == "/rst":
                            conn.reset_stream(sid, error_code=8)
                        elif path == "/trailers":
                            conn.send_headers(sid, [(":status", "200"), ("content-type", "application/grpc")])
                            conn.send_data(sid, b"\0\0\0\0\5hello")
                            conn.send_headers(sid, [("grpc-status", "0"), ("grpc-message", "fine")], end_stream=True)
                        elif path.startswith("/big/"):
                            n = int(path[5:])
                            conn.send_headers(sid, [(":status", "200"), ("content-length", str(n))])
                            data = b"y" * n
                            off = 0
                            while off < n:              # within the windows okena gives
                                w = min(conn.local_flow_control_window(sid), conn.max_outbound_frame_size,
                                        n - off)
                                if w <= 0:
                                    c.sendall(conn.data_to_send())
                                    for e2 in conn.receive_data(c.recv(65536)):
                                        pass
                                    continue
                                conn.send_data(sid, data[off:off + w])
                                off += w
                            conn.end_stream(sid)
                        else:
                            info = {"path": path, "method": h.get(":method"), "authority": h.get(":authority"),
                                    "scheme": h.get(":scheme"), "te": h.get("te"), "body": len(b),
                                    "md5": hashlib.md5(b).hexdigest(), "conn": conns["n"],
                                    "headers": sorted(k for k in h if not k.startswith(":"))}
                            body = json.dumps(info).encode()
                            conn.send_headers(sid, [(":status", "200"), ("content-length", str(len(body)))])
                            conn.send_data(sid, body, end_stream=True)
                        if path == "/goaway":
                            conn.close_connection()
                            c.sendall(conn.data_to_send())
                            return
                c.sendall(conn.data_to_send())
        except Exception:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def h1_backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", H1B))
    s.listen(64)

    def handle(c):
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                _, buf = buf.split(b"\r\n\r\n", 1)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nchain!")
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def h1(port, path, method="GET", body=None, chunked=False, extra=""):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    head = f"{method} {path} HTTP/1.1\r\nHost: front.test\r\nConnection: close\r\n{extra}"
    if body is not None and chunked:
        payload = b"".join(b"%x\r\n%s\r\n" % (len(body[i:i + 7000]), body[i:i + 7000])
                           for i in range(0, len(body), 7000)) + b"0\r\n\r\n"
        s.sendall(head.encode() + b"Transfer-Encoding: chunked\r\n\r\n" + payload)
    elif body is not None:
        s.sendall(head.encode() + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    else:
        s.sendall(head.encode() + b"\r\n")
    data = b""
    try:
        while (d := s.recv(65536)):
            data += d
    except socket.timeout:
        pass
    s.close()
    return data


def status(data):
    try:
        return int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def h1_body(data):
    head, _, body = data.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        out = b""
        while True:
            line, _, body = body.partition(b"\r\n")
            n = int(line.split(b";")[0] or b"0", 16)
            if n == 0:
                return out, body
            out, body = out + body[:n], body[n + 2:]
    return body, b""


def main():
    if h2 is None:
        print("skip h2 upstream: pip install h2")
        return 0
    threading.Thread(target=h2_backend, daemon=True).start()
    threading.Thread(target=h1_backend, daemon=True).start()
    tls_part = ""
    if KTLS:
        sh = lambda *a: subprocess.run(a, cwd=tmp, check=True, capture_output=True)
        sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key")
        sh("openssl", "req", "-new", "-x509", "-key", "ca.key", "-sha256", "-subj", "/CN=test-ca", "-days", "2",
           "-out", "ca.pem")
        sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
        sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=front.test", "-out", "leaf.csr")
        (tmp / "ext.cnf").write_text("subjectAltName=DNS:front.test\n")
        sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
           "-days", "2", "-sha256", "-extfile", "ext.cnf", "-out", "leaf.pem")
        tls_part = f"""http 127.0.0.1:{TCHAIN} {{ route /* {{ to pool midt }} }}
pool midt {{
    protocol h2
    tls {{ trust {tmp}/ca.pem; sni front.test }}
    server 127.0.0.1:{TMID}
}}
http 127.0.0.1:{TMID} {{
    http2 on
    tls {{ cert {tmp}/leaf.pem; key {tmp}/leaf.key }}
    route /* {{ to 127.0.0.1:{H1B} }}
}}
"""
    conf = tmp / "okena.conf"
    conf.write_text(tls_part + f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{FRONT} {{
    http2 on
    route /* {{ to pool h2b }}
}}
pool h2b {{
    protocol h2
    server 127.0.0.1:{H2B}
}}
http 127.0.0.1:{CHAIN} {{ route /* {{ to pool mid }} }}
pool mid {{
    protocol h2
    server 127.0.0.1:{MID}
}}
http 127.0.0.1:{MID} {{
    http2 on
    route /* {{ to 127.0.0.1:{H1B} }}
}}
http 127.0.0.1:{DOWN} {{
    http2 on
    route /* {{ to pool gone }}
}}
pool gone {{
    protocol h2
    server 127.0.0.1:{BASE + 9}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    check("okena check: pools with protocol h2", r.returncode == 0, r.stderr)
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.5)
        cases()
        log.seek(0)
        text = log.read()
        check("no worker died", "killed" not in text and "exited with status" not in text, text[-400:])
    finally:
        p.terminate()
        p.wait(10)
    print(f"h2 upstream {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


def cases():
    d = h1(FRONT, "/hello?a=1")
    info = json.loads(h1_body(d)[0] or b"{}")
    check("an HTTP/1.1 client, an HTTP/2 backend: 200", status(d) == 200 and info.get("path") == "/hello?a=1", d[:200])
    check("  :authority from Host, :scheme http, te: trailers",
          info.get("authority") == "front.test" and info.get("scheme") == "http" and info.get("te") == "trailers",
          str(info))
    check("  no connection-specific field reaches the backend",
          not {"connection", "transfer-encoding", "keep-alive", "host"} & set(info.get("headers", [])),
          str(info.get("headers")))
    first = info.get("conn")
    d = h1(FRONT, "/again")
    check("  the next request rides the same upstream connection",
          json.loads(h1_body(d)[0] or b"{}").get("conn") == first, d[-200:])

    body = os.urandom(40000)
    d = h1(FRONT, "/echo", "POST", body)
    info = json.loads(h1_body(d)[0] or b"{}")
    check("POST with content-length: the body arrives whole as DATA",
          info.get("body") == len(body) and info.get("md5") == hashlib.md5(body).hexdigest(), str(info))
    d = h1(FRONT, "/echo", "POST", body, chunked=True)
    info = json.loads(h1_body(d)[0] or b"{}")
    check("POST chunked: unframed, whole",
          info.get("body") == len(body) and info.get("md5") == hashlib.md5(body).hexdigest(), str(info))

    d = h1(FRONT, "/trailers", extra="TE: trailers\r\n")
    data, trailers = h1_body(d)
    check("trailers of an HTTP/2 backend reach an HTTP/1.1 client (after the last chunk)",
          data == b"\0\0\0\0\5hello" and b"grpc-status: 0" in trailers and b"grpc-message: fine" in trailers,
          d[-200:])

    d = h1(FRONT, "/big/300000")
    check("a 300 KB response through the windows", status(d) == 200 and len(h1_body(d)[0]) == 300000,
          f"{len(d)}")

    d = h1(FRONT, "/rst")
    check("a stream the backend resets: 502", status(d) == 502, d[:80])

    # concurrency: 20 at once, on few upstream connections
    before = conns["n"]
    res = [None] * 20

    def one(i):
        res[i] = h1(FRONT, f"/c/{i}")
    ths = [threading.Thread(target=one, args=(i,)) for i in range(20)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    ok = all(status(x) == 200 and json.loads(h1_body(x)[0] or b"{}").get("path") == f"/c/{i}"
             for i, x in enumerate(res))
    check("20 requests at once", ok, str([status(x) for x in res]))
    check("  on at most 4 upstream connections", conns["n"] - before <= 4, f"{conns['n'] - before} opened")

    # an HTTP/2 client end to end, trailers as trailers
    import h2.connection as hc
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
    c = hc.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
    c.initiate_connection()
    c.send_headers(1, [(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/trailers")],
                   end_stream=True)
    s.sendall(c.data_to_send())
    evs, deadline = [], time.time() + 5
    while time.time() < deadline and not any(isinstance(e, h2.events.StreamEnded) for e in evs):
        d = s.recv(65536)
        if not d:
            break
        evs += c.receive_data(d)
        s.sendall(c.data_to_send())
    s.close()
    tr = [dict((k.decode(), v.decode()) for k, v in e.headers) for e in evs if isinstance(e, h2.events.TrailersReceived)]
    check("an HTTP/2 client gets the backend's trailers as trailers",
          tr == [{"grpc-status": "0", "grpc-message": "fine"}], str(tr))

    d = h1(FRONT, "/goaway")
    check("the backend answers, then GOAWAY and closes", status(d) == 200, d[:80])
    time.sleep(0.2)
    d = h1(FRONT, "/after-goaway")
    check("  the next request goes on a new connection", status(d) == 200, d[:120])

    d = h1(CHAIN, "/chain")
    check("okena -> okena over HTTP/2 -> an HTTP/1.1 backend", status(d) == 200 and h1_body(d)[0] == b"chain!",
          d[-120:])
    # a gRPC request okena cannot serve: a gRPC answer (Trailers-Only)
    s = socket.create_connection(("127.0.0.1", DOWN), timeout=5)
    c = hc.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
    c.initiate_connection()
    c.send_headers(1, [(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", "/pkg.Svc/Call"),
                       ("content-type", "application/grpc"), ("te", "trailers")])
    c.send_data(1, b"\0\0\0\0\0", end_stream=True)
    s.sendall(c.data_to_send())
    evs, deadline = [], time.time() + 5
    while time.time() < deadline and not any(isinstance(e, h2.events.StreamEnded) for e in evs):
        d = s.recv(65536)
        if not d:
            break
        evs += c.receive_data(d)
        s.sendall(c.data_to_send())
    s.close()
    resp = [e for e in evs if isinstance(e, h2.events.ResponseReceived)]
    hdrs = dict((k.decode(), v.decode()) for k, v in resp[0].headers) if resp else {}
    check("a gRPC request okena cannot serve: 200, grpc-status 14 (UNAVAILABLE)",
          hdrs.get(":status") == "200" and hdrs.get("grpc-status") == "14"
          and hdrs.get("content-type") == "application/grpc", str(hdrs))
    check("  as Trailers-Only: END_STREAM on the HEADERS, no DATA",
          resp and resp[0].stream_ended is not None and not any(isinstance(e, h2.events.DataReceived) for e in evs),
          str(evs))
    if KTLS:
        d = h1(TCHAIN, "/chain")
        check("okena -> okena over HTTP/2 on TLS (ALPN h2) -> an HTTP/1.1 backend",
              status(d) == 200 and h1_body(d)[0] == b"chain!", d[-120:])
        d = h1(TCHAIN, "/again")
        check("  the next request on the same TLS connection", status(d) == 200 and h1_body(d)[0] == b"chain!",
              d[-120:])
    else:
        print("skip  HTTP/2 on TLS to a backend: the tls module is not loaded")
    t0 = time.time()
    d = h1(DOWN, "/x")
    check("a backend down: 502, at once", status(d) == 502 and time.time() - t0 < 2, d[:80])


if __name__ == "__main__":
    sys.exit(main())
