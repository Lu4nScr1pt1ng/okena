#!/usr/bin/env python3
"""gRPC-Web, on one engine (argument), in front of a gRPC server (HTTP/2, the h2
package): a browser's application/grpc-web+proto request reaches it as gRPC
(content-type application/grpc+proto, te: trailers); its answer comes back as
gRPC-Web: content-type application/grpc-web+proto, the messages, then its
trailers (grpc-status, grpc-message) as a trailer frame; over HTTP/1.1 and
HTTP/2. A trailers-only answer (an error) as its head. The text mode
(application/grpc-web-text): the request's base64 decoded on its way (its pieces
split anywhere, a sender's padding after each message), the answer encoded as it
goes, padded only at its end, the trailer frame in it. A pool of HTTP/1.1:
passed on as it is."""
import base64
import http.client
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    print("skip grpcweb: no h2 package")
    sys.exit(0)

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 59400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
GRPC, H1B, LST = BASE, BASE + 1, BASE + 2
fails = 0
SEEN = []


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def frame(msg, flag=0):
    return struct.pack(">BI", flag, len(msg)) + msg


def frames(data):
    out, i = [], 0
    while i + 5 <= len(data):
        flag, n = struct.unpack(">BI", data[i:i + 5])
        out.append((flag, data[i + 5:i + 5 + n]))
        i += 5 + n
    return out, i == len(data)


def grpc_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", GRPC))
    s.listen(16)

    def handle(c):
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding=None))
        conn.initiate_connection()
        c.sendall(conn.data_to_send())
        heads, bodies = {}, {}
        while True:
            d = c.recv(65536)
            if not d:
                return
            for e in conn.receive_data(d):
                if isinstance(e, h2.events.RequestReceived):
                    heads[e.stream_id] = {k.decode(): v.decode() for k, v in e.headers}
                    bodies[e.stream_id] = b""
                elif isinstance(e, h2.events.DataReceived):
                    bodies[e.stream_id] += e.data
                    conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, h2.events.StreamEnded):
                    sid, h, b = e.stream_id, heads[e.stream_id], bodies[e.stream_id]
                    SEEN.append((h, b))
                    if h.get(":path") == "/svc.Echo/Missing":
                        conn.send_headers(sid, [(":status", "200"), ("content-type", "application/grpc+proto"),
                                                ("grpc-status", "5"), ("grpc-message", "no such thing")], end_stream=True)
                    else:
                        ct = h.get("content-type", "")
                        conn.send_headers(sid, [(":status", "200"), ("content-type", ct)])
                        msgs, _ = frames(b)
                        out = b"".join(frame(m[::-1]) for _, m in msgs)
                        for i in range(0, len(out), 16384):     # (within a frame's size)
                            conn.send_data(sid, out[i:i + 16384])
                        conn.send_headers(sid, [("grpc-status", "0"), ("grpc-message", "fine")], end_stream=True)
            c.sendall(conn.data_to_send())
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def h1_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", H1B))
    s.listen(16)
    while True:
        c, _ = s.accept()
        d = b""
        while b"\r\n\r\n" not in d:
            d += c.recv(65536)
        head, body = d.split(b"\r\n\r\n", 1)
        n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
        while len(body) < n:
            body += c.recv(65536)
        SEEN.append(({"_h1": head.decode()}, body))
        c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 0\r\n\r\n")
        c.close()


def post(path, body, ctype="application/grpc-web+proto", port=LST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", path, body=body, headers={"content-type": ctype, "x-grpc-web": "1"})
    r = c.getresponse()
    d = r.read()
    c.close()
    return r, d


def h2_post(path, body, ctype="application/grpc-web+proto"):
    s = socket.create_connection(("127.0.0.1", LST), 5)
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
    conn.initiate_connection()
    conn.send_headers(1, [(":method", "POST"), (":path", path), (":scheme", "http"), (":authority", "x"),
                          ("content-type", ctype)])
    for i in range(0, len(body), 10000):                # (pieces, within a frame's size)
        conn.send_data(1, body[i:i + 10000], end_stream=i + 10000 >= len(body))
    s.sendall(conn.data_to_send())
    heads, data, trailers, done = {}, b"", None, False
    while not done:
        d = s.recv(65536)
        if not d:
            break
        for e in conn.receive_data(d):
            if isinstance(e, h2.events.ResponseReceived):
                heads = {k.decode(): v.decode() for k, v in e.headers}
            elif isinstance(e, h2.events.DataReceived):
                data += e.data
                conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
            elif isinstance(e, h2.events.TrailersReceived):
                trailers = e.headers
            elif isinstance(e, h2.events.StreamEnded):
                done = True
        s.sendall(conn.data_to_send())
    s.close()
    return heads, data, trailers


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-grpcweb-", dir="/tmp"))
    threading.Thread(target=grpc_server, daemon=True).start()
    threading.Thread(target=h1_server, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool grpc {{ server 127.0.0.1:{GRPC}; protocol h2 }}
pool web {{ server 127.0.0.1:{H1B} }}
http 127.0.0.1:{LST} {{
    http2 on
    route /h1/* {{ to pool web }}
    route /* {{ to pool grpc }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        body = frame(b"hello") + frame(b"world!")
        r, d = post("/svc.Echo/Say", body)
        h, b = SEEN[-1] if SEEN else ({}, b"")
        check("the gRPC server gets gRPC: application/grpc+proto, te: trailers, the messages",
              h.get("content-type") == "application/grpc+proto" and h.get("te") == "trailers" and b == body, (h, b))
        fs, whole = frames(d)
        check("HTTP/1.1: gRPC-Web back: its content-type, the messages, then the trailer frame",
              r.status == 200 and r.getheader("content-type") == "application/grpc-web+proto" and whole
              and [m for f, m in fs if f == 0] == [b"olleh", b"!dlrow"] and fs and fs[-1][0] == 0x80
              and b"grpc-status: 0" in fs[-1][1].replace(b"grpc-status:0", b"grpc-status: 0")
              and b"fine" in fs[-1][1], (r.status, r.getheaders(), d))
        r, d = post("/svc.Echo/Missing", frame(b"x"))
        check("a trailers-only answer (an error): grpc-status in its head, no body",
              r.status == 200 and r.getheader("grpc-status") == "5" and r.getheader("grpc-message") == "no such thing"
              and d == b"", (r.status, r.getheaders(), d))
        heads, data, trailers = h2_post("/svc.Echo/Say", frame(b"abc"))
        fs, whole = frames(data)
        check("HTTP/2: the same, its trailers in the data, none as HTTP trailers",
              heads.get("content-type") == "application/grpc-web+proto" and whole
              and fs[0] == (0, b"cba") and fs[-1][0] == 0x80 and b"fine" in fs[-1][1] and trailers is None,
              (heads, data, trailers))
        big = bytes(range(256)) * 80 + b"tail"           # (pieces end anywhere in a group)
        body = frame(b"hello") + frame(big)
        n = len(SEEN)
        r, d = post("/svc.Echo/Say", base64.b64encode(body), ctype="application/grpc-web-text+proto")
        h, b = SEEN[-1] if len(SEEN) > n else ({}, b"")
        check("text: the gRPC server gets gRPC, the body decoded, no content-length of the base64's",
              h.get("content-type") == "application/grpc+proto" and b == body and "content-length" not in h,
              (h, len(b)))
        try:
            fs, whole = frames(base64.b64decode(d, validate=True))
        except Exception as e:
            fs, whole = [], str(e)
        check("text, HTTP/1.1: its content-type, all of it one base64 (padded at its end only), the trailer frame in it",
              r.status == 200 and r.getheader("content-type") == "application/grpc-web-text+proto" and whole is True
              and [m for f, m in fs if f == 0] == [b"olleh", big[::-1]] and fs[-1][0] == 0x80 and b"fine" in fs[-1][1],
              (r.status, r.getheaders(), d[:80], whole))
        n = len(SEEN)
        r, d = post("/svc.Echo/Say", base64.b64encode(frame(b"a")) + base64.b64encode(frame(b"bc")),
                    ctype="application/grpc-web-text")
        h, b = SEEN[-1] if len(SEEN) > n else ({}, b"")
        check("text: a sender's padding after each message", b == frame(b"a") + frame(b"bc") and r.status == 200, (h, b))
        r, d = post("/svc.Echo/Say", b"AAAA!!!!", ctype="application/grpc-web-text")
        check("text: what is not base64 fails, nothing for the server", r.status >= 500 or d == b"", (r.status, d))
        heads, data, trailers = h2_post("/svc.Echo/Say", base64.b64encode(body), ctype="application/grpc-web-text")
        try:
            fs, whole = frames(base64.b64decode(data, validate=True))
        except Exception as e:
            fs, whole = [], str(e)
        check("text, HTTP/2: the same",
              heads.get("content-type") == "application/grpc-web-text" and whole is True
              and [m for f, m in fs if f == 0] == [b"olleh", big[::-1]] and fs[-1][0] == 0x80 and trailers is None,
              (heads, data[:80], whole, trailers))
        r, d = post("/h1/svc", frame(b"hi"))
        h, b = SEEN[-1]
        check("a pool of HTTP/1.1 (gRPC-Web itself): as it is",
              "content-type: application/grpc-web+proto" in h.get("_h1", "").lower() and r.status == 200, h)
        r = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        r.request("POST", "/svc.Echo/Say", body=frame(b"plain"), headers={"content-type": "application/grpc"})
        rr = r.getresponse()
        rr.read()
        check("plain gRPC (no -web): its content-type as it was", rr.getheader("content-type") == "application/grpc", rr.getheaders())
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"grpcweb {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
