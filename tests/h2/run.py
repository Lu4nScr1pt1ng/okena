#!/usr/bin/env python3
"""HTTP/2 towards clients (src/http/h2.inc), driven by the h2 package
against a live okena, on one engine (argument: io_uring or epoll):
prior knowledge on a plain listener and ALPN h2 on a TLS one; streams
interleaved; request bodies with and without content-length; a large
response through a small window (flow control); what reaches the backend
(an HTTP/1.1 request: :authority as Host, cookies joined); the refusals
(malformed requests reset, a bad preface or a broken header block ends the
connection) and the control frames (SETTINGS, PING, RST_STREAM, rapid
reset, GOAWAY)."""
import http.server
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 24000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLSL = BASE, BASE + 1, BASE + 2
tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h2-"))
failures = 0

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
except ImportError:
    h2 = None


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, body, code=200, extra=()):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_any(self):
        n = 0
        body = b""
        if self.headers.get("Content-Length"):
            body = self.rfile.read(int(self.headers["Content-Length"]))
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b""):
                        pass
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        if self.path.startswith("/big/"):
            n = int(self.path[5:])
            return self.reply(b"x" * n)
        if self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"hello", b", ", b"world"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
            return
        if self.path == "/trailers":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "application/grpc")
            self.end_headers()
            self.wfile.write(b"5\r\nhello\r\n0\r\nGrpc-Status: 0\r\ngrpc-message: all good\r\nConnection: x\r\n\r\n")
            return
        if self.path == "/slow":
            time.sleep(1)
        info = {"method": self.command, "path": self.path, "body": len(body),
                "md5": __import__("hashlib").md5(body).hexdigest(),
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "cookies": self.headers.get_all("Cookie") or []}
        self.reply(json.dumps(info).encode(), extra=[("X-Back", "yes"), ("Connection", "keep-alive")])

    do_GET = do_POST = do_PUT = do_HEAD = handle_any


class BackServer(http.server.ThreadingHTTPServer):
    request_queue_size = 256            # the default 5 drops concurrent connects (1 s SYN retries)


def backend():
    srv = BackServer(("127.0.0.1", BACK), Back)
    srv.daemon_threads = True
    srv.serve_forever()


class Client:
    """A blocking h2 client over a socket (plain or TLS)."""

    def __init__(self, port, tls=False, window=None):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            s = ctx.wrap_socket(s, server_hostname="localhost")
            self.alpn = s.selected_alpn_protocol()
        self.s = s
        cfg = h2.config.H2Configuration(client_side=True, header_encoding=None,
                                         normalize_outbound_headers=False, validate_outbound_headers=False)
        self.c = h2.connection.H2Connection(cfg)
        self.c.initiate_connection()
        if window:
            self.c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: window})
        self.flush()
        self.events = []

    def flush(self):
        data = self.c.data_to_send()
        if data:
            self.s.sendall(data)

    def request(self, path, method="GET", headers=(), body=None, end=True):
        sid = self.c.get_next_available_stream_id()
        hdrs = [(":method", method), (":scheme", "http"), (":authority", "okena.test"), (":path", path)]
        hdrs += list(headers)
        self.c.send_headers(sid, hdrs, end_stream=body is None and end)
        if body is not None:
            i = 0
            while i < len(body):
                w = min(self.c.local_flow_control_window(sid), 8000)
                if w <= 0:      # okena gives credit back as its queue drains
                    n = len(self.events)
                    self.pump(lambda: len(self.events) > n, timeout=2)
                    continue
                chunk = body[i:i + w]
                i += len(chunk)
                self.c.send_data(sid, chunk, end_stream=i >= len(body) and end)
                self.flush()
            if not body and end:
                self.c.send_data(sid, b"", end_stream=True)
        self.flush()
        return sid

    def pump(self, until, timeout=5, credit=True):
        deadline = time.time() + timeout
        while not until() and time.time() < deadline:
            try:
                data = self.s.recv(65536)
            except socket.timeout:
                break
            except OSError:                 # reset after a GOAWAY
                self.events.append("eof")
                break
            if not data:
                self.events.append("eof")
                break
            for e in self.c.receive_data(data):
                self.events.append(e)
                if credit and isinstance(e, h2.events.DataReceived):
                    self.c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
            self.flush()

    def response(self, sid, timeout=5):
        done = lambda: any(isinstance(e, (h2.events.StreamEnded, h2.events.StreamReset)) and e.stream_id == sid
                           for e in self.events if not isinstance(e, str)) or "eof" in self.events
        self.pump(done, timeout)
        hdrs, body, reset = {}, b"", None
        for e in self.events:
            if isinstance(e, str) or getattr(e, "stream_id", None) != sid:
                continue
            if isinstance(e, h2.events.ResponseReceived):
                hdrs = {k.decode(): v.decode() for k, v in e.headers}
            elif isinstance(e, h2.events.DataReceived):
                body += e.data
            elif isinstance(e, h2.events.StreamReset):
                reset = e.error_code
        return hdrs, body, reset

    def close(self):
        self.s.close()


def raw(port, data, wait=1.0):
    """Bytes in, whatever comes back until the server closes or goes quiet."""
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    s.sendall(data)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    return out


def frames(data):
    out, i = [], 0
    while i + 9 <= len(data):
        n = int.from_bytes(data[i:i + 3], "big")
        out.append((data[i + 3], data[i + 4], int.from_bytes(data[i + 5:i + 9], "big") & 0x7FFFFFFF,
                    data[i + 9:i + 9 + n]))
        i += 9 + n
    return out


def goaway_code(data):
    for t, f, sid, p in frames(data):
        if t == 7:
            return int.from_bytes(p[4:8], "big")
    return None


def main():
    if h2 is None:
        print("skip h2: pip install h2")
        return 0
    threading.Thread(target=backend, daemon=True).start()
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost",
                    "-days", "2", "-out", tmp / "c.pem"], check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{PLAIN} {{
    http2 on
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{TLSL} {{
    http2 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        for _ in range(100):
            log.seek(0)
            if "started with" in log.read():
                break
            time.sleep(0.05)
        time.sleep(0.2)
        run_cases()
        log.seek(0)
        text = log.read()
        check("no worker died", "exited with status" not in text and "killed" not in text, text[-500:])
    finally:
        p.terminate()
        p.wait(10)
    if failures:
        log.seek(0)
        print(log.read()[-2000:])
    print(f"h2 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


def run_cases():
    c = Client(PLAIN)
    sid = c.request("/hello?x=1", headers=[("cookie", "a=1"), ("user-agent", "t"), ("cookie", "b=2")])
    hdrs, body, reset = c.response(sid)
    info = json.loads(body or b"{}")
    check("prior knowledge: GET answered over h2", hdrs.get(":status") == "200" and info.get("path") == "/hello?x=1",
          f"{hdrs} {body[:200]!r} reset={reset}")
    check("  the backend saw HTTP/1.1 with :authority as Host",
          info.get("headers", {}).get("host") == "okena.test", str(info.get("headers")))
    check("  cookies joined into one field", info.get("cookies") == ["a=1; b=2"], str(info.get("cookies")))
    check("  connection-specific fields dropped from the response",
          "connection" not in hdrs and hdrs.get("x-back") == "yes", str(hdrs))

    # ten streams at once, answered in any order
    sids = [c.request(f"/s/{i}") for i in range(10)]
    got = [json.loads(c.response(s)[1] or b"{}").get("path") for s in sids]
    check("ten interleaved streams on one connection", got == [f"/s/{i}" for i in range(10)], str(got))

    body = os.urandom(50000)
    sid = c.request("/post", "POST", headers=[("content-length", str(len(body)))], body=body)
    info = json.loads(c.response(sid)[1] or b"{}")
    check("POST with content-length: the body arrives whole",
          info.get("body") == len(body) and info.get("md5") == __import__("hashlib").md5(body).hexdigest(), str(info))
    sid = c.request("/post2", "POST", body=body)
    info = json.loads(c.response(sid)[1] or b"{}")
    check("POST without content-length: chunked towards the backend, whole",
          info.get("body") == len(body) and info.get("md5") == __import__("hashlib").md5(body).hexdigest(), str(info))
    sid = c.request("/chunked")
    hdrs, body, _ = c.response(sid)
    check("a chunked response arrives as DATA, unframed", body == b"hello, world", f"{hdrs} {body!r}")
    sid = c.request("/trailers")
    c.response(sid)
    trailers = [dict((k.decode(), v.decode()) for k, v in e.headers) for e in c.events
                if isinstance(e, h2.events.TrailersReceived) and e.stream_id == sid]
    check("a backend's trailers arrive as HTTP/2 trailers (gRPC's status)",
          trailers == [{"grpc-status": "0", "grpc-message": "all good"}], str(trailers))
    sid = c.request("/hello", "HEAD")
    hdrs, body, reset = c.response(sid)
    check("HEAD: headers, no body", hdrs.get(":status") == "200" and body == b"" and reset is None, f"{hdrs} {body!r}")
    c.close()

    with socket.create_connection(("127.0.0.1", PLAIN), timeout=5) as t:
        t.sendall(b"GET /trailers HTTP/1.1\r\nHost: x\r\nTE: trailers\r\nConnection: close\r\n\r\n")
        data = b""
        while (d := t.recv(65536)):
            data += d
    check("and to an HTTP/1.1 client after the last chunk",
          data.endswith(b"0\r\nGrpc-Status: 0\r\ngrpc-message: all good\r\nConnection: x\r\n\r\n"), data[-120:])

    # a megabyte through a 16 KiB stream window, credited as it is read
    c = Client(PLAIN, window=16384)
    sid = c.request("/big/1048576")
    hdrs, body, reset = c.response(sid, timeout=10)
    check("1 MiB through a 16 KiB window (flow control)", len(body) == 1048576 and reset is None,
          f"{len(body)} reset={reset}")
    c.close()

    # malformed requests are reset, the connection goes on
    c = Client(PLAIN)
    for name, hdrs in (("an upper-case field name", [("X-Up", "1")]),
                       ("a connection-specific field", [("connection", "keep-alive")]),
                       ("te other than trailers", [("te", "gzip")])):
        sid = c.c.get_next_available_stream_id()
        c.c.send_headers(sid, [(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/")] + hdrs,
                         end_stream=True)
        c.flush()
        _, _, reset = c.response(sid)
        check(f"{name}: RST_STREAM PROTOCOL_ERROR", reset == 1, f"reset={reset}")
    sid = c.request("/after")
    check("  and the connection still serves", json.loads(c.response(sid)[1] or b"{}").get("path") == "/after")
    # PING
    c.c.ping(b"12345678")
    c.flush()
    c.pump(lambda: any(isinstance(e, h2.events.PingAckReceived) for e in c.events if not isinstance(e, str)))
    check("PING answered", any(isinstance(e, h2.events.PingAckReceived) and e.ping_data == b"12345678"
                               for e in c.events if not isinstance(e, str)))
    # the client cancels a slow request
    sid = c.request("/slow")
    time.sleep(0.1)
    c.c.reset_stream(sid)
    c.flush()
    sid2 = c.request("/next")
    check("a stream the client reset does not stop the others",
          json.loads(c.response(sid2)[1] or b"{}").get("path") == "/next")
    c.close()

    # connection errors
    out = raw(PLAIN, b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")
    check("a bad preface: GOAWAY PROTOCOL_ERROR", goaway_code(out) == 1, out[:80])
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    out = raw(PLAIN, preface + b"\x00\x00\x01\x01\x05\x00\x00\x00\x01" + b"\x80")   # HEADERS, index 0
    check("a broken header block: GOAWAY COMPRESSION_ERROR", goaway_code(out) == 9, out[-40:])
    out = raw(PLAIN, preface + b"\x00\x00\x08\x06\x00\x00\x00\x00\x01" + b"12345678")   # PING on a stream
    check("PING on a stream: GOAWAY PROTOCOL_ERROR", goaway_code(out) == 1, out[-40:])
    out = raw(PLAIN, preface + b"\x00\x00\x03\x04\x00\x00\x00\x00\x00" + b"abc")       # SETTINGS, not 6n
    check("SETTINGS of a bad length: GOAWAY FRAME_SIZE_ERROR", goaway_code(out) == 6, out[-40:])
    import hpack as hp
    import struct

    def fr(typ, flags, sid, payload=b""):
        return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) + struct.pack(">I", sid) + payload

    req = hp.Encoder().encode([(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/")])

    def rst_code(data, sid):
        for t, f, s_, p in frames(data):
            if t == 3 and s_ == sid:
                return int.from_bytes(p[:4], "big")
        return None
    out = raw(PLAIN, preface + fr(1, 1, 1, req[:3]) + fr(9, 0, 1) * 100)     # CONTINUATION, empty, forever
    check("a CONTINUATION flood: GOAWAY ENHANCE_YOUR_CALM", goaway_code(out) == 11, out[-40:])
    out = raw(PLAIN, preface + fr(2, 0, 3, b"\0" * 4))                       # PRIORITY of 4 bytes
    check("PRIORITY of a bad length: RST_STREAM FRAME_SIZE_ERROR", rst_code(out, 3) == 6, out[-40:])
    out = raw(PLAIN, preface + fr(6, 0, 0, b"12345678") * 3000, wait=2)
    check("a PING flood: GOAWAY ENHANCE_YOUR_CALM", goaway_code(out) == 11, out[-40:])
    out = raw(PLAIN, preface + fr(1, 5, 5, req) + fr(1, 5, 3, req))         # stream 3 after 5
    check("HEADERS on a lower stream id: GOAWAY PROTOCOL_ERROR", goaway_code(out) == 1, out[-40:])
    trailers = hp.Encoder().encode([(":path", "/x")])
    post = hp.Encoder().encode([(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", "/")])
    out = raw(PLAIN, preface + fr(1, 4, 1, post) + fr(0, 0, 1, b"abc") + fr(1, 5, 1, trailers))
    check("trailers with a pseudo-field: RST_STREAM PROTOCOL_ERROR", rst_code(out, 1) == 1, out[-40:])

    # rapid reset: HEADERS then RST_STREAM, over and over
    c = Client(PLAIN)
    for _ in range(400):
        sid = c.c.get_next_available_stream_id()
        c.c.send_headers(sid, [(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/slow")],
                         end_stream=True)
        c.c.reset_stream(sid)
    try:
        c.flush()
    except OSError:
        pass
    c.pump(lambda: any(isinstance(e, h2.events.ConnectionTerminated) for e in c.events if not isinstance(e, str))
           or "eof" in c.events, timeout=3)
    term = [e for e in c.events if isinstance(e, h2.events.ConnectionTerminated)]
    check("rapid reset: GOAWAY ENHANCE_YOUR_CALM", term and term[0].error_code == 11, str(term))
    c.close()

    # a client that answers every DATA frame (credit and a ping, as gRPC's
    # BDP estimator does) is doing what it should: the budget for cheap
    # frames grows with what okena sends
    c = Client(PLAIN, window=100)
    sid = c.request("/big/400000")
    got, frames_in, end = 0, 0, False
    deadline = time.time() + 10
    while not end and time.time() < deadline:
        try:
            data = c.s.recv(65536)
        except (socket.timeout, OSError):
            break
        if not data:
            break
        for e in c.c.receive_data(data):
            if isinstance(e, h2.events.DataReceived):
                got += len(e.data)
                frames_in += 1
                c.c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                c.c.ping(os.urandom(8))
            elif isinstance(e, (h2.events.StreamEnded, h2.events.ConnectionTerminated)):
                end = True
        c.flush()
    check(f"a client crediting and pinging after each of {frames_in} DATA frames: not cut off",
          got == 400000, f"{got} bytes")
    c.close()

    # a client that stops reading a while (OUT fills with DATA) and pings:
    # the acks wait for room, the connection is not cut
    c = Client(PLAIN, window=2 ** 30)
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)     # the kernel holds little of it
    c.c.increment_flow_control_window(2 ** 30 - 65535)
    c.flush()
    sid = c.request("/big/8000000")
    time.sleep(0.5)
    for i in range(5):
        c.c.ping(bytes([i]) * 8)
    c.flush()
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    c.pump(lambda: any(isinstance(e, (h2.events.StreamEnded, h2.events.ConnectionTerminated))
                       for e in c.events if not isinstance(e, str)) or "eof" in c.events, timeout=10)
    got = sum(len(e.data) for e in c.events if isinstance(e, h2.events.DataReceived))
    acks = sum(1 for e in c.events if isinstance(e, h2.events.PingAckReceived))
    term = [e for e in c.events if isinstance(e, h2.events.ConnectionTerminated)]
    c.pump(lambda: sum(1 for e in c.events if isinstance(e, h2.events.PingAckReceived)) >= 5, timeout=2)
    acks = sum(1 for e in c.events if isinstance(e, h2.events.PingAckReceived))
    check("pings while okena's output is full of DATA: answered, not GOAWAY",
          got == 8000000 and acks == 5 and not term, f"{got} bytes, {acks} acks, {term}")
    c.close()

    # ALPN h2 over TLS
    c = Client(TLSL, tls=True)
    check("TLS: ALPN chose h2", c.alpn == "h2", str(c.alpn))
    sids = [c.request(f"/tls/{i}") for i in range(5)]
    got = [json.loads(c.response(s)[1] or b"{}").get("path") for s in sids]
    check("TLS: five streams answered", got == [f"/tls/{i}" for i in range(5)], str(got))
    sid = c.request("/big/300000")
    check("TLS: 300 KB response", len(c.response(sid, timeout=10)[1]) == 300000)
    c.close()
    # an h1 client on the same TLS listener
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", TLSL), timeout=5), server_hostname="localhost") as t:
        t.sendall(b"GET /h1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while (d := t.recv(65536)):
            data += d
    check("TLS: an HTTP/1.1 client still served", data.startswith(b"HTTP/1.1 200"), data[:60])


if __name__ == "__main__":
    sys.exit(main())
