#!/usr/bin/env python3
"""HTTP/3 and QUIC (`http3 on`) against a live okena, on one engine
(argument): aioquic as the client (a venv in build/qenv: python3 -m venv
build/qenv && build/qenv/bin/pip install aioquic; skipped without it) and
curl when it speaks HTTP/3. The handshake (v1 and v2), Version
Negotiation, GETs and POSTs of megabytes both ways (with and without
content-length), many streams at once on one connection, and transfers
through a relay that drops a tenth of the datagrams each way."""
import hashlib
import os
import pathlib
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
VENV = ROOT / "build" / "qenv" / "bin" / "python"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"

try:
    import asyncio
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated, StreamReset
    from aioquic.quic.packet import QuicProtocolVersion
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip h3: no aioquic (python3 -m venv build/qenv && build/qenv/bin/pip install aioquic)")
    sys.exit(0)

BASE = 29000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, RELAY = BASE, BASE + 1, BASE + 2
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


def backend():
    import http.server
    import socketserver

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path.startswith("/big/"):
                n = int(self.path[5:])
                body = bytes(random.Random(n).randbytes(n))
            else:
                body = f"hello {self.path} {self.headers.get('Host')}\n".encode()
            self.send_response(404 if self.path == "/missing" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Back", "yes")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            b = self.rfile.read(n) if n else b""
            if not n and self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    sz = int(self.rfile.readline().split(b";")[0], 16)
                    if sz == 0:
                        self.rfile.readline()
                        break
                    b += self.rfile.read(sz)
                    self.rfile.readline()
            body = hashlib.md5(b).hexdigest().encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class T(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 256
    T(("127.0.0.1", BACK), H).serve_forever()


def relay(drop):
    """A UDP relay to okena dropping `drop` of the datagrams each way."""
    rng = random.Random(7)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", RELAY))
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.connect(("127.0.0.1", LST))
    client = [None]

    def back():
        while True:
            d = up.recv(65536)
            if client[0] and rng.random() >= drop:
                s.sendto(d, client[0])
    threading.Thread(target=back, daemon=True).start()
    while True:
        d, a = s.recvfrom(65536)
        client[0] = a
        if rng.random() >= drop:
            up.send(d)


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.res = {}
        self.ended = {}
        self.closed = None

    def quic_event_received(self, ev):
        if isinstance(ev, ConnectionTerminated):
            self.closed = ev
            for f in self.ended.values():
                if not f.done():
                    f.set_result(None)
        if isinstance(ev, StreamReset) and ev.stream_id in self.ended:
            self.ended[ev.stream_id].set_result(None)
        for e in self.h3.handle_event(ev):
            r = self.res.setdefault(e.stream_id, {"headers": None, "body": b""})
            if isinstance(e, HeadersReceived) and r["headers"] is None:
                r["headers"] = dict(e.headers)
            if isinstance(e, DataReceived):
                r["body"] += e.data
            if getattr(e, "stream_ended", False) and e.stream_id in self.ended:
                self.ended[e.stream_id].set_result(None)

    async def request(self, method, path, body=None, length=True):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b":method", method.encode()), (b":scheme", b"https"), (b":authority", b"h3.test"),
                (b":path", path.encode())]
        if body is not None and length:
            hdrs.append((b"content-length", str(len(body)).encode()))
        self.ended[sid] = asyncio.get_running_loop().create_future()
        self.h3.send_headers(sid, hdrs, end_stream=body is None)
        if body is not None:
            self.h3.send_data(sid, body, end_stream=True)
        self.transmit()
        try:
            await asyncio.wait_for(self.ended[sid], 20)
        except asyncio.TimeoutError:
            return {"headers": None, "body": b"", "timeout": sid}
        return self.res.get(sid, {"headers": None, "body": b""})


def config(version=None):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    if version:
        cfg.supported_versions = [version]
    return cfg


async def cases():
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        check("handshake: ALPN h3", c._quic.tls.alpn_negotiated == "h3", str(c._quic.tls.alpn_negotiated))
        r = await c.request("GET", "/hello?x=1")
        h = r["headers"] or {}
        check("GET: the backend's 200, its fields, :authority as Host",
              h.get(b":status") == b"200" and h.get(b"x-back") == b"yes"
              and r["body"] == b"hello /hello?x=1 h3.test\n", str(r)[:200])
        r = await c.request("GET", "/missing")
        check("its status as it is (404)", (r["headers"] or {}).get(b":status") == b"404", str(r["headers"]))
        n = 3_000_000
        r = await c.request("GET", f"/big/{n}")
        check("GET of 3 MB, whole", r["body"] == bytes(random.Random(n).randbytes(n)),
              f"{len(r['body'])} bytes {r['headers']} {r['body'][:120]}")
        up = os.urandom(3_000_000)
        r = await c.request("POST", "/up", up)
        check("POST of 3 MB with content-length", r["body"] == hashlib.md5(up).hexdigest().encode(), str(r)[:120])
        r = await c.request("POST", "/up", up[:500_000], length=False)
        check("POST of 500 KB without content-length (chunk-framed to the backend)",
              r["body"] == hashlib.md5(up[:500_000]).hexdigest().encode(), str(r)[:120])
        rs = await asyncio.gather(*[c.request("GET", f"/s{i}") for i in range(20)])
        check("20 streams at once on one connection",
              all(x["body"] == f"hello /s{i} h3.test\n".encode() for i, x in enumerate(rs)),
              str([x["body"][:20] for x in rs]))
        rs = await asyncio.gather(*[c.request("GET", f"/big/{200_000 + i}") for i in range(8)])
        check("8 responses of 200 KB at once, interleaved",
              all(x["body"] == bytes(random.Random(200_000 + i).randbytes(200_000 + i)) for i, x in enumerate(rs)),
              str([(len(x["body"]), x.get("timeout"), (x["headers"] or {}).get(b":status")) for x in rs]))
    async with connect("127.0.0.1", LST, configuration=config(QuicProtocolVersion.VERSION_2),
                       create_protocol=Client) as c:
        r = await c.request("GET", "/v2")
        check("QUIC version 2 (RFC 9369)", r["body"] == b"hello /v2 h3.test\n" and c._quic._version == 0x6B3343CF,
              str(r)[:100])
    # through a lossy relay: what is lost is sent again
    threading.Thread(target=relay, args=(0.1,), daemon=True).start()
    async with connect("127.0.0.1", RELAY, configuration=config(), create_protocol=Client) as c:
        n = 1_000_000
        r = await c.request("GET", f"/big/{n}")
        check("GET of 1 MB with a tenth of the datagrams lost each way",
              r["body"] == bytes(random.Random(n).randbytes(n)), f"{len(r['body'])} bytes {r.get('timeout')} {c.closed} {c._quic._state} {c._quic._loss.bytes_in_flight} "
              f"{[(k, v.sender.highest_offset, v.receiver._highest_offset if hasattr(v.receiver, '_highest_offset') else '') for k, v in c._quic._streams.items()]}")
        up = os.urandom(500_000)
        r = await c.request("POST", "/up", up)
        check("POST of 500 KB the same way", r["body"] == hashlib.md5(up).hexdigest().encode(), str(r)[:80])


def version_negotiation():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    pkt = bytes([0xC0]) + bytes.fromhex("1a2a3a4a") + b"\x08" + b"D" * 8 + b"\x08" + b"S" * 8
    s.sendto(pkt.ljust(1200, b"\0"), ("127.0.0.1", LST))
    try:
        d = s.recv(2048)
    except socket.timeout:
        d = b""
    check("an unknown version: Version Negotiation offering v2 and v1",
          d[1:5] == b"\0\0\0\0" and d[6:14] == b"S" * 8 and d[15:23] == b"D" * 8
          and d[23:31] == bytes.fromhex("6b3343cf00000001"), d.hex())


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h3-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test,DNS:localhost", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    threading.Thread(target=backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{LST} {{
    http2 on
    http3 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    access_log {tmp / 'access.log'}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.5)
        asyncio.run(cases())
        version_negotiation()
        curl = shutil.which("curl")
        if curl and "HTTP3" in subprocess.run([curl, "--version"], capture_output=True, text=True).stdout:
            r = subprocess.run([curl, "-qsk", "--http3-only", "--resolve", f"h3.test:{LST}:127.0.0.1",
                                f"https://h3.test:{LST}/curl"], capture_output=True, timeout=20)
            check("curl (ngtcp2) over HTTP/3", r.stdout.startswith(b"hello /curl h3.test"), r.stdout[:80] + r.stderr[:80])
        log.seek(0)
        text = log.read()
        check("no worker died", "killed" not in text and "exited with status" not in text, text[-300:])
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    if failures:
        try:
            print("".join(l for l in open(tmp / "access.log") if '"status":200' not in l)[-2000:])
        except OSError:
            pass
    print(f"h3 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
