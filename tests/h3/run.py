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
BACK, LST, RELAY, RETRY, V2 = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
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
            if self.path == "/slow":
                time.sleep(1)
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


def mtu_relay(port, mtu, seen):
    """A UDP relay to okena that drops datagrams larger than `mtu` (a path
    that takes no more); seen[0]: the largest of okena's it forwarded."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.connect(("127.0.0.1", LST))
    client = [None]

    def back():
        while True:
            d = up.recv(65536)
            if client[0] and len(d) <= mtu:
                seen[0] = max(seen[0], len(d))
                s.sendto(d, client[0])
    threading.Thread(target=back, daemon=True).start()
    while True:
        d, a = s.recvfrom(65536)
        client[0] = a
        if len(d) <= mtu:
            up.send(d)


def ecn_relay(port, marks):
    """A UDP relay to okena that records the ECN codepoint of each of its
    datagrams."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    up.connect(("127.0.0.1", LST))
    client = [None]

    def back():
        while True:
            d, anc, _, _ = up.recvmsg(65536, 64)
            marks.append(anc[0][2][0] & 3 if anc else 0)
            if client[0]:
                s.sendto(d, client[0])
    threading.Thread(target=back, daemon=True).start()
    while True:
        d, a = s.recvfrom(65536)
        client[0] = a
        up.send(d)


def rebind_relay(port, moves):
    """A UDP relay to okena whose own address changes (a NAT rebinding)
    after each count of client datagrams in `moves`: (count, source IP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    client = [None]
    ups = []

    def new_up(ip):
        for old in ups:                                 # the old address is gone
            old.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind((ip, 0))
        u.connect(("127.0.0.1", LST))
        ups.append(u)

        def back():
            while True:
                try:
                    d = u.recv(65536)
                except OSError:
                    return
                if client[0]:
                    s.sendto(d, client[0])
        threading.Thread(target=back, daemon=True).start()
    new_up("127.0.0.1")
    n, moves = 0, list(moves)
    while True:
        d, a = s.recvfrom(65536)
        client[0] = a
        n += 1
        if moves and n == moves[0][0]:
            new_up(moves.pop(0)[1])
        ups[-1].send(d)


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        if self._quic.configuration.alpn_protocols == ["hq-interop"]:
            from aioquic.h0.connection import H0Connection
            self.h3 = H0Connection(self._quic)
        else:
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
            return dict(self.res.get(sid, {"headers": None, "body": b""}), timeout=sid)
        return self.res.get(sid, {"headers": None, "body": b""})


def config(version=None):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    # v1 unless asked (aioquic's key updates in v2 use v1's label, "quic ku",
    # not RFC 9369's "quicv2 ku")
    cfg.supported_versions = [version or QuicProtocolVersion.VERSION_1]
    return cfg


async def cases():
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        check("handshake: ALPN h3", c._quic.tls.alpn_negotiated == "h3", str(c._quic.tls.alpn_negotiated))
        r = await c.request("GET", "/hello?x=1")
        h = r["headers"] or {}
        check("GET: the backend's 200, its fields, :authority as Host",
              h.get(b":status") == b"200" and h.get(b"x-back") == b"yes" and b"alt-svc" not in h
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
        bodies = []
        for k in range(3):                               # the client updates its keys
            c._quic.request_key_update()
            r = await c.request("GET", f"/ku{k}")
            bodies.append(r["body"])
        check("key updates (RFC 9001 6): okena follows each, its packets in the new phase",
              bodies == [f"hello /ku{k} h3.test\n".encode() for k in range(3)], str(bodies))
        spare = len(c._quic._peer_cid_available)
        bodies = []
        for k in range(2):                               # onto the spare IDs, the old ones retired
            c._quic.change_connection_id()
            r = await c.request("GET", f"/cid{k}")
            bodies.append(r["body"])
        check("spare connection IDs (NEW_CONNECTION_ID); the client moves onto them and retires the old",
              spare >= 1 and bodies == [b"hello /cid0 h3.test\n", b"hello /cid1 h3.test\n"]
              and c._quic._peer_cid.sequence_number == 2, f"{spare} spare, {bodies}, seq {c._quic._peer_cid.sequence_number}")
        rs = await asyncio.gather(*[c.request("GET", f"/s{i}") for i in range(20)])
        check("20 streams at once on one connection",
              all(x["body"] == f"hello /s{i} h3.test\n".encode() for i, x in enumerate(rs)),
              str([x["body"][:20] for x in rs]))
        ok = True
        for b in range(5):                               # past the 100 streams allowed at first
            rs = await asyncio.gather(*[c.request("GET", f"/m{b}-{i}") for i in range(50)])
            ok = ok and all(x["body"] == f"hello /m{b}-{i} h3.test\n".encode() for i, x in enumerate(rs))
        check("250 requests on one connection (MAX_STREAMS raised, the stream table reused)", ok)
        rs = await asyncio.gather(*[c.request("GET", f"/big/{200_000 + i}") for i in range(8)])
        check("8 responses of 200 KB at once, interleaved",
              all(x["body"] == bytes(random.Random(200_000 + i).randbytes(200_000 + i)) for i, x in enumerate(rs)),
              str([(len(x["body"]), x.get("timeout"), (x["headers"] or {}).get(b":status")) for x in rs]))
    async with connect("127.0.0.1", LST, configuration=config(QuicProtocolVersion.VERSION_2),
                       create_protocol=Client) as c:
        r = await c.request("GET", "/v2")
        check("QUIC version 2 (RFC 9369)", r["body"] == b"hello /v2 h3.test\n" and c._quic._version == 0x6B3343CF,
              str(r)[:100])
    # hq-interop (the interop runner's HTTP/0.9): the body alone, many at once
    cfg = config()
    cfg.alpn_protocols = ["hq-interop"]
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client) as c:
        n = 300_000
        rs = await asyncio.gather(c.request("GET", "/hq"), c.request("GET", f"/big/{n}"),
                                  *[c.request("GET", f"/hq{i}") for i in range(30)])
        check("hq-interop: HTTP/0.9 on QUIC, the body alone, 32 streams at once",
              c._quic.tls.alpn_negotiated == "hq-interop" and rs[0]["body"] == b"hello /hq localhost\n"
              and rs[1]["body"] == bytes(random.Random(n).randbytes(n))
              and all(r["body"] == f"hello /hq{i} localhost\n".encode() for i, r in enumerate(rs[2:])),
              str([(i, r["body"][:30], r.get("timeout")) for i, r in enumerate(rs) if r.get("timeout")]))
    from aioquic.tls import CipherSuite
    cfg = config()
    cfg.cipher_suites = [CipherSuite.CHACHA20_POLY1305_SHA256]
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client) as c:
        r1 = await c.request("GET", "/cc")
        c._quic.request_key_update()
        r2 = await c.request("GET", "/cc2")
        check("ChaCha20-Poly1305, and a key update with it",
              r1["body"] == b"hello /cc h3.test\n" and r2["body"] == b"hello /cc2 h3.test\n", str((r1, r2))[:120])
    cfg = config()
    cfg.supported_versions = [QuicProtocolVersion.VERSION_1, QuicProtocolVersion.VERSION_2]
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client) as c:
        r = await c.request("GET", "/cvn")
        check("v1 offering v2 stays in v1 by default", r["body"] == b"hello /cvn h3.test\n"
              and c._quic._version == QuicProtocolVersion.VERSION_1, f"{r['body'][:40]} {c._quic._version}")
    async with connect("127.0.0.1", V2, configuration=cfg, create_protocol=Client) as c:
        r = await c.request("GET", "/cvn")
        check("`http3 v2`: compatible version negotiation (RFC 9368), v1 offering v2 ends in v2",
              r["body"] == b"hello /cvn h3.test\n" and c._quic._version == QuicProtocolVersion.VERSION_2,
              f"{r['body'][:40]} {c._quic._version}")
    # resumption: the ticket the first connection got resumes the second
    tickets = []
    cfg = config()
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client,
                       session_ticket_handler=tickets.append) as c:
        await c.request("GET", "/t1")
        for _ in range(20):
            if tickets:
                break
            await asyncio.sleep(0.05)
    cfg = config()
    cfg.session_ticket = tickets[0] if tickets else None
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client) as c:
        r = await c.request("GET", "/t2")
        check("resumption: a session ticket at 1-RTT, the next connection resumes with it (no 0-RTT)",
              len(tickets) >= 1 and c._quic.tls.session_resumed and r["body"] == b"hello /t2 h3.test\n"
              and not c._quic.tls.early_data_accepted,
              f"{len(tickets)} tickets, resumed {c._quic.tls.session_resumed}, {r['body'][:30]}")
    # `http3 retry`: a Retry first, its token back, then the handshake
    for ver, name in ((None, "v1"), (QuicProtocolVersion.VERSION_2, "v2")):
        async with connect("127.0.0.1", RETRY, configuration=config(ver), create_protocol=Client) as c:
            r = await c.request("GET", "/retried")
            check(f"http3 retry ({name}): a Retry, then the connection with its token",
                  r["body"] == b"hello /retried h3.test\n" and c._quic._retry_count == 1, str(r)[:100])
    # ECN: marked until a client's plain ACKs show it does not report the marks
    marks = []
    threading.Thread(target=ecn_relay, args=(RELAY + 13, marks), daemon=True).start()
    async with connect("127.0.0.1", RELAY + 13, configuration=config(), create_protocol=Client) as c:
        r = await c.request("GET", "/big/300000")
        check("ECN: ECT(0) at first, no marks once plain ACKs show the client does not report them",
              len(r["body"]) == 300000 and marks[0] == 2 and marks[-1] == 0 and marks[-20:] == [0] * 20,
              f"{len(r['body'])} bytes, marks {marks[:4]}..{marks[-4:]}")
    # the path MTU: 1200 until shown otherwise, probes find what the path takes
    for port, mtu, low, high in ((RELAY + 11, 1280, 1200, 1280), (RELAY + 12, 1500, 1401, 1452)):
        seen = [0]
        threading.Thread(target=mtu_relay, args=(port, mtu, seen), daemon=True).start()
        async with connect("127.0.0.1", port, configuration=config(), create_protocol=Client) as c:
            n = 1_000_000
            r = await c.request("GET", f"/big/{n}")
            check(f"a path of MTU {mtu}: 1 MB whole, datagrams up to {seen[0]}",
                  r["body"] == bytes(random.Random(n).randbytes(n)) and low <= seen[0] <= high,
                  f"{len(r['body'])} bytes {r.get('timeout')} largest {seen[0]}")
    # a NAT rebinding mid-transfer: a new port, then a new IP address
    threading.Thread(target=rebind_relay, args=(RELAY + 10, [(60, "127.0.0.1"), (300, "127.0.0.2")]),
                     daemon=True).start()
    async with connect("127.0.0.1", RELAY + 10, configuration=config(), create_protocol=Client) as c:
        n = 1_000_000
        r = await c.request("GET", f"/big/{n}")
        r2 = await c.request("GET", "/after-move")
        check("NAT rebinding mid-transfer (a new port, then a new IP): okena follows the client",
              r["body"] == bytes(random.Random(n).randbytes(n)) and r2["body"] == b"hello /after-move h3.test\n",
              f"{len(r['body'])} bytes {r.get('timeout')} {r2['body'][:40]}")
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


async def rapid_reset():
    """Requests opened and cancelled at once (STOP_SENDING), over and over: past 200 a
    second the connection closes with H3_EXCESSIVE_LOAD."""
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/hello")
        for i in range(300):
            sid = c._quic.get_next_available_stream_id()
            c.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"h3.test"),
                                    (b":path", b"/slow")], end_stream=True)
            c.transmit()
            await asyncio.sleep(0.001)
            c._quic.stop_stream(sid, 0x10C)                # STOP_SENDING: the answer is not wanted
            c.transmit()
            if c.closed:
                break
        for _ in range(30):
            if c.closed:
                break
            await asyncio.sleep(0.1)
        check("rapid reset: 300 requests opened and cancelled, the connection closes (H3_EXCESSIVE_LOAD)",
              c.closed is not None and c.closed.error_code == 0x107, str(c.closed))


async def stateless_reset(p):
    """A worker that restarts no longer holds the connection: a packet for
    it gets a Stateless Reset carrying the token the transport parameters
    announced (the key is the supervisor's, the same in the new worker)."""
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/hello")
        cid, token = c._quic._peer_cid.cid, c._quic._peer_cid.stateless_reset_token
        workers = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
        for w in workers:
            os.kill(int(w), 9)
        await asyncio.sleep(0.6)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(bytes([0x41]) + cid + os.urandom(60), ("127.0.0.1", LST))
        try:
            d = s.recv(2048)
        except socket.timeout:
            d = b""
        check("a worker restarted: a Stateless Reset with the announced token",
              len(token) == 16 and 21 <= len(d) < 69 and d[0] & 0xC0 == 0x40 and d[-16:] == token,
              f"{len(workers)} workers, {d.hex()} vs {token.hex()}")
        s.sendto(bytes([0x41]) + cid + b"x" * 34, ("127.0.0.1", LST))
        try:
            d = s.recv(2048)
        except socket.timeout:
            d = b""
        check("  always shorter than what triggered it (43 bytes: 42)", len(d) == 42 and d[-16:] == token, d.hex())


async def drain(p):
    """SIGTERM: GOAWAY, what is in flight finishes, then CONNECTION_CLOSE
    (H3_NO_ERROR) and the worker exits."""
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/hello")
        slow = asyncio.ensure_future(c.request("GET", "/slow"))
        await asyncio.sleep(0.3)
        p.terminate()
        r = await slow
        check("draining: a request in flight still finishes", r["body"] == b"hello /slow h3.test\n", str(r)[:120])
        for _ in range(30):
            if c.closed:
                break
            await asyncio.sleep(0.1)
        check("  then CONNECTION_CLOSE with H3_NO_ERROR", c.closed is not None and c.closed.error_code == 0x100,
              str(c.closed))
    t0 = time.time()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        pass
    check("  and okena exits before its drain timeout", p.poll() is not None and time.time() - t0 < 4,
          f"{p.poll()} after {time.time() - t0:.1f}s")


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
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=8s }}
http 127.0.0.1:{LST} {{
    http2 on
    http3 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    access_log {tmp / 'access.log'}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{V2} {{
    http3 v2
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{RETRY} {{
    http3 retry
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
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
            r = subprocess.run([curl, "-qsk", "--http3-only", "--resolve", f"h3.test:{RETRY}:127.0.0.1",
                                f"https://h3.test:{RETRY}/curl"], capture_output=True, timeout=20)
            check("curl through a Retry", r.stdout.startswith(b"hello /curl h3.test"), r.stdout[:80] + r.stderr[:80])
        for v in ("--http1.1", "--http2"):
            r = subprocess.run(["curl", "-qski", v, "--resolve", f"h3.test:{LST}:127.0.0.1",
                                f"https://h3.test:{LST}/alt"], capture_output=True, timeout=20)
            check(f"Alt-Svc on TCP ({v[2:]}) points at HTTP/3 on the port",
                  f'alt-svc: h3=":{LST}"; ma=86400'.encode() in r.stdout.lower(), r.stdout[:300])
        asyncio.run(rapid_reset())
        asyncio.run(stateless_reset(p))
        asyncio.run(drain(p))
        log.seek(0)
        text = log.read()
        text = text.replace("killed by signal 9", "")       # (the stateless reset case)
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
