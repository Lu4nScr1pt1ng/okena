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
sys.stdout.reconfigure(line_buffering=True)     # (each line as it comes: what took long shows)

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
INNER_H2, INNER_TLS = BASE + 16, BASE + 17
PREF, PREF_TO = BASE + 18, BASE + 19
EARLY = BASE + 20
SLOW = BASE + 21
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
            if "/big/" in self.path:                    # (/viah2/big/N, /viatls/big/N too)
                n = int(self.path.split("/big/")[1])
                body = bytes(random.Random(n).randbytes(n))
            else:
                body = f"hello {self.path} {self.headers.get('Host')}\n".encode()
                if self.path.startswith("/e"):
                    body = f"{self.path} early={self.headers.get('Early-Data')}".encode()
                if self.headers.get("X-Dyn"):
                    body = f"{self.headers.get('X-Dyn')}|{self.headers.get('X-Stay')}".encode()
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

        def handle_error(self, *a):
            pass                    # (tracebacks from daemon threads at exit abort Python)
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
            self.res.setdefault(ev.stream_id, {"headers": None, "body": b""})["reset"] = ev.error_code
            self.ended[ev.stream_id].set_result(None)
        for e in self.h3.handle_event(ev):
            r = self.res.setdefault(e.stream_id, {"headers": None, "body": b""})
            if isinstance(e, HeadersReceived) and r["headers"] is None:
                r["headers"] = dict(e.headers)
            if isinstance(e, DataReceived):
                r["body"] += e.data
            if getattr(e, "stream_ended", False) and e.stream_id in self.ended:
                self.ended[e.stream_id].set_result(None)

    async def request(self, method, path, body=None, length=True, extra=()):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b":method", method.encode()), (b":scheme", b"https"), (b":authority", b"h3.test"),
                (b":path", path.encode())] + list(extra)
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
        n = 3_000_000
        for via in ("viah2", "viatls"):                  # their areas are not the send ring's
            r = await c.request("GET", f"/{via}/big/{n}")
            check(f"3 MB through a backend pool that uses {via[3:]}: whole",
                  r["body"] == bytes(random.Random(n).randbytes(n)), f"{len(r['body'])} bytes {str(r)[:100]}")
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
    # QPACK's dynamic table: the client inserts, okena confirms; many values
    # evict and move the entries
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        stay = b"the-same-long-value-" + b"s" * 60
        ok = True
        for i in range(100):                    # (~20 KB inserted: the table turns over and over;
            v = f"value-{i}-".encode() + b"x" * (i % 90)   # qpack_raw's evictions are by hand)
            r = await c.request("GET", "/dyn", extra=[(b"x-dyn", v), (b"x-stay", stay), (f"x-n{i % 7}".encode(), v)])
            ok = ok and r["body"] == v + b"|" + stay
        check("QPACK dynamic table: 100 requests inserting, evicting; every value right",
              ok and c.h3._encoder_bytes_sent > 20 and c.h3._decoder_bytes_received > 10 and c.closed is None,
              f"{r['body'][:40]} encoder {c.h3._encoder_bytes_sent} decoder {c.h3._decoder_bytes_received} {c.closed}")
    await qpack_raw()
    from aioquic.tls import CipherSuite
    cfg = config()
    cfg.cipher_suites = [CipherSuite.CHACHA20_POLY1305_SHA256]
    async with connect("127.0.0.1", LST, configuration=cfg, create_protocol=Client) as c:
        r1 = await c.request("GET", "/cc")
        c._quic.request_key_update()
        r2 = await c.request("GET", "/cc2")
        check("ChaCha20-Poly1305, and a key update with it",
              r1["body"] == b"hello /cc h3.test\n" and r2["body"] == b"hello /cc2 h3.test\n", f"{r1['body']} {r2['body']} {r2.get('timeout')} {c.closed}")
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
    # 0-RTT: on a listener that takes it, safe requests in early data
    for port, on in ((EARLY, True), (LST, False)):
        tickets = []
        async with connect("127.0.0.1", port, configuration=config(), create_protocol=Client,
                           session_ticket_handler=tickets.append) as c:
            await c.request("GET", "/warm")
            for _ in range(20):
                if tickets:
                    break
                await asyncio.sleep(0.05)
        cfg = config()
        cfg.session_ticket = tickets[0] if tickets else None
        async with connect("127.0.0.1", port, configuration=cfg, create_protocol=Client,
                           wait_connected=False) as c:
            g = asyncio.ensure_future(c.request("GET", "/e1"))
            p = asyncio.ensure_future(c.request("POST", "/e2", b"x" * 10))
            rg, rp = await g, await p
            took = c._quic.tls.early_data_accepted
            if on:
                check("0-RTT (`early_data on`): taken; a GET in it served, the backend told (Early-Data: 1)",
                      took and rg["body"] == b"/e1 early=1", f"took {took} {rg['body'][:40]} {tickets[0].max_early_data_size if tickets else None}")
                check("  a POST in it refused unprocessed (REQUEST_REJECTED), to be sent again",
                      rp.get("reset") == 0x10B, str(rp)[:120])
            else:
                check("0-RTT not taken where the listener does not say so (the requests go in 1-RTT)",
                      not took and rg["body"] == b"/e1 early=None", f"took {took} {rg['body'][:40]}")
    # preferred_address: the client validates it and moves there
    async with connect("127.0.0.1", PREF, configuration=config(), create_protocol=Client) as c:
        pa = c._quic._remote_preferred_address
        froms, took = set(), c.datagram_received
        c.datagram_received = lambda d, a: (froms.add(a[1]), took(d, a))[1]
        bodies = []
        for i in range(6):
            r = await c.request("GET", f"/pa{i}")
            bodies.append(r["body"])
            await asyncio.sleep(0.05)
        n = 2_000_000
        rb = await c.request("GET", f"/big/{n}")
        check("  2 MB after the move (the client's probes on its new path answered there, not moving it)",
              rb["body"] == bytes(random.Random(n).randbytes(n)), f"{len(rb['body'])} bytes {rb.get('timeout')}")
        check("preferred_address: announced, validated by the client, the connection moved there",
              pa is not None and pa.ipv4_address == ("127.0.0.1", PREF_TO) and len(pa.connection_id) == 8
              and bodies == [f"hello /pa{i} h3.test\n".encode() for i in range(6)]
              and c._quic._network_paths[0].addr[1] == PREF_TO,
              f"{pa} paths {[(p.addr, p.is_validated) for p in c._quic._network_paths]} {bodies[-1][:30]}")
        check("preferred_address: its datagrams come from that socket (1-RTT packets remember theirs)",
              PREF_TO in froms, str(froms))
    # a small probe from another address (spoofable: it is not validated)
    # answered with 3x its size at most, not padded to 1200
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/probe")
        q = c._quic
        q._write_ping_frame = lambda b, uids=[], comment="": b.start_frame(0).push_bytes(b"\x1a12345678")
        for space in q._spaces.values():	# (an ACK would make it not a probe: the connection moves)
            space.ack_at = None
        q.send_ping(1)
        probe = min((d for d, _ in q.datagrams_to_send(now=time.time())), key=len)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(probe, ("127.0.0.1", LST))
        try:
            answer = len(s.recv(2048))
        except TimeoutError:
            answer = 0
        s.close()
        check("a small PATH_CHALLENGE from another address: answered, 3x its size at most",
              0 < answer <= 3 * len(probe) and len(probe) < 400, f"{len(probe)} -> {answer}")
        r = await c.request("GET", "/after-probe")
        check("  and the connection did not move for it", r["body"].startswith(b"hello /after-probe"), str(r)[:80])
        # a flood of them: only so many answers a second
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        for i in range(60):
            for space in q._spaces.values():
                space.ack_at = None
            q.send_ping(2)
            for d, _ in q.datagrams_to_send(now=time.time()):
                s.sendto(d, ("127.0.0.1", LST))
        answers = 0
        try:
            while True:
                s.recv(2048)
                answers += 1
        except TimeoutError:
            pass
        s.close()
        check("  60 of them at once: at most the second's budget answered", 0 < answers <= 16, str(answers))
    # slow clients, the connection kept alive: a head that never ends, a
    # body that stops
    async with connect("127.0.0.1", SLOW, configuration=config(), create_protocol=Client) as c:
        q = c._quic
        head, body = q.get_next_available_stream_id(), None
        c.ended[head] = asyncio.get_running_loop().create_future()
        q.send_stream_data(head, b"\x01\x40\x40\x00\x00")
        body = q.get_next_available_stream_id()
        c.ended[body] = asyncio.get_running_loop().create_future()
        c.h3.send_headers(body, [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"h3.test"),
                                 (b":path", b"/up"), (b"content-length", b"1000")])
        q.send_stream_data(body, b"\x00\x40\x64abc")
        c.transmit()
        for i in range(20):
            await asyncio.sleep(0.2)
            q.send_ping(4 + i)
            c.transmit()
            if c.ended[head].done() and c.ended[body].done():
                break
        rh, rb = c.res.get(head, {}), c.res.get(body, {})
        check("timeout header: a head that never ends, H3_REQUEST_INCOMPLETE", rh.get("reset") == 0x10D, str(rh)[:80])
        check("timeout body_idle: a body that stops, 408",
              (rb.get("headers") or {}).get(b":status") == b"408", str(rb)[:80])
        r = await c.request("GET", "/after-slow")
        check("  and the connection goes on", r["body"].startswith(b"hello /after-slow"), str(r)[:80])
    # okena's own answer has no pool: a redirect used to take the worker down
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        r = await c.request("GET", "/away")
        h = r["headers"] or {}
        check("a redirect: answered, the connection goes on",
              h.get(b":status") == b"302" and h.get(b"location") == b"/elsewhere"
              and (await c.request("GET", "/after-away"))["body"].startswith(b"hello /after-away"), str(r)[:100])
    # a small answer is one datagram: its ACK goes with it, MAX_STREAMS only
    # when the client is running out
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/one")			# (its fields in QPACK's table: no more inserts)
        await asyncio.sleep(0.05)
        got, took = [0], c.datagram_received
        c.datagram_received = lambda d, a: (got.__setitem__(0, got[0] + 1), took(d, a))[1]
        for i in range(10):
            await c.request("GET", "/one")
            await asyncio.sleep(0.01)
        # (two a request: this backend writes its head and its body apart)
        check("10 small answers, in about as many datagrams", got[0] <= 22, str(got[0]))
    # HEADERS frames split across packets on several streams at once (quiche
    # in 0-RTT): each answered, in turn, none refused
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        q = c._quic
        ids, frames = [], []
        for i in range(4):
            sid = q.get_next_available_stream_id()
            q._get_or_create_stream_for_send(sid)
            c.ended[sid] = asyncio.get_running_loop().create_future()
            path = b"/split%d" % i
            block = bytes([0, 0, 0xD1, 0xD7, 0x50, 7]) + b"h3.test" + bytes([0x51, len(path)]) + path
            ids.append(sid)
            frames.append(bytes([1, len(block)]) + block)
        for sid, f in zip(ids, frames):
            q.send_stream_data(sid, f[:5])
            c.transmit()
            await asyncio.sleep(0.01)
        for sid, f in reversed(list(zip(ids, frames))):
            q.send_stream_data(sid, f[5:], end_stream=True)
            c.transmit()
            await asyncio.sleep(0.01)
        await asyncio.wait([c.ended[s] for s in ids], timeout=3)
        bodies = [c.res.get(s, {}).get("body") for s in ids]
        check("4 heads split at once: all answered, none refused",
              bodies == [b"hello /split%d h3.test\n" % i for i in range(4)],
              str([(c.res.get(s, {}).get("reset"), c.res.get(s, {}).get("body")) for s in ids]))
        r = await c.request("GET", "/after-split")
        check("  and the connection goes on", r["body"].startswith(b"hello /after-split"), str(r)[:80])
    # an ACK of a packet never sent (an optimistic ACK): PROTOCOL_VIOLATION
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=Client) as c:
        await c.request("GET", "/ack")
        q = c._quic
        q._write_ping_frame = lambda b, uids=[], comment="": b.start_frame(0).push_bytes(
            b"\x02\xbf\xff\xff\xff\x00\x00\x00")
        q.send_ping(3)
        c.transmit()
        await asyncio.sleep(0.2)
        code = q._close_event.error_code if q._close_event else None
        check("an ACK of a packet never sent: PROTOCOL_VIOLATION", code == 0x0A, str(code))
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


def qp_i(v, bits, high=0):
    """A QPACK integer of a prefix of `bits`, the first byte's high bits."""
    m = (1 << bits) - 1
    if v < m:
        return bytes([high | v])
    out, v = [high | m], v - m
    while v >= 128:
        out.append(v % 128 | 128)
        v //= 128
    return bytes(out + [v])


def qp_lit(b):
    return qp_i(len(b), 7) + b


class RawClient(QuicConnectionProtocol):
    """QUIC with no HTTP/3 layer: streams' bytes as they come."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.got, self.ended, self.closed = {}, {}, None

    def quic_event_received(self, ev):
        if isinstance(ev, ConnectionTerminated):
            self.closed = ev
            for f in self.ended.values():
                if not f.done():
                    f.set_result(None)
        if hasattr(ev, "data") and hasattr(ev, "stream_id"):
            self.got[ev.stream_id] = self.got.get(ev.stream_id, b"") + ev.data
            if ev.end_stream and ev.stream_id in self.ended and not self.ended[ev.stream_id].done():
                self.ended[ev.stream_id].set_result(None)


def h3_body(b):
    """The DATA frames' bytes of a raw response stream."""
    out, i = b"", 0

    def var():
        nonlocal i
        n = 1 << (b[i] >> 6)
        v = int.from_bytes(b[i:i + n], "big") & ((1 << (8 * n - 2)) - 1)
        i += n
        return v
    while i < len(b):
        t, n = var(), var()
        if t == 0:
            out += b[i:i + n]
        i += n
    return out


async def qpack_raw():
    """QPACK by hand on the encoder stream: inserts past the capacity, then
    field sections referencing what is left in each way there is."""
    async with connect("127.0.0.1", LST, configuration=config(), create_protocol=RawClient) as c:
        enc = c._quic.get_next_available_stream_id(is_unidirectional=True)
        ins = bytes([2]) + qp_i(1024, 5, 0x20)           # the type, Set Capacity
        for i in range(198):                             # literal name, evicting, moving the bytes
            ins += qp_i(6, 5, 0x40) + b"x-junk" + qp_lit(b"j" * (40 + i % 60))
        ins += qp_i(5, 5, 0x40) + b"x-dyn" + qp_lit(b"from-table")   # index 198
        ins += qp_i(6, 5, 0x40) + b"x-stay" + qp_lit(b"also-table")  # index 199
        ric = 200
        c._quic.send_stream_data(enc, ins)
        c.transmit()
        await asyncio.sleep(0.2)

        async def section(prefix, lines):
            sid = c._quic.get_next_available_stream_id()
            base = bytes([0xC0 | 17, 0xC0 | 23]) + qp_i(0, 4, 0x50) + qp_lit(b"h3.test") + qp_i(1, 4, 0x50) + qp_lit(b"/raw")
            block = prefix + base + lines
            c.ended[sid] = asyncio.get_running_loop().create_future()
            c._quic.send_stream_data(sid, bytes([1]) + bytes([0x40 | len(block) >> 8, len(block) & 255]) + block, True)
            c.transmit()
            try:
                await asyncio.wait_for(c.ended[sid], 5)
            except asyncio.TimeoutError:
                pass
            return h3_body(c.got.get(sid, b""))

        # a malformed request (no :path) with its body and its end in the same
        # packet: the stream refused, nothing after it read, the connection
        # going on
        sid = c._quic.get_next_available_stream_id()
        bad = bytes([0, 0, 0xC0 | 20, 0xC0 | 23]) + qp_i(0, 4, 0x50) + qp_lit(b"h3.test")
        c.ended[sid] = asyncio.get_running_loop().create_future()
        c._quic.send_stream_data(sid, bytes([1, len(bad)]) + bad + bytes([0, 3]) + b"abc", True)
        c.transmit()
        await asyncio.sleep(0.3)
        eic = qp_i(ric % 128 + 1, 8)
        r = await section(eic + qp_i(0, 7), qp_i(1, 6, 0x80) + qp_i(0, 6, 0x80))
        check("a malformed request with its body in one packet: refused, the connection lives",
              c.closed is None and r == b"from-table|also-table", f"{c.closed} {r}")
        r = await section(eic + qp_i(0, 7), qp_i(1, 6, 0x80) + qp_i(0, 6, 0x80))
        check("QPACK by hand: indexed entries, after evictions and compaction", r == b"from-table|also-table", str(r))
        r = await section(eic + qp_i(1, 7, 0x80), qp_i(0, 4, 0x10) + qp_i(1, 4, 0x10))
        check("  post-base references (Base below the Insert Count)", r == b"from-table|also-table", str(r))
        r = await section(eic + qp_i(0, 7), qp_i(1, 4, 0x40) + qp_lit(b"mine") + qp_i(0, 6, 0x80))
        check("  a name from the table, a value of its own", r == b"mine|also-table", str(r))
        await section(eic + qp_i(0, 7), qp_i(150, 6, 0x80))
        for _ in range(20):
            if c.closed:
                break
            await asyncio.sleep(0.1)
        check("  a reference to an evicted entry: QPACK_DECOMPRESSION_FAILED",
              c.closed is not None and c.closed.error_code == 0x200, str(c.closed))


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
        master = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()[0]	# (under timeout)
        workers = subprocess.run(["pgrep", "-P", master], capture_output=True, text=True).stdout.split()
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
    route /away {{ redirect 302 /elsewhere }}
    route /viah2/* {{ to pool viah2 }}
    route /viatls/* {{ to pool viatls }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
pool viah2 {{
    protocol h2
    server 127.0.0.1:{INNER_H2}
}}
pool viatls {{
    tls {{ trust {tmp / 'c.pem'}; sni h3.test }}
    server 127.0.0.1:{INNER_TLS}
}}
http 127.0.0.1:{INNER_H2} {{
    http2 on
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{INNER_TLS} {{
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{EARLY} {{
    http3 on
    early_data on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{SLOW} {{
    http3 on
    timeout {{ header 1s; body_idle 1s }}
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{PREF} {{
    http3 on
    preferred_address 127.0.0.1:{PREF_TO}
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
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
    p = subprocess.Popen(["timeout", "--foreground", "150", str(BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.5)
        asyncio.run(cases())
        version_negotiation()
        curl = shutil.which("curl")
        if curl and "HTTP3" in subprocess.run([curl, "--version"], capture_output=True, text=True).stdout:
            r = subprocess.run([curl, "-qsk", "--http3-only", "--resolve", f"h3.test:{LST}:127.0.0.1",
                                f"https://h3.test:{LST}/curl"], capture_output=True, timeout=20)
            check("curl (ngtcp2) over HTTP/3", r.stdout.startswith(b"hello /curl h3.test"), r.stdout[:80] + r.stderr[:80])
            up = tmp / "up.bin"
            up.write_bytes(os.urandom(5_000_000))
            r = subprocess.run([curl, "-qsk", "--http3-only", "--resolve", f"h3.test:{LST}:127.0.0.1",
                                "--data-binary", f"@{up}", f"https://h3.test:{LST}/up"], capture_output=True, timeout=30)
            check("curl uploads 5 MB (its datagrams GSO-sent, taken whole by GRO)",
                  r.stdout == hashlib.md5(up.read_bytes()).hexdigest().encode(), r.stdout[:80] + r.stderr[:80])
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
