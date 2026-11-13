#!/usr/bin/env python3
"""HTTP/3 at the edges this review touched, on one engine (argument): limits {
body_size } (413 for a content-length past it and for a body that grows past it);
a head larger than okena takes resets that stream alone (H3_EXCESSIVE_LOAD), and
the next request on the connection is served, a Huffman-coded one and a raw one.
Handshakes never answered (a flood's) put new clients through a Retry, and
go after 5 s without a word: a few seconds later clients come straight
in again, not after the idle timeout."""
import asyncio
import http.server
import socket
import os
import pathlib
import shutil
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
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, StreamReset
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip h3 edges: no aioquic")
    sys.exit(0)
BASE = 34500 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L, B = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); self.rfile.read(n) if n else None
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


class C(QuicConnectionProtocol):
    def __init__(s, *a, **k):
        super().__init__(*a, **k); s.h3 = H3Connection(s._quic); s.res = {}; s.ev = {}; s.closed = None
    def quic_event_received(s, ev):
        if isinstance(ev, ConnectionTerminated):
            s.closed = (ev.error_code, ev.reason_phrase)
            for f in s.ev.values():
                if not f.done(): f.set_result(None)
        if isinstance(ev, StreamReset) and ev.stream_id in s.ev:
            s.res.setdefault(ev.stream_id, {})["reset"] = ev.error_code; s.ev[ev.stream_id].set_result(None)
        for e in s.h3.handle_event(ev):
            r = s.res.setdefault(e.stream_id, {})
            if isinstance(e, HeadersReceived) and "status" not in r: r["status"] = dict(e.headers).get(b":status")
            if getattr(e, "stream_ended", False) and e.stream_id in s.ev and not s.ev[e.stream_id].done(): s.ev[e.stream_id].set_result(None)
    async def req(s, method, path, body=None, extra=(), cl=True):
        sid = s._quic.get_next_available_stream_id()
        h = [(b":method", method.encode()), (b":scheme", b"https"), (b":authority", b"h3.test"), (b":path", path.encode())] + list(extra)
        if body is not None and cl: h.append((b"content-length", str(len(body)).encode()))
        s.ev[sid] = asyncio.get_running_loop().create_future()
        s.h3.send_headers(sid, h, end_stream=body is None)
        if body is not None: s.h3.send_data(sid, body, end_stream=True)
        s.transmit()
        try: await asyncio.wait_for(s.ev[sid], 5)
        except asyncio.TimeoutError: return {"timeout": True}
        return s.res.get(sid, {})
async def cases():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE, server_name="h3.test")
    async with connect("127.0.0.1", L, configuration=cfg, create_protocol=C) as c:
        r = await c.req("GET", "/")
        check("a request: 200", r.get("status") == b"200", r)
        r = await c.req("POST", "/", b"x" * 5000)
        check("body_size: a content-length past it, 413", r.get("status") == b"413", r)
        r = await c.req("POST", "/", b"x" * 5000, cl=False)
        check("  a body that grows past it, 413", r.get("status") == b"413", r)
        r = await c.req("POST", "/", b"x" * 500)
        check("  one within it, 200", r.get("status") == b"200", r)
        r = await c.req("GET", "/", extra=[(b"x-big", b"a" * 20000)])
        check("a head past what okena takes (Huffman-coded): that stream reset, H3_EXCESSIVE_LOAD",
              r.get("reset") == 0x107 and c.closed is None, (r, c.closed))
        r = await c.req("GET", "/")
        check("  the next request on the connection: 200", r.get("status") == b"200" and c.closed is None, (r, c.closed))
        raw = bytes(range(0x21, 0x7F)) * 220            # (what Huffman makes longer: sent raw, 20 KB)
        r = await c.req("GET", "/", extra=[(b"x-raw", raw)])
        check("  and a raw one: no connection error", c.closed is None, (r, c.closed))
        r = await c.req("GET", "/")
        check("  still serving", r.get("status") == b"200", r)
    # 80 handshakes begun and never answered: past 64 not yet validated
    # (QUIC_RETRY_AT) a new client gets a Retry first
    flood = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    for _ in range(80):
        q = QuicConnection(configuration=fcfg)
        q.connect(("127.0.0.1", L), now=time.time())
        for d, _ in q.datagrams_to_send(now=time.time()):
            flood.sendto(d, ("127.0.0.1", L))
        await asyncio.sleep(0.002)

    async def retries():
        async with connect("127.0.0.1", L, configuration=cfg, create_protocol=C) as c:
            r = await c.req("GET", "/")
            return c._quic._retry_count, r.get("status")
    await asyncio.sleep(0.3)
    n, st = await retries()
    check("80 handshakes never answered: a new client goes through a Retry", n == 1 and st == b"200", (n, st))
    t0 = time.monotonic()
    while time.monotonic() - t0 < 20:
        n, st = await retries()
        if n == 0:
            break
        await asyncio.sleep(0.5)
    took = time.monotonic() - t0
    check("  they go after 5 s of silence: no Retry again", n == 0 and st == b"200" and took < 12,
          (n, st, round(took, 1)))
    flood.close()


def main():
    threading.Thread(target=S(("127.0.0.1", B), H).serve_forever, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h3edges-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test", "-days", "2"], check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\npool b {{ server 127.0.0.1:{B} }}\n"
                    f"http 127.0.0.1:{L} {{ http3 on; limits {{ body_size 1KiB }}; tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}; "
                    f"route /* {{ to pool b }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        time.sleep(0.5)
        asyncio.run(cases())
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"h3 edges {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
