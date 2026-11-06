#!/usr/bin/env python3
"""`cors` on a route, on one engine (argument): origins matched whole, a star
that only stands for a host, credentials never with any origin, Vary, preflights
answered here without spending the backend or a rate limit, the headers on
okena's own answers too, the backend's dropped, and each protocol."""
import asyncio
import http.client
import http.server
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    import aioquic  # noqa: F401
    HAVE_H3 = True
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    HAVE_H3 = False

ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 27000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
failures = 0
seen = [0]
A = "https://app.example.com"


def check(what, ok, more=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f": {more}"))
    failures += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        seen[0] += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        if "own" in self.path:
            self.send_header("Access-Control-Allow-Origin", "https://backend.says")
        self.end_headers()
        self.wfile.write(b"ok")

    do_OPTIONS = do_GET

    def log_message(self, *a):
        pass


def ask(path, origin=None, method="GET", headers=None):
    h = dict(headers or {})
    if origin:
        h["Origin"] = origin
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request(method, path, headers=h)
    r = c.getresponse()
    r.read()
    c.close()
    return r


CONF = """okena {{ workers 2; io_engine {engine} }}
http 127.0.0.1:{tls} {{
    http2 on
    http3 on
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ to 127.0.0.1:{back}; cors origins=https://app.example.com }}
}}
http 127.0.0.1:{lst} {{
    route /api {{ to 127.0.0.1:{back}; cors origins=https://app.example.com,https://b.test:8443 methods=GET,PUT headers=x-a,x-b expose=x-total max_age=10m credentials }}
    route /own {{ to 127.0.0.1:{back}; cors origins=https://app.example.com }}
    route /any {{ to 127.0.0.1:{back}; cors origins=* }}
    route /wild {{ to 127.0.0.1:{back}; cors origins=https://*.example.com }}
    route /echo {{ to 127.0.0.1:{back}; cors origins=https://app.example.com }}
    route /lim {{ to 127.0.0.1:{back}; cors origins=https://app.example.com; limit 1/h burst=1 }}
    route /gone {{ to 127.0.0.1:1; cors origins=https://app.example.com }}
    route /plain {{ to 127.0.0.1:{back} }}
}}
"""


async def h3_case(port, tmp):
    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    import ssl
    got = {}
    done = asyncio.Event()

    class C(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.h3 = H3Connection(self._quic)

        def quic_event_received(self, ev):
            for e in self.h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    got.update({k.decode(): v.decode() for k, v in e.headers})
                    done.set()

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", port, configuration=cfg, create_protocol=C) as c:
        sid = c._quic.get_next_available_stream_id()
        c.h3.send_headers(sid, [(b":method", b"OPTIONS"), (b":scheme", b"https"), (b":authority", b"c.test"),
                                (b":path", b"/x"), (b"origin", A.encode()),
                                (b"access-control-request-method", b"GET")], end_stream=True)
        c.transmit()
        await asyncio.wait_for(done.wait(), 5)
    return got


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-cors-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=c.test",
                    "-addext", "subjectAltName=DNS:c.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    http.server.ThreadingHTTPServer.request_queue_size = 64
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    text = CONF.format(engine=ENGINE, lst=LST, back=BACK, tls=TLS, tmp=tmp)
    conf.write_text(text)
    p = subprocess.Popen(["timeout", "--foreground", "30", str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        H_ = lambda r, n: r.getheader(n)
        r = ask("/api", A)
        check("allowed: echoed, not *, credentials, expose, Vary",
              H_(r, "access-control-allow-origin") == A and H_(r, "access-control-allow-credentials") == "true"
              and H_(r, "access-control-expose-headers") == "x-total" and H_(r, "vary") == "Origin", str(r.getheaders()))
        r = ask("/api", "https://b.test:8443")
        check("the list's second, with its port", H_(r, "access-control-allow-origin") == "https://b.test:8443", str(r.getheaders()))
        for bad in ("https://evil.com", "https://app.example.com.evil.com", "http://app.example.com",
                    "https://app.example.co", "https://b.test", "null", "https://APP.example.com"):
            r = ask("/api", bad)
            check(f"not allowed {bad}: served, no permission, Vary",
                  r.status == 200 and H_(r, "access-control-allow-origin") is None and H_(r, "vary") == "Origin",
                  str(r.getheaders()))
        r = ask("/api")
        check("no Origin: nothing added but Vary", H_(r, "access-control-allow-origin") is None and H_(r, "vary") == "Origin", str(r.getheaders()))
        r = ask("/any", "https://whoever.test")
        check("origins=*: *, no Vary", H_(r, "access-control-allow-origin") == "*" and H_(r, "vary") is None, str(r.getheaders()))
        r = ask("/wild", "https://a.b.example.com")
        check("https://*.example.com: a subdomain", H_(r, "access-control-allow-origin") == "https://a.b.example.com", str(r.getheaders()))
        for bad in ("https://example.com", "https://x.evil.com/.example.com", "https://evil.com#.example.com",
                    "http://a.example.com", "https://a.example.com.evil.com", "https://.example.co"):
            r = ask("/wild", bad)
            check(f"the star does not take {bad}", H_(r, "access-control-allow-origin") is None, str(r.getheaders()))
        before = seen[0]
        r = ask("/api", A, "OPTIONS", {"Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "x-a"})
        check("preflight: 204 from okena, all it needs",
              r.status == 204 and seen[0] == before and H_(r, "access-control-allow-origin") == A
              and H_(r, "access-control-allow-methods") == "GET,PUT" and H_(r, "access-control-allow-headers") == "x-a,x-b"
              and H_(r, "access-control-max-age") == "600" and H_(r, "access-control-allow-credentials") == "true"
              and "Access-Control-Request-Method" in H_(r, "vary"), f"{r.status} {r.getheaders()} {seen[0] - before}")
        r = ask("/echo", A, "OPTIONS", {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-mine"})
        check("  no list: the headers it asks for, usual methods",
              H_(r, "access-control-allow-headers") == "x-mine" and "POST" in H_(r, "access-control-allow-methods"), str(r.getheaders()))
        r = ask("/api", "https://evil.com", "OPTIONS", {"Access-Control-Request-Method": "PUT"})
        check("  an origin not allowed: 204, no permission", r.status == 204 and seen[0] == before
              and H_(r, "access-control-allow-origin") is None and H_(r, "access-control-allow-methods") is None, str(r.getheaders()))
        before = seen[0]
        r = ask("/api", A, "OPTIONS")
        check("OPTIONS without the request method: not a preflight, the backend's", r.status == 200 and seen[0] == before + 1, str(r.status))
        r = ask("/own", A)
        check("the backend's own say dropped", r.getheader("access-control-allow-origin") == A
              and len([1 for k, v in r.getheaders() if k.lower() == "access-control-allow-origin"]) == 1, str(r.getheaders()))
        rs = [ask("/lim", A, "OPTIONS", {"Access-Control-Request-Method": "GET"}).status for _ in range(5)]
        a, b = ask("/lim", A), ask("/lim", A)
        check("preflights spend no rate limit, a 429 says its origin",
              rs == [204] * 5 and a.status == 200 and b.status == 429 and H_(b, "access-control-allow-origin") == A,
              f"{rs} {a.status} {b.status} {b.getheaders()}")
        r = ask("/gone", A)
        check("okena's own error too", r.status >= 500 and H_(r, "access-control-allow-origin") == A, f"{r.status} {r.getheaders()}")
        r = ask("/plain", A)
        check("a route without it: untouched", H_(r, "access-control-allow-origin") is None and H_(r, "vary") is None, str(r.getheaders()))
        for proto in ("h1", "h2"):
            q = subprocess.run(["timeout", "10", str(BIN), "bench", f"https://127.0.0.1:{TLS}/x", f"proto={proto}",
                                "conns=2", "duration=1s", "warmup=0s", "workers=1", "format=kv", "method=OPTIONS",
                                f"header=origin: {A}", "header=access-control-request-method: GET"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
            check(f"preflights over {proto}", int(kv.get("ok", 0)) > 50 and kv.get("errors") == "0", q.stdout[:100])
        if HAVE_H3:
            g = asyncio.run(asyncio.wait_for(h3_case(TLS, tmp), 8))
            check("a preflight over h3", g.get(":status") == "204" and g.get("access-control-allow-origin") == A, str(g))
        check("the worker lives", ask("/plain").status == 200)
    finally:
        p.terminate()
        p.wait(10)
    for bad in ("cors", "cors methods=GET", "cors origins=* credentials", "cors origins=https://*.*.example.com"):
        c = tmp / "bad.conf"
        c.write_text(text.replace("cors origins=https://app.example.com,https://b.test:8443 methods=GET,PUT headers=x-a,x-b expose=x-total max_age=10m credentials", bad, 1))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{bad}: refused", q.returncode not in (0, 124) and "cors" in q.stderr, f"{q.returncode} {q.stderr[:90]}")
    if failures:
        print((tmp / "log").read_text()[-400:])
    print(f"cors {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
