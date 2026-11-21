#!/usr/bin/env python3
"""PROXY protocol received (`proxy_protocol accept`), on one engine (argument:
io_uring or epoll): v1 and v2 headers on tcp and http listeners, the client
they name used everywhere (the header sent on, X-Forwarded-For, allow,
per_source), what follows the header left intact (an L4 stream, a request, a
TLS handshake), headers that arrive in pieces, LOCAL and UNKNOWN, `from`
lists, and connections that are not headers at all."""
import http.server
import os
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 25500 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, HBACK = BASE, BASE + 1
TCP, TCPFROM, TCPOTHER, HTTP, HTTPS, LIM = (BASE + i for i in range(2, 8))
# (BASE + 8 .. 11 left for the other engine's offset)
SIG = b"\r\n\r\n\x00\r\nQUIT\n"

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def v1(src, dst, sport, dport):
    fam = "TCP6" if ":" in src else "TCP4"
    return f"PROXY {fam} {src} {dst} {sport} {dport}\r\n".encode()


def v2(src, dst, sport, dport, tlvs=b"", local=False):
    if local:
        return SIG + bytes([0x20, 0x00]) + struct.pack("!H", len(tlvs)) + tlvs
    if ":" in src:
        body = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
        fam = 0x21
    else:
        body = socket.inet_pton(socket.AF_INET, src) + socket.inet_pton(socket.AF_INET, dst)
        fam = 0x11
    body += struct.pack("!HH", sport, dport) + tlvs
    return SIG + bytes([0x21, fam]) + struct.pack("!H", len(body)) + body


def read_header(c):
    """The v2 header okena sends on: (src, dst, sport, dport)."""
    hdr = b""
    while len(hdr) < 16:
        hdr += c.recv(16 - len(hdr))
    assert hdr[:12] == SIG, hdr
    length = struct.unpack("!H", hdr[14:16])[0]
    body = b""
    while len(body) < length:
        body += c.recv(length - len(body))
    if hdr[13] == 0x11:
        return (socket.inet_ntop(socket.AF_INET, body[0:4]), socket.inet_ntop(socket.AF_INET, body[4:8]),
                *struct.unpack("!HH", body[8:12]))
    return (socket.inet_ntop(socket.AF_INET6, body[0:16]), socket.inet_ntop(socket.AF_INET6, body[16:32]),
            *struct.unpack("!HH", body[32:36]))


seen = {}


def tcp_backend():
    """Reads okena's PROXY v2 header, then a tag; answers "ok" + the tag."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(256)

    def handle(c):
        try:
            h = read_header(c)
            tag = c.recv(64)
            seen[tag] = h
            c.sendall(b"ok" + tag)
        except Exception as e:
            seen[b"error"] = repr(e)
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = (self.headers.get("x-forwarded-for") or "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def connect(port, family=socket.AF_INET, host="127.0.0.1"):
    c = socket.socket(family)
    c.settimeout(5)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.connect((host, port))
    return c


def tcp_through(header, tag, port=TCP, pieces=1):
    """Sends header + tag in `pieces` writes; returns (answer, what the backend saw)."""
    c = connect(port)
    data = header + tag
    step = max(1, len(header) // pieces)
    try:
        for i in range(0, len(header), step):
            c.sendall(data[i:i + step] if i + step < len(header) else data[i:len(header)])
            if pieces > 1:
                time.sleep(0.03)
        c.sendall(tag)
        r = b""
        while len(r) < 2 + len(tag):
            d = c.recv(64)
            if not d:
                break
            r += d
    except OSError as e:
        r = repr(e).encode()
    finally:
        c.close()
    return r, seen.get(tag)


def closed_without_answer(port, data, wait=3):
    c = connect(port)
    try:
        c.sendall(data)
        c.settimeout(wait)
        return c.recv(64) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False
    finally:
        c.close()


def http_get(port, header, path="/", tls=False):
    c = connect(port)
    c.sendall(header)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c = ctx.wrap_socket(c, server_hostname="pp.test")
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: pp.test\r\nConnection: close\r\n\r\n".encode())
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    head, _, body = r.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0
    return status, body.decode(errors="replace")


tcp_backend()
hs = http.server.ThreadingHTTPServer(("127.0.0.1", HBACK), Echo)
threading.Thread(target=hs.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "pp.key"],
               check=True, capture_output=True, cwd=tmp)
subprocess.run(["openssl", "req", "-new", "-x509", "-key", "pp.key", "-subj", "/CN=pp.test", "-addext",
                "subjectAltName=DNS:pp.test", "-days", "2", "-out", "pp.pem"],
               check=True, capture_output=True, cwd=tmp)
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off
    workers 4
    io_engine {ENGINE}
    drain delay=0s timeout=1s
}}
tcp 127.0.0.1:{TCP} {{
    to 127.0.0.1:{BACK}
    proxy_protocol accept
    proxy_protocol send v2
}}
tcp 127.0.0.1:{TCPFROM} {{
    to 127.0.0.1:{BACK}
    proxy_protocol accept 127.0.0.0/8
    proxy_protocol send v2
}}
tcp 127.0.0.1:{TCPOTHER} {{
    to 127.0.0.1:{BACK}
    proxy_protocol accept 10.9.9.0/24 2001:db8::/32
    proxy_protocol send v2
}}
tcp 127.0.0.1:{LIM} {{
    to 127.0.0.1:{BACK}
    proxy_protocol accept
    proxy_protocol send v2
    limits {{ per_source 1 }}
}}
http 127.0.0.1:{HTTP} {{
    proxy_protocol accept
    timeout {{ header 1s }}
    route /only/* {{ allow 203.0.113.0/24; to 127.0.0.1:{HBACK} }}
    route /* {{ to 127.0.0.1:{HBACK} }}
}}
http 127.0.0.1:{HTTPS} {{
    tls {{ cert {tmp}/pp.pem key={tmp}/pp.key }}
    proxy_protocol accept
    route /* {{ to 127.0.0.1:{HBACK} }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())

    # the slow ones first, beside the rest: a header that never completes
    pool = ThreadPoolExecutor(4)
    stuck = pool.submit(closed_without_answer, HTTP, b"PROXY TCP4 1.2.3.4", 4)

    r, h = tcp_through(v1("203.0.113.7", "198.51.100.1", 4444, 80), b"t-v1")
    check("tcp, v1: the client the header names goes on in the header sent",
          r == b"okt-v1" and h == ("203.0.113.7", "198.51.100.1", 4444, 80), f"{r} {h}")
    r, h = tcp_through(v2("203.0.113.8", "198.51.100.2", 5555, 443), b"t-v2")
    check("tcp, v2 over IPv4", r == b"okt-v2" and h == ("203.0.113.8", "198.51.100.2", 5555, 443), f"{r} {h}")
    tlvs = bytes([0x05, 0x00, 0x04]) + b"abcd" + bytes([0x02, 0x00, 0x07]) + b"pp.test"
    r, h = tcp_through(v2("2001:db8::7", "2001:db8::1", 6666, 8443, tlvs), b"t-v2six")
    check("tcp, v2 over IPv6 with TLVs (skipped)",
          r == b"okt-v2six" and h == ("2001:db8::7", "2001:db8::1", 6666, 8443), f"{r} {h}")
    r, h = tcp_through(v1("2001:db8::9", "2001:db8::1", 7, 9), b"t-v1six")
    check("tcp, v1 TCP6", r == b"okt-v1six" and h == ("2001:db8::9", "2001:db8::1", 7, 9), f"{r} {h}")
    r, h = tcp_through(v2("", "", 0, 0, local=True), b"t-local")
    check("tcp, v2 LOCAL: the connection's own addresses",
          r == b"okt-local" and h is not None and h[0] == "127.0.0.1" and h[3] == TCP, f"{r} {h}")
    r, h = tcp_through(b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n", b"t-unknown")
    check("tcp, v1 UNKNOWN: the connection's own addresses",
          r == b"okt-unknown" and h is not None and h[0] == "127.0.0.1", f"{r} {h}")
    r, h = tcp_through(v1("192.0.2.33", "192.0.2.1", 1234, 80), b"t-pieces", pieces=5)
    check("tcp, v1 arriving in five pieces", r == b"okt-pieces" and h == ("192.0.2.33", "192.0.2.1", 1234, 80),
          f"{r} {h}")
    big = bytes([0x04, 0x02, 0x00]) + bytes(512)       # a NOOP TLV past the first look
    r, h = tcp_through(v2("192.0.2.44", "192.0.2.1", 4321, 80, big), b"t-big", pieces=3)
    check("tcp, a 560-byte v2 header in pieces", r == b"okt-big" and h == ("192.0.2.44", "192.0.2.1", 4321, 80),
          f"{r} {h}")

    check("tcp: no header at all is closed, nothing forwarded",
          closed_without_answer(TCP, b"GET / HTTP/1.1\r\n\r\n"))
    check("tcp: a broken v1 header is closed", closed_without_answer(TCP, b"PROXY TCP4 1.2.3 4.5.6.7 1 2\r\nx"))
    check("tcp: a v1 line with a port past 65535 is closed",
          closed_without_answer(TCP, b"PROXY TCP4 1.2.3.4 4.5.6.7 70000 2\r\nx"))
    check("tcp: a v2 header of version 3 is closed",
          closed_without_answer(TCP, SIG + bytes([0x31, 0x11, 0, 12]) + bytes(12) + b"x"))
    check("tcp: a v2 header too short for its family is closed",
          closed_without_answer(TCP, SIG + bytes([0x21, 0x11, 0, 4]) + bytes(4) + b"x"))

    r, h = tcp_through(v1("203.0.113.9", "198.51.100.3", 9999, 22), b"t-from", port=TCPFROM)
    check("from 127.0.0.0/8: a listed peer's header is read",
          r == b"okt-from" and h == ("203.0.113.9", "198.51.100.3", 9999, 22), f"{r} {h}")
    r, h = tcp_through(b"", b"t-direct", port=TCPOTHER)
    check("a peer outside `from` is a direct client: no header expected, its own address",
          r == b"okt-direct" and h is not None and h[0] == "127.0.0.1" and h[3] == TCPOTHER, f"{r} {h}")

    # per_source counts the clients the headers name
    a = connect(LIM)
    a.sendall(v1("198.51.100.50", "192.0.2.1", 1, 2) + b"held-a")
    b = connect(LIM)
    b.sendall(v1("198.51.100.51", "192.0.2.1", 1, 2) + b"held-b")
    ra, rb = a.recv(16), b.recv(16)
    check("per_source 1: two clients behind one balancer both get in", ra == b"okheld-a" and rb == b"okheld-b",
          f"{ra} {rb}")
    a.close()
    b.close()
    time.sleep(0.1)
    hold = connect(LIM)
    hold.sendall(v1("198.51.100.60", "192.0.2.1", 1, 2))
    time.sleep(0.2)
    again_closed = closed_without_answer(LIM, v1("198.51.100.60", "192.0.2.1", 3, 2) + b"held-c")
    check("per_source 1: the same client named twice: the second is refused", again_closed)
    hold.close()

    st, body = http_get(HTTP, v1("203.0.113.20", "192.0.2.1", 1111, 80))
    check("http: X-Forwarded-For is the header's client", st == 200 and body == "203.0.113.20", f"{st} {body}")
    st, body = http_get(HTTP, v2("2001:db8::20", "2001:db8::1", 1111, 80))
    check("http: an IPv6 client from a v2 header", st == 200 and body == "2001:db8::20", f"{st} {body}")
    st, body = http_get(HTTP, v1("203.0.113.21", "192.0.2.1", 1111, 80), "/only/x")
    check("http: allow 203.0.113.0/24 lets the header's client in", st == 200, f"{st} {body}")
    st, body = http_get(HTTP, v1("198.51.100.21", "192.0.2.1", 1111, 80), "/only/x")
    check("http: and refuses another (403)", st == 403, f"{st} {body}")
    st, body = http_get(HTTPS, v2("203.0.113.30", "192.0.2.1", 2222, 443), tls=True)
    check("https: the TLS handshake after the header, the client in X-Forwarded-For",
          st == 200 and body == "203.0.113.30", f"{st} {body}")

    check("http: a header that never completes is closed by the header timeout", stuck.result())
    check("the backend never saw a broken stream", b"error" not in seen, str(seen.get(b"error")))
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())

    # what okena check says
    bad = tmp / "bad.conf"
    bad.write_text(f"""http 127.0.0.1:1 {{ proxy_protocol send v2; route /* {{ respond 200 }} }}
tcp 127.0.0.1:2 {{ to 127.0.0.1:3; proxy_protocol accept; proxy_protocol accept }}
tcp 127.0.0.1:4 {{ to 127.0.0.1:3; proxy_protocol accept 10.0.0.0/33 }}
tcp 127.0.0.1:5 {{ to 127.0.0.1:3; proxy_protocol send }}
""")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    msg = out.stdout + out.stderr
    check("check: send on an http listener, two accepts, a bad range, send without a version",
          out.returncode != 0 and "for tcp listeners" in msg and "a second proxy_protocol" in msg
          and "10.0.0.0/33" in msg and "takes a version" in msg, msg)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"peer accept ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
