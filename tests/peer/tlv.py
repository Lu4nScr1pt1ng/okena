#!/usr/bin/env python3
"""PROXY protocol v2 TLVs (proxy_protocol accept), on one engine (argument):
authority, unique ID, ALPN, the SSL version, AWS's VPC endpoint, Azure's
LinkID and GCP's PSC ID given to routes as ${proxy.NAME} in headers and
`match proxy.NAME=VALUE`, and to the access logs (http and tcp) as a "proxy"
object; an HTTP/2 stream has its connection's; a TLV with a CR or an LF in it
is left out (no header injection); a v1 header or a LOCAL one has none."""
import http.server
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 31600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L, LT, TB = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def tlv(t, v):
    return bytes([t]) + struct.pack(">H", len(v)) + v


UID = bytes(range(16))
TLVS = (tlv(0x02, b"app.example") + tlv(0x05, UID) + tlv(0x01, b"h2")
        + tlv(0x20, b"\x01" + struct.pack(">I", 0) + tlv(0x21, b"TLSv1.3") + tlv(0x22, b"cn"))
        + tlv(0xEA, b"\x01vpce-0abc123") + tlv(0xEE, b"\x01" + struct.pack("<I", 0x12345678))
        + tlv(0xE0, struct.pack(">Q", 0x0102030405060708)) + tlv(0x04, b"\x00\x00\x00\x00"))


def v2(tlvs=TLVS, cmd=0x21, sport=40000):
    addr = socket.inet_aton("10.1.2.3") + socket.inet_aton("10.0.0.9") + struct.pack(">HH", sport, 443)
    if cmd == 0x20:
        addr = b""
    body = addr + tlvs
    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes([cmd, 0x11 if cmd == 0x21 else 0x00]) + struct.pack(">H", len(body)) + body


def get(path, header, port=L):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(header + f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
    r = b""
    while (d := c.recv(65536)):
        r += d
    c.close()
    head, _, body = r.partition(b"\r\n\r\n")
    return head.split(b" ")[1].decode() if head else "", body


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
tsrv = socket.socket()
tsrv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tsrv.bind(("127.0.0.1", TB))
tsrv.listen(16)


def tcp_echo():
    while True:
        c, _ = tsrv.accept()
        d = c.recv(100)
        c.sendall(d)
        c.close()


threading.Thread(target=tcp_echo, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
alog = tmp / "access.log"
l4log = tmp / "l4.log"
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
http 127.0.0.1:{L} {{
    proxy_protocol accept
    http2 on
    access_log {alog}
    route /vpce {{
        match proxy.aws_vpce=vpce-0abc123 {{ respond 200 "by the endpoint" }}
        respond 200 "another way"
    }}
    route /* {{
        header set x-auth "${{proxy.authority}}"
        header set x-uid "${{proxy.unique_id}}"
        header set x-alpn "${{proxy.alpn}}"
        header set x-ssl "${{proxy.ssl_version}}"
        header set x-vpce "${{proxy.aws_vpce}}"
        header set x-az "${{proxy.azure_linkid}}"
        header set x-gcp "${{proxy.gcp_psc}}"
        to 127.0.0.1:{BACK}
    }}
}}
tcp 127.0.0.1:{LT} {{ proxy_protocol accept; access_log {l4log}; to 127.0.0.1:{TB} }}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)


def lines(path, pred, wait=3):
    end = time.time() + wait
    while time.time() < end:
        if path.exists():
            for x in path.read_text().splitlines():
                try:
                    j = json.loads(x)
                except ValueError:
                    continue
                if pred(j):
                    return j
        time.sleep(0.05)
    return {}


try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    st, b = get("/a", v2())
    h = json.loads(b) if st == "200" else {}
    check("${proxy.authority} ${proxy.alpn} ${proxy.ssl_version}", h.get("x-auth") == "app.example" and h.get("x-alpn") == "h2"
          and h.get("x-ssl") == "TLSv1.3", h)
    check("${proxy.unique_id} in hex", h.get("x-uid") == UID.hex(), h.get("x-uid"))
    check("the clouds': aws_vpce, azure_linkid, gcp_psc", h.get("x-vpce") == "vpce-0abc123" and h.get("x-az") == str(0x12345678)
          and h.get("x-gcp") == str(0x0102030405060708), h)
    check("match proxy.aws_vpce=", get("/vpce", v2())[1] == b"by the endpoint"
          and get("/vpce", v2(tlv(0x02, b"x")))[1] == b"another way")
    j = lines(alog, lambda j: j.get("target") == "/a")
    check("the access log's \"proxy\"", j.get("proxy", {}).get("aws_vpce") == "vpce-0abc123"
          and j["proxy"].get("unique_id") == UID.hex() and j["proxy"].get("authority") == "app.example", j)
    st, b = get("/inj", v2(tlv(0x02, b"evil\r\nX-Admin: 1") + tlv(0xEA, b"\x01vpce-1")))
    h = json.loads(b) if st == "200" else {}
    check("a TLV with CR LF: left out, the others kept", h.get("x-auth") == "" and "x-admin" not in h and h.get("x-vpce") == "vpce-1", h)
    st, b = get("/v1", b"PROXY TCP4 10.1.2.3 10.0.0.9 40000 443\r\n")
    h = json.loads(b) if st == "200" else {}
    check("a v1 header: none", st == "200" and h.get("x-vpce") == "" and h.get("x-auth") == "", h)
    st, b = get("/local", v2(TLVS, cmd=0x20))
    h = json.loads(b) if st == "200" else {}
    check("a LOCAL header: none", st == "200" and h.get("x-vpce") == "", h)
    st, b = get("/next", v2(b""))
    h = json.loads(b) if st == "200" else {}
    check("the next connection's, not the last one's", h.get("x-vpce") == "", h)
    try:
        import h2.config
        import h2.connection
        c = socket.create_connection(("127.0.0.1", L), timeout=5)
        c.sendall(v2())
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        conn.send_headers(1, [(":method", "GET"), (":path", "/h2"), (":scheme", "http"), (":authority", "t")], end_stream=True)
        c.sendall(conn.data_to_send())
        body, done, end = b"", False, time.time() + 4
        while not done and time.time() < end:
            d = c.recv(65536)
            if not d:
                break
            for ev in conn.receive_data(d):
                if type(ev).__name__ == "DataReceived":
                    body += ev.data
                if type(ev).__name__ == "StreamEnded":
                    done = True
            c.sendall(conn.data_to_send())
        c.close()
        h = json.loads(body) if body else {}
        check("an HTTP/2 stream: its connection's TLVs", h.get("x-vpce") == "vpce-0abc123", h)
    except ImportError:
        print("skip h2: no h2 package")
    c = socket.create_connection(("127.0.0.1", LT), timeout=5)
    c.sendall(v2() + b"ping")
    r = c.recv(100)
    c.close()
    j = lines(l4log, lambda j: j.get("proto") == "tcp")
    check("tcp: through, and its log's \"proxy\"", r == b"ping" and j.get("proxy", {}).get("gcp_psc") == str(0x0102030405060708), (r, j))
    bad = tmp / "bad.conf"
    bad.write_text(f'http 127.0.0.1:1 {{ route / {{ header set x "${{proxy.nope}}"; respond 200 }} }}\n')
    q = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True, timeout=10)
    check("an unknown ${proxy.NAME}: refused", q.returncode != 0 and "proxy.aws_vpce" in q.stderr, q.stderr[-200:])
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails or sys.exc_info()[0]:
        log.seek(0)
        print(log.read()[-1500:])
print(f"proxy tlvs ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
