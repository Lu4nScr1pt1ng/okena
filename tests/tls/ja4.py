#!/usr/bin/env python3
"""JA4, on one engine (argument): the fingerprint okena computes for a
client's ClientHello against one computed here from the same bytes (a Python
client whose hello is captured on its way out), as ${tls.ja4}, in the access
log, as `match tls.ja4=` and `limit key=tls.ja4`; over HTTP/2 a stream gets its
connection's, over HTTP/3 it starts with q; a plain connection has none; with
nothing using it nothing is computed."""
import hashlib
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
BASE = 15200 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, TLS, PLAIN, BARE = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
seen = []


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


GREASE = {0x0a0a + 0x1010 * i for i in range(16)}


def ja4(hello, quic=False):
    """FoxIO's JA4 of a ClientHello handshake message (its 4-byte header first)."""
    p = 4
    legacy = int.from_bytes(hello[p:p + 2], "big")
    p += 34
    p += 1 + hello[p]
    n = int.from_bytes(hello[p:p + 2], "big")
    ciphers = [int.from_bytes(hello[p + 2 + i:p + 4 + i], "big") for i in range(0, n, 2)]
    p += 2 + n
    p += 1 + hello[p]
    end = p + 2 + int.from_bytes(hello[p:p + 2], "big")
    p += 2
    exts, sigs, alpn, sni, ver = [], [], "00", False, legacy
    while p + 4 <= end:
        t = int.from_bytes(hello[p:p + 2], "big")
        ln = int.from_bytes(hello[p + 2:p + 4], "big")
        d = hello[p + 4:p + 4 + ln]
        p += 4 + ln
        if t in GREASE:
            continue
        exts.append(t)
        if t == 0:
            sni = True
        elif t == 0x10 and len(d) > 3 and d[2]:
            v = d[3:3 + d[2]]
            a, b = chr(v[0]), chr(v[-1])
            alpn = a + b if a.isascii() and a.isalnum() and b.isascii() and b.isalnum() else v.hex()[0] + v.hex()[-1]
        elif t == 0x2b:
            vs = [int.from_bytes(d[1 + i:3 + i], "big") for i in range(0, d[0], 2)]
            vs = [x for x in vs if x not in GREASE]
            ver = max(vs) if vs else ver
        elif t == 0x0d:
            sigs = [int.from_bytes(d[2 + i:4 + i], "big") for i in range(0, int.from_bytes(d[:2], "big"), 2)]
            sigs = [x for x in sigs if x not in GREASE]
    ciphers = [c for c in ciphers if c not in GREASE]
    v = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}.get(ver, "00")
    a = ("q" if quic else "t") + v + ("d" if sni else "i") + "%02d%02d" % (min(len(ciphers), 99), min(len(exts), 99)) + alpn
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    b = h(",".join("%04x" % c for c in sorted(ciphers))) if ciphers else "0" * 12
    rest = sorted(e for e in exts if e not in (0, 0x10))
    s = ",".join("%04x" % e for e in rest)
    if sigs:
        s += "_" + ",".join("%04x" % x for x in sigs)
    c = h(s) if rest else "0" * 12
    return f"{a}_{b}_{c}"


def fetch(port, path, sni="ja4.test", alpn=("http/1.1",), ciphers=None):
    """A request over TLS whose ClientHello is kept: (its JA4 here, status, body)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(list(alpn))
    if ciphers:
        ctx.set_ciphers(ciphers)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)
    s = socket.create_connection(("127.0.0.1", port), 5)
    first = b""
    while True:
        try:
            obj.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            done = False
        data = out.read()
        if data:
            if not first:
                first = data
            s.sendall(data)
        if done:
            break
        got = s.recv(65536)
        if not got:
            raise OSError("closed in the handshake")
        inc.write(got)
    obj.write(f"GET {path} HTTP/1.1\r\nHost: ja4.test\r\nConnection: close\r\n\r\n".encode())
    s.sendall(out.read())
    resp = b""
    while True:
        try:
            chunk = obj.read(65536)
            if not chunk:
                break
            resp += chunk
            continue
        except ssl.SSLWantReadError:
            pass
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
        got = s.recv(65536)
        if not got:
            break
        inc.write(got)
    s.close()
    # the first record's handshake message (one record: a ClientHello fits)
    hello = first[5:5 + int.from_bytes(first[3:5], "big")]
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head else 0
    return ja4(hello), status, body.decode(errors="replace")


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        v = self.headers.get("x-ja4", "")
        seen.append(v)
        b = v.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def log_lines(path, want=1):
    for i in range(40):
        lines = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
        if len(lines) >= want:
            return lines
        time.sleep(0.1)
    return lines


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ja4."))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=ja4.test", "-days", "2"],
                   check=True, capture_output=True)
    threading.Thread(target=S(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    alog = tmp / "access.log"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    access_log {alog}
    route /blocked {{
        match tls.ja4=@BLOCKED@ {{ respond 403 }}
        to pool b
    }}
    route /limited {{ limit 2/m burst=2 key=tls.ja4; to pool b }}
    route /* {{ header set x-ja4 "${{tls.ja4}}"; to pool b }}
}}
http 127.0.0.1:{PLAIN} {{ route /* {{ header set x-ja4 "[${{tls.ja4}}]"; to pool b }} }}
""")
    # the fingerprint of this client, to block it by name
    p = None
    try:
        text = conf.read_text()
        conf.write_text(text.replace("@BLOCKED@", "none"))
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", TLS), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        mine, st, body = fetch(TLS, "/x")
        check("${tls.ja4}: the fingerprint of the hello as it went out", st == 200 and body == mine, (st, body, mine))
        check("  of its form", len(body) == 36 and body.startswith("t13d") and body[10] == "_" and body[23] == "_", body)
        other, st, body = fetch(TLS, "/x", alpn=("http/1.1", "x-other"), ciphers="ECDHE+AESGCM")
        check("another hello, another fingerprint, still the same as here", st == 200 and body == other and other != mine,
              (body, other, mine))
        other, st, body = fetch(TLS, "/x", sni=None)
        check("  no SNI: i", st == 200 and body == other and body[3] == "i", (body, other))
        old12, st, body = fetch(TLS, "/x", ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0")
        check("  and over TLS 1.2 handshakes too", st == 200 and body == old12, (body, old12))
        q = subprocess.run(["timeout", "8", "curl", "-q", "-sk", "--http2", f"https://localhost:{TLS}/x", f"https://localhost:{TLS}/y"],
                           capture_output=True, text=True)
        a, b = q.stdout[:36], q.stdout[36:]
        check("HTTP/2: each stream its connection's", len(a) == 36 and a == b and a.startswith("t13d") and a[8:10] == "h2", q.stdout)
        n = len(seen)
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{TLS}/q", "proto=h3", "conns=1", "workers=1",
                            "rate=20", "duration=500ms", "warmup=0s", "format=kv"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        h3 = [x for x in seen[n:] if x]
        check("HTTP/3: q, TLS 1.3, h3", h3 and all(x.startswith("q13") and x[8:10] == "h3" and len(x) == 36 for x in h3),
              (seen[n:n + 3], q.stdout[:100]))
        r = subprocess.run(["curl", "-s", f"http://127.0.0.1:{PLAIN}/x"], capture_output=True, text=True).stdout
        check("no TLS: empty", r == "[]", r)
        lines = log_lines(alog, 5)
        check("the access log's ja4", any(x.get("ja4") == mine for x in lines), [x.get("ja4") for x in lines][:4])
        # limit by fingerprint: this client runs out, another does not
        codes = [fetch(TLS, "/limited")[1] for i in range(4)]
        other_code = fetch(TLS, "/limited", alpn=("http/1.1", "x-other"), ciphers="ECDHE+AESGCM")[1]
        check("limit key=tls.ja4: each fingerprint its own bucket", codes[:2] == [200, 200] and 429 in codes[2:] and other_code == 200,
              (codes, other_code))
        p.terminate()
        p.wait(10)
        # match: this client's fingerprint refused, another's let through
        conf.write_text(text.replace("@BLOCKED@", mine))
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log2", "w"))
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", TLS), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        check("match tls.ja4=: that client refused", fetch(TLS, "/blocked")[1] == 403)
        check("  another let through", fetch(TLS, "/blocked", alpn=("http/1.1", "x-other"), ciphers="ECDHE+AESGCM")[1] == 200)
        p.terminate()
        p.wait(10)
        # nothing uses it: nothing computed (no record, the variable empty)
        conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{BARE} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    access_log {alog}
    route /* {{ to pool b }}
}}
""")
        alog.write_text("")
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log3", "w"))
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", BARE), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        fetch(BARE, "/x")
        lines = log_lines(alog)
        check("not asked for: not in the log", lines and all("ja4" not in x for x in lines), lines[:1])
        p.terminate()
        p.wait(10)
        conf.write_text(conf.read_text().replace("io_engine", "ja4 on; io_engine"))
        alog.write_text("")
        p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log4", "w"))
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", BARE), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        mine2 = fetch(BARE, "/x")[0]
        lines = log_lines(alog)
        check("okena { ja4 on }: in the log", any(x.get("ja4") == mine2 for x in lines), lines[:1])
    finally:
        if p:
            p.terminate()
            p.wait(10)
    logs = "".join((tmp / n).read_text() for n in ("log", "log2", "log3", "log4") if (tmp / n).exists())
    check("no worker died", "killed" not in logs and "restarting" not in logs, logs[-300:])
    print(f"ja4 {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
