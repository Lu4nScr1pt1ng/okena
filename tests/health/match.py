#!/usr/bin/env python3
"""Health checks that look at the answer: `health tcp send= match=` (a Redis
primary told from its replica by INFO replication), a protocol that speaks
first (a banner, match= alone), `health http ... match=` on the body (also
when it spans reads, past a long head), and `health udp send= match=` (an
answer, a wrong one, an ICMP refusal). State from okena_backend_health_up."""
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 15400 + os.getpid() % 80 * 16
(PRIMARY, REPLICA, BANNER_OK, BANNER_BAD, HTTP_OK, HTTP_BAD, HTTP_LONG,
 UDP_OK, UDP_BAD, UDP_NONE, METRICS, L1, L2, L3, L4) = (BASE + i for i in range(15))

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def tcp_server(port, handle):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=lambda: (handle(c), c.close()), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def redis(role):
    def handle(c):
        try:
            d = b""
            while b"\r\n" not in d:
                x = c.recv(256)
                if not x:
                    return
                d += x
            if d.startswith(b"INFO replication"):
                body = f"# Replication\r\nrole:{role}\r\nconnected_slaves:0\r\n".encode()
                c.sendall(b"$%d\r\n%s\r\n" % (len(body), body))
            else:
                c.sendall(b"+PONG\r\n")
            time.sleep(0.1)
        except OSError:
            pass
    return handle


def banner(text):
    def handle(c):
        try:
            c.sendall(text)
            time.sleep(0.2)
        except OSError:
            pass
    return handle


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body = b""
    pad = 0

    def do_GET(self):
        self.send_response(200)
        for i in range(self.pad):
            self.send_header(f"X-Pad-{i}", "x" * 60)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


def http_server(port, body, pad=0):
    cls = type("H%d" % port, (H,), {"body": body, "pad": pad})
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), cls)
    s.handle_error = lambda *a: None
    threading.Thread(target=s.serve_forever, daemon=True).start()


def udp_server(port, answer):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))

    def loop():
        while True:
            d, a = s.recvfrom(2048)
            if d == b"\x01ping":
                s.sendto(answer, a)
    threading.Thread(target=loop, daemon=True).start()


tcp_server(PRIMARY, redis("master"))
tcp_server(REPLICA, redis("slave"))
tcp_server(BANNER_OK, banner(b"220 mail.test ESMTP ready\r\n"))
tcp_server(BANNER_BAD, banner(b"554 go away\r\n"))
http_server(HTTP_OK, b'{"status":"ok","db":"up"}')
http_server(HTTP_BAD, b'{"status":"degraded","db":"down"}')
# a long head (past the first read) and the mark split across two reads
http_server(HTTP_LONG, b"y" * 4090 + b"READY-MARK" + b"z" * 100, pad=80)
udp_server(UDP_OK, b"pong")
udp_server(UDP_BAD, b"nope")

tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 1; metrics 127.0.0.1:{METRICS}; drain delay=0s timeout=1s }}
pool redis {{
    server 127.0.0.1:{PRIMARY}
    server 127.0.0.1:{REPLICA}
    health tcp send="INFO replication\\r\\n" match="role:master" every=150ms rise=1 fall=3
}}
pool smtp {{
    server 127.0.0.1:{BANNER_OK}
    server 127.0.0.1:{BANNER_BAD}
    health tcp match="220 " every=150ms rise=1 fall=1
}}
pool web {{
    server 127.0.0.1:{HTTP_OK}
    server 127.0.0.1:{HTTP_BAD}
    server 127.0.0.1:{HTTP_LONG}
    health http GET /health match="\\"status\\":\\"ok\\"" every=150ms rise=1 fall=1
}}
pool marked {{
    server 127.0.0.1:{HTTP_LONG}
    health http GET /health match="READY-MARK" every=150ms rise=1 fall=1
}}
pool dns {{
    server 127.0.0.1:{UDP_OK}
    server 127.0.0.1:{UDP_BAD}
    server 127.0.0.1:{UDP_NONE}
    health udp send="\\x01ping" match="pong" every=150ms timeout=300ms rise=1 fall=1
}}
tcp 127.0.0.1:{L1} {{ to pool redis }}
tcp 127.0.0.1:{L2} {{ to pool smtp }}
http 127.0.0.1:{L3} {{ route /a {{ to pool web }} route /b {{ to pool marked }} }}
udp 127.0.0.1:{L4} {{ to pool dns }}
""".replace("} route /b", "}\n    route /b"))
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)


def health():
    try:
        m = urllib.request.urlopen(f"http://127.0.0.1:{METRICS}/metrics", timeout=3).read().decode()
    except OSError:
        return {}
    out = {}
    for line in m.splitlines():
        if line.startswith("okena_backend_health_up{"):
            pool = line.split('pool="')[1].split('"')[0]
            addr = line.split('server="')[1].split('"')[0]
            out[(pool, int(addr.rsplit(":", 1)[1]))] = int(line.split()[-1])
    return out


try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    want = {("redis", PRIMARY): 1, ("redis", REPLICA): 0, ("smtp", BANNER_OK): 1, ("smtp", BANNER_BAD): 0,
            ("web", HTTP_OK): 1, ("web", HTTP_BAD): 0, ("web", HTTP_LONG): 0, ("marked", HTTP_LONG): 1,
            ("dns", UDP_OK): 1, ("dns", UDP_BAD): 0, ("dns", UDP_NONE): 0}
    h = {}
    for _ in range(60):                  # metrics are at most a second old
        h = health()
        if all(h.get(k) == v for k, v in want.items()):
            break
        time.sleep(0.1)
    check("redis: send INFO replication, match role:master: the primary up", h.get(("redis", PRIMARY)) == 1, str(h))
    check("  the replica down", h.get(("redis", REPLICA)) == 0, str(h))
    check("a protocol that speaks first: match= alone reads its banner",
          h.get(("smtp", BANNER_OK)) == 1 and h.get(("smtp", BANNER_BAD)) == 0, str(h))
    check("http match= on the body: ok up, degraded down",
          h.get(("web", HTTP_OK)) == 1 and h.get(("web", HTTP_BAD)) == 0, str(h))
    check("  a body without it down, however long its head", h.get(("web", HTTP_LONG)) == 0, str(h))
    check("  a mark split across reads, after a head of 5 KB", h.get(("marked", HTTP_LONG)) == 1, str(h))
    check("udp send= match=: the right answer up, a wrong one and an ICMP refusal down",
          h.get(("dns", UDP_OK)) == 1 and h.get(("dns", UDP_BAD)) == 0 and h.get(("dns", UDP_NONE)) == 0, str(h))
    seen = set()
    for _ in range(6):
        c = socket.create_connection(("127.0.0.1", L1), timeout=3)
        c.sendall(b"INFO replication\r\n")
        seen.add(b"role:master" in c.recv(256))
        c.close()
    check("traffic goes to the primary only", seen == {True}, str(seen))
    log.seek(0)
    t = log.read()
    check("the reason is logged", "does not hold match=" in t, t[-400:])
    check("no crash", "killed by signal" not in t)

    bad = tmp / "bad.conf"
    bad.write_text(f"""pool a {{ server 127.0.0.1:1; health http GET / send=x }}
pool b {{ server 127.0.0.1:1; health grpc match=x }}
pool c {{ server 127.0.0.1:1; health tcp match="" }}
tcp 127.0.0.1:2 {{ to pool a }}
tcp 127.0.0.1:3 {{ to pool b }}
tcp 127.0.0.1:4 {{ to pool c }}
""")
    out = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    msg = out.stdout + out.stderr
    check("check: send= on http, match= on grpc, an empty match=",
          out.returncode != 0 and "send= is for tcp and udp" in msg and "match= is for tcp, udp and http" in msg
          and "match= is 1 to 255 bytes" in msg, msg)
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read()[-3000:])
print(f"health match: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
