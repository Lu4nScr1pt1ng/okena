#!/usr/bin/env python3
"""`allow` and `deny` on one engine (argument), and that a body reaches the backend byte
for byte: what signed webhooks need of a proxy."""
import hashlib
import http.client
import http.server
import os
import pathlib
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 5000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)
BACK, LST, TLS = BASE, BASE + 1, BASE + 2
fails = 0
seen = {}


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def go(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            b = b""
            while True:
                n = int(self.rfile.readline().split(b";")[0], 16)
                if n == 0:
                    self.rfile.readline()
                    break
                b += self.rfile.read(n)
                self.rfile.readline()
        else:
            b = self.rfile.read(int(self.headers.get("content-length", 0)))
        seen[self.path] = b
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = go

    def log_message(self, *a):
        pass


def get(path, **h):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", path, headers={k.replace("_", "-"): v for k, v in h.items()})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acl."))
    s = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    (tmp / "keys").write_text("a:k\n")
    (tmp / "list").write_text("# sources\n\n10.1.2.3\n192.0.2.0/24  # a range\n" + "".join(f"172.{i % 16 + 16}.{i >> 8 & 255}.{i & 255}\n" for i in range(5000)) + "127.0.0.0/8\n")
    (tmp / "list2").write_text("10.0.0.0/8\n")
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2", "-out", tmp / "c.pem"], check=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    trusted_proxies 127.0.0.2
    route /in/* {{ allow 127.0.0.0/8; to pool b }}
    route /out/* {{ allow 10.0.0.0/8 192.0.2.1; to pool b }}
    route /denied/* {{ deny 127.0.0.1; to pool b }}
    route /both/* {{ allow 127.0.0.0/8; deny 127.0.0.1/32; to pool b }}
    route /other/* {{ deny 10.0.0.0/8 2001:db8::/32; to pool b }}
    route /six/* {{ allow 2001:db8::/32; to pool b }}
    route /file/* {{ allow file:{tmp}/list; to pool b }}
    route /nofile/* {{ allow file:{tmp}/list2; to pool b }}
    route /first/* {{ deny 127.0.0.0/8; auth api_key header=x-k keys={tmp}/keys; to pool b }}
    route /m/* {{
        allow 10.0.0.0/8
        match header:x-open=1 {{ allow 127.0.0.0/8 }}
        to pool b
    }}
    route /body/* {{ to pool b }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    route /body/* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        check("allow: in the range", get("/in/x") == 200)
        check("  not in it: 403", get("/out/x") == 403)
        check("deny", get("/denied/x") == 403)
        check("a deny wins over an allow", get("/both/x") == 403)
        check("deny of others: fine", get("/other/x") == 200)
        check("an IPv6 range is nothing to an IPv4 client", get("/six/x") == 403)
        check("a list in a file, 5000 lines", get("/file/x") == 200)
        check("  not in it", get("/nofile/x") == 403)
        check("before auth: it says nothing of keys", get("/first/x") == 403)
        check("in a block: it replaces", get("/m/x", x_open="1") == 200 and get("/m/x") == 403)
        # the body
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        R = random.Random(5)
        for what, b in (("binary", R.randbytes(300000)), ("CRLF and NUL", b"\r\n\x00\r\n\r\n0\r\n\r\n" * 100), ("empty", b"")):
            c.request("POST", "/body/" + what.split()[0], body=b, headers={"Content-Length": str(len(b))})
            c.getresponse().read()
            check(f"a body, {what}: byte for byte", seen.get("/body/" + what.split()[0]) == b)
        b = R.randbytes(100000)
        c.request("POST", "/body/ch", body=iter([b[:1], b[1:50000], b[50000:]]), encode_chunked=True, headers={"Transfer-Encoding": "chunked"})
        c.getresponse().read()
        check("  chunked: byte for byte", seen.get("/body/ch") == b)
        c.close()
        # over HTTP/2 with TLS, past where a frame and a record stop lining up
        for n in (16000, 16385, 17000, 33000, 65537, 100000, 1 << 20):
            b = R.randbytes(n)
            (tmp / "b").write_bytes(b)
            q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_version}", "--data-binary", f"@{tmp}/b",
                                "-H", "Content-Type: application/octet-stream", f"https://localhost:{TLS}/body/h2{n}"], capture_output=True, text=True)
            check(f"  over HTTP/2, {n} bytes: byte for byte", q.stdout == "2" and seen.get(f"/body/h2{n}") == b, (q.stdout, len(seen.get(f"/body/h2{n}", b""))))
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    for line in ("allow nope", "deny 10.0.0.0/99", f"allow file:{tmp}/nosuch"):
        c = tmp / "bad.conf"
        c.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ {line}; to pool b }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{line[:30]}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"acl {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
