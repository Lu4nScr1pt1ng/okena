#!/usr/bin/env python3
"""Forward proxy (`tunnel`), on one engine (argument): CONNECT to a name and
to an address, a TLS conversation through the tunnel, bytes the client sent
with its CONNECT, host blocks as the destinations allowed, ports=, private
and loopback addresses refused (also behind a name), names that do not
exist, Host that is not the target, auth and allow on the route, other
methods on a tunnel route, CONNECT where no route tunnels, and the access log.

Runs itself again in a user, mount and network namespace with its own
/etc/resolv.conf and a DNS server of its own (as tests/dns/run.py)."""
import base64
import hashlib
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"

if os.environ.get("OKENA_TUN_NS") != "1":
    env = dict(os.environ, OKENA_TUN_NS="1")
    sys.exit(subprocess.call(["unshare", "-rmn", sys.executable, "-I", __file__, *sys.argv[1:]], env=env))

subprocess.check_call(["ip", "link", "set", "lo", "up"])
PUB, PUB2, PRIV = "198.51.100.7", "203.0.113.9", "10.1.2.3"
for a in (PUB, PUB2, PRIV):
    subprocess.check_call(["ip", "addr", "add", a + "/32", "dev", "lo"])
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "resolv.conf").write_text("nameserver 127.0.0.1\n")
(tmp / "hosts").write_text("127.0.0.1 localhost\n")
for name in ("resolv.conf", "hosts"):
    subprocess.check_call(["mount", "--bind", str(tmp / name), f"/etc/{name}"])
RECORDS = {"echo.test": PUB, "secure.test": PUB, "other.test": PUB2, "inside.test": PRIV, "sneaky.test": "127.0.0.1",
           "meta.test": "169.254.169.254"}
PROXY, ECHO, TLSP, PROXY2 = 3128, 7000, 8443, 3129
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 53))
    while True:
        q, peer = s.recvfrom(512)
        qid, = struct.unpack("!H", q[:2])
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        qtype, = struct.unpack("!H", q[i + 1:i + 3])
        question = q[12:i + 5]
        name = ".".join(labels).lower()
        a = RECORDS.get(name)
        ans, n = b"", 0
        if a and qtype == 1:
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(a)
            n = 1
        rcode = 0 if a else 3
        s.sendto(struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, n, 0, 0) + question + ans, peer)


def echo_server(addr, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(64)

    def one(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(b"echo:" + d)
        except OSError:
            pass
        c.close()
    while True:
        c, _ = s.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def tls_server(addr, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            t = ctx.wrap_socket(c, server_side=True)
            t.recv(100)
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret")
            t.close()
        except (OSError, ssl.SSLError):
            c.close()


def connect(target, host=None, extra=b"", port=PROXY, headers=b""):
    """CONNECT target: (status line, socket, what came after the head)."""
    s = socket.create_connection(("127.0.0.1", port), 8)
    h = (host if host is not None else target)
    req = f"CONNECT {target} HTTP/1.1\r\n".encode() + (f"Host: {h}\r\n".encode() if h else b"") + headers + b"\r\n" + extra
    s.sendall(req)
    d = b""
    while b"\r\n\r\n" not in d:
        g = s.recv(4096)
        if not g:
            break
        d += g
    head, _, rest = d.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(errors="replace"), s, rest


def status(target, **kw):
    line, s, _ = connect(target, **kw)
    s.close()
    return line.split(" ")[1] if " " in line else line


def main():
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=echo.test", "-days", "2"],
                   check=True, capture_output=True)
    threading.Thread(target=dns_server, daemon=True).start()
    for a in (PUB, PUB2, PRIV, "127.0.0.1"):
        threading.Thread(target=echo_server, args=(a, ECHO), daemon=True).start()
    threading.Thread(target=tls_server, args=(PUB, TLSP), daemon=True).start()
    for i in range(100):
        try:
            socket.create_connection((PUB, TLSP), 1).close()
            break
        except OSError:
            time.sleep(0.05)
    salt = "c0ffee"
    (tmp / "users").write_text(f"proxy:{salt}:{hashlib.sha256((salt + 'secret').encode()).hexdigest()}\n")
    alog = tmp / "access.log"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; overload off }}
pool web {{ server {PUB}:{ECHO} }}
http 127.0.0.1:{PROXY} {{
    access_log {alog}
    host echo.test {{
        route /* {{ tunnel ports={ECHO},{TLSP} }}
    }}
    host inside.test sneaky.test meta.test {{
        route /* {{ tunnel ports={ECHO} }}
    }}
    host other.test {{
        route /* {{ tunnel ports={ECHO}; allow 10.0.0.0/8 }}
    }}
    host nowhere.test {{
        route /* {{ tunnel ports={ECHO} }}
    }}
    host secure.test {{
        route /* {{ tunnel ports={ECHO}; auth basic users={tmp}/users realm=proxy }}
    }}
    host mixed.test {{
        route /* {{ tunnel ports={ECHO}; to pool web }}
    }}
    route /* {{ respond 404 }}
}}
http 127.0.0.1:{PROXY2} {{
    host inside.test {{ route /* {{ tunnel ports={ECHO} private=on }} }}
    host plain.test {{ route /* {{ to pool web }} }}
    route /* {{ tunnel ports={ECHO} }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", PROXY), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            print(log.read_text()[-2000:])
        line, s, rest = connect(f"echo.test:{ECHO}")
        ok = line.startswith("HTTP/1.1 200")
        if ok:
            s.sendall(b"hello")
            d = rest
            while len(d) < 10:
                d += s.recv(100)
        s.close()
        check("CONNECT to a name: 200, then the bytes both ways", ok and d == b"echo:hello", (line, rest))
        line, s, rest = connect(f"echo.test:{ECHO}", extra=b"early")
        d = rest
        while line.startswith("HTTP/1.1 200") and len(d) < 10:
            g = s.recv(100)
            if not g:
                break
            d += g
        s.close()
        check("  what the client sent with its CONNECT goes first", d == b"echo:early", (line, d))
        line, s, rest = connect(f"{PUB}:{ECHO}", port=PROXY2)
        if line.startswith("HTTP/1.1 200"):
            s.sendall(b"x")
            rest += s.recv(100)
        s.close()
        check("  to an address, by the listener's own route", rest == b"echo:x", (line, rest))
        line, s, rest = connect(f"echo.test:{TLSP}", host="echo.test")
        body = b""
        if line.startswith("HTTP/1.1 200"):
            ctx = ssl.create_default_context(cafile=str(tmp / "c.pem"))
            t = ctx.wrap_socket(s, server_hostname="echo.test")
            t.sendall(b"GET / HTTP/1.1\r\nHost: echo.test\r\n\r\n")
            while True:
                g = t.recv(4096)
                if not g:
                    break
                body += g
            t.close()
        check("  TLS end to end through it (Host without the port)", body.endswith(b"secret"), (line, body[-60:]))
        check("a port not listed: 403", status("echo.test:22") == "403")
        check("a host no block names: no tunnel (405)", status(f"unknown.test:{ECHO}") == "405")
        check("a private address: 403", status(f"{PRIV}:{ECHO}", port=PROXY2) == "403")
        check("  a name pointing at one: 403", status(f"inside.test:{ECHO}") == "403")
        check("  at loopback: 403", status(f"sneaky.test:{ECHO}") == "403")
        check("  at the cloud's metadata: 403", status(f"meta.test:{ECHO}") == "403")
        check("  private=on lets a private one through", status(f"inside.test:{ECHO}", port=PROXY2) == "200")
        check("a name that does not exist: 502", status(f"nowhere.test:{ECHO}") == "502")
        check("Host not the target: 400", status(f"echo.test:{ECHO}", host="other.test") == "400")
        line, s, rest = connect(f"secure.test:{ECHO}")
        s.close()
        check("auth basic: 407 and Proxy-Authenticate without credentials", line.startswith("HTTP/1.1 407"), line)
        cred = b"Proxy-Authorization: Basic " + base64.b64encode(b"proxy:secret") + b"\r\n"
        check("  Proxy-Authorization lets it through", status(f"secure.test:{ECHO}", headers=cred) == "200")
        bad = b"Proxy-Authorization: Basic " + base64.b64encode(b"proxy:nope") + b"\r\n"
        check("  a wrong password: 407", status(f"secure.test:{ECHO}", headers=bad) == "407")
        check("the route's allow: 403", status(f"other.test:{ECHO}") == "403")
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Host: echo.test",
                            f"http://127.0.0.1:{PROXY}/x"], capture_output=True, text=True).stdout
        check("another method on a tunnel-only route: 405", r == "405", r)
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Host: mixed.test",
                            f"http://127.0.0.1:{PROXY}/x"], capture_output=True, text=True).stdout
        check("  on one with `to` too: there (the echo server is no HTTP server: 502)", r == "502", r)
        check("CONNECT where no route tunnels: 405", status(f"plain.test:{ECHO}", port=PROXY2) == "405")
        # many at once, through the resolver
        res = []

        def one():
            line, s, rest = connect(f"echo.test:{ECHO}")
            if line.startswith("HTTP/1.1 200"):
                s.sendall(b"n")
                rest += s.recv(100)
            s.close()
            res.append(rest == b"echo:n")
        th = [threading.Thread(target=one) for i in range(100)]
        [t.start() for t in th]
        [t.join() for t in th]
        check("100 tunnels at once", res.count(True) == 100, res.count(True))
        r = subprocess.run(["curl", "-s", "-x", f"http://127.0.0.1:{PROXY}", "--proxytunnel", "-k", "--resolve",
                            f"echo.test:{TLSP}:{PUB}", f"https://echo.test:{TLSP}/"], capture_output=True, text=True)
        check("curl through it as its proxy", r.stdout == "secret", r.stdout + r.stderr[-200:])
        for i in range(40):
            lines = [json.loads(x) for x in alog.read_text().splitlines() if x.strip()]
            if any(x.get("method") == "CONNECT" and x.get("status") == 200 for x in lines):
                break
            time.sleep(0.1)
        hit = [x for x in lines if x.get("method") == "CONNECT" and x.get("status") == 200 and x.get("target") == f"echo.test:{ECHO}"]
        check("the access log: CONNECT, its target, where it went, a request id", hit and hit[0].get("upstream") == f"echo.test:{ECHO}"
              and len(hit[0].get("request_id", "")) == 16, hit[:1] or lines[:2])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    if fails:
        print(t[-2000:])
    check("no worker died", "killed" not in t and "restarting" not in t, t[-400:])
    print(f"tunnel {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
