#!/usr/bin/env python3
"""Backends by name: /etc/hosts, DNS with search domains, names that
appear late, addresses that change, several addresses per name, AAAA,
and a DNS server that goes away.

Runs itself again inside a user, mount and network namespace, where it
may bind port 53 and mount its own /etc/resolv.conf and /etc/hosts over
the real ones, so okena runs unmodified against a fake DNS server.
"""
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

if os.environ.get("OKENA_DNS_NS") != "1":
    env = dict(os.environ, OKENA_DNS_NS="1")
    sys.exit(subprocess.call(["unshare", "-rmn", sys.executable, "-I", __file__, *sys.argv[1:]], env=env))

subprocess.check_call(["ip", "link", "set", "lo", "up"])
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "resolv.conf").write_text("search svc.test\nnameserver 127.0.0.1\noptions ndots:1\n")
(tmp / "hosts").write_text("127.0.0.1 localhost\n127.0.0.5   fromhosts  alias\n")
for name in ("resolv.conf", "hosts"):
    subprocess.check_call(["mount", "--bind", str(tmp / name), f"/etc/{name}"])

# name -> list of addresses ("127.0.0.2" or "::1"); TTL 1 s
records = {}
dns_up = threading.Event()
dns_up.set()


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 53))
    while True:
        q, peer = s.recvfrom(512)
        if not dns_up.is_set():
            continue
        qid, flags, qd = struct.unpack("!HHH", q[:6])
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        qtype, = struct.unpack("!H", q[i + 1:i + 3])
        question = q[12:i + 5]
        name = ".".join(labels).lower()
        addrs = records.get(name)
        answers = b""
        count = 0
        for a in addrs or []:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            t = 28 if fam == socket.AF_INET6 else 1
            if t != qtype:
                continue
            rdata = socket.inet_pton(fam, a)
            answers += b"\xc0\x0c" + struct.pack("!HHIH", t, 1, 1, len(rdata)) + rdata
            count += 1
        rcode = 0 if addrs is not None else 3
        hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, count, 0, 0)
        s.sendto(hdr + question + answers, peer)


threading.Thread(target=dns_server, daemon=True).start()


def echo_backend(addr, port, tag):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(256)

    def handle(c):
        try:
            if c.recv(100):
                c.sendall(tag)
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


for addr, tag in (("127.0.0.2", b"two"), ("127.0.0.3", b"three"), ("127.0.0.4", b"four"),
                  ("127.0.0.5", b"five"), ("::1", b"six")):
    echo_backend(addr, 7000, tag)


def ask(port):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.sendall(b"hi")
        r = c.recv(10)
        c.close()
        return r
    except OSError:
        return b""


def wait_for(port, want, seconds):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if ask(port) == want:
            return time.time() - t0
        time.sleep(0.1)
    return None


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


records["api.svc.test"] = ["127.0.0.2"]
records["multi.svc.test"] = ["127.0.0.3", "127.0.0.4"]
records["v6.svc.test"] = ["::1"]
conf = tmp / "okena.conf"
conf.write_text("""
okena { workers 2 }
tcp 127.0.0.1:8001 { to fromhosts:7000 }
tcp 127.0.0.1:8002 { to api:7000 }
tcp 127.0.0.1:8003 { to late.svc.test:7000 }
tcp 127.0.0.1:8004 { to multi:7000 }
tcp 127.0.0.1:8005 { to v6:7000 }
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    check("name from /etc/hosts", ask(8001) == b"five")
    check("name through a search domain", ask(8002) == b"two")
    check("IPv6 address from AAAA", ask(8005) == b"six")
    seen = {ask(8004) for _ in range(40)}
    check("every address of a name gets traffic", seen == {b"three", b"four"}, str(seen))
    check("a name that does not exist yet does not stop okena", p.poll() is None)
    check("its listener fails fast meanwhile", ask(8003) == b"")
    records["late.svc.test"] = ["127.0.0.2"]
    t = wait_for(8003, b"two", 6)
    check("the name is picked up once it exists", t is not None, f"{t:.1f}s" if t else "never")
    # the backend moves (a container recreated with a new address)
    records["api.svc.test"] = ["127.0.0.3"]
    t = wait_for(8002, b"three", 6)
    check("a changed address is followed", t is not None, f"{t:.1f}s" if t else "never")
    # DNS goes away: the last known addresses keep serving
    dns_up.clear()
    time.sleep(3)
    ok = sum(ask(8002) == b"three" for _ in range(20))
    check("DNS down: last known addresses keep serving", ok == 20, f"{ok}/20")
    dns_up.set()
    log.seek(0)
    text = log.read()
    check("resolutions are logged", "api resolved to 127.0.0.2" in text and "multi resolved to 127.0.0.3, 127.0.0.4" in text
          and "v6 resolved to ::1" in text, "")
    check("lookup failures are logged once, then quiet", text.count("cannot resolve late.svc.test") == 1)
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(10)
    log.seek(0)
    if failures or "-v" in sys.argv:
        print(log.read())
print(f"dns: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
