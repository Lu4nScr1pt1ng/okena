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
# name -> list of (priority, weight, port, target): SRV, TTL 1 s
srv = {}
asked_edns = []


def dns_name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"
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
        if qtype == 33:
            arcount, = struct.unpack("!H", q[10:12])
            asked_edns.append(arcount == 1)
            for prio, weight, port, target in srv.get(name, []):
                rdata = struct.pack("!HHH", prio, weight, port) + dns_name(target)
                answers += b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 1, len(rdata)) + rdata
                count += 1
            rcode = 0 if name in srv else 3
            hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, count, 0, 0)
            reply = hdr + question + answers
            if len(reply) > 512 and arcount == 0:
                reply = hdr[:2] + struct.pack("!H", 0x8380) + hdr[4:6] + b"\0\0" + hdr[8:] + question   # TC, no answers
            s.sendto(reply, peer)
            continue
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


BACKEND_EMPTY = []


def echo_backend(addr, port, tag):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(256)

    def handle(c):
        try:
            d = c.recv(100)
            if d:
                c.sendall(tag)
            else:
                BACKEND_EMPTY.append(tag)
        except OSError as e:
            BACKEND_EMPTY.append(repr(e))
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
for addr, port, tag in (("127.0.0.2", 7101, b"srv-a"), ("127.0.0.3", 7102, b"srv-b"), ("127.0.0.4", 7103, b"srv-c")):
    echo_backend(addr, port, tag)


def ask(port):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.sendall(b"hi")
        r = c.recv(10)
        c.close()
        return r
    except OSError as e:
        if "--stress" in sys.argv:
            return repr(e).encode()
        return b""


def wait_all(port, want, seconds):
    """Until ten answers in a row are want."""
    t0 = time.time()
    while time.time() - t0 < seconds:
        if all(ask(port) == want for _ in range(10)):
            return time.time() - t0
        time.sleep(0.1)
    return None


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
records["a.srv.test"] = ["127.0.0.2"]
records["b.srv.test"] = ["127.0.0.3"]
records["c.srv.test"] = ["127.0.0.4"]
for i in range(40):
    records[f"n{i}.srv.test"] = [f"127.0.1.{i + 1}"]
srv["_web._tcp.srv.test"] = [(10, 5, 7101, "a.srv.test"), (10, 5, 7102, "b.srv.test"), (20, 5, 7103, "c.srv.test")]
srv["_many._tcp.srv.test"] = [(10, 1, 7000, f"n{i}.srv.test") for i in range(40)]
conf = tmp / "okena.conf"
conf.write_text("""
okena {
    workers 2
    metrics 127.0.0.1:9464
}
tcp 127.0.0.1:8001 { to fromhosts:7000 }
tcp 127.0.0.1:8002 { to api:7000 }
tcp 127.0.0.1:8003 { to late.svc.test:7000 }
tcp 127.0.0.1:8004 { to multi:7000 }
tcp 127.0.0.1:8005 { to v6:7000 }
pool web { discover srv _web._tcp.srv.test }
pool many { discover srv _many._tcp.srv.test. }
tcp 127.0.0.1:8010 { to pool web }
tcp 127.0.0.1:8011 { to pool many }
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
    # (under load the fake server can be slow to answer okena's first lookup,
    # at startup: okena starts anyway, and the control process gets it soon)
    check("name through a search domain", wait_for(8002, b"two", 3) is not None)
    # ::1 on a loopback that was just brought up can take a moment
    check("IPv6 address from AAAA", wait_for(8005, b"six", 3) is not None)
    if "--stress" in sys.argv:
        import collections
        t0 = time.time()
        c = collections.Counter()
        times = []
        for _ in range(600):
            a = time.time()
            c[ask(8004)] += 1
            times.append(time.time() - a)
        print("backend saw no request on:", BACKEND_EMPTY)
        print("stress:", dict(c), f"max {max(times) * 1000:.0f} ms", f"{time.time() - t0:.1f}s")
        time.sleep(1.2)
        import urllib.request
        text = urllib.request.urlopen("http://127.0.0.1:9464/metrics").read().decode()
        print("\n".join(l for l in text.splitlines() if "multi" in l and not l.endswith(" 0")))
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
    # SRV: the records' ports, the lowest priority, backups behind
    seen = {ask(8010) for _ in range(30)}
    check("discover srv: each record's target and port", seen == {b"srv-a", b"srv-b"}, str(seen))
    check("  asked with EDNS0", asked_edns and all(asked_edns), str(asked_edns[:4]))
    log.seek(0)
    check("  40 records past 512 bytes, all taken", "discover srv _many._tcp.srv.test: 40 servers" in log.read())
    srv["_web._tcp.srv.test"] = [(10, 5, 7102, "b.srv.test"), (20, 5, 7103, "c.srv.test")]
    t = wait_all(8010, b"srv-b", 4)
    check("  a record taken out: no more there", t is not None, f"{t}")
    srv["_web._tcp.srv.test"] = [(20, 5, 7103, "c.srv.test")]
    t = wait_for(8010, b"srv-c", 4)
    check("  only a higher priority left: it serves", t is not None, f"{t}")
    srv["_web._tcp.srv.test"] = [(10, 5, 7101, "a.srv.test"), (20, 5, 7103, "c.srv.test")]
    t = wait_all(8010, b"srv-a", 4)
    check("  the lower one back: the higher is a backup again", t is not None, f"{t}")
    # DNS goes away: the last known addresses keep serving
    dns_up.clear()
    time.sleep(3)
    answers = [ask(8002) for _ in range(20)]
    ok = answers.count(b"three")
    check("DNS down: last known addresses keep serving", ok == 20, f"{ok}/20 {sorted(set(answers))}")
    ok = sum(ask(8010) == b"srv-a" for _ in range(20))
    check("  and the SRV servers too", ok == 20, f"{ok}/20")
    dns_up.set()
    log.seek(0)
    text = log.read()
    check("resolutions are logged", "api resolved to 127.0.0.2" in text and "multi resolved to 127.0.0.3, 127.0.0.4" in text
          and "v6 resolved to ::1" in text, "")
    # once for each reason: a slow first answer says "no answer", then "no such name"
    check("lookup failures are logged once, then quiet", text.count("cannot resolve late.svc.test: no such name") == 1
          and text.count("cannot resolve late.svc.test: no answer") <= 1, text[-400:])
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(10)
    log.seek(0)
    if failures or "-v" in sys.argv:
        print(log.read())
print(f"dns: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
