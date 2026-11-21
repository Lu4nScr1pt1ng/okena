#!/usr/bin/env python3
"""allow/deny on tcp and udp listeners, on one engine (argument): a refused
client is closed (tcp) or dropped (udp) before a backend is asked; behind
`proxy_protocol accept` the header's client is the one judged; refusals are
counted by reason in okena_listener_refused_total."""
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
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 11400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, UBACK, TALLOW, TDENY, TPP, UALLOW, METRICS = (BASE + i for i in range(7))

failures = 0
hits = {"tcp": 0, "udp": 0}


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def tcp_echo():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(64)

    def handle(c):
        hits["tcp"] += 1
        try:
            while (d := c.recv(100)):
                c.sendall(d)
        except OSError:
            pass
        c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UBACK))

    def loop():
        while True:
            d, a = s.recvfrom(2048)
            hits["udp"] += 1
            s.sendto(d, a)
    threading.Thread(target=loop, daemon=True).start()


def tcp_try(port, src, data=b"hi"):
    c = socket.socket()
    c.settimeout(2)
    c.bind((src, 0))
    try:
        c.connect(("127.0.0.1", port))
        c.sendall(data)
        return c.recv(64)
    except OSError:
        return b""
    finally:
        c.close()


def udp_try(port, src):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.6)
    s.bind((src, 0))
    try:
        s.sendto(b"ping", ("127.0.0.1", port))
        return s.recv(64)
    except OSError:
        return b""
    finally:
        s.close()


def v1(src):
    return f"PROXY TCP4 {src} 192.0.2.1 1000 80\r\n".encode()


tcp_echo()
udp_echo()
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "deny.txt").write_text("# who may not\n127.0.0.3\n")
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 2; io_engine {ENGINE}; metrics 127.0.0.1:{METRICS}; drain delay=0s timeout=1s }}
tcp 127.0.0.1:{TALLOW} {{
    to 127.0.0.1:{BACK}
    allow 127.0.0.0/30
    deny file:{tmp}/deny.txt
}}
tcp 127.0.0.1:{TDENY} {{
    to 127.0.0.1:{BACK}
    deny 127.0.0.2
}}
tcp 127.0.0.1:{TPP} {{
    to 127.0.0.1:{BACK}
    proxy_protocol accept
    allow 203.0.113.0/24
}}
udp 127.0.0.1:{UALLOW} {{
    to 127.0.0.1:{UBACK}
    allow 127.0.0.2
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

    check("tcp allow 127.0.0.0/30: 127.0.0.1 gets through", tcp_try(TALLOW, "127.0.0.1") == b"hi")
    before = hits["tcp"]
    check("tcp: 127.0.0.9, outside every allow, is closed", tcp_try(TALLOW, "127.0.0.9") == b"")
    check("tcp: a deny from a file wins over an allow", tcp_try(TALLOW, "127.0.0.3") == b"")
    check("tcp: the backend never saw a refused client", hits["tcp"] == before, str(hits["tcp"] - before))
    check("tcp deny alone: 127.0.0.2 closed", tcp_try(TDENY, "127.0.0.2") == b"")
    check("tcp deny alone: everyone else served", tcp_try(TDENY, "127.0.0.1") == b"hi")
    check("behind proxy_protocol accept: the header's client is judged (allowed)",
          tcp_try(TPP, "127.0.0.1", v1("203.0.113.5") + b"hi") == b"hi")
    check("  and refused", tcp_try(TPP, "127.0.0.1", v1("198.51.100.5") + b"hi") == b"")
    check("  a broken PROXY header", tcp_try(TPP, "127.0.0.1", b"PROXY nope\r\nhi") == b"")
    check("udp allow 127.0.0.2: it gets its answer", udp_try(UALLOW, "127.0.0.2") == b"ping")
    before = hits["udp"]
    check("udp: 127.0.0.1 is dropped", udp_try(UALLOW, "127.0.0.1") == b"")
    check("udp: the backend never saw it", hits["udp"] == before)

    time.sleep(1.2)                      # (workers publish their counters each second)
    m = urllib.request.urlopen(f"http://127.0.0.1:{METRICS}/metrics", timeout=5).read().decode()
    def refused(port, reason):
        for line in m.splitlines():
            if line.startswith("okena_listener_refused_total") and f":{port}\"" in line and f'reason="{reason}"' in line:
                return int(line.split()[-1])
        return -1
    check("metrics: refused by allow/deny, per listener",
          refused(TALLOW, "denied") == 2 and refused(TDENY, "denied") == 1 and refused(UALLOW, "denied") >= 1,
          f"{refused(TALLOW, 'denied')} {refused(TDENY, 'denied')} {refused(UALLOW, 'denied')}")
    check("metrics: a broken PROXY header", refused(TPP, "proxy_protocol") == 1 and refused(TPP, "denied") == 1,
          f"{refused(TPP, 'proxy_protocol')} {refused(TPP, 'denied')}")
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"l4 acl ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
