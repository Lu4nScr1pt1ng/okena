#!/usr/bin/env python3
"""access_log on tcp and udp listeners, on one engine (argument): a JSON line
per connection when it closes and per flow when it ends, with the client,
its port, the upstream, bytes both ways and the duration; a client refused
before any backend has "upstream": null."""
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 12400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, UBACK, T, U = BASE, BASE + 1, BASE + 2, BASE + 3

failures = 0


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
        try:
            while (d := c.recv(100)):
                c.sendall(d + d)          # twice as much back
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
            s.sendto(d + b"!", a)
    threading.Thread(target=loop, daemon=True).start()


tcp_echo()
udp_echo()
tmp = pathlib.Path(tempfile.mkdtemp())
alog = tmp / "l4.log"
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
tcp 127.0.0.1:{T} {{
    to 127.0.0.1:{BACK}
    deny 127.0.0.5
    access_log {alog}
}}
udp 127.0.0.1:{U} {{
    to 127.0.0.1:{UBACK}
    responses 1
    access_log {alog}
}}
""")


def lines(n, wait=4.0):
    end = time.time() + wait
    while time.time() < end:
        if alog.exists():
            got = [json.loads(x) for x in alog.read_text().splitlines() if x.strip()]
            if len(got) >= n:
                return got
        time.sleep(0.05)
    return [json.loads(x) for x in alog.read_text().splitlines() if x.strip()] if alog.exists() else []


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

    c = socket.create_connection(("127.0.0.1", T), timeout=3)
    port = c.getsockname()[1]
    c.sendall(b"hello")
    got = b""
    while len(got) < 10:
        got += c.recv(64)
    time.sleep(0.05)
    c.close()
    d = socket.socket()
    d.bind(("127.0.0.5", 0))
    d.settimeout(3)
    d.connect(("127.0.0.1", T))
    try:
        d.recv(10)
    except OSError:
        pass
    d.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    u.sendto(b"ping", ("127.0.0.1", U))
    uport = u.getsockname()[1]
    r = u.recv(64)
    u.close()

    got_lines = lines(3)
    by = {}
    for x in got_lines:
        by.setdefault((x.get("proto"), x.get("client")), x)
    t = by.get(("tcp", "127.0.0.1"), {})
    check("tcp: a line when the connection closes, bytes both ways",
          t.get("bytes_in") == 5 and t.get("bytes_out") == 10 and t.get("client_port") == port, str(t))
    check("tcp: the upstream and the listener",
          t.get("upstream") == f"127.0.0.1:{BACK}" and t.get("listener") == f"127.0.0.1:{T}", str(t))
    check("tcp: a duration and a time", isinstance(t.get("duration_ms"), float) and t.get("duration_ms") >= 0
          and "T" in t.get("time", ""), str(t))
    dn = by.get(("tcp", "127.0.0.5"), {})
    check("tcp: a denied client has a line, upstream null, nothing moved",
          dn and dn.get("upstream") is None and dn.get("bytes_in") == 0 and dn.get("bytes_out") == 0, str(dn))
    uu = by.get(("udp", "127.0.0.1"), {})
    check("udp: a line when the flow ends (responses 1)",
          r == b"ping!" and uu.get("bytes_in") == 4 and uu.get("bytes_out") == 5 and uu.get("client_port") == uport
          and uu.get("upstream") == f"127.0.0.1:{UBACK}", str(uu))
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
        print(alog.read_text() if alog.exists() else "(no access log)")
print(f"l4 access log ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
