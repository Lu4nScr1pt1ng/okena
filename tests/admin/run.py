#!/usr/bin/env python3
"""Admin endpoints: /metrics in Prometheus format with counts that match
the traffic, /live, /ready (503 while draining), okena health, and the
supervisor's counters across a reload and a worker crash."""
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
# ports 21000-21999: this suite's own range (none overlap)
BASE = 21000 + os.getpid() % 99 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, MET = BASE, BASE + 1, BASE + 2


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(256)

    def handle(c):
        try:
            while (d := c.recv(65536)):
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def get(path):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{MET}{path}", timeout=3)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def metrics():
    status, text = get("/metrics")
    assert status == 200
    values = {}
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        m = re.fullmatch(r'([a-z_]+)(\{[^}]*\})? (\d+)', line)
        assert m, f"not Prometheus text: {line!r}"
        values[m.group(1) + (m.group(2) or "")] = int(m.group(3))
    return values


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


backend()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{
    workers 2
    io_engine {ENGINE}
    metrics 127.0.0.1:{MET}
    drain delay=2s timeout=3s
}}
pool echo {{ server 127.0.0.1:{BACK} }}
tcp 127.0.0.1:{LST} {{
    to pool echo
    limits {{ per_source 2 }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
L = f'{{listener="127.0.0.1:{LST}"'
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    check("/live", get("/live")[0] == 200)
    check("/ready while serving", get("/ready")[0] == 200)
    check("unknown path is 404", get("/nope")[0] == 404)
    h = subprocess.run([str(BIN), "health", str(conf)], capture_output=True, text=True)
    check("okena health: ready", h.returncode == 0 and h.stdout.strip() == "ready")

    # traffic: 10 connections, 1000 bytes each way
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", LST), timeout=3)
        c.sendall(b"x" * 1000)
        got = b""
        while len(got) < 1000:
            got += c.recv(4096)
        c.close()
    # a session ends when both sides have closed (through the backend), and
    # counts for per_source until then: let the ten finish first
    t0 = time.time()
    while time.time() - t0 < 5 and metrics()[f"okena_listener_active{L}}}"] != 0:
        time.sleep(0.2)
    held = [socket.create_connection(("127.0.0.1", LST), timeout=3) for _ in range(2)]
    ok_held = 0
    for c in held:
        c.sendall(b"y")
        ok_held += c.recv(1) == b"y"
    check("two connections held", ok_held == 2)
    refused = 0
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", LST), timeout=3)
        c.sendall(b"z")
        try:
            refused += c.recv(1) == b""
        except OSError:
            refused += 1
        c.close()
    time.sleep(1.3)                     # workers publish once a second
    m = metrics()
    check("connections counted", m[f"okena_listener_connections_total{L}}}"] == 12 + 0, str(m[f"okena_listener_connections_total{L}}}"]))
    check("bytes counted each way", m[f'okena_listener_bytes_total{L},direction="in"}}'] == 10002
          and m[f'okena_listener_bytes_total{L},direction="out"}}'] == 10002)
    check("active connections", m[f"okena_listener_active{L}}}"] == 2, str(m[f"okena_listener_active{L}}}"]))
    check("per_source refusals counted", m[f'okena_listener_refused_total{L},reason="per_source"}}'] == 3 == refused,
          f"{m[f'okena_listener_refused_total{L},reason=\"per_source\"}}']} counted, {refused} seen, "
          f"{m['okena_per_source_untracked_total']} untracked")
    srv = f'{{pool="echo",server="127.0.0.1:{BACK}"}}'
    check("backend connects counted", m[f"okena_backend_connects_total{srv}"] == 12)
    for c in held:
        c.close()

    # supervisor counters
    os.kill(int(subprocess.check_output(["pgrep", "-P", str(p.pid), "-x", "okena-worker"]).split()[0]), signal.SIGKILL)
    time.sleep(0.5)
    p.send_signal(signal.SIGHUP)
    time.sleep(1.5)
    m = metrics()
    check("restarts and reloads counted", m["okena_restarts_total"] == 1 and m["okena_reloads_total"] == 1,
          f'{m["okena_restarts_total"]} restarts, {m["okena_reloads_total"]} reloads')

    # draining: /ready fails at once, traffic still served during the delay
    p.send_signal(signal.SIGTERM)
    time.sleep(0.3)
    check("/ready is 503 while draining", get("/ready")[0] == 503)
    h = subprocess.run([str(BIN), "health", str(conf)], capture_output=True, text=True)
    check("okena health: not ready while draining", h.returncode == 1)
    c = socket.create_connection(("127.0.0.1", LST), timeout=3)
    c.sendall(b"q")
    check("still serving during the drain delay", c.recv(1) == b"q")
    c.close()
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"admin ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
