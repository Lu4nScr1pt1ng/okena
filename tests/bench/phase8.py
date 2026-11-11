#!/usr/bin/env python3
"""Phase 8's exit, measured: (1) the hit path from the page cache with zero copies,
against the same body copied through okena (a memory cache hit); throughput, okena's
CPU per GiB and okena_zero_copy_bytes_total against the bytes sent; (2) a
purge-and-refill storm: a prefix purge every 50 ms under load, and what reaches the
origin, at a light and at a heavy client load.

okena on cores 2-3 (2 workers), wrk on 8-15, the origin where the kernel puts it.
Run: python3 tests/bench/phase8.py"""
import http.server
import os
import pathlib
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 24500
BACK, LST, MET = BASE, BASE + 1, BASE + 2
BIG = random.Random(8).randbytes(4 << 20)
SMALL = random.Random(9).randbytes(16 << 10)
HOST = "shop.example"
hits = {"n": 0, "t": []}
lock = threading.Lock()


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = BIG if self.path.startswith(("/m/", "/d/")) else SMALL
        if self.path.startswith("/p/"):
            with lock:
                hits["n"] += 1
                hits["t"].append(time.monotonic())
            time.sleep(0.002)               # an origin that takes a moment
        # one write: a head and a body apart meet Nagle and a delayed ACK (40 ms)
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 512


def until(fn, seconds=10):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def metric(name):
    t = urllib.request.urlopen(f"http://127.0.0.1:{MET}/metrics", timeout=5).read().decode()
    return sum(int(float(m)) for m in re.findall(rf"^{name}(?:{{[^}}]*}})? (\S+)", t, re.M))


def cpu(master):
    """okena's processes' (user, system) seconds"""
    hz = os.sysconf("SC_CLK_TCK")
    u = s = 0
    for d in pathlib.Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            f = (d / "stat").read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if d.name == str(master) or f[1] == str(master):
            u, s = u + int(f[11]), s + int(f[12])
    return u / hz, s / hz


def wrk(path, conns, threads, secs, script=None):
    a = ["taskset", "-c", "8-15", "wrk", f"-t{threads}", f"-c{conns}", f"-d{secs}s", "--latency", "-H", f"Host: {HOST}"]
    if script:
        a += ["-s", str(script)]
    out = subprocess.run(a + [f"http://127.0.0.1:{LST}{path}"], capture_output=True, text=True, timeout=secs + 30).stdout
    rps = float(re.search(r"Requests/sec:\s+(\S+)", out).group(1))
    n = int(re.search(r"(\d+) requests in", out).group(1))
    p99 = re.search(r"99%\s+(\S+)", out).group(1)
    errs = re.search(r"Non-2xx or 3xx responses: (\d+)|Socket errors: (.*)", out)
    return rps, n, p99, errs.group(0) if errs else ""


def start(tmp, conf):
    log = tmp / "log"
    p = subprocess.Popen(["taskset", "-c", "2-3", str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "a"))
    if not until(lambda: socket.create_connection(("127.0.0.1", MET), 1).close() or True):
        sys.exit("okena did not start: " + log.read_text()[-400:])
    return p


def stop(p):
    p.terminate()
    p.wait(15)


def get(path):
    r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{LST}{path}", headers={"Host": HOST}), timeout=10)
    r.read()
    return r.headers.get("Cache-Status", "")


def zero_copy(tmp, engine):
    print(f"== the hit path, {engine}: 4 MiB bodies, 32 connections, 5 s each")
    site = tmp / "site"
    (site / "f").mkdir(parents=True, exist_ok=True)
    (site / "f" / "big.bin").write_bytes(BIG)
    store = tmp / f"store-{engine}"
    store.mkdir()
    def conf(name, mem, disk=True):
        (tmp / name).write_text(f"""okena {{ workers 2; io_engine {engine}; drain delay=0s timeout=1s
    metrics 127.0.0.1:{MET}; cache_memory {mem}{f"; cache_disk {store} size=256MiB" if disk else ""} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    route /f/* {{ files {site} }}
    route /* {{ cache 1h max=8MiB; to pool b }}
}}
""")
        return tmp / name
    # memory only: each worker holds the body, and copies it out
    mem = conf("mem.conf", "64MiB", disk=False)
    # with the disk: filled by this one (one worker fetches, the other finds it on
    # disk), then stopped; the next finds it on disk only (memory too small for it)
    fill = conf("fill.conf", "64MiB")
    disk = conf("disk.conf", "1MiB")
    p = start(tmp, fill)
    try:
        for _ in range(8):
            get("/m/big.bin")
    finally:
        stop(p)
    rows = []
    for c, path, what in ((disk, "/f/big.bin", "files, zero copy"), (mem, "/m/big.bin", "memory cache hit, copied"),
                          (disk, "/m/big.bin", "disk cache hit, zero copy")):
        p = start(tmp, c)
        try:
            run = 0                     # (each worker its own memory: until both have it)
            for _ in range(60):
                st = get(path)
                run = run + 1 if not path.startswith("/m/") or ("hit" in st and (c == disk) == ("disk" in st)) else 0
                if run == 6:
                    break
            else:
                sys.exit(f"not the hit wanted: {st}")
            wrk(path, 32, 4, 1)
            z0, c0 = metric("okena_zero_copy_bytes_total"), cpu(p.pid)
            rps, n, p99, err = wrk(path, 32, 4, 5)
            z1, c1 = metric("okena_zero_copy_bytes_total"), cpu(p.pid)
        finally:
            stop(p)
        gib = n * len(BIG) / (1 << 30)
        us, ss = c1[0] - c0[0], c1[1] - c0[1]
        rows.append((what, rps * len(BIG) * 8 / 1e9, (us + ss) / gib, us / gib, (z1 - z0) / (n * len(BIG)), p99, err))
    print(f"{'':28} {'Gbit/s':>7} {'CPU s/GiB':>9} {'user':>6} {'zero-copy':>9} {'p99':>8}")
    for what, gbit, cg, ug, zc, p99, err in rows:
        print(f"{what:28} {gbit:7.1f} {cg:9.3f} {ug:6.3f} {zc:9.0%} {p99:>8} {err}")


def storm(tmp):
    print("== purge-and-refill: 16 hot objects of 16 KiB, a prefix purge every 50 ms for 5 s")
    store = tmp / "pstore"
    store.mkdir()
    conf = tmp / "storm.conf"
    conf.write_text(f"""okena {{ workers 2; drain delay=0s timeout=1s; metrics 127.0.0.1:{MET}; admin unix:{tmp}/a.sock
    cache_memory 64MiB; cache_disk {store} size=64MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{ route /* {{ cache 1h; to pool b }} }}
""")
    script = tmp / "rot.lua"
    script.write_text('local i = 0\nrequest = function()\n  i = (i + 1) % 16\n'
                      '  return wrk.format("GET", "/p/k" .. i)\nend\n')
    print(f"{'clients':>8} {'phase':>8} {'req/s':>9} {'p99':>8} {'origin':>7} {'origin/s':>8} {'purges':>6} {'per purge':>9}")
    for conns, threads in ((4, 2), (128, 8)):
        p = start(tmp, conf)
        try:
            wrk("/", conns, threads, 1, script)
            for phase in ("quiet", "storm"):
                done = threading.Event()
                purges = [0]

                def purger():
                    while not done.is_set():
                        t = time.monotonic()
                        subprocess.run([str(BIN), "purge", "prefix", f"{HOST}/p/", "-c", str(conf)], capture_output=True, timeout=10)
                        purges[0] += 1
                        done.wait(max(0, 0.05 - (time.monotonic() - t)))
                h0 = hits["n"]
                th = threading.Thread(target=purger) if phase == "storm" else None
                if th:
                    th.start()
                rps, n, p99, err = wrk("/", conns, threads, 5, script)
                done.set()
                if th:
                    th.join()
                o = hits["n"] - h0
                per = f"{o / purges[0]:9.1f}" if purges[0] else f"{'-':>9}"
                print(f"{conns:8} {phase:>8} {rps:9.0f} {p99:>8} {o:7} {o / 5:8.0f} {purges[0]:6} {per} {err}")
        finally:
            stop(p)
    print("(per purge: origin requests for each purge of the 16 objects; one fill per object and worker is 32)")


def main():
    if not shutil.which("wrk"):
        sys.exit("wrk is needed")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-phase8-", dir="/tmp"))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    try:
        for engine in ("io_uring", "epoll"):
            zero_copy(tmp, engine)
        storm(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


main()
