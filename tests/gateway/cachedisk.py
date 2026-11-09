#!/usr/bin/env python3
"""`cache_disk`, on one engine (argument): the second tier of `cache`, on disk, one
for all workers and processes. What one worker fills the others serve; it outlives a
reload, an upgrade and a restart; when it is full the oldest goes; what a client is
being sent is never overwritten under it; what is on disk is checked before it is
served (garbage is a miss, never an answer); a new size makes a new store."""
import hashlib
import http.client
import http.server
import os
import pathlib
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 44000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST, MET = BASE, BASE + 1, BASE + 2
fails = 0
hits = {}
lock = threading.Lock()


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def body_of(path):
    """What the backend answers for a path: /x/NAME?size=N, the same bytes each time."""
    size = int(path.split("size=")[1]) if "size=" in path else 32
    return random.Random(path.split("?")[0]).randbytes(size)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with lock:
            hits[self.path] = hits.get(self.path, 0) + 1
        b = body_of(self.path)
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def handle_error(self, *a):
        pass


def get(path, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request(method, path)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, r.getheader("cache-status", ""), b, r


def many(path, n=40):
    out = []
    ts = [threading.Thread(target=lambda: out.append(get(path))) for _ in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def disk_counters():
    """(on a failure: what the store counted, once a second's publishing is past)"""
    import re
    import urllib.request
    time.sleep(1.1)
    try:
        t = urllib.request.urlopen(f"http://127.0.0.1:{MET}/metrics", timeout=3).read().decode()
    except OSError:
        return None
    d = {k: int(v) for k, v in re.findall(r"^okena_cache_disk_(\w+)_total (\d+)", t, re.M)}
    return d


def conf_text(tmp, size="8MiB", workers=4):
    return f"""okena {{ workers {workers}; io_engine {ENGINE}; drain delay=0s timeout=1s; upgrade {tmp}/up.sock; metrics 127.0.0.1:{MET}
    cache_memory 1MiB; cache_disk {tmp}/store size={size} }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    http2 on
    route /swr/* {{ cache 1s stale-while-revalidate=30s; to pool b }}
    route /* {{ cache 1h max=1MiB; to pool b }}
}}
"""


def start(conf, log, upgrade=False):
    cmd = [str(BIN)] + (["upgrade"] if upgrade else []) + ["-c", str(conf)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=open(log, "a"))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-cachedisk-", dir="/tmp"))
    (tmp / "store").mkdir()
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(conf_text(tmp))
    log = tmp / "log"
    procs = [start(conf, log)]
    try:
        check("okena starts, with a new store", until(lambda: get("/up")[0] == 200)
              and "cache_disk: a new store in" in log.read_text(), log.read_text()[-400:])
        check("  its files", all((tmp / "store" / n).exists() for n in ("okena.idx", "okena.dat", "okena.lock")),
              list((tmp / "store").iterdir()))

        # one worker fills, the others serve it from disk
        p = "/x/shared?size=150000"
        s, cs, b, _ = get(p)
        check("a miss fills", s == 200 and b == body_of(p), (s, cs))
        out = many(p)
        disk = [o for o in out if "detail=disk" in o[1]]
        check("the other workers serve what one filled: the backend heard once", hits.get(p) == 1
              and all(o[0] == 200 and o[2] == body_of(p) for o in out) and disk, (hits.get(p), len(disk), {o[1] for o in out}))
        check("  a hit from disk says so, with its age and ttl", disk and disk[0][1].startswith("okena; hit; ttl=")
              and disk[0][3].getheader("age") is not None, disk[0][1] if disk else None)
        h = [get(p, "HEAD") for _ in range(12)]
        check("  HEAD reads it: its length, no body", all(x[0] == 200 and x[2] == b"" and x[3].getheader("content-length") == "150000" for x in h),
              [(x[0], x[3].getheader("content-length")) for x in h])

        # a reload: new workers, empty memory, the store as it was
        conf.write_text(conf_text(tmp, workers=3))
        n0 = log.read_text().count("configuration reloaded")
        procs[0].send_signal(signal.SIGHUP)
        until(lambda: log.read_text().count("configuration reloaded") > n0)
        out = many(p, 20)
        check("a reload: served from disk, the backend not asked", hits.get(p) == 1 and all(o[2] == body_of(p) for o in out)
              and any("detail=disk" in o[1] for o in out), (hits.get(p), {o[1] for o in out}))

        # an upgrade: another process on the same store
        procs.append(start(conf, log, upgrade=True))
        until(lambda: procs[0].poll() is not None, 10)
        out = many(p, 20)
        check("an upgrade: the new process serves it from disk", procs[0].poll() == 0 and hits.get(p) == 1
              and all(o[2] == body_of(p) for o in out), (procs[0].poll(), hits.get(p)))

        # a restart: left clean, kept
        procs[-1].send_signal(signal.SIGTERM)
        procs[-1].wait(10)
        procs.append(start(conf, log))
        until(lambda: get("/up")[0] == 200)
        out = many(p, 20)
        check("a restart: still there", hits.get(p) == 1 and all(o[2] == body_of(p) for o in out)
              and log.read_text().count("a new store") == 1, (hits.get(p), log.read_text().count("a new store")))

        # what a client is being sent is not overwritten: a reader that holds it (HTTP/2,
        # its window not given back) pins it while the store is filled over and over
        import h2.config
        import h2.connection
        import h2.events
        slow = "/x/slow?size=400000"
        get(slow)
        held = None
        for _ in range(40):
            c = socket.create_connection(("127.0.0.1", LST), timeout=5)
            hc = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
            hc.initiate_connection()
            sid = hc.get_next_available_stream_id()
            hc.send_headers(sid, [(":method", "GET"), (":path", slow), (":scheme", "http"), (":authority", f"127.0.0.1:{LST}")], end_stream=True)
            c.sendall(hc.data_to_send())
            data, heads, ended, owed = b"", None, False, []
            while heads is None:
                for e in hc.receive_data(c.recv(65536)):
                    if isinstance(e, h2.events.ResponseReceived):
                        heads = dict((k.decode(), v.decode()) for k, v in e.headers)
                    elif isinstance(e, h2.events.DataReceived):
                        data += e.data
                        owed.append((e.flow_controlled_length, e.stream_id))
                c.sendall(hc.data_to_send())
            if "detail=disk" in heads.get("cache-status", ""):
                held = c
                break
            c.close()
        check("  (a reader on a worker that has it on disk only)", held is not None)
        if held:
            c.settimeout(0.3)
            try:                                # what the window lets through: then it waits
                while True:
                    for e in hc.receive_data(c.recv(65536)):
                        if isinstance(e, h2.events.DataReceived):
                            data += e.data
                            owed.append((e.flow_controlled_length, e.stream_id))
            except socket.timeout:
                pass
            for i in range(40):                 # 12 MB through an 8 MB store
                get(f"/x/churn{i}?size=300000")
            c.settimeout(5)
            for n, i in owed:                   # the window, given back
                hc.acknowledge_received_data(n, i)
            c.sendall(hc.data_to_send())
            seen = []
            try:
                while not ended:
                    d = c.recv(65536)
                    if not d:
                        seen.append("closed")
                        break
                    for e in hc.receive_data(d):
                        seen.append(type(e).__name__)
                        if isinstance(e, h2.events.DataReceived):
                            data += e.data
                            hc.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                        elif isinstance(e, h2.events.StreamEnded):
                            ended = True
                    c.sendall(hc.data_to_send())
            except socket.timeout:
                seen.append("timed out")
            c.close()
            check("a reader holding an answer gets every byte right while the store fills over it",
                  hashlib.sha256(data).digest() == hashlib.sha256(body_of(slow)).digest(),
                  (len(data), len(owed), sum(n for n, _ in owed), [x for x in seen if x != "DataReceived"][-6:],
                   hc.local_flow_control_window(1), hc.outbound_flow_control_window))

        # full: the oldest went, the newest are there, every answer right
        for i in range(40):
            get(f"/x/fifo{i}?size=200000")
        before = dict(hits)
        early = [get(f"/x/fifo{i}?size=200000") for i in range(3)]
        late = many("/x/fifo39?size=200000", 20)
        check("full: the oldest went (asked again), the newest stayed", all(hits[f"/x/fifo{i}?size=200000"] == 2 for i in range(3))
              and hits["/x/fifo39?size=200000"] == before["/x/fifo39?size=200000"] == 1
              and all(x[2] == body_of("/x/fifo0?size=200000") for x in early[:1])
              and all(x[2] == body_of("/x/fifo39?size=200000") for x in late),
              ([hits[f"/x/fifo{i}?size=200000"] for i in range(3)], hits["/x/fifo39?size=200000"], disk_counters()))

        # S3-FIFO: what is asked for again outlives a scan of what is asked for once
        hot = [f"/x/hot{i}?size=200000" for i in range(5)]
        for q in hot:
            get(q)
        for _ in range(3):
            for q in hot:
                many(q, 4)                      # (hits from the other workers' disk)
        ghost = "/x/ghost?size=200000"
        get(ghost)                              # asked for once
        h_hot = [hits[q] for q in hot]
        for i in range(48):                     # 9.6 MB of one-hit wonders through 8 MB
            get(f"/x/scan{i}?size=200000")
        out = [get(q) for q in hot for _ in range(2)]
        check("S3-FIFO: what was asked for again outlives a scan bigger than the store",
              [hits[q] for q in hot] == h_hot and all(o[0] == 200 for o in out),
              ([hits[q] - h for q, h in zip(hot, h_hot)]))
        h_g = hits[ghost]
        get(ghost)
        check("  the scan's one-hit wonders went (one of them, asked again: fetched)", hits[ghost] == h_g + 1, hits[ghost])
        for i in range(48):
            get(f"/x/scan2-{i}?size=200000")
        many(ghost, 6)
        check("  it came back as a ghost: straight to the main log, and outlived the next scan",
              hits[ghost] == h_g + 1, hits[ghost] - h_g)

        # the keeper killed: started again, and the store goes on
        def keeper():
            for d in pathlib.Path("/proc").iterdir():
                try:
                    if d.name.isdigit() and (d / "comm").read_text().strip() == "okena-cache" \
                            and f"PPid:\t{procs[-1].pid}\n" in (d / "status").read_text():
                        return int(d.name)
                except OSError:
                    pass
        k0 = keeper()
        if k0:
            os.kill(k0, signal.SIGKILL)
        check("the cache keeper killed: started again", k0 and until(lambda: keeper() not in (None, k0), 5)
              and "cache keeper exited, restarting it" in log.read_text(), (k0, keeper()))
        for i in range(48):
            get(f"/x/scan3-{i}?size=200000")
        q = "/x/after-keeper?size=100000"
        get(q)
        out = many(q, 12)
        check("  and the store goes on: filled, served from disk", hits[q] == 1 and any("detail=disk" in o[1] for o in out), hits[q])

        # stale within its window, from disk: served at once, fetched again
        sw = "/swr/a?size=1000"
        get(sw)
        time.sleep(1.3)
        out = many(sw, 12)
        check("stale on disk, within stale-while-revalidate: served, and fetched again", all(o[0] == 200 and o[2] == body_of(sw) for o in out)
              and any("ttl=-" in o[1] for o in out) and until(lambda: hits.get(sw, 0) >= 2, 3), (hits.get(sw), {o[1] for o in out}))

        # garbage where the answers are: a miss, never an answer
        procs[-1].send_signal(signal.SIGTERM)
        procs[-1].wait(10)
        dat = tmp / "store" / "okena.dat"
        with open(dat, "r+b") as f:
            n = dat.stat().st_size
            f.write(random.Random(3).randbytes(n))
        procs.append(start(conf, log))
        until(lambda: get("/up")[0] == 200)
        h0 = hits.get("/x/fifo39?size=200000")
        out = many("/x/fifo39?size=200000", 12)
        check("garbage on disk: not served, asked again, answered right", hits["/x/fifo39?size=200000"] > h0
              and all(o[0] == 200 and o[2] == body_of("/x/fifo39?size=200000") for o in out), hits["/x/fifo39?size=200000"] - h0)

        # each check of a record on its own: its mark, its place, its key
        def corrupt(at, name):
            nonlocal_q = f"/x/field-{name}?size=50000"
            get(nonlocal_q)
            many(nonlocal_q, 8)
            procs[-1].send_signal(signal.SIGTERM)
            procs[-1].wait(10)
            raw = bytearray(dat.read_bytes())
            n = 0
            for off in range(0, len(raw) - 64, 64):
                if raw[off:off + 4] == b"OKR1":
                    raw[off + at] ^= 0x55
                    n += 1
            dat.write_bytes(bytes(raw))
            procs.append(start(conf, log))
            until(lambda: get("/up")[0] == 200)
            h0 = hits[nonlocal_q]
            out = many(nonlocal_q, 8)
            check(f"a record whose {name} is wrong: not served, asked again", n and hits[nonlocal_q] > h0
                  and all(o[2] == body_of(nonlocal_q) for o in out), (n, hits[nonlocal_q] - h0))
        corrupt(0, "mark")
        corrupt(16, "place")
        corrupt(40, "key")

        # another size: a new store, put in place while the old one is in use
        conf.write_text(conf_text(tmp, size="4MiB"))
        n0 = log.read_text().count("configuration reloaded")
        procs[-1].send_signal(signal.SIGHUP)
        until(lambda: log.read_text().count("configuration reloaded") > n0)
        q = "/x/resized?size=100000"
        get(q)
        out = many(q, 20)
        check("a new size: a new store, used by all", log.read_text().count("a new store") == 2 and hits[q] == 1
              and any("detail=disk" in o[1] for o in out), (log.read_text().count("a new store"), hits[q]))
    finally:
        for pr in procs:
            if pr.poll() is None:
                pr.terminate()
        for pr in procs:
            try:
                pr.wait(10)
            except subprocess.TimeoutExpired:
                pr.kill()

    # a directory that cannot be had: memory only, said
    bad = tmp / "bad.conf"
    bad.write_text(conf_text(tmp).replace(f"{tmp}/store", f"{tmp}/nowhere"))
    log2 = tmp / "log2"
    q = start(bad, log2)
    try:
        check("a store that cannot be had: said, and answers kept in memory", until(lambda: get("/x/m")[0] == 200)
              and "answers are kept in memory only" in log2.read_text(), log2.read_text()[-300:])
    finally:
        q.terminate()
        q.wait(10)
    t = log.read_text() + log2.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"cachedisk {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
