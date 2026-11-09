#!/usr/bin/env python3
"""`cache ... slice=`, on one engine (argument): a large object kept as slices,
each fetched once with a Range of its own; a whole GET put together from them, a
Range answered from the slices it covers (and only those fetched), across slices,
past the end (416); an object smaller than a slice; a backend that does not slice
(the request goes to it as it came); HEAD, HTTP/2, many clients at once, another
worker reading the slices from disk, and a purge."""
import http.client
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

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 51000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
S = 65536
fails = 0
asked = []                                      # (path, range or None)
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


def obj(path):
    n = 1000 if "small" in path else 1_000_000
    return random.Random(path).randbytes(n)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def answer(self, body):
        path = self.path
        b = obj(path)
        rng = self.headers.get("Range")
        with lock:
            asked.append((path, rng))
        m = re.fullmatch(r"bytes=(\d+)-(\d+)", rng or "")
        if m and "norange" not in path:
            a, z = int(m.group(1)), min(int(m.group(2)), len(b) - 1)
            if "liar" in path:                  # whatever was asked: its first slice
                a, z = 0, int(m.group(2)) - int(m.group(1))
            part = b[a:z + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{z}/{len(b)}")
            self.send_header("Content-Length", str(len(part)))
            self.send_header("ETag", '"v1"')
            self.end_headers()
            if body:
                self.wfile.write(part)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("ETag", '"v1"')
        self.end_headers()
        if body:
            self.wfile.write(b)

    def do_GET(self):
        self.answer(True)

    def do_HEAD(self):
        self.answer(False)

    def log_message(self, *a):
        pass


class Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def get(path, rng=None, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=10)
    c.request(method, path, headers={"Host": "t", **({"Range": rng} if rng else {})})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, r


def of(path):
    with lock:
        return [x for x in asked if x[0] == path]


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-slice-", dir="/tmp"))
    (tmp / "store").mkdir()
    threading.Thread(target=Srv(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s; admin unix:{tmp}/a.sock
    cache_memory 16MiB; cache_disk {tmp}/store size=32MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    http2 on
    route /* {{ cache 1h slice=64KiB; to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get("/up/small")[0] == 200), log.read_text()[-300:])
        big = obj("/big")
        s, b, r = get("/big")
        want = {f"bytes={i * S}-{i * S + S - 1}" for i in range((len(big) + S - 1) // S)}
        got = of("/big")
        check("a whole GET: put together from its slices, each fetched once with a Range",
              s == 200 and b == big and r.getheader("content-length") == str(len(big))
              and {g[1] for g in got} == want and len(got) == len(want), (s, len(b), len(got), [g[1] for g in got if g[1] not in want][:3]))
        n0 = len(of("/big"))
        out = [get("/big") for _ in range(4)]
        check("  again: all from the cache (both workers, memory or disk)", all(o[0] == 200 and o[1] == big for o in out)
              and len(of("/big")) == n0, len(of("/big")) - n0)

        b2 = obj("/big2")
        s, b, r = get("/big2", "bytes=500000-500099")
        check("a Range of something not kept: only its slice is fetched, the answer is a 206",
              s == 206 and b == b2[500000:500100] and r.getheader("content-range") == f"bytes 500000-500099/{len(b2)}"
              and [g[1] for g in of("/big2")] == [f"bytes={7 * S}-{8 * S - 1}"], (s, r.getheader("content-range"), of("/big2")))
        b3 = obj("/big3")
        s, b, r = get("/big3", "bytes=60000-140000")
        check("  across slices: each it covers, in turn", s == 206 and b == b3[60000:140001] and len(of("/big3")) == 3,
              (s, len(b), of("/big3")))
        s, b, r = get("/big", f"bytes={len(big) - 10}-")
        check("  to the end", s == 206 and b == big[-10:], (s, len(b)))
        s, b, r = get("/big", f"bytes={len(big)}-")
        check("  past it: 416", s == 416 and r.getheader("content-range") == f"bytes */{len(big)}", (s, r.getheader("content-range")))

        sm = obj("/small")
        s, b, r = get("/small")
        check("an object smaller than a slice: one slice, all of it", s == 200 and b == sm and len(of("/small")) == 1, (s, len(b), of("/small")))

        nr = obj("/norange")
        s, b, r = get("/norange")
        check("a backend that does not slice: the request goes to it as it came, the answer whole",
              s == 200 and b == nr, (s, len(b)))
        s, b, r = get("/norange", "bytes=0-9")
        check("  a Range too (its 200 is an answer to it)", s == 200 and b == nr, (s, len(b)))

        liar = obj("/liar")
        try:
            s, b, r = get("/liar")
            got = b
        except http.client.IncompleteRead as e:
            got = e.partial                     # cut: what came must still be right
        check("a backend whose Content-Range is not the slice asked for: never its bytes in the wrong place (cut)",
              got == liar[:len(got)] and len(got) <= S, len(got))
        s, b, r = get("/big", method="HEAD")
        check("HEAD: the object's head", s == 200 and b == b"" and r.getheader("content-length") == str(len(big)),
              (s, r.getheader("content-length")))

        import h2.config
        import h2.connection
        import h2.events
        k = socket.create_connection(("127.0.0.1", LST), timeout=10)
        hc = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        hc.initiate_connection()
        hc.send_headers(1, [(":method", "GET"), (":path", "/big"), (":scheme", "http"), (":authority", "t")], end_stream=True)
        k.sendall(hc.data_to_send())
        data, ended = b"", False
        while not ended:
            for e in hc.receive_data(k.recv(65536)):
                if isinstance(e, h2.events.DataReceived):
                    data += e.data
                    hc.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, h2.events.StreamEnded):
                    ended = True
            k.sendall(hc.data_to_send())
        k.close()
        check("HTTP/2: all of it", data == big, len(data))

        b4 = obj("/big4")
        res = []
        ts = [threading.Thread(target=lambda: res.append(get("/big4"))) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check("8 clients at once on what is not kept: all right, each slice fetched a few times at most",
              len(res) == 8 and all(x[0] == 200 and x[1] == b4 for x in res) and len(of("/big4")) <= 2 * 16,
              ([(x[0], len(x[1])) for x in res], len(of("/big4"))))

        n0 = len(of("/big"))
        r = subprocess.run([str(BIN), "purge", "url", "t/big", "-c", str(conf)], capture_output=True, text=True, timeout=10)
        s, b, _ = get("/big")
        check("a purge: its slices are fetched again", s == 200 and b == big and len(of("/big")) > n0, (r.stdout, len(of("/big")) - n0))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"slice {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
