#!/usr/bin/env python3
"""Purge, on one engine (argument): by URL, by prefix, by tag (Cache-Tag,
Surrogate-Key), from every worker's memory and from the disk store; asked with
`okena purge` or POST /purge on the metrics listener (its token); fanned out to the
`fleet`; kept across a restart with the store; a fetch in flight when the purge came
is purged too; a ring gone round takes what came before as purged."""
import http.client
import http.server
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 49000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LA, MA, LB, MB = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
TOKEN = "s3cret-purge-token-0123"
HOST = "shop.example"
fails = 0
hits = {}
n = {"v": 0}
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


TAGS = {"/t/1": ("Cache-Tag", "blue, red"), "/t/2": ("Surrogate-Key", "green blue"), "/t/3": ("Cache-Tag", "red")}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with lock:
            hits[self.path] = hits.get(self.path, 0) + 1
            n["v"] += 1
            v = n["v"]
        if self.path.startswith("/slow"):
            time.sleep(0.6)
        b = f"{self.path} #{v}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        if self.path in TAGS:
            self.send_header(*TAGS[self.path])
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def get(path, port=LA):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Host": HOST})
    r = c.getresponse()
    b = r.read()
    c.close()
    return b


def many(path, k=12, port=LA):
    out = []
    ts = [threading.Thread(target=lambda: out.append(get(path, port))) for _ in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def purge(conf, *words):
    return subprocess.run([str(BIN), "purge", *words, "-c", str(conf)], capture_output=True, text=True, timeout=20)


def post(port, query, token=TOKEN):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/purge?{query}", method="POST", data=b"")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        return urllib.request.urlopen(req, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-purge-", dir="/tmp"))
    (tmp / "store").mkdir()
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    ca, cb = tmp / "a.conf", tmp / "b.conf"
    (tmp / "token").write_text(TOKEN + "\n")
    ca.write_text(f"""okena {{ workers 4; io_engine {ENGINE}; drain delay=0s timeout=1s; admin unix:{tmp}/a.sock
    metrics 127.0.0.1:{MA} token={tmp}/token; fleet 127.0.0.1:{MB}
    cache_memory 1MiB; cache_disk {tmp}/store size=8MiB }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LA} {{ route /* {{ cache 1h; to pool b }} }}
""")
    cb.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s; admin unix:{tmp}/b.sock
    metrics 127.0.0.1:{MB} token={tmp}/token }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LB} {{ route /* {{ cache 1h; to pool b }} }}
""")
    la, lb = tmp / "la", tmp / "lb"
    pa = subprocess.Popen([str(BIN), "-c", str(ca)], stdout=subprocess.DEVNULL, stderr=open(la, "w"))
    pb = subprocess.Popen([str(BIN), "-c", str(cb)], stdout=subprocess.DEVNULL, stderr=open(lb, "w"))
    procs = [pa, pb]
    try:
        check("two instances start", until(lambda: get("/up") and get("/up", LB)) and until(lambda: post(MA, "tag=nothing") == 200),
              (la.read_text()[-300:], lb.read_text()[-300:]))

        # by URL: every worker, memory and disk
        old = get("/p/a")
        many("/p/a")
        h = hits["/p/a"]
        r = purge(ca, "url", f"http://{HOST}/p/a")
        check("okena purge url: done", r.returncode == 0 and r.stdout.startswith("ok"), (r.stdout, r.stderr))
        out = many("/p/a", 16)
        check("  and no worker serves the old answer any more", old not in out and hits["/p/a"] > h, (hits["/p/a"] - h, set(out)))
        h = hits["/p/a"]
        many("/p/a", 16)
        check("  the new one is kept again", hits["/p/a"] <= h + 4, hits["/p/a"] - h)

        # by prefix
        for q in ("/p/dir/x", "/p/dir/y?z=1", "/p/other"):
            get(q)
            many(q, 4)
        hx, hy, ho = hits["/p/dir/x"], hits["/p/dir/y?z=1"], hits["/p/other"]
        r = purge(ca, "prefix", f"{HOST}/p/dir/")
        get("/p/dir/x"), get("/p/dir/y?z=1"), get("/p/other")
        check("okena purge prefix: what is under it, and nothing else",
              hits["/p/dir/x"] == hx + 1 and hits["/p/dir/y?z=1"] == hy + 1 and hits["/p/other"] == ho, (r.stdout, hits))

        # by tag, from both headers
        for q in TAGS:
            get(q)
            many(q, 4)
        before = {q: hits[q] for q in TAGS}
        st = post(MA, "tag=blue")
        for q in TAGS:
            get(q)
        check("POST /purge?tag=: Cache-Tag and Surrogate-Key both name it, the rest stays",
              st == 200 and hits["/t/1"] == before["/t/1"] + 1 and hits["/t/2"] == before["/t/2"] + 1
              and hits["/t/3"] == before["/t/3"], (st, {q: hits[q] - before[q] for q in TAGS}))
        check("  the token: without it 401, a wrong one 401, a bad purge 400",
              post(MA, "tag=x", None) == 401 and post(MA, "tag=x", "nope") == 401 and post(MA, "what=x") == 400)

        # the fleet: asked here, done there too
        get("/f/1", LB)
        get("/f/1", LB)
        hf = hits["/f/1"]
        r = purge(ca, "url", f"{HOST}/f/1")
        get("/f/1", LB)
        check("the fleet: okena purge asks the others, and says how they answered",
              f"fleet 127.0.0.1:{MB}: ok" in r.stdout and hits["/f/1"] == hf + 1, (r.stdout, r.stderr, hits["/f/1"] - hf))

        # a fetch in flight when the purge came: purged too
        res = []
        t = threading.Thread(target=lambda: res.append(get("/slow/a")))
        t.start()
        time.sleep(0.25)
        purge(ca, "url", f"{HOST}/slow/a")
        t.join()
        h = hits["/slow/a"]
        get("/slow/a")
        check("a fetch begun before the purge: not kept past it", hits["/slow/a"] == h + 1, hits["/slow/a"] - h)

        # kept across a restart, with the store
        old = get("/r/a")
        many("/r/a")
        purge(ca, "url", f"{HOST}/r/a")
        pa.send_signal(signal.SIGTERM)
        pa.wait(10)
        pa = subprocess.Popen([str(BIN), "-c", str(ca)], stdout=subprocess.DEVNULL, stderr=open(la, "a"))
        procs.append(pa)
        until(lambda: get("/up"))
        out = many("/r/a", 8)
        check("a restart: what was purged stays purged (the ring is in the store)", old not in out, set(out))

        # the ring gone round: what came before is taken as purged, what came after kept
        old = get("/w/old")
        for i in range(1100):
            st = post(MA, f"tag=noise{i}")
            if st != 200:
                break
        new = get("/w/new")
        h_old, h_new = hits["/w/old"], hits["/w/new"]
        get("/w/old"), get("/w/new")
        check("1100 purges (more than the ring): older answers fetched again, newer ones kept",
              st == 200 and hits["/w/old"] == h_old + 1 and hits["/w/new"] == h_new, (st, hits["/w/old"] - h_old, hits["/w/new"] - h_new))

        r = purge(ca, "colour", "blue")
        check("okena purge with something else: said, and refused", r.returncode != 0 and "purge url" in (r.stdout + r.stderr), (r.stdout, r.stderr))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
    t = la.read_text() + lb.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"purge {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
