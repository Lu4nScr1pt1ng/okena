#!/usr/bin/env python3
"""`signed_urls`, on one engine (argument): only links the origin signed (HMAC-SHA256
of path or prefix, expiry, client address), until they expire; every way of being
wrong a 403; prefix= for a whole directory (an HLS stream), ip= for one client, key2=
for a rotation; the cache keeps one answer for every link to the same thing, and a
cached answer still wants a link; `okena sign` makes them."""
import base64
import hashlib
import hmac
import http.client
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 52000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
KEY = b"the-origin-signs-with-this-key-0123"
OLD = b"an-older-key-still-good-for-a-while"
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


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        with lock:
            hits[path] = hits.get(path, 0) + 1
        b = f"content of {path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def sign(path, ttl=60, key=KEY, prefix=None, ip=None, exp=None):
    exp = exp if exp is not None else int(time.time()) + ttl
    msg = f"{prefix or path}\n{exp}\n{ip or ''}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    q = f"expires={exp}"
    if prefix:
        q += "&prefix=" + urllib.parse.quote(prefix, safe="")
    if ip:
        q += f"&ip={ip}"
    return f"{path}?{q}&sig={sig}"


def get(target):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request("GET", target, headers={"Host": "t"})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-signed-", dir="/tmp"))
    (tmp / "key").write_bytes(KEY + b"\n")
    (tmp / "old").write_bytes(OLD + b"\n")
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    route /v/* {{ signed_urls key={tmp}/key; cache 1h; to pool b }}
    route /r/* {{ signed_urls key={tmp}/key key2={tmp}/old; to pool b }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get("/open")[0] == 200), log.read_text()[-300:])
        check("a signed route without a signature: 403", get("/v/a")[0] == 403)
        s, b = get(sign("/v/a"))
        check("a link the origin signed: served", s == 200 and b == b"content of /v/a", (s, b))
        exp = int(time.time()) - 1
        bad = {
            "expired": sign("/v/a", exp=exp),
            "signed for another path": sign("/v/b").replace("/v/b", "/v/a", 1),
            "its expiry changed": sign("/v/a").replace("expires=", "expires=9", 1),
            "a signature of garbage": "/v/a?expires=9999999999&sig=" + "A" * 43,
            "a short signature": "/v/a?expires=9999999999&sig=abc",
            "no expiry": "/v/a?sig=" + sign("/v/a").split("sig=")[1],
            "signed with another key": sign("/v/a", key=b"some-other-key-entirely-123456"),
            "sig= twice": sign("/v/a") + "&sig=" + "B" * 43,
        }
        res = {k: get(v)[0] for k, v in bad.items()}
        check("every way of being wrong: 403", all(v == 403 for v in res.values()), res)

        pre = "/v/movie/"
        segs = [f"{pre}seg{i}.ts" for i in range(3)]
        q = sign(segs[0], prefix=pre).split("?")[1]
        res = [get(f"{s_}?{q}")[0] for s_ in segs]
        check("prefix=: one signature for every path under it", res == [200, 200, 200], res)
        check("  and none outside it", get(f"/v/other.ts?{q}")[0] == 403 and get(f"/v/movi?{q}")[0] == 403)
        check("ip=: for that client", get(sign("/v/ip", ip="127.0.0.1"))[0] == 200)
        check("  not for another", get(sign("/v/ip", ip="10.0.0.9"))[0] == 403)

        check("key2=: links of the old key still work, during a rotation",
              get(sign("/r/a", key=OLD))[0] == 200 and get(sign("/r/a", key=KEY))[0] == 200)

        # the cache: one answer for every link to it, and a link still wanted
        h0 = hits.get("/v/c", 0)
        a1 = get(sign("/v/c", ttl=60))
        a2 = get(sign("/v/c", ttl=120))
        a3 = get(sign("/v/c", ttl=180, ip="127.0.0.1"))
        check("the cache: one answer for every link (expires, sig, ip are not in its key)",
              a1 == a2 == a3 and a1[0] == 200 and hits.get("/v/c", 0) == h0 + 1, (hits.get("/v/c", 0) - h0))
        check("  and a cached answer still wants a link", get("/v/c")[0] == 403 and get("/v/c?expires=1&sig=x")[0] == 403)

        r = subprocess.run([str(BIN), "sign", str(tmp / "key"), "/v/cli", "1h"], capture_output=True, text=True, timeout=10)
        link = r.stdout.strip()
        check("okena sign: a link that works", r.returncode == 0 and link.startswith("/v/cli?expires=") and get(link)[0] == 200,
              (r.stdout, r.stderr))
        r = subprocess.run([str(BIN), "sign", str(tmp / "key"), "/v/hls/a.ts", "1h", "prefix=/v/hls/"], capture_output=True, text=True, timeout=10)
        q = r.stdout.strip().split("?")[1]
        check("  with prefix=", get(f"/v/hls/b.ts?{q}")[0] == 200, r.stdout)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"signed {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
