#!/usr/bin/env python3
"""CDN providers' ranges by name, on one engine (argument): `trusted_proxies
cloudflare` believes X-Forwarded-For from Cloudflare's addresses only; `allow
cloudflare` lets only them in; file:PATH takes a fresher list; `okena ranges` prints
what is built in; a name okena does not know is refused when the file is read. The
addresses are put on this namespace's loopback, and connected from."""
import http.client
import http.server
import os
import pathlib
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
BASE = 53000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, TRUST, GATE, FILE_L = BASE, BASE + 1, BASE + 2, BASE + 3
CF = "173.245.48.1"                             # one of Cloudflare's
MINE = "10.9.9.9"                               # in a file
fails = 0
seen = []


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
        seen.append(self.headers.get("X-Forwarded-For"))
        b = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Conn(http.client.HTTPConnection):
    def __init__(self, port, src):
        super().__init__("127.0.0.1", port, timeout=5, source_address=(src, 0))


def get(port, src="127.0.0.1", xff=None):
    c = Conn(port, src)
    c.request("GET", "/x", headers={"Host": "t", **({"X-Forwarded-For": xff} if xff else {})})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status, (seen[-1] if seen else None)


def main():
    for a in (CF, MINE):
        subprocess.run(["ip", "addr", "add", f"{a}/32", "dev", "lo"], check=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ranges-", dir="/tmp"))
    (tmp / "mine.txt").write_text(f"# ours\n{MINE}/32\n\n192.0.2.0/24\n")
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{TRUST} {{ trusted_proxies cloudflare; route /* {{ to pool b }} }}
http 127.0.0.1:{GATE} {{ route /* {{ allow cloudflare; to pool b }} }}
http 127.0.0.1:{FILE_L} {{ trusted_proxies file:{tmp}/mine.txt; route /* {{ to pool b }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get(TRUST)[0] == 200), log.read_text()[-300:])
        s, x = get(TRUST, CF, "203.0.113.5")
        check("trusted_proxies cloudflare: from Cloudflare, its X-Forwarded-For counts", s == 200 and x == f"203.0.113.5, {CF}", x)
        s, x = get(TRUST, "127.0.0.1", "203.0.113.5")
        check("  from anyone else, it does not (okena writes its own)", s == 200 and x == "127.0.0.1", x)
        check("allow cloudflare: Cloudflare in, the rest 403", get(GATE, CF)[0] == 200 and get(GATE, "127.0.0.1")[0] == 403)
        s, x = get(FILE_L, MINE, "198.51.100.7")
        check("trusted_proxies file:PATH: a list of one's own (comments, blank lines)", s == 200 and x == f"198.51.100.7, {MINE}", x)
        s, x = get(FILE_L, CF, "198.51.100.7")
        check("  and what is not in it is not believed", x == CF, x)
    finally:
        p.terminate()
        p.wait(10)
    r = subprocess.run([str(BIN), "ranges", "cloudflare"], capture_output=True, text=True, timeout=10)
    check("okena ranges cloudflare: the list built in", r.returncode == 0 and "173.245.48.0/20" in r.stdout and "2606:4700::/32" in r.stdout,
          r.stdout[:200])
    r = subprocess.run([str(BIN), "ranges", "akamia"], capture_output=True, text=True, timeout=10)
    check("  a name it does not know: said", r.returncode != 0, r.stderr)
    bad = tmp / "bad.conf"
    bad.write_text(conf.read_text().replace("trusted_proxies cloudflare", "trusted_proxies cloudfare"))
    r = subprocess.run([str(BIN), "check", "-c", str(bad)], capture_output=True, text=True, timeout=10)
    check("a misspelt provider is refused with the file", r.returncode != 0 and "cloudfare" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-300:])
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"ranges {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
