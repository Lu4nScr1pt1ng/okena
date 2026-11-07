#!/usr/bin/env python3
"""`okena backend` and `okena reload`, over the `admin` socket: a drain, a
weight, what a reload keeps of them, and what a bad caller gets."""
import collections
import http.client
import http.server
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, MET = 18490, 18491
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        r = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(r)))
        self.end_headers()
        self.wfile.write(r)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def back(name):
    s = S(("127.0.0.1", 0), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"127.0.0.1:{s.server_address[1]}"


STALLS = []


def get(c=None):
    k = c or http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    try:
        k.request("GET", "/")
        r = k.getresponse()
        b = r.read().decode()
    except TimeoutError:
        # (rare, under load, after a reload on io_uring: what the sockets say)
        port = k.sock.getsockname()[1] if k.sock else None
        ss = subprocess.run(["ss", "-tanpi"], capture_output=True, text=True).stdout
        STALLS.append((time.strftime("%T"), port, "\n".join(l for l in ss.splitlines() if str(port) in l or f":{LST}" in l)[-3000:]))
        k.close()
        return 0, "stalled"
    if not c:
        k.close()
    return r.status, b


def spread(n=60):
    return collections.Counter(get()[1] for i in range(n))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-admin-", dir="/tmp"))
    sock = tmp / "a.sock"
    conf = tmp / "okena.conf"
    (sa, A), (sb, B) = back("a"), back("b")

    def write(servers, extra=""):
        lines = "".join(f"    server {s}\n" for s in servers)
        conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; admin unix:{sock}; metrics 127.0.0.1:{MET}; upgrade {tmp}/u.sock; watchdog 2s }}
pool p {{
    balance round-robin
{lines}}}
http 127.0.0.1:{LST} {{
    route /* {{ to pool p }}
}}
{extra}""")

    def ok(*a):
        return subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=40)

    def lst():
        return ok("backend", "list").stdout

    def line(s):
        return next((x for x in lst().splitlines() if f" {s} " in x), "")

    def raw(b, wait=2):
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(wait + 2)
        c.connect(str(sock))
        c.sendall(b)
        c.shutdown(socket.SHUT_WR)
        r = b""
        try:
            while True:
                x = c.recv(65536)
                if not x:
                    break
                r += x
        except OSError:
            pass
        c.close()
        return r

    write([A, B])
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(100):
            if sock.exists():
                break
            time.sleep(0.05)
        check("the socket is there, the owner's", stat.S_IMODE(os.stat(sock).st_mode) == 0o600, sock.exists() and oct(os.stat(sock).st_mode))
        check("  and nothing is left beside it", not (tmp / "a.sock.new").exists())
        check("both serve", set(spread()) == {"a", "b"})
        r = ok("backend", "list")
        check("list: each one, its weight, what it does, its state", r.returncode == 0 and re.search(f"^p {A} weight=1 active=\\d+ up$", r.stdout, re.M) and re.search(f"^p {B} weight=1 active=\\d+ up$", r.stdout, re.M), r)

        keep = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        first = get(keep)[1]
        r = ok("backend", "drain", "p", A if first == "a" else B)
        check("drain: done, and says nothing more", r.returncode == 0 and r.stdout == "", r)
        other = "b" if first == "a" else "a"
        time.sleep(0.05)
        check("  nothing new goes there", spread() == {other: 60}, spread())
        check("  and the list says so", line(A if first == "a" else B).endswith(" drain"), lst())
        check("  a connection through the proxy goes on", get(keep)[0] == 200)
        keep.close()
        r = ok("backend", "up", "p", A if first == "a" else B)
        check("up: it comes back", r.returncode == 0 and set(spread()) == {"a", "b"}, r)

        ok("backend", "drain", "p", A)
        ok("backend", "drain", "p", B)
        r = get()
        check("every one drained: an error, not a drained one in despair", r[0] == 502, r)
        ok("backend", "up", "p", A)
        ok("backend", "up", "p", B)

        r = ok("backend", "weight", "p", A, "9")
        n = spread(200)
        check("weight: as told", r.returncode == 0 and n["a"] > 150 and n["b"] > 0, (r, n))
        check("  shown", "weight=9" in line(A), lst())
        ok("backend", "weight", "p", A, "0")
        n = spread(200)
        check("  0: as in the file", 60 < n["a"] < 140 and "weight=1" in line(A), n)

        for what, args in (("no such server", ("drain", "p", "10.9.9.9:1")),
                           ("no such pool", ("drain", "nope", A)),
                           ("a weight too big", ("weight", "p", A, "70000")),
                           ("a weight that is no number", ("weight", "p", A, "1x"))):
            r = ok("backend", *args)
            check(f"{what}: refused", r.returncode == 1 and r.stderr.startswith("err:"), r)
        r = subprocess.run([str(BIN), "backend", "drain", "p"], capture_output=True, text=True)
        check("a command short of words: usage", r.returncode != 0, r)

        # bad callers
        for what, b in (("nothing", b""), ("no line", b"list"), ("a long one", b"x" * 9000),
                        ("a line of zeros", b"\0" * 100 + b"\n"), ("too many words", b"drain p " + A.encode() + b" more\n"),
                        ("names too long", b"drain " + b"p" * 200 + b" " + b"a" * 200 + b"\n"),
                        ("weight no digits", b"weight p " + A.encode() + b" \n"), ("binary", bytes(range(256)) + b"\n")):
            r = raw(b)
            check(f"{what}: nothing done", not r.startswith(b"ok"), r[:60])
        check("  and it goes on answering", ok("backend", "list").returncode == 0)
        for i in range(300):
            r = raw(f"up p 10.0.0.{i}:1\n".encode())
        check("many that do not exist fill nothing", ok("backend", "drain", "p", A).returncode == 0)
        ok("backend", "up", "p", A)

        # reloads
        ok("backend", "drain", "p", A)
        ok("backend", "weight", "p", B, "4")
        write([A, B], "# a comment\n")
        r = ok("reload")
        check("reload: says it did", r.returncode == 0 and r.stdout == "reloaded\n", r)
        check("  a drain outlives it", line(A).endswith(" drain") and spread(20) == {"b": 20}, lst())
        check("  and a weight", "weight=4" in line(B), lst())
        write([B])
        check("a server that goes", ok("reload").returncode == 0 and line(A) == "", lst())
        write([A, B])
        check("  and returns, as in the file", ok("reload").returncode == 0 and line(A).endswith(" up") and set(spread()) == {"a", "b"}, lst())
        ok("backend", "weight", "p", B, "0")

        blocker = socket.socket()
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", 18492))
        blocker.listen(1)
        write([A, B], "http 127.0.0.1:18492 { route /* { to pool p } }\n")
        r = ok("reload")
        check("a reload that fails says so", r.returncode == 1 and "did not take" in r.stderr, r)
        check("  and what runs goes on", set(spread()) == {"a", "b"})
        blocker.close()
        write([A, B])
        conf.write_text(conf.read_text() + "nonsense here\n")
        r = ok("reload")
        check("a file that is wrong: it is told", r.returncode != 0, r)
        write([A, B])

        # its process
        ok("backend", "drain", "p", A)
        kids = subprocess.run(["pgrep", "-P", str(p.pid), "-x", "okena-admin"], capture_output=True, text=True).stdout.split()
        if kids:
            os.kill(int(kids[0]), 9)
        for i in range(100):
            if ok("backend", "list").returncode == 0:
                break
            time.sleep(0.05)
        check("its process killed: another, that knows", bool(kids) and line(A).endswith(" drain"), (kids, lst()))
        c = http.client.HTTPConnection("127.0.0.1", MET, timeout=5)
        c.request("GET", "/ready")
        check("metrics answer beside it", c.getresponse().status == 200)
        c.close()
        ok("backend", "up", "p", A)

        # a new binary
        q = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stderr=open(tmp / "log2", "w"))
        for i in range(100):
            if p.poll() is not None:
                break
            time.sleep(0.05)
        check("upgrade: the new one answers there", p.poll() == 0 and ok("backend", "list").returncode == 0 and set(spread()) == {"a", "b"}, p.poll())
        check("  on the same terms", stat.S_IMODE(os.stat(sock).st_mode) == 0o600 and not (tmp / "a.sock.new").exists())
        q.terminate()
        q.wait(10)
        p.wait(10)
    finally:
        for x in (p,):
            if x.poll() is None:
                x.terminate()
                x.wait(10)
    text = log.read_text()
    for t, port, ss in STALLS:
        print(f"stalled at {t} from port {port}; the log:\n{text[-600:]}\nsockets:\n{ss}", flush=True)
    check("no request stalled", not STALLS, len(STALLS))
    check("no process died", "killed" not in text.replace("okena-admin", ""), text[-300:])
    bad = tmp / "bad.conf"
    bad.write_text(f"okena {{ admin /tmp/x.sock }}\npool p {{ server {A} }}\nhttp 127.0.0.1:{LST} {{ route /* {{ to pool p }} }}\n")
    r = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True, timeout=10)
    check("admin needs unix:", r.returncode != 0, r)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"admin {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
