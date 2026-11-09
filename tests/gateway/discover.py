#!/usr/bin/env python3
"""`discover file` on one engine (argument): a pool whose servers are the
lines of a file, followed as it changes, and kept when it goes wrong."""
import collections
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

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, CAP = 18680, 18681
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def setup(self):
        super().setup()
        self.server.accepted += 1               # a new connection from okena

    def do_GET(self):
        if "s=" in self.path:
            time.sleep(float(self.path.split("s=")[1]))
        b = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def backend(name):
    s = S(("127.0.0.1", 0), H)
    s.name, s.accepted = name, 0
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def get(port=LST, path="/"):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        c.request("GET", path)
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def spread(n=40, port=LST):
    return collections.Counter(get(port)[1] for i in range(n))


def until(fn, seconds=4):
    t = time.time()
    while time.time() - t < seconds:
        v = fn()
        if v:
            return time.time() - t
        time.sleep(0.1)
    return None


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-disc-", dir="/tmp"))
    b = {n: backend(n) for n in ("a", "b", "c", "d")}
    port = {n: s.server_address[1] for n, s in b.items()}
    lst = tmp / "servers.list"
    few = tmp / "few.list"

    def write(f, text):
        new = f.with_suffix(".new")                # the way to write it: whole, then renamed
        new.write_text(text)
        os.rename(new, f)

    write(lst, f"# the servers\n127.0.0.1:{port['a']}\n127.0.0.1:{port['b']}   # and b\n")
    write(few, f"127.0.0.1:{port['a']}\n127.0.0.1:{port['b']}\n127.0.0.1:{port['c']}\n")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool p {{ balance round-robin; discover file {lst} }}
pool q {{ balance round-robin; discover file {few} max=2 }}
http 127.0.0.1:{LST} {{ route /* {{ to pool p }} }}
http 127.0.0.1:{CAP} {{ route /* {{ to pool q }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(100):
            try:
                st = get()
                if st[0]:
                    break
            except OSError:
                pass
            time.sleep(0.05)
        check("from the start: the file's servers", st[0] == 200 and set(spread()) == {"a", "b"}, (st, spread()))
        check("max=2: only the first two lines", set(spread(port=CAP)) == {"a", "b"}, spread(port=CAP))

        write(lst, f"127.0.0.1:{port['a']}\n127.0.0.1:{port['b']}\n127.0.0.1:{port['c']}\n")
        t = until(lambda: "c" in spread(20))
        check("a line added: served within a couple of seconds", t is not None and t < 3, t)
        check("  and the log says so", "servers.list: 3 servers" in log.read_text(), log.read_text()[-300:])

        # the same lines in another order: every slot keeps its address and connections
        spread(60)
        before = {n: s.accepted for n, s in b.items()}
        write(lst, f"127.0.0.1:{port['c']}\n127.0.0.1:{port['a']}\n127.0.0.1:{port['b']}\n")
        time.sleep(2.5)
        n = spread(60)
        after = {k: b[k].accepted - before[k] for k in b}
        check("another order: the same servers, and no connection made anew", set(n) == {"a", "b", "c"} and sum(after.values()) <= 2, (n, after))

        write(lst, f"127.0.0.1:{port['a']}\n127.0.0.1:{port['c']}\n")
        t = until(lambda: "b" not in spread(20))
        check("a line taken out: no more there", t is not None and t < 3, t)

        write(lst, f"127.0.0.1:{port['a']} weight=3\n127.0.0.1:{port['c']}\n")
        time.sleep(2.5)
        n = spread(80)
        check("weight=3: three to one", 2.4 <= n["a"] / max(n["c"], 1) <= 3.6, n)

        # what goes wrong keeps what was there
        good = spread(20)
        write(lst, f"127.0.0.1:{port['a']}\nthis is not an address\n")
        time.sleep(2.5)
        check("a bad line: nothing changes", set(spread(20)) == set(good), spread(20))
        check("  and it is said once", log.read_text().count("not ADDRESS[:PORT]") == 1, log.read_text()[-300:])
        os.unlink(lst)
        time.sleep(2.5)
        check("the file gone: the servers stay", set(spread(20)) == set(good) and "cannot be read" in log.read_text())
        write(lst, f"127.0.0.1:{port['d']}\n")
        t = until(lambda: set(spread(10)) == {"d"})
        check("  and back: followed again", t is not None, (t, spread(10), log.read_text()[-500:]))

        # emptied in place, as an editor truncates: believed only after 3 s
        with open(lst, "w"):
            pass
        seen = []
        t0 = time.time()
        while time.time() - t0 < 2.5:            # without the wait, it would be gone by 2 s
            seen.append(get()[0])
            time.sleep(0.1)
        with open(lst, "w") as f:
            f.write(f"127.0.0.1:{port['d']}\n")
        time.sleep(2.5)
        check("truncated, then written: never without servers", set(seen) == {200} and get()[0] == 200, (collections.Counter(seen), get()))
        with open(lst, "w"):
            pass
        t = until(lambda: get()[0] != 200, 7)
        check("empty for good: no servers, after 3 s", t is not None and t > 2.5, t)

        # a request in flight on a server that goes: its connection is not kept
        # for the address that takes its slot
        write(lst, f"127.0.0.1:{port['a']}\n")
        until(lambda: set(spread(10)) == {"a"})
        slow = []
        ts = [threading.Thread(target=lambda: slow.append(get(LST, "/?s=2.5"))) for i in range(4)]
        for x in ts:
            x.start()
        time.sleep(0.3)
        write(lst, f"127.0.0.1:{port['d']}\n")
        time.sleep(1.6)
        for x in ts:
            x.join()
        after = spread(30)
        check("an address replaced while its requests run: none of its connections serves the new one",
              after == {"d": 30} and [r[1] for r in slow] == ["a"] * 4, (after, slow))

        # the source's port for lines without one
        conf.write_text(conf.read_text().replace(f"discover file {lst} }}", f"discover file {lst} port={port['b']} }}"))
        write(lst, "127.0.0.1\n")
        subprocess.run(["kill", "-HUP", str(p.pid)])
        t = until(lambda: get()[1] == "b")
        check("port=: for lines without one, and after a reload", t is not None, (t, get()))
    finally:
        p.terminate()
        p.wait(10)
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text and "control process exited" not in text, text[-300:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool p {{ {line} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("a relative path", "discover file servers.list")
    bad("max=0", f"discover file {lst} max=0")
    bad("max past 256", f"discover file {lst} max=300")
    bad("port=0", f"discover file {lst} port=0")
    bad("a kind it does not know", f"discover zookeeper {lst}")
    g = tmp / "only.conf"
    g.write_text(f"pool p {{ discover file {lst} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
    r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
    check("a pool with only discover is a pool", r.returncode == 0, r.stderr[-200:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"discover {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
