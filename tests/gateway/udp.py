#!/usr/bin/env python3
"""`udp` listeners on one engine (argument): DNS (one answer), a game (a long
flow, both ways), syslog (no answer), and what goes wrong around them."""
import collections
import http.client
import os
import pathlib
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
DNS, GAME, LOG, FEW, SIX, MET, MANY = 18600, 18601, 18602, 18603, 18604, 18605, 18606
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Echo:
    """Answers each datagram with its name and the datagram; keeps who wrote."""

    def __init__(self, name, port=0, family=socket.AF_INET, extra=0, silent=False):
        self.s = socket.socket(family, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        self.s.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", port))
        self.port = self.s.getsockname()[1]
        self.addr = f"[::1]:{self.port}" if family == socket.AF_INET6 else f"127.0.0.1:{self.port}"
        self.name, self.extra, self.silent = name.encode(), extra, silent
        self.got = []
        self.alive = True
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while self.alive:
            try:
                b, a = self.s.recvfrom(70000)
            except OSError:
                return
            self.got.append((b, a))
            if self.silent:
                continue
            for i in range(1 + self.extra):
                try:
                    self.s.sendto(self.name + b":" + b, a)
                except OSError:
                    pass

    def stop(self):
        self.alive = False
        self.s.close()


def client(family=socket.AF_INET, t=1.0):
    c = socket.socket(family, socket.SOCK_DGRAM)
    c.settimeout(t)
    return c


def ask(port, msg=b"q", c=None, t=1.0, host="127.0.0.1"):
    k = c or client(t=t)
    k.sendto(msg, (host, port))
    try:
        r = k.recv(70000)
    except OSError:
        r = None
    if not c:
        k.close()
    return r


def metric(name, port=None):
    c = http.client.HTTPConnection("127.0.0.1", MET, timeout=3)
    c.request("GET", "/metrics")
    t = c.getresponse().read().decode()
    c.close()
    return sum(float(m.group(2)) for m in re.finditer(rf"^{name}(?:{{([^}}]*)}})? (\S+)$", t, re.M)
               if port is None or f":{port}" in (m.group(1) or ""))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-udp-", dir="/tmp"))
    conf = tmp / "okena.conf"
    a, b, c, d, l1 = Echo("a"), Echo("b"), Echo("c"), Echo("d", extra=4), Echo("log", silent=True)
    six = Echo("six", family=socket.AF_INET6)
    many = Echo("m", extra=39)                   # 40 answers to each datagram

    text = f"""okena {{ workers 2; io_engine {ENGINE}; metrics 127.0.0.1:{MET}; upgrade {tmp}/u.sock; admin unix:{tmp}/a.sock }}
pool dns {{ balance round-robin; server {a.addr}; server {b.addr} }}
pool game {{ server {c.addr} }}
pool logs {{ server {l1.addr} }}
pool burst {{ server {d.addr} }}
pool six {{ server {six.addr} }}
pool many {{ server {many.addr} }}
udp 127.0.0.1:{DNS} {{ to pool dns; responses 1; timeout {{ idle 2s }} }}
udp 127.0.0.1:{GAME} {{ to pool burst; timeout {{ idle 2s }} }}
udp 127.0.0.1:{LOG} {{ to pool logs; responses 0; timeout {{ idle 2s }} }}
udp 127.0.0.1:{FEW} {{ to pool game; timeout {{ idle 30s }}; limits {{ connections 16 }} }}
udp :{SIX} {{ to pool six }}
udp 127.0.0.1:{MANY} {{ to pool many }}
tcp 127.0.0.1:{DNS} {{ to pool game }}
"""
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))

    def okc(*x):
        return subprocess.run([str(BIN), *x, "-c", str(conf)], capture_output=True, text=True, timeout=40)

    q = None
    try:
        for i in range(100):
            if ask(DNS, t=0.05):
                break
            time.sleep(0.05)
        else:
            print("did not start:", log.read_text()[-400:], flush=True)

        # DNS
        n = collections.Counter()
        for i in range(40):
            r = ask(DNS, b"query%d" % i)
            n[r.split(b":")[0] if r else None] += 1
        check("dns: every question answered, and shared", n[b"a"] + n[b"b"] == 40 and n[b"a"] > 0 and n[b"b"] > 0, n)
        time.sleep(0.2)
        time.sleep(1.2)                          # (stats are published each second)
        check("  a flow ends at its answer", metric("okena_listener_active") == 0, metric("okena_listener_active"))
        check("  and each was counted", metric("okena_listener_connections_total") >= 40, metric("okena_listener_connections_total"))
        r = ask(DNS, b"x" * 60000, t=2)
        check("a datagram of 60000 bytes goes through whole", r and len(r) == 60002, r and len(r))
        r = ask(DNS, b"")
        check("an empty one too", r in (b"a:", b"b:"), r)

        # a game: a long flow, one source port, one backend
        k = client()
        seen = collections.Counter()
        addrs = set()
        d.got.clear()
        for i in range(30):
            k.sendto(b"tick%d" % i, ("127.0.0.1", GAME))
            for j in range(5):
                seen[k.recv(100)] += 1
        addrs = {x[1] for x in d.got}
        check("a game: the same flow, in order, several answers to one", len(seen) == 30 and all(v == 5 for v in seen.values()) and len(addrs) == 1, (len(seen), addrs))
        ks = [client() for i in range(32)]
        for i, x in enumerate(ks):
            x.sendto(b"c%d" % i, ("127.0.0.1", GAME))
        good = 0
        for i, x in enumerate(ks):
            good += sum(x.recv(100) == b"d:c%d" % i for j in range(5))
        check("  32 at once: each hears only its own", good == 160, good)
        for x in ks:
            x.close()
        # more answers than a turn takes from one flow, and than fit one send
        ks = [client(t=2) for i in range(16)]
        for x in ks:
            x.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        for i, x in enumerate(ks):
            x.sendto(b"%d" % i, ("127.0.0.1", MANY))
        heard = []
        for i, x in enumerate(ks):
            n = 0
            try:
                while n < 40:
                    n += x.recv(100) == b"m:%d" % i
            except OSError:
                pass
            heard.append(n)
        check("  16 flows of 40 answers each: none waits for a next datagram", heard == [40] * 16, heard)
        for x in ks:
            x.close()

        # one way
        l1.got.clear()
        s = client()
        for i in range(2000):
            s.sendto(b"<13>line %d" % i, ("127.0.0.1", LOG))
            if i % 100 == 99:
                time.sleep(0.005)               # (the test's own receiver, in Python, under load)
        for i in range(100):
            if len(l1.got) == 2000:
                break
            time.sleep(0.02)
        check("syslog: 2000 lines, none lost, in order", [x[0] for x in l1.got] == [b"<13>line %d" % i for i in range(2000)], len(l1.got))
        kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
        before = max(len(os.listdir(f"/proc/{w}/fd")) for w in kids)
        for i in range(200):
            x = client()
            x.sendto(b"<13>from another port", ("127.0.0.1", LOG))
            x.close()
        time.sleep(0.2)
        kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
        most = max(len(os.listdir(f"/proc/{w}/fd")) for w in kids)
        check("  200 sources take no descriptors", most <= before + 2, (before, most))
        s.close()

        # the address it listens on, v6 and dual stack
        r = ask(SIX, b"v4", host="127.0.0.1")
        check("`udp :port` over IPv4, to a backend over IPv6", r == b"six:v4", r)
        k6 = client(socket.AF_INET6)
        k6.sendto(b"v6", ("::1", SIX))
        try:
            r = k6.recv(100)
            src = None
            k6.connect(("::1", SIX))
            k6.send(b"v6c")
            r2 = k6.recv(100)
        except OSError as e:
            r, r2 = None, e
        check("  and over IPv6, answering from the address written to", r == b"six:v6" and r2 == b"six:v6c", (r, r2))
        k6.close()
        k2 = client()
        k2.connect(("127.0.0.1", SIX))           # the kernel takes only that source
        k2.send(b"c")
        try:
            r = k2.recv(100)
        except OSError as e:
            r = e
        check("  a connected client hears it from 127.0.0.1", r == b"six:c", r)
        k2.close()
        k3 = client()
        k3.bind(("127.0.0.1", 0))                # (or the kernel picks 127.0.0.2, and so would okena)
        k3.sendto(b"lo2", ("127.0.0.2", SIX))
        try:
            r, frm = k3.recvfrom(100)
        except OSError as e:
            r, frm = e, None
        check("  written to 127.0.0.2, it comes from 127.0.0.2", r == b"six:lo2" and frm and frm[0] == "127.0.0.2", (r, frm))
        k3.close()

        # same port, both protocols
        s = socket.create_connection(("127.0.0.1", DNS), 2)
        s.sendall(b"")
        check("tcp on the same port as udp", s.getpeername()[1] == DNS)
        s.close()

        # a table that fills
        ks = []
        for i in range(120):
            x = client(t=0.2)
            x.sendto(b"f", ("127.0.0.1", FEW))
            ks.append(x)
        got = 0
        for x in ks:
            try:
                got += x.recv(10) == b"c:f"
            except OSError:
                pass
        check("a table of 16: the rest are dropped, no one crashes", 8 <= got <= 40, got)
        time.sleep(0.1)
        k = client()
        hold = ask(FEW, b"mine", c=k)
        time.sleep(0.1)
        for x in ks:
            x.close()
        ks = []
        time.sleep(1.2)
        n = metric("okena_listener_active", FEW)
        check("  no more than it has room for", 8 <= n <= 18, n)
        n = metric("okena_listener_refused_total", FEW)
        check("  and the rest are counted as refused", n >= 80, n)

        # failing backends
        b.stop()
        time.sleep(0.05)
        good = sum(ask(DNS, b"q", t=0.3) == b"a:q" for i in range(30))
        check("a backend gone: ICMP takes it out, the rest are answered", good >= 20, good)
        check("  and the log says so", "ejected" in log.read_text(), log.read_text()[-200:])
        check("  and its failures count", metric("okena_backend_connect_failures_total") >= 3, metric("okena_backend_connect_failures_total"))

        # drain, the admin way: flows that exist stay
        k = client()
        ask(GAME, b"x", c=k)
        while True:
            try:
                k.recv(100)
            except OSError:
                break
            k.settimeout(0.05)
        r = okc("backend", "list")
        check("backend list knows them", d.addr in r.stdout and a.addr in r.stdout, r)
        k.close()
        okc("backend", "drain", "logs", l1.addr)
        time.sleep(0.05)
        l1.got.clear()
        s = client()
        s.sendto(b"after", ("127.0.0.1", LOG))
        time.sleep(0.2)
        check("drain: no server left, nothing goes", len(l1.got) == 0, l1.got)
        s.close()
        okc("backend", "up", "logs", l1.addr)

        # quiet flows go
        before = metric("okena_listener_active")
        x = client()
        ask(GAME, b"stays", c=x)
        time.sleep(1.5)
        ask(GAME, b"stays", c=x)                 # used: it must not go with the rest
        x2 = client()
        ask(GAME, b"goes", c=x2)
        time.sleep(1.6)
        d.got.clear()
        ask(GAME, b"stays", c=x)
        time.sleep(4.5)
        active = metric("okena_listener_active")
        check("flows that went quiet are forgotten", active < 20, (before, active))
        x.close()
        x2.close()

        # a reload, with a question in the air
        silent = Echo("late", silent=True)
        conf.write_text(text.replace(c.addr, silent.addr))
        k = client(t=3)
        k.sendto(b"before", ("127.0.0.1", FEW))
        time.sleep(0.2)
        r = okc("reload")
        check("reload", r.returncode == 0, r)
        # (workers that are new have not heard that b is gone: a try is lost on it)
        got_reply = [ask(DNS, b"after reload", t=0.3) for i in range(6)]
        check("  it goes on", b"a:after reload" in got_reply, got_reply)
        conf.write_text(text)
        k.close()
        okc("reload")

        # the old worker waits for its answer
        lazy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        lazy.bind(("127.0.0.1", 0))
        conf.write_text(text.replace(f"server {a.addr}; server {b.addr}", f"server 127.0.0.1:{lazy.getsockname()[1]}"))
        r = okc("reload")
        k = client(t=3)
        k.sendto(b"slow", ("127.0.0.1", DNS))
        msg, frm = lazy.recvfrom(100)
        conf.write_text(text)
        r = okc("reload")
        time.sleep(0.5)
        lazy.sendto(b"answer", frm)
        try:
            r = k.recv(100)
        except OSError as e:
            r = e
        check("a reload: an answer on its way still gets there", r == b"answer", r)
        k.close()
        lazy.close()

        # a new binary, on the same sockets
        conf.write_text(text)
        q = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stderr=open(tmp / "log2", "w"))
        k = client(t=0.3)
        lost = 0
        end = time.time() + 1.0
        n = 0
        while p.poll() is None and time.time() < end + 5:
            n += 1
            if ask(GAME, b"u", t=0.3) is None:
                lost += 1
        left = time.time()
        while p.poll() is None and time.time() - left < 12:
            time.sleep(0.05)
        check("upgrade: the old one left, asked all the while", p.poll() == 0 and n > 3 and lost <= 1 and time.time() - left < 1,
              (p.poll(), n, lost, round(time.time() - left, 2), log.read_text()[-300:], (tmp / "log2").read_text()[-600:]))
        check("  the new one answers", ask(GAME, b"new") == b"d:new")
        with socket.socket() as t:
            t.settimeout(2)
            t.connect(("127.0.0.1", DNS))
        check("  and has the tcp socket on that port too", True)
    finally:
        for x in (q, p):
            if x and x.poll() is None:
                x.terminate()
                try:
                    x.wait(10)
                except subprocess.TimeoutExpired:
                    x.kill()
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t and "seccomp" not in t, t[-400:])

    def bad(what, conf_text, word):
        f = tmp / "bad.conf"
        f.write_text(conf_text)
        r = subprocess.run([str(BIN), "check", str(f)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0 and word in r.stderr, r)

    bad("responses not a number", "pool p { server 127.0.0.1:1 }\nudp :5000 { to pool p; responses x }\n", "responses")
    bad("per_source", "pool p { server 127.0.0.1:1 }\nudp :5000 { to pool p; limits { per_source 3 } }\n", "per_source")
    bad("no target", "udp :5000 { responses 1 }\n", "to")
    bad("responses on tcp", "pool p { server 127.0.0.1:1 }\ntcp :5000 { to pool p; responses 1 }\n", "responses")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"udp {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
