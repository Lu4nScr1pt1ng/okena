#!/usr/bin/env python3
"""A configuration far past the old fixed tables (64 listeners, 512 pools, 1024
servers, 1024 routes, 1024 host names), on one engine (argument): 300
listeners, 2000 pools of 5 servers, a listener with 20000 routes and one with
20000 host blocks. `okena check` takes well under a second (each of those
lookups was a walk of the tree: it took 15 s), the last route, the last host
and the last listener each reach their own pool (the backend answers with the
address it was reached at, which names the pool), a listener's `response
header` reaches its last route, okena's memory stays what the configuration
uses and not what the tables could hold, and a reload to a changed
configuration of the same size is served at once."""
import os
import pathlib
import resource
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
BASE = 30000 + (500 if ENGINE == "epoll" else 0)
NL, NP, PER, NR, NH = 300, 2000, 5, 20000, 20000
NG = 1000          # each gateway feature, past its old table (256 or 64)
GW = BASE + NL     # their listener
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 0))                     # every 127/8 address reaches it
    s.listen(256)

    def one(c):
        buf = b""
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
                while b"\r\n\r\n" in buf:
                    _, _, buf = buf.partition(b"\r\n\r\n")
                    body = c.getsockname()[0].encode()
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        c.close()

    def run():
        while True:
            c, _ = s.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()

    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()[1]


def pool_net(p):
    return f"127.{1 + p // 256}.{p % 256}."


def config(bport, gen, page="/dev/null"):
    out = [f"okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=2s }}"]
    for p in range(NP):
        srv = " ".join(f"server {pool_net(p)}{s + 1}:{bport};" for s in range(PER))
        out.append(f"pool p{p} {{ {srv} }}")
    out.append(f"http 127.0.0.1:{BASE} {{")
    out.append("    response header set x-scale yes")
    for r in range(NR):
        out.append(f"    route /g{gen}/r{r} {{ to pool p{r % NP} }}")
    out.append("}")
    out.append(f"http 127.0.0.1:{BASE + 1} {{")
    for h in range(NH):
        out.append(f"    host h{h}.test {{ route /* {{ to pool p{(h + gen) % NP} }} }}")
    out.append("}")
    for i in range(2, NL):
        out.append(f"http 127.0.0.1:{BASE + i} {{ route /* {{ to pool p{i % NP} }} }}")
    out.append("pool dead { server 127.0.0.1:1 }")
    out.append(f"http 127.0.0.1:{GW} {{")
    for i in range(NG):
        rate = "1/s" if i == NG - 1 else "1000/s"
        out.append(f"    route /lim{i} {{ limit {rate} key=client.ip; to pool p{i % NP} }}")
        out.append(f"    route /cors{i} {{ cors origins=https://a{i}.test methods=GET; to pool p{i % NP} }}")
        out.append(f"    route ~^/rx{i}/[0-9]+$ {{ to pool p{i % NP} }}")
        out.append(f"    route /e{i} {{ errors 502 file={page}; to pool dead }}")
    out.append("}")
    return "\n".join(out) + "\n"


def get(port, path="/", host="a"):
    k = socket.create_connection(("127.0.0.1", port), 5)
    k.settimeout(5)
    k.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    d = b""
    try:
        while True:
            x = k.recv(4096)
            if not x:
                break
            d += x
    except OSError:
        pass
    k.close()
    return d


def until(f, t=10):
    end = time.time() + t
    while time.time() < end:
        try:
            if f():
                return True
        except OSError:
            pass
        time.sleep(0.02)
    return f()


def pss_kib(pid):
    """Proportional set size of okena and every process under it (pages the
    workers share with the supervisor counted once)."""
    total = 0
    pids = [pid]
    seen = set()
    while pids:
        q = pids.pop()
        if q in seen:
            continue
        seen.add(q)
        try:
            for line in open(f"/proc/{q}/smaps_rollup"):
                if line.startswith("Pss:"):
                    total += int(line.split()[1])
            for t in os.listdir(f"/proc/{q}/task"):
                pids += [int(c) for c in open(f"/proc/{q}/task/{t}/children").read().split()]
        except OSError:
            pass
    return total


def children(pid):
    try:
        return [int(c) for t in os.listdir(f"/proc/{pid}/task") for c in open(f"/proc/{pid}/task/{t}/children").read().split()]
    except OSError:
        return []


def main():
    bport = backend()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-scale-"))
    conf = tmp / "okena.conf"
    page = tmp / "down.html"
    page.write_text("down, page 999\n")
    cfg = lambda gen: config(bport, gen, page)
    conf.write_text(cfg(0))
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    c = subprocess.run([str(BIN), "check", "-c", str(conf)], capture_output=True, text=True)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    # CPU time, not the clock: the suites run side by side
    took = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
    check(f"check: 301 listeners, 2001 pools, 10001 servers, 44000 routes, 20000 hosts, {NG} each of limit, cors, regex, error page", c.returncode == 0 and f"ok ({NL + 1} listeners, {NP + 1} pools, {NP * PER + 1} servers)" in c.stdout + c.stderr, (c.returncode, (c.stdout + c.stderr)[-300:]))
    check("  in well under a second of CPU", took < 0.5, f"{took:.2f}s")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        up = until(lambda: pool_net((NL - 1) % NP).encode() in get(BASE + NL - 1).split(b"\r\n\r\n")[-1])
        check("the last listener reaches its own pool", up, log.read_text()[-300:])
        r = get(BASE, f"/g0/r{NR - 1}")
        check("the last of 20000 routes reaches its own pool", pool_net((NR - 1) % NP).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        check("  with the listener's response header", b"\r\nx-scale: yes\r\n" in r.lower(), r[:300])
        r = get(BASE, "/g0/r12345")
        check("a route in the middle too", pool_net(12345 % NP).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        r = get(BASE, "/nope")
        check("a path no route has: 404", r.startswith(b"HTTP/1.1 404"), r[:60])
        r = get(BASE + 1, "/", f"h{NH - 1}.test")
        check("the last of 20000 host names reaches its own pool", pool_net((NH - 1) % NP).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        # the gateway features, each the last of a thousand
        r = get(GW, f"/lim{NG - 1}")
        r2 = get(GW, f"/lim{NG - 1}")
        check("the last of a thousand rate limits: its own (1/s: the second 429)", r.startswith(b"HTTP/1.1 200") and r2.startswith(b"HTTP/1.1 429"), (r[:40], r2[:40]))
        k = socket.create_connection(("127.0.0.1", GW), 5)
        k.settimeout(5)
        k.sendall(f"GET /cors{NG - 1} HTTP/1.1\r\nHost: a\r\nOrigin: https://a{NG - 1}.test\r\nConnection: close\r\n\r\n".encode())
        r = b""
        while True:
            x = k.recv(4096)
            if not x:
                break
            r += x
        check("the last of a thousand cors: its own origin allowed", f"access-control-allow-origin: https://a{NG - 1}.test".encode() in r.lower(), r[:300])
        r = get(GW, f"/rx{NG - 1}/42")
        check("the last of a thousand regex routes: its own pool", pool_net((NG - 1) % NP).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        r = get(GW, f"/e{NG - 1}")
        check("the last of a thousand error pages: its page", r.startswith(b"HTTP/1.1 502") and b"down, page 999" in r, r[:200])
        r = get(BASE + 1, "/", "H777.TEST")
        check("  names without case", pool_net(777 % NP).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        # the state is reserved address space, not memory accounted at exec:
        # a mapping of its own marked no-reserve, and no large bss in the ELF
        flags = ""
        here = False
        for line in open(f"/proc/{p.pid}/smaps"):
            if line[:1] in "0123456789abcdef" and "-" in line.split()[0]:
                here = line.startswith("10000000-")
            elif here and line.startswith("VmFlags:"):
                flags = line
        ph = subprocess.run(["readelf", "-lW", str(BIN)], capture_output=True, text=True).stdout
        rw = [l.split() for l in ph.splitlines() if "LOAD" in l and " RW " in l]
        check("the state: reserved, not accounted (no-reserve, 4 KiB pages; no large bss)",
              " nr" in flags and " nh" in flags and all(int(x[5], 16) < 1 << 20 for x in rw), (flags, rw))
        kib = pss_kib(p.pid)
        # what the configuration uses, not what the tables could hold (they
        # are hundreds of MiB of address space, reserved, untouched; about 40
        # MiB here)
        check("memory: what the configuration uses", kib < 64 * 1024, f"{kib} KiB")
        before = len(children(p.pid))
        # clients all through the reload, on a listener both have: none lost
        # (a draining io_uring worker left with accepts still armed, and a
        # connection one of them took was closed unanswered)
        stop, lost, served = [False], [], [0]

        def client():
            while not stop[0]:
                try:
                    r = get(BASE + 2)
                except OSError as e:
                    r = repr(e).encode()
                if r.startswith(b"HTTP/1.1 200"):
                    served[0] += 1
                else:
                    lost.append(r[:60])
                time.sleep(0.005)              # (the other suites run beside this one)
        ts = [threading.Thread(target=client, daemon=True) for _ in range(2)]
        for c in ts:
            c.start()
        conf.write_text(cfg(1))
        t = time.time()
        p.send_signal(signal.SIGHUP)
        moved = until(lambda: pool_net((NR - 1) % NP).encode() in get(BASE, f"/g1/r{NR - 1}").split(b"\r\n\r\n")[-1], 20)
        until(lambda: len(children(p.pid)) <= before, 15)
        stop[0] = True
        for c in ts:
            c.join(10)
        check("  no request lost while it reloaded", not lost and served[0] > 0, (len(lost), served[0], lost[:3], log.read_text()[-700:]))
        check("reload: the new routes served", moved, log.read_text()[-400:])
        check("  in a few seconds", time.time() - t < 10, f"{time.time() - t:.1f}s")
        r = get(BASE, "/g0/r1")
        check("  the old ones gone", r.startswith(b"HTTP/1.1 404"), r[:60])
        r = get(BASE + 1, "/", "h0.test")
        check("  a host block's new pool", pool_net(1).encode() in r.split(b"\r\n\r\n")[-1], r[-120:])
        # once the old workers are gone (theirs is the old configuration's)
        until(lambda: len(children(p.pid)) <= before, 15)
        kib2 = pss_kib(p.pid)
        check("  memory after the reload still what is used", kib2 < 64 * 1024, f"{kib2} KiB")
        check("okena still running", p.poll() is None, log.read_text()[-300:])
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if fails else 0)


main()
