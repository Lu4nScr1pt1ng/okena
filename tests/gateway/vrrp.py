#!/usr/bin/env python3
"""`vrrp`, on one engine (argument): two okenas on the two ends of a veth pair, one
floating address. The higher priority is master and holds it, says so in VRRPv3
adverts (TTL 255, a checksum over the pseudo-header) and a gratuitous ARP; a drain,
a tracked pool with no server up, or a stop gives it to the other at once; back,
the first takes it again (preempt); a reload that leaves vrrp as it was changes
nothing."""
import http.server
import os
import pathlib
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 57000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BA, BB, LA, LB = BASE, BASE + 1, BASE + 2, BASE + 3
VIP = "10.9.0.100"
fails = 0


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


def ip(*a):
    subprocess.run(["ip", *a], check=True, capture_output=True)


NS = {}                                         # the other side's namespace: a process in it


def holds(dev):
    pre = ["nsenter", "-t", str(NS["b"]), "-n"] if dev == "vb" else []
    out = subprocess.run(pre + ["ip", "-o", "-4", "addr", "show", "dev", dev], capture_output=True, text=True).stdout
    return f" {VIP}/" in out


def who():
    a, b = holds("va"), holds("vb")
    return "a" if a and not b else "b" if b and not a else "both" if a else "none"


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def backend(port):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def checksum(src, dst, msg):
    data = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 112, len(msg)) + msg
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def main():
    # two hosts: this namespace (va) and another (vb), a veth between them (in one
    # namespace a packet from its own address would be dropped as a martian)
    hold = subprocess.Popen(["unshare", "-n", "sleep", "600"])
    NS["b"] = hold.pid
    until(lambda: os.readlink(f"/proc/{hold.pid}/ns/net") != os.readlink("/proc/self/ns/net"), 3)
    inb = ["nsenter", "-t", str(hold.pid), "-n"]
    ip("link", "add", "va", "type", "veth", "peer", "name", "vb")
    ip("link", "set", "vb", "netns", str(hold.pid))
    ip("addr", "add", "10.9.0.1/24", "dev", "va")
    ip("link", "set", "va", "up")
    subprocess.run(inb + ["ip", "addr", "add", "10.9.0.2/24", "dev", "vb"], check=True)
    subprocess.run(inb + ["ip", "link", "set", "vb", "up"], check=True)
    subprocess.run(inb + ["ip", "link", "set", "lo", "up"], check=True)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-vrrp-", dir="/tmp"))
    back_a = backend(BA)
    sb = http.server.ThreadingHTTPServer(("10.9.0.1", BB), H)      # (B's, reached over the link)
    threading.Thread(target=sb.serve_forever, daemon=True).start()

    def conf(name, dev, prio, back, lst):
        c = tmp / f"{name}.conf"
        c.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=1s timeout=1s; admin unix:{tmp}/{name}.sock }}
vrrp {dev} vrid=51 priority={prio} address={VIP}/24 advert=100ms track=web
pool web {{ server {back}; health tcp every=200ms fall=1 rise=1 }}
http {lst} {{ route /* {{ to pool web }} }}
""")
        return c
    ca, cb = conf("a", "va", 150, f"127.0.0.1:{BA}", f"127.0.0.1:{LA}"), conf("b", "vb", 100, f"10.9.0.1:{BB}", f"127.0.0.1:{LB}")
    # what A puts on the link: its frames, as they go out of va
    adverts, arps = [], []
    pkt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    pkt.bind(("va", 0x0003))

    def sniff():
        while True:
            try:
                f = pkt.recv(2048)
            except OSError:
                return
            if f[12:14] == b"\x08\x06":
                arps.append(f)
            elif f[12:14] == b"\x08\x00" and f[14 + 9] == 112:
                adverts.append(f[14:])
    threading.Thread(target=sniff, daemon=True).start()

    la, lb = tmp / "la", tmp / "lb"
    pa = subprocess.Popen([str(BIN), "-c", str(ca)], stdout=subprocess.DEVNULL, stderr=open(la, "w"))
    pb = subprocess.Popen(inb + [str(BIN), "-c", str(cb)], stdout=subprocess.DEVNULL, stderr=open(lb, "w"))
    procs = [pa, pb]
    cli = lambda c, *a: subprocess.run([str(BIN), *a, "-c", str(c)], capture_output=True, text=True, timeout=10)
    try:
        check("the higher priority is master: the address on va", until(lambda: who() == "a", 6), (who(), la.read_text()[-300:], lb.read_text()[-300:]))
        check("  and stays: the other one backup", not until(lambda: who() != "a", 1.5), who())
        mine = [d for d in adverts if d[12:16] == socket.inet_aton("10.9.0.1")]
        good = False
        if mine:
            d = mine[-1]
            ihl = (d[0] & 15) * 4
            v = d[ihl:]
            good = (d[8] == 255 and v[0] == 0x31 and v[1] == 51 and v[2] == 150 and v[3] == 1
                    and (struct.unpack("!H", v[4:6])[0] & 0xFFF) == 10 and v[8:12] == socket.inet_aton(VIP)
                    and checksum("10.9.0.1", "224.0.0.18", v[:6] + b"\0\0" + v[8:12]) == struct.unpack("!H", v[6:8])[0])
        check("its adverts: VRRPv3, TTL 255, vrid, priority, 10 cs, the address, the checksum", good, mine[-1][:40].hex() if mine else None)
        check("  and a gratuitous ARP for the address", any(len(a) >= 42 and a[28:32] == socket.inet_aton(VIP) and a[38:42] == socket.inet_aton(VIP) for a in arps), len(arps))

        cli(ca, "drain")
        check("okena drain on the master: it gives the address up, the other takes it", until(lambda: who() == "b", 4), who())
        cli(ca, "resume")
        check("  resume: the higher priority takes it back (preempt)", until(lambda: who() == "a", 4), who())

        back_a.shutdown()
        back_a.server_close()
        check("its tracked pool with no server up: the other one", until(lambda: who() == "b", 5), who())
        back_a = backend(BA)
        check("  a server back: it again", until(lambda: who() == "a", 5), who())

        before = la.read_text().count("master")
        n0 = la.read_text().count("configuration reloaded")
        pa.send_signal(signal.SIGHUP)
        until(lambda: la.read_text().count("configuration reloaded") > n0, 5)
        check("a reload that leaves vrrp as it was: nothing moves", not until(lambda: who() != "a", 1.5) and la.read_text().count("master") == before,
              (who(), la.read_text()[-300:]))

        t0 = time.time()
        pa.send_signal(signal.SIGTERM)
        check("a stop: given up, the other takes it at once (not after 3 adverts)", until(lambda: who() == "b", 2) and time.time() - t0 < 2, who())
        pa.wait(10)
        pa = subprocess.Popen([str(BIN), "-c", str(ca)], stdout=subprocess.DEVNULL, stderr=open(la, "a"))
        procs.append(pa)
        check("  back: it takes it again", until(lambda: who() == "a", 6), who())
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
    hold.kill()
    hold.wait()
    t = la.read_text() + lb.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"vrrp {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
