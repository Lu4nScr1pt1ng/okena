#!/usr/bin/env python3
"""`vrrp` over IPv6, on one engine (argument): two okenas on the two ends of a veth
pair, one floating IPv6 address. The higher priority is master and holds it, says
so in VRRPv3 adverts to ff02::12 from its link-local address (hop limit 255, a
checksum over the IPv6 pseudo-header) and an unsolicited Neighbor Advertisement
(Override, its MAC); a drain or a stop gives it to the other at once; back, the
first takes it again."""
import os
import pathlib
import shutil
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
BASE = 63400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LA, LB = BASE, BASE + 1
VIP = "2001:db8:9::100"
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


NS = {}


def addrs(dev):
    pre = ["nsenter", "-t", str(NS["b"]), "-n"] if dev == "vb" else []
    return subprocess.run(pre + ["ip", "-o", "-6", "addr", "show", "dev", dev], capture_output=True, text=True).stdout


def who():
    a, b = f" {VIP}/" in addrs("va"), f" {VIP}/" in addrs("vb")
    return "a" if a and not b else "b" if b and not a else "both" if a else "none"


def checksum(src, dst, msg):
    data = src + dst + struct.pack("!IxxxB", len(msg), 112) + msg
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF


def main():
    hold = subprocess.Popen(["unshare", "-n", "sleep", "600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    NS["b"] = hold.pid
    try:
        body(hold)
    finally:
        hold.kill()
        hold.wait()
    print(f"vrrp6 {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


def body(hold):
    until(lambda: os.readlink(f"/proc/{hold.pid}/ns/net") != os.readlink("/proc/self/ns/net"), 3)
    inb = ["nsenter", "-t", str(hold.pid), "-n"]
    run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)
    run("ip", "link", "add", "va", "type", "veth", "peer", "name", "vb")
    run("ip", "link", "set", "vb", "netns", str(hold.pid))
    # no duplicate address detection: the link-local addresses at once
    pathlib.Path("/proc/sys/net/ipv6/conf/va/accept_dad").write_text("0")
    run(*inb, "sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/vb/accept_dad")
    run("ip", "link", "set", "va", "up")
    run(*inb, "ip", "link", "set", "vb", "up")
    run(*inb, "ip", "link", "set", "lo", "up")
    ok = until(lambda: "scope link" in addrs("va") and "scope link" in addrs("vb") and "tentative" not in addrs("va") + addrs("vb"), 5)
    check("the link-local addresses", ok, addrs("va") + addrs("vb"))
    lla = socket.inet_pton(socket.AF_INET6, addrs("va").split(" inet6 ")[1].split("/")[0])
    link = subprocess.run(["ip", "-o", "link", "show", "va"], capture_output=True, text=True).stdout
    mac = bytes.fromhex(link.split("link/ether ")[1].split()[0].replace(":", ""))
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-vrrp6-", dir="/tmp"))

    def conf(name, dev, prio, lst):
        c = tmp / f"{name}.conf"
        c.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=1s timeout=1s; admin unix:{tmp}/{name}.sock }}
vrrp {dev} vrid=52 priority={prio} address={VIP}/64 advert=100ms
http {lst} {{ route /* {{ respond 404 }} }}
""")
        return c
    ca, cb = conf("a", "va", 150, f"127.0.0.1:{LA}"), conf("b", "vb", 100, f"127.0.0.1:{LB}")
    adverts, nas = [], []
    pkt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    pkt.bind(("va", 0x0003))

    def sniff():
        while True:
            try:
                f, a = pkt.recvfrom(2048)
            except OSError:
                return
            if a[2] != socket.PACKET_OUTGOING or f[12:14] != b"\x86\xdd":
                continue
            if f[14 + 6] == 112:
                adverts.append(f[14:])
            elif f[14 + 6] == 58 and f[54] == 136:
                nas.append(f[14:])
    threading.Thread(target=sniff, daemon=True).start()

    la, lb = tmp / "la", tmp / "lb"
    pa = subprocess.Popen([str(BIN), "-c", str(ca)], stdout=subprocess.DEVNULL, stderr=open(la, "w"))
    pb = subprocess.Popen(inb + [str(BIN), "-c", str(cb)], stdout=subprocess.DEVNULL, stderr=open(lb, "w"))
    procs = [pa, pb]
    cli = lambda c, *a: subprocess.run([str(BIN), *a, "-c", str(c)], capture_output=True, text=True, timeout=10)
    try:
        check("the higher priority is master: the address on va", until(lambda: who() == "a", 6), (who(), la.read_text()[-300:], lb.read_text()[-300:]))
        check("  and stays: the other one backup", not until(lambda: who() != "a", 1.5), who())
        group = socket.inet_pton(socket.AF_INET6, "ff02::12")
        vip = socket.inet_pton(socket.AF_INET6, VIP)
        good = False
        if adverts:
            d = adverts[-1]
            v = d[40:]
            good = (d[7] == 255 and d[8:24] == lla and d[24:40] == group and len(v) == 24
                    and v[0] == 0x31 and v[1] == 52 and v[2] == 150 and v[3] == 1
                    and (struct.unpack("!H", v[4:6])[0] & 0xFFF) == 10 and v[8:24] == vip
                    and checksum(lla, group, v[:6] + b"\0\0" + v[8:]) == struct.unpack("!H", v[6:8])[0])
        check("its adverts: VRRPv3 to ff02::12 from its link-local, hop limit 255, vrid, priority, 10 cs, the address, the checksum",
              good, adverts[-1][:64].hex() if adverts else None)
        good = any(d[7] == 255 and d[24:40] == socket.inet_pton(socket.AF_INET6, "ff02::1") and d[40] == 136
                   and d[44] & 0x20 and d[48:64] == vip and d[64:66] == b"\x02\x01" and d[66:72] == mac for d in nas)
        check("  and an unsolicited Neighbor Advertisement: Override, the address, its MAC", good, [d.hex() for d in nas[-2:]])

        cli(ca, "drain")
        check("okena drain on the master: it gives the address up, the other takes it", until(lambda: who() == "b", 4), who())
        cli(ca, "resume")
        check("  resume: the higher priority takes it back (preempt)", until(lambda: who() == "a", 4), who())

        t0 = time.time()
        pa.terminate()
        check("a stop: given up, the other takes it at once", until(lambda: who() == "b", 2) and time.time() - t0 < 2, who())
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
    t = la.read_text() + lb.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)


main()
