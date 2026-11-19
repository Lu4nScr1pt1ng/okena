#!/usr/bin/env python3
"""TLS 1.3 KeyUpdate from the client (RFC 8446 4.6.3) on an https listener whose
records okena seals itself: `k` (update_not_requested) and `K` (requested:
okena's own KeyUpdate comes back), each with requests before and after, through
openssl s_client. One engine (argument)."""
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
PORT = 19600 + os.getpid() % 300
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


def until(proc, out, want, count, t=5.0):
    """read proc's stdout into out until want appears count times"""
    end = time.time() + t
    while out[0].count(want) < count and time.time() < end:
        r, _, _ = select.select([proc.stdout], [], [], max(end - time.time(), 0))
        if not r:
            break
        d = os.read(proc.stdout.fileno(), 65536)
        if not d:
            break
        out[0] += d
    return out[0].count(want) >= count


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ku-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"],
                   check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\n"
                    f"http 127.0.0.1:{PORT} {{\n tls {{ cert {tmp}/c.pem key={tmp}/k.pem }}\n route /* {{ respond 200 \"hi\" }}\n}}\n")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        for letter, what in ((b"k", "update_not_requested"), (b"K", "update_requested: okena's KeyUpdate back")):
            c = subprocess.Popen(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-tls1_3", "-msg"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = [b""]
            req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
            c.stdin.write(req)
            c.stdin.flush()
            first = until(c, out, b"HTTP/1.1 200", 1)
            c.stdin.write(letter + b"\n")           # (s_client: a line of only this letter)
            c.stdin.flush()
            time.sleep(0.05)
            c.stdin.write(req)
            c.stdin.flush()
            second = until(c, out, b"HTTP/1.1 200", 2)
            back = out[0].count(b"<<< TLS 1.3, Handshake [length 0005], KeyUpdate")
            c.kill()
            c.wait()
            ok = first and second and (back == 1 if letter == b"K" else back == 0)
            check(f"KeyUpdate, {what}: the next request answered under the new keys", ok,
                  (first, second, back, out[0][-300:]))
    finally:
        p.terminate()
        p.wait(10)
    log = (tmp / "log").read_text()
    check("no worker died", "killed" not in log and "restarting" not in log, log[-300:])
    print(f"keyupdate {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
