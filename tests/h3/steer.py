#!/usr/bin/env python3
"""QUIC packets steered to the worker that holds their connection, on one
engine (argument): okena with 4 workers, connections whose client address
changes (a NAT rebinding, a new port each time) during a download. The
kernel spreads datagrams over the workers' sockets by address, so without
the connection ID steering (qs_steer) a moved connection lands on a worker
that does not know it, which answers with a stateless reset."""
import asyncio
import os
import pathlib
import random
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    import aioquic  # noqa: F401
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip h3 steering: no aioquic")
    sys.exit(0)
sys.path.insert(0, str(HERE))
import run as t  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 30000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
t.BACK, t.LST = BASE, BASE + 1
CONNS, MOVES = 8, (40, 120, 220)
CIDS = []
KEYED = False
KEY = "fdf726a9893ec05c0632d3956680baf0"


def aes(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def qlb_decrypt(key, cid):
    """draft-ietf-quic-load-balancers 5.5.2: an 8 octet ID: 7 bytes, odd"""
    def out(half, i):
        return aes(key, half + bytes(10) + bytes([7, i]))[:4]

    def xor(a, b):
        return bytes(p ^ q for p, q in zip(a, b))

    def first(h):
        return bytes([h[0] & 0x0F]) + h[1:]

    def last(h):
        return h[:3] + bytes([h[3] & 0xF0])
    left, right = last(cid[1:5]), first(cid[4:8])
    left = last(xor(left, out(right, 4)))
    right = first(xor(right, out(left, 3)))
    left = last(xor(left, out(right, 2)))
    right = first(xor(right, out(left, 1)))
    return left[:3] + bytes([left[3] | right[0]]) + right[1:]


async def one(i):
    port = BASE + 2 + i + (20 if KEYED else 0)
    threading.Thread(target=t.rebind_relay, args=(port, [(m, "127.0.0.1") for m in MOVES]),
                     daemon=True).start()
    await asyncio.sleep(0.05)
    async with t.connect("127.0.0.1", port, configuration=t.config(), create_protocol=t.Client) as c:
        n = 300_000 + i
        r = await c.request("GET", f"/big/{n}")
        CIDS.append(c._quic._peer_cid.cid)
        return r["body"] == bytes(random.Random(n).randbytes(n))


async def cases():
    ok = await asyncio.gather(*[one(i) for i in range(CONNS)])
    t.check(f"{CONNS} connections over 4 workers, each moving 3 times: every one finishes", all(ok), str(ok))
    if KEYED:
        plain = [qlb_decrypt(bytes.fromhex(KEY), x) for x in CIDS]
        t.check("QUIC-LB encrypted: the server ID comes back with the key, and the rest differs",
                all(len(x) == 8 for x in CIDS) and all(p[:2] == b"\xbe\xef" for p in plain)
                and len({p[2:] for p in plain}) == CONNS, str([p.hex() for p in plain]))
        t.check("  never in the clear", not any(b"\xbe\xef" in x for x in CIDS), str([x.hex() for x in CIDS]))
        t.check("  rotation in the first three bits, workers in the free ones",
                all(x[0] >> 5 == 2 for x in CIDS) and len({(x[0] & 0x1F) % 4 for x in CIDS}) > 1,
                str([x[0] for x in CIDS]))
    else:
        t.check("QUIC-LB (quic_server_id beef): IDs of 8, a first octet, the server ID, the worker",
                all(len(x) == 8 and x[:3] == b"\x07\xbe\xef" and x[3] < 4 for x in CIDS)
                and len({x[3] for x in CIDS}) > 1, str([x.hex() for x in CIDS]))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-steer-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    threading.Thread(target=t.backend, daemon=True).start()
    # the draft's own vectors: what checks okena's IDs is right first
    t.check("QUIC-LB decryption, the draft's vectors",
            qlb_decrypt(bytes.fromhex(KEY), bytes.fromhex("0767947d29be054a")).hex() == "31441a9c69c275"
            and qlb_decrypt(bytes.fromhex("8f95f09245765f80256934e50c66207f"),
                            bytes.fromhex("0720b1d07b359d3c")).hex() == "ed793aee080dbf")
    global KEYED
    conf = tmp / "okena.conf"
    for KEYED, sid in ((False, "beef"), (True, f"beef key={KEY} rotation=2")):
        CIDS.clear()
        conf.write_text(f"""okena {{ workers 4; io_engine {ENGINE}; quic_server_id {sid} }}
http 127.0.0.1:{t.LST} {{
    http3 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{t.BACK} }}
}}
""")
        log = open(tmp / "okena.log", "w+")
        p = subprocess.Popen(["timeout", "--foreground", "60", str(t.BIN), "-c", str(conf)], stderr=log)
        try:
            time.sleep(0.6)
            asyncio.run(cases())
        finally:
            p.terminate()
            p.wait(10)
        time.sleep(0.3)
    # a key half read would leave the IDs in the clear
    for bad in ("beef key=abcd", f"beef key={KEY[:-1]}x", "beef rotation=7", "abcdef", "xy"):
        conf.write_text(conf.read_text().replace(f"quic_server_id beef key={KEY} rotation=2", f"quic_server_id {bad}"))
        r = subprocess.run(["timeout", "5", str(t.BIN), "-c", str(conf)], capture_output=True, text=True)
        t.check(f"quic_server_id {bad[:22]}: refused", r.returncode not in (0, 124) and "quic_server_id" in r.stderr,
                f"{r.returncode} {r.stderr[:80]}")
        conf.write_text(conf.read_text().replace(f"quic_server_id {bad}", f"quic_server_id beef key={KEY} rotation=2"))
    print(f"h3 steering {ENGINE}: {'all passed' if not t.failures else f'{t.failures} failed'}")
    return 1 if t.failures else 0


if __name__ == "__main__":
    sys.exit(main())
