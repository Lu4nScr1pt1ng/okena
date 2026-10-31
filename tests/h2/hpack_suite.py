#!/usr/bin/env python3
"""HPACK (src/http/hpack.inc) through build/kat: the examples of RFC 7541
appendix C byte for byte, a differential run against the hpack package
(random header lists over one connection's dynamic table, Huffman on and
off, table size updates, eviction), the encoder decoded by the package,
and malformed or random blocks: refused or decoded as the package
decodes them, never anything else. The bound on expansion is checked too
(a block that indexes a large entry many times)."""
import os
import pathlib
import random
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
KAT = ROOT / "build" / "kat"
failures = 0

try:
    import hpack
except ImportError:
    hpack = None


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


def decode(blocks, limit=4096):
    """okena's decoder over a list of blocks: a list of lists of (name, value),
    with the error code in place of a block's list where it failed."""
    data = b"d" + struct.pack("<I", limit) + b"".join(struct.pack("<I", len(b)) + b for b in blocks)
    out = bytes.fromhex(subprocess.run([str(KAT)], input=data, capture_output=True).stdout.decode().strip())
    res, cur, i = [], [], 0
    while i + 2 <= len(out):
        n = int.from_bytes(out[i:i + 2], "little")
        i += 2
        if n == 0xFFFF:
            res.append(cur)
            cur = []
        elif n == 0xFFFE:
            res.append(out[i])
            break
        else:
            name = out[i:i + n]
            i += n
            vl = int.from_bytes(out[i:i + 2], "little")
            cur.append((name, out[i + 2:i + 2 + vl]))
            i += 2 + vl
    return res


def encode(fields):
    data = b"n" + b"".join(struct.pack("<H", len(n)) + n + struct.pack("<H", len(v)) + v for n, v in fields)
    return bytes.fromhex(subprocess.run([str(KAT)], input=data, capture_output=True).stdout.decode().strip() or "")


def hint(v, prefix, high=0):
    """An HPACK integer (RFC 7541 5.1)."""
    m = (1 << prefix) - 1
    if v < m:
        return bytes([high | v])
    out, v = bytearray([high | m]), v - m
    while v >= 128:
        out.append(v & 127 | 128)
        v >>= 7
    return bytes(out + bytes([v]))


H = bytes.fromhex
# RFC 7541 C.3 (requests without Huffman), C.4 (with), one connection each
C3 = [H("828684410f7777772e6578616d706c652e636f6d"),
      H("828684be58086e6f2d6361636865"),
      H("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")]
C4 = [H("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
      H("828684be5886a8eb10649cbf"),
      H("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")]
C3_WANT = [
    [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")],
    [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com"),
     (b"cache-control", b"no-cache")],
    [(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/index.html"),
     (b":authority", b"www.example.com"), (b"custom-key", b"custom-value")],
]
# C.5 (responses without Huffman), C.6 (with), a 256-byte table: eviction
C5 = [H("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d54"
        "6e1768747470733a2f2f7777772e6578616d706c652e636f6d"),
      H("4803333037c1c0bf"),
      H("88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a6970"
        "7738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167"
        "653d333630303b2076657273696f6e3d31")]
C6 = [H("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"),
      H("4883640effc1c0bf"),
      H("88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007")]
C5_WANT = [
    [(b":status", b"302"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
     (b"location", b"https://www.example.com")],
    [(b":status", b"307"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
     (b"location", b"https://www.example.com")],
    [(b":status", b"200"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT"),
     (b"location", b"https://www.example.com"), (b"content-encoding", b"gzip"),
     (b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")],
]


def main():
    if not KAT.exists():
        print("build/kat missing (make build/kat)")
        return 1
    check("RFC 7541 C.3: requests, no Huffman, the dynamic table", decode(C3) == C3_WANT, str(decode(C3)))
    check("RFC 7541 C.4: requests, Huffman", decode(C4) == C3_WANT, str(decode(C4)))
    check("RFC 7541 C.5: responses, a 256-byte table (eviction)", decode(C5, 256) == C5_WANT, str(decode(C5, 256)))
    check("RFC 7541 C.6: responses, Huffman, eviction", decode(C6, 256) == C5_WANT, str(decode(C6, 256)))

    # refusals
    check("index 0", decode([b"\x80"]) == [1])
    check("an index past both tables", decode([b"\xff\x00"]) == [1])
    check("a size update above the limit", decode([hint(4097, 5, 0x20)], 4096) == [1])
    check("a size update at the limit", decode([hint(4096, 5, 0x20) + b"\x82"], 4096) == [[(b":method", b"GET")]])
    check("a size update after a field", decode([b"\x82\x20"]) == [1])
    check("a size update to 0 first, then fields", decode([b"\x20\x82"]) == [[(b":method", b"GET")]])
    check("a truncated integer", decode([b"\xff"]) == [1])
    check("a string longer than the block", decode([b"\x00\x05ab"]) == [1])
    check("Huffman: EOS in a string", decode([b"\x00\x81\x61\x84\xff\xff\xff\xff"]) == [1])
    check("Huffman: padding longer than 7 bits", decode([b"\x00\x81\x61\x82\x1c\xff"]) == [1])
    check("Huffman: padding not all ones", decode([b"\x00\x81\x61\x81\x00"]) == [1])
    # a bomb: one 4000-byte entry, then a block indexing it 100 times
    big = b"\x40" + b"\x01a" + hint(4000, 7) + b"x" * 4000          # name "a", a 4000-byte value
    res = decode([big, b"\xbe" * 100])
    check("an HPACK bomb ends in TOO_BIG, not in memory", len(res) == 2 and res[1] == 2, str(res)[:200])

    if hpack is None:
        print("skip the differential run: pip install hpack")
    else:
        rng = random.Random(int.from_bytes(os.urandom(4), "little"))
        names = [b"content-type", b"x-custom", b"cookie", b"user-agent", b":path", b"accept",
                 b"x-a", b"authorization", b"x-long-header-name-for-tests"]

        def rnd_value():
            n = rng.choice([0, 1, 5, 20, 100, 700])
            return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789-_./ =;%\x01\xff") for _ in range(n))

        bad = 0
        for conn in range(150):
            limit = rng.choice([4096, 256, 0, 1024])
            enc = hpack.Encoder()
            enc.header_table_size = limit
            blocks, want = [], []
            for _ in range(rng.randint(1, 8)):
                hdrs = [(rng.choice(names), rnd_value()) for _ in range(rng.randint(1, 10))]
                if rng.random() < 0.2:
                    enc.header_table_size = rng.choice([0, min(128, limit), limit])   # never above ours
                blocks.append(enc.encode(hdrs, huffman=rng.random() < 0.5))
                want.append(hdrs)
            got = decode(blocks, limit)
            if got != want:
                bad += 1
                if bad == 1:
                    print("  first mismatch:", limit, blocks[:2], got[:2], want[:2])
        check("150 connections of random headers decoded as encoded by the hpack package", bad == 0, f"{bad} differ")

        bad = 0
        for _ in range(300):
            hdrs = [(rng.choice(names + [b":status", b"server", b"content-length", b"date"]),
                     rng.choice([b"200", b"404", b"gzip", rnd_value()])) for _ in range(rng.randint(1, 12))]
            try:
                got = hpack.Decoder().decode(encode(hdrs), raw=True)
            except Exception as e:
                got = repr(e)
            if [(bytes(n), bytes(v)) for n, v in got] != hdrs if not isinstance(got, str) else True:
                bad += 1
        check("300 encoded field lists decoded by the hpack package", bad == 0, f"{bad} differ")

        # random and mutated blocks: refused, or exactly the package's result
        bad = crashes = 0
        for i in range(1500):
            if i % 2:
                blk = os.urandom(rng.randint(1, 40))
            else:
                blk = bytearray(hpack.Encoder().encode([(rng.choice(names), rnd_value())]))
                for _ in range(rng.randint(1, 3)):
                    blk[rng.randrange(len(blk))] = rng.randrange(256)
                blk = bytes(blk)
            r = subprocess.run([str(KAT)], input=b"d" + struct.pack("<I", 4096) + struct.pack("<I", len(blk)) + blk,
                               capture_output=True)
            if r.returncode != 0:
                crashes += 1
                continue
            ours = decode([blk])
            try:
                ref = [[(bytes(n), bytes(v)) for n, v in hpack.Decoder().decode(blk, raw=True)]]
            except Exception:
                ref = None
            if isinstance(ours[0], list) and ref is not None and ours != ref:
                bad += 1
        check("1500 random and mutated blocks: no crash", crashes == 0, f"{crashes} crashed")
        check("  and what is accepted decodes as the package decodes it", bad == 0, f"{bad} differ")

    print(f"hpack: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
