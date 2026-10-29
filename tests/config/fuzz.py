#!/usr/bin/env python3
"""Mutation fuzzing of the configuration parser and checker.

Every input must end with status 0 (valid) or 2 (rejected): never a
signal, a hang or another status.
"""
import pathlib
import random
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parent.parent / "build" / "okena"
TOKENS = [b"{", b"}", b";", b"\n", b"#", b'"', b"=", b"\\", b"tcp", b"pool",
          b"to", b"server", b":", b"[", b"]", b"::", b"okena", b"workers",
          b"\x00", b"\xff", b"\t", b"\r", b"9" * 30, b"a" * 300, b"1.5s"]


def mutate(rng: random.Random, data: bytes) -> bytes:
    data = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.randrange(4)
        pos = rng.randint(0, len(data))
        if op == 0 and data:
            del data[pos:pos + rng.randint(1, 16)]
        elif op == 1:
            data[pos:pos] = rng.choice(TOKENS)
        elif op == 2 and data:
            data[min(pos, len(data) - 1)] = rng.randrange(256)
        else:
            data[pos:pos] = rng.choice(TOKENS) * rng.randint(1, 40)
    return bytes(data)


def main() -> int:
    cases = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    rng = random.Random(1)
    seeds = [p.read_bytes() for p in sorted(HERE.glob("*.conf"))]
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "f.conf"
        for i in range(cases):
            data = mutate(rng, rng.choice(seeds))
            path.write_bytes(data)
            p = subprocess.run([str(BIN), "check", str(path)],
                               capture_output=True, timeout=10)
            if p.returncode not in (0, 2):
                crash = HERE / f"crash-{i}.bin"
                crash.write_bytes(data)
                print(f"status {p.returncode} on case {i}, saved {crash}")
                return 1
    print(f"config fuzz: {cases} cases, no crash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
