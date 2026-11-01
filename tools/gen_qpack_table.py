#!/usr/bin/env python3
"""Writes src/quic/qpack_tables.inc: QPACK's static table (RFC 9204
Appendix A), 99 (name, value) pairs as offsets into one string pool, read
from the RFC's text (argument: rfc9204.txt). A value the table wraps over
lines joins without a space after '-' or '/', with one otherwise (after
';'). The output is committed; building okena needs none of this."""
import pathlib
import re
import sys

OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "quic" / "qpack_tables.inc"


def parse(text):
    a = text.index("\nAppendix A.  Static Table")
    b = text.index("\nAppendix B.", a)
    rows, cur = [], None
    for line in text[a:b].splitlines():
        m = re.match(r"^   \| (\d*)\s*\| (.*?)\s*\| (.*?)\s*\|$", line)
        if not m:
            continue
        idx, name, value = m.groups()
        if idx:
            cur = [int(idx), name.strip(), value.strip()]
            rows.append(cur)
        elif cur is not None:
            if name.strip():
                cur[1] += name.strip()
            if value.strip():
                sep = "" if cur[2].endswith(("-", "/")) else " "
                cur[2] += sep + value.strip()
    assert [r[0] for r in rows] == list(range(99)), "not 0..98"
    return [(n, v) for _, n, v in rows]


def main():
    table = parse(open(sys.argv[1]).read())
    pool, offs = bytearray(), []
    for name, value in table:
        offs.append((len(pool), len(name)))
        pool += name.encode()
        offs.append((len(pool), len(value)))
        pool += value.encode()
    out = ["; QPACK's static table (RFC 9204 Appendix A), written by",
           "; tools/gen_qpack_table.py: do not edit.", "", "rodata", "\talign 8",
           "\t; entry i (0..98) at i * 8: name offset (w), name length (w), value",
           "\t; offset (w), value length (w), into qp_pool", "\tqp_static:"]
    flat = [x for o in offs for x in o]
    for i in range(0, len(flat), 8):
        out.append("\tdw " + ", ".join(str(x) for x in flat[i:i + 8]))
    out.append("\tqp_pool:")
    for i in range(0, len(pool), 16):
        out.append("\tdb " + ", ".join(str(b) for b in pool[i:i + 16]))
    out += ["end rodata", ""]
    OUT.write_text("\n".join(out))
    for i, (n, v) in enumerate(table):
        print(i, n, repr(v))


if __name__ == "__main__":
    main()
