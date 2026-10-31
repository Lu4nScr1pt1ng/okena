#!/usr/bin/env python3
"""Writes src/http/hpack_tables.inc: the tables of HPACK (RFC 7541).

* The static table (Appendix A): 61 (name, value) pairs, as offsets into
  one string pool.
* The Huffman code (Appendix B): for encoding, each symbol's code and
  length; for decoding, the code is canonical (codes of a length are
  consecutive and follow the shorter ones), so per length the first code,
  how many there are and where they start in the symbols sorted by
  (length, symbol).

The values come from the hpack package (pip install hpack), checked here
to be canonical; the output is committed, so building okena needs none of
this."""
import pathlib

from hpack.huffman_constants import REQUEST_CODES as CODES, REQUEST_CODES_LENGTH as LENS
from hpack.table import HeaderTable

OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "http" / "hpack_tables.inc"


def main():
    static = HeaderTable.STATIC_TABLE
    assert len(static) == 61
    pool, offs = bytearray(), []
    for name, value in static:
        offs.append((len(pool), len(name)))
        pool += name
        offs.append((len(pool), len(value)))
        pool += value
    syms = sorted(range(257), key=lambda s: (LENS[s], s))
    code, prev = 0, LENS[syms[0]]
    for i, s in enumerate(syms):
        if i:
            code = (code + 1) << (LENS[s] - prev)
            prev = LENS[s]
        assert CODES[s] == code, "not canonical"
    first, count, start = [0] * 31, [0] * 31, [0] * 31
    for i, s in enumerate(syms):
        n = LENS[s]
        if count[n] == 0:
            first[n], start[n] = CODES[s], i
        count[n] += 1

    def rows(directive, values, per=12):
        return "\n".join(f"\t{directive} " + ", ".join(str(v) for v in values[i:i + per])
                         for i in range(0, len(values), per))

    lines = [
        "; HPACK tables (RFC 7541 appendices A and B), written by",
        "; tools/gen_hpack_tables.py: do not edit.",
        "",
        "rodata",
        "\talign 8",
        "\t; static table entry i (1..61) at (i - 1) * 8: name offset (w), name",
        "\t; length (w), value offset (w), value length (w), into hp_pool",
        "\thp_static:",
        rows("dw", [x for i in range(61) for x in (offs[2 * i][0], offs[2 * i][1],
                                                     offs[2 * i + 1][0], offs[2 * i + 1][1])], 8),
        "\thp_pool:",
        rows("db", list(pool), 16),
        "\talign 4",
        "\t; Huffman, encoding: the code of symbol s (dd), then its length (db)",
        "\thp_hcode:",
        rows("dd", list(CODES), 8),
        "\thp_hlen:",
        rows("db", list(LENS), 16),
        "\talign 4",
        "\t; Huffman, decoding (canonical): per length 0..30 the first code (dd),",
        "\t; the number of codes (dw) and their start in hp_hsyms (dw)",
        "\thp_hfirst:",
        rows("dd", first, 8),
        "\thp_hcount:",
        rows("dw", count, 16),
        "\thp_hstart:",
        rows("dw", start, 16),
        "\thp_hsyms:",
        rows("dw", syms, 16),
        "end rodata",
        "",
    ]
    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT} ({len(pool)} bytes of static strings)")


if __name__ == "__main__":
    main()
