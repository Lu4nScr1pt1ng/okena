#!/usr/bin/env python3
"""`okena fmt [-w] FILE`: each line indented by the blocks it is in (braces
inside words, strings and comments not counted), trailing blanks gone, empty
lines collapsed, comments kept; formatting twice changes nothing; -w writes it
back keeping its mode; a file that does not parse is left as it is (exit 2)."""
import os
import pathlib
import subprocess
import sys
import tempfile

BIN = pathlib.Path(__file__).resolve().parents[2] / "build" / "okena"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


MESSY = '\n\n# top comment\nokena {   workers 1   \n      }\npool p {\nserver 127.0.0.1:9   # the one\n  }\n\n\n\nhttp :8080 {\n route /v1/* { rewrite path /v1/{*} -> /{*}; to pool p }\n    route /x {\n respond 200 "a { b # c"\n}\n  }\n\n'
WANT = '# top comment\nokena {   workers 1\n}\npool p {\n    server 127.0.0.1:9   # the one\n}\n\nhttp :8080 {\n    route /v1/* { rewrite path /v1/{*} -> /{*}; to pool p }\n    route /x {\n        respond 200 "a { b # c"\n    }\n}\n'

with tempfile.TemporaryDirectory() as d:
    f = pathlib.Path(d) / "okena.conf"
    f.write_text(MESSY)
    os.chmod(f, 0o640)
    r = subprocess.run([str(BIN), "fmt", str(f)], capture_output=True, text=True, timeout=10)
    check("the layout made canonical, comments and strings as written", r.returncode == 0 and r.stdout == WANT, repr(r.stdout))
    g = pathlib.Path(d) / "again.conf"
    g.write_text(r.stdout)
    r2 = subprocess.run([str(BIN), "fmt", str(g)], capture_output=True, text=True, timeout=10)
    check("  twice: the same", r2.stdout == r.stdout)
    r = subprocess.run([str(BIN), "fmt", "-w", str(f)], capture_output=True, text=True, timeout=10)
    check("-w: written back, its mode kept", r.returncode == 0 and f.read_text() == WANT and (f.stat().st_mode & 0o777) == 0o640,
          (r.returncode, oct(f.stat().st_mode)))
    bad = "http :8080 {\n  route /x { respond 404\n"
    f.write_text(bad)
    r = subprocess.run([str(BIN), "fmt", "-w", str(f)], capture_output=True, text=True, timeout=10)
    check("a file that does not parse: its errors, exit 2, left as it is", r.returncode == 2 and f.read_text() == bad and "error" in r.stderr,
          (r.returncode, r.stderr[-200:]))
print("fmt: " + ("all passed" if not fails else f"{fails} failed"))
sys.exit(1 if fails else 0)
