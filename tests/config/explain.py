#!/usr/bin/env python3
"""`okena explain FILE`: the configuration as okena will run it, defaults
written out (pools, listeners, routes, retries, timeouts), compared with what
it should say for tests/config/explain.conf.in; a file with errors: exit 2."""
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parent.parent / "build" / "okena"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


r = subprocess.run([str(BIN), "explain", str(HERE / "explain.conf.in")], capture_output=True, text=True, timeout=10)
want = (HERE / "explain.want").read_text()
if r.stdout != want:
    import difflib
    sys.stdout.writelines(difflib.unified_diff(want.splitlines(True), r.stdout.splitlines(True), "want", "got"))
check("defaults written out, as compiled", r.returncode == 0 and r.stdout == want, r.stderr[-300:])
with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
    f.write("http :8080 {\n")
    f.flush()
    r = subprocess.run([str(BIN), "explain", f.name], capture_output=True, text=True, timeout=10)
    check("a file with errors: its errors, exit 2", r.returncode == 2 and "error" in r.stderr, r.returncode)
print("explain: " + ("all passed" if not fails else f"{fails} failed"))
sys.exit(1 if fails else 0)
