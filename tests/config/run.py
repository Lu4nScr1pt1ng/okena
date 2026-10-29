#!/usr/bin/env python3
"""Golden tests for `okena check`.

Each tests/config/NAME.conf is checked; stdout, stderr and the exit status
must match NAME.out. Run with --update to rewrite the .out files after
reviewing the new output.
"""
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parent.parent / "build" / "okena"


def run(conf: pathlib.Path) -> str:
    p = subprocess.run([str(BIN), "check", conf.name], cwd=HERE,
                       capture_output=True, text=True, timeout=10)
    return f"exit: {p.returncode}\n--- stdout\n{p.stdout}--- stderr\n{p.stderr}"


def main() -> int:
    update = "--update" in sys.argv
    failed = 0
    cases = sorted(HERE.glob("*.conf"))
    for conf in cases:
        got = run(conf)
        golden = conf.with_suffix(".out")
        if update:
            golden.write_text(got)
            continue
        want = golden.read_text() if golden.exists() else "<missing .out>"
        if got != want:
            failed += 1
            print(f"FAIL {conf.name}")
            import difflib
            sys.stdout.writelines(difflib.unified_diff(
                want.splitlines(True), got.splitlines(True), "want", "got"))
    if not update:
        print(f"config: {len(cases) - failed}/{len(cases)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
