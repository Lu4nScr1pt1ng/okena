#!/usr/bin/env python3
"""`okena check --diff FILE`: against the running instance (its admin
socket): the file as started, "no change", exit 0; edited (a route added, a
pool's connect changed, a listener added): the blocks that change, "~" with
"-" and "+" lines, a new block "+", exit 1; the instance itself untouched."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 49000 + os.getpid() % 90 * 10
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-diff-"))
    conf = tmp / "okena.conf"
    text = f"""okena {{ workers 1; admin unix:{tmp}/admin.sock }}
pool p {{ server 127.0.0.1:9 }}
http 127.0.0.1:{L} {{ route /a {{ to pool p }} }}
"""
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            if (tmp / "admin.sock").exists():
                try:
                    socket.create_connection(("127.0.0.1", L), 1).close()
                    break
                except OSError:
                    pass
            time.sleep(0.05)
        r = subprocess.run([str(BIN), "check", "--diff", str(conf)], capture_output=True, text=True, timeout=10)
        check("as started: no change, exit 0", r.returncode == 0 and "no change" in r.stdout, (r.returncode, r.stdout, r.stderr))
        conf.write_text(text.replace("server 127.0.0.1:9 }", "server 127.0.0.1:9; connect warm=2 }")
                        .replace("route /a { to pool p } }", "route /a { to pool p }; route /b { respond 410 } }")
                        + f"tcp 127.0.0.1:{L + 1} {{ to pool p }}\n")
        r = subprocess.run([str(BIN), "check", "--diff", str(conf)], capture_output=True, text=True, timeout=10)
        o = r.stdout
        check("edited: exit 1", r.returncode == 1, (r.returncode, r.stderr))
        check("  the pool: ~ with its connect line - and +", "~ pool p {" in o and "-     connect timeout=2s max=512 idle=50s warm=0" in o
              and "+     connect timeout=2s max=512 idle=50s warm=2" in o, o)
        check("  the listener: + the route", f"~ http 127.0.0.1:{L} {{" in o and "+     route /b { respond 410 }" in o, o)
        check("  a new listener: + its block", f"+ tcp 127.0.0.1:{L + 1} {{" in o, o)
        check("  what does not change is not said", "~ okena {" not in o and "route /a" not in o, o)
        check("the instance: untouched (no reload)", "reload" not in log.read_text(), log.read_text()[-300:])
    finally:
        p.terminate()
        p.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)
    print("diff: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
