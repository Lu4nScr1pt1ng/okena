#!/usr/bin/env python3
"""`okena { last_good on }`: a start writes FILE.good, its includes written
into it; a reload that fails keeps the running configuration and the copy; a
start with FILE broken runs on the copy, and says so; once FILE is fixed a
reload reads it again (and the copy follows); without last_good nothing is
written and a broken FILE does not start."""
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 40000 + os.getpid() % 90 * 10
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def code(path="/x"):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{L}{path}", timeout=3)
        return 200
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 0


def until(f, t=5):
    end = time.time() + t
    while time.time() < end:
        if f():
            return True
        time.sleep(0.02)
    return f()


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-lastgood-"))
    (tmp / "conf.d").mkdir()
    (tmp / "conf.d" / "a.conf").write_text("pool p { server 127.0.0.1:9 }\n")
    conf, good = tmp / "okena.conf", tmp / "okena.conf.good"
    ok_text = f'okena {{ workers 1; last_good on }}\ninclude "conf.d/*.conf"\nhttp 127.0.0.1:{L} {{ route /x {{ respond 404 }}; route /* {{ to pool p }} }}\n'
    conf.write_text(ok_text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("it serves", until(lambda: code() == 404), code())
        g = good.read_text() if good.exists() else ""
        check("a start writes FILE.good, its include written into it", "pool p" in g and "include" not in g and "respond 404" in g, g)
        check("  readable by its owner only", good.exists() and (good.stat().st_mode & 0o777) == 0o600)
        conf.write_text(ok_text.replace("respond 404", "respond 404 {"))
        p.send_signal(signal.SIGHUP)
        check("a broken reload is refused", until(lambda: "reload rejected" in log.read_text()), log.read_text()[-400:])
        check("  the running one serves, the copy as it was", code() == 404 and good.read_text() == g)
    finally:
        p.terminate()
        p.wait(10)
    # a start with FILE broken: the copy
    log2 = tmp / "log2"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log2, "w"))
    try:
        check("a start with FILE broken runs on the copy", until(lambda: code() == 404), log2.read_text()[-400:])
        t = log2.read_text()
        check("  and says so, after FILE's errors", "error" in t and "last_good:" in t and "starting on the last good configuration" in t, t[-500:])
        conf.write_text(ok_text.replace("respond 404", "respond 410"))
        p.send_signal(signal.SIGHUP)
        check("FILE fixed: a reload reads it, not the copy", until(lambda: code() == 410), code())
        check("  and the copy follows", until(lambda: "respond 410" in good.read_text()))
    finally:
        p.terminate()
        p.wait(10)
    # without last_good: nothing written; a broken FILE does not start
    good.unlink()
    conf.write_text(ok_text.replace("last_good on", "last_good off"))
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=subprocess.DEVNULL)
    try:
        until(lambda: code() == 404)
        check("last_good off: no copy", not good.exists())
    finally:
        p.terminate()
        p.wait(10)
    conf.write_text("http {\n")
    r = subprocess.run([str(BIN), "-c", str(conf)], capture_output=True, timeout=10)
    check("  a broken FILE and no copy: refused, as before", r.returncode == 2, (r.returncode, r.stderr[-200:]))
    shutil.rmtree(tmp, ignore_errors=True)
    print("lastgood: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
