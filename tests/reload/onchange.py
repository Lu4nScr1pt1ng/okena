#!/usr/bin/env python3
"""`okena { reload on-change }`: an edit to the file reloads within a few
seconds; so does a file added to an included directory; a broken edit is
tried once (one rejection, not one a second), the running configuration
serving; fixing it reloads; without it nothing is watched."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
L = 48000 + os.getpid() % 90 * 10
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


def until(f, t=6):
    end = time.time() + t
    while time.time() < end:
        if f():
            return True
        time.sleep(0.05)
    return f()


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-onchange-"))
    (tmp / "conf.d").mkdir()
    conf = tmp / "okena.conf"
    text = f'okena {{ workers 1; reload on-change }}\ninclude "conf.d/*.conf"\nhttp 127.0.0.1:{L} {{ route /x {{ respond 404 }}; route /y {{ respond 404 }} }}\n'
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("it serves", until(lambda: code() == 404), code())
        conf.write_text(text.replace("route /x { respond 404 }", "route /x { respond 410 }"))
        check("an edit to the file: reloaded within a few seconds", until(lambda: code() == 410), log.read_text()[-300:])
        (tmp / "conf.d" / "z.conf").write_text("pool zz { server 127.0.0.1:9 }\n")
        check("a file added to an included directory: reloaded", until(lambda: log.read_text().count("configuration reloaded") >= 2),
              log.read_text()[-300:])
        conf.write_text(text.replace("route /x { respond 404 }", "route /x { respond 410 {"))
        check("a broken edit: rejected", until(lambda: "reload rejected" in log.read_text()), log.read_text()[-300:])
        until(lambda: False, 3)
        check("  once, not again each second; the running one serves", log.read_text().count("reload rejected") == 1 and code() == 410,
              log.read_text().count("reload rejected"))
        conf.write_text(text.replace("route /x { respond 404 }", "route /x { respond 403 }"))
        check("fixed: reloaded", until(lambda: code() == 403), code())
    finally:
        p.terminate()
        p.wait(10)
    conf.write_text(text.replace(" reload on-change", ""))
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=subprocess.DEVNULL)
    try:
        until(lambda: code() == 404)
        conf.write_text(text.replace(" reload on-change", "").replace("route /x { respond 404 }", "route /x { respond 410 }"))
        until(lambda: False, 2.5)
        check("without it: nothing watched", code() == 404, code())
    finally:
        p.terminate()
        p.wait(10)
    shutil.rmtree(tmp, ignore_errors=True)
    print("onchange: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
