#!/usr/bin/env python3
"""`okena { overload off; reload on-change }`: an edit to the file reloads within a few
seconds; so does a file added to an included directory, a certificate and
key replaced in place (the new one served, without a restart), and the files
of a listener with missing=skip coming (it opens); a broken edit is
tried once (one rejection, not one a second), the running configuration
serving; fixing it reloads; without it nothing is watched."""
import os
import pathlib
import shutil
import ssl
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
    for n in ("a", "b"):                 # two pairs: the one served, the renewal
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", tmp / f"{n}.key",
                        "-out", tmp / f"{n}.crt", "-subj", f"/CN=pair-{n}", "-days", "2"], check=True, capture_output=True)
    shutil.copy(tmp / "a.crt", tmp / "server.crt")
    shutil.copy(tmp / "a.key", tmp / "server.key")
    text = (f'okena {{ overload off; workers 1; reload on-change }}\ninclude "conf.d/*.conf"\nhttp 127.0.0.1:{L} {{ route /x {{ respond 404 }}; route /y {{ respond 404 }} }}\n'
            f'http 127.0.0.1:{L + 1} {{ tls {{ cert {tmp}/server.crt key={tmp}/server.key }}\n route /* {{ respond 200 }} }}\n'
            f'http 127.0.0.1:{L + 2} {{ tls {{ cert {tmp}/opt/c.crt key={tmp}/opt/c.key missing=skip }}\n route /* {{ respond 200 }} }}\n')
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("it serves", until(lambda: code() == 404), code())
        def opt_up():
            try:
                ssl.get_server_certificate(("127.0.0.1", L + 2), timeout=2)
                return True
            except OSError:
                return False
        check("missing=skip, its files not there: that listener alone not opened, said",
              not opt_up() and "missing=skip" in log.read_text(), log.read_text()[-300:])
        (tmp / "opt").mkdir()
        shutil.copy(tmp / "a.key", tmp / "opt" / "c.key")
        shutil.copy(tmp / "a.crt", tmp / "opt" / "c.crt")
        check("  they come: opened (reload on-change)", until(opt_up), log.read_text()[-300:])
        def served():
            try:
                return ssl.get_server_certificate(("127.0.0.1", L + 1), timeout=3)
            except OSError:
                return ""
        first = served()
        shutil.copy(tmp / "b.key", tmp / "server.key")
        shutil.copy(tmp / "b.crt", tmp / "server.crt")
        renewed = (tmp / "b.crt").read_text().strip()
        check("a certificate and key replaced in place: the new one served, no restart",
              first.strip() == (tmp / "a.crt").read_text().strip() and until(lambda: served().strip() == renewed)
              and p.poll() is None, log.read_text()[-300:])
        conf.write_text(text.replace("route /x { respond 404 }", "route /x { respond 410 }"))
        check("an edit to the file: reloaded within a few seconds", until(lambda: code() == 410), log.read_text()[-300:])
        (tmp / "conf.d" / "z.conf").write_text("pool zz { server 127.0.0.1:9 }\n")
        check("a file added to an included directory: reloaded", until(lambda: log.read_text().count("configuration reloaded") >= 4),
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
