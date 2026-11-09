#!/usr/bin/env python3
"""`user` on one engine (argument), in a namespace of its own with uids to
spare (unshare --map-auto): the processes that face the network run as the
user and group with no capability, the supervisor stays root (a reload reads
a key only root may read), the logger's files are the user's, workers still
die with the supervisor (a change of credentials clears the parent-death
signal), names are looked up; and what is refused."""
import http.client
import http.server
import os
import pathlib
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 41000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, TLSL, BACK = BASE, BASE + 1, BASE + 2
UID = GID = 4242
fails = 0


def inside():
    """Into a user and network namespace with uids beyond 0 mapped."""
    if os.environ.get("OKENA_PRIVDROP_NS") == "1":
        return
    if shutil.which("newuidmap") is None:
        print(f"skip privdrop {ENGINE}: no newuidmap (uidmap) to map users")
        sys.exit(0)
    probe = subprocess.run(["unshare", "--map-auto", "--map-root-user", "true"], capture_output=True)
    if probe.returncode != 0:
        print(f"skip privdrop {ENGINE}: no subordinate uids for this user ({probe.stderr.decode().strip()[:80]})")
        sys.exit(0)
    env = dict(os.environ, OKENA_PRIVDROP_NS="1")
    os.execvpe("unshare", ["unshare", "--map-auto", "--map-root-user", "-n", "sh", "-c",
                           'ip link set lo up && exec "$0" "$@"', sys.executable, "-I", __file__, ENGINE], env)


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get(port=LST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def tls_get():
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    c = http.client.HTTPSConnection("127.0.0.1", TLSL, timeout=5, context=ctx)
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def status(pid):
    out = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        k, _, v = line.partition(":")
        out[k] = v.split()
    return out


def children(sup):
    out = {}
    for d in pathlib.Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                st = status(d.name)
                if st.get("PPid") == [str(sup)]:
                    out[int(d.name)] = (d / "comm").read_text().strip()
            except OSError:
                pass
    return out


def main():
    inside()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-privdrop-", dir="/tmp"))
    os.chmod(tmp, 0o755)
    logs = tmp / "logs"
    logs.mkdir()
    os.chown(logs, UID, GID)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "k.pem",
                    "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"], check=True, capture_output=True)
    os.chmod(tmp / "k.pem", 0o600)                          # root's alone
    threading.Thread(target=http.server.HTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    good = f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; user {UID}:{GID} }}
pool b {{ health tcp every=500ms; server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{ access_log {logs}/access.log; route /* {{ to pool b }} }}
http 127.0.0.1:{TLSL} {{ tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}; route /* {{ to pool b }} }}
"""
    conf.write_text(good)
    os.chmod(conf, 0o644)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    try:
        check("okena starts and serves", until(lambda: get() == 200 and tls_get() == 200), log.read_text()[-300:])
        check("  and says who serves", f"the processes facing the network run as uid {UID}, gid {GID}, with no capability" in log.read_text())
        kids = children(p.pid)
        workers = [k for k, c in kids.items() if c == "okena-worker"]
        others = [k for k, c in kids.items() if c in ("okena-logger", "okena-health")]
        dropped = [k for k in workers + others]
        bad = {}
        for k in dropped:
            st = status(k)
            if st["Uid"] != [str(UID)] * 4 or st["Gid"] != [str(GID)] * 4 or st.get("Groups") != [str(GID)] \
                    or int(st["CapEff"][0], 16) or int(st["CapPrm"][0], 16):
                bad[k] = (kids[k], st["Uid"], st["Gid"], st.get("Groups"), st["CapEff"], st["CapPrm"])
        check("workers, health, logger: the user and group, no capability", len(workers) == 2 and len(others) == 2 and not bad, (kids, bad))
        sst = status(p.pid)
        check("  the supervisor stays root", sst["Uid"][0] == "0", sst["Uid"])
        get()
        until(lambda: (logs / "access.log").exists() and (logs / "access.log").stat().st_size > 0)
        check("  the access log is the user's", (logs / "access.log").stat().st_uid == UID)

        # a reload: its compiler reads the key only root may read
        conf.write_text(good + "# again\n")
        p.send_signal(signal.SIGHUP)
        check("a reload reads a key only root may read", until(lambda: "reload rejected" not in log.read_text() and
                                                              len([k for k, c in children(p.pid).items() if c == "okena-worker" and k not in workers]) == 2)
              and tls_get() == 200, log.read_text()[-300:])
        now = [k for k, c in children(p.pid).items() if c == "okena-worker"]
        check("  its new workers as the user too", all(status(k)["Uid"][0] == str(UID) for k in now), now)
    finally:
        # the supervisor killed outright: its children must go with it
        kids = list(children(p.pid))
        p.kill()
        p.wait(10)
    gone = until(lambda: not any(pathlib.Path(f"/proc/{k}").exists() and status(k).get("State", ["Z"])[0] != "Z" for k in kids), 5)
    check("the supervisor killed: its children, as the user, go too (parent-death signal set again)", gone, kids)
    for k in kids:                              # (those that did not: not left behind)
        try:
            os.kill(k, signal.SIGKILL)
        except OSError:
            pass
    t = log.read_text()
    check("no process died of its filters", "seccomp" not in t and "cannot become" not in t, t[-300:])

    def bad(what, line, as_user=False):
        g = tmp / "bad.conf"
        g.write_text(f"okena {{ drain delay=0s timeout=1s; {line} }}\npool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{BASE + 9} {{ route /* {{ to pool b }} }}\n")
        os.chmod(g, 0o644)
        if as_user and not (tmp / "okena").exists():
            shutil.copy(BIN, tmp / "okena")       # (the user may not reach the build's directory)
            os.chmod(tmp / "okena", 0o755)
        cmd = [str(tmp / "okena"), "-c", str(g)] if as_user else [str(BIN), "check", str(g)]
        pre = (lambda: (os.setgid(GID), os.setuid(UID))) if as_user else None
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, preexec_fn=pre)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
        return r
    bad("a name that is no user's", "user nosuchuser-okena")
    bad("a group that is no group's", "user 4242:nosuchgroup-okena")
    r = bad("not root, and another user named", "user 0", as_user=True)
    check("  saying why", "okena is not root here, so it cannot become uid 0" in r.stderr, r.stderr[-200:])
    (tmp / "nobody.conf").write_text("okena { user nobody }\npool b { server 127.0.0.1:1 }\nhttp 127.0.0.1:1 { route /* { to pool b } }\n")
    r = subprocess.run([str(BIN), "check", str(tmp / "nobody.conf")], capture_output=True, text=True, timeout=10)
    check("a name from /etc/passwd: taken", r.returncode == 0, r.stderr[-200:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"privdrop {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    return 1 if fails else 0


sys.exit(main())
