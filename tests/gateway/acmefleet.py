#!/usr/bin/env python3
"""A fleet sharing the acme directory (shared=on), on one engine (argument): two
okena instances, one DIR, the acme suite's CA; it validates HTTP-01 on both
instances' ports (as a CA reaching any of a fleet behind one name would), so the
one not ordering answers too (DIR/NAME/http-01). One order a certificate, both
serving it; a stale lock (an instance gone while ordering) removed and ordered;
a fresh one (another instance ordering) waited on, and the certificate it leaves
taken by both, not ordered again; the locks and challenges gone after."""
import datetime
import http.server
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acme as A  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BIN = A.BIN
BASE = 45400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, CA, PX, TX, PY, TY = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5
fails = 0
SEEN = []                         # (port, name, ok)


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def validate(az):
    """HTTP-01 asked of both instances: valid when both answer it"""
    want = az["token"] + "." + az["thumb"]
    ok = True
    for port in (PX, PY):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/.well-known/acme-challenge/{az['token']}",
                                         headers={"Host": az["name"]})
            with urllib.request.urlopen(req, timeout=3) as r:
                got = r.read().decode()
                one = r.status == 200 and got == want
        except Exception as e:
            got, one = repr(e), False
        SEEN.append((port, az["name"], one))
        ok = ok and one
    with az["st"].lock:
        az["status"] = "valid" if ok else "invalid"
        az["st"].log.append(("validated", (az["name"], ok, got)))


A.validate = validate


def orders(st, name):
    return [e[1] for e in st.log if e[0] == "order"].count([name])


def serial(port, name, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    import socket
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=name) as t:
            from cryptography import x509
            return x509.load_der_x509_certificate(t.getpeercert(binary_form=True)).serial_number


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-acmefleet-", dir="/tmp"))
    k, c = A.make_ca()
    st = A.CAState(k, c, CA)
    st.bad_nonce_once = False
    sk = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sc = A.issue(k, c, sk.public_key(), ["localhost"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=5))
    (tmp / "srv.pem").write_bytes(sc.public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    (tmp / "ca.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", CA), A.H)
    srv.st = st
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), A.Back).serve_forever, daemon=True).start()
    d = tmp / "acme"
    for n in ("g.example.test", "h.example.test"):
        (d / n).mkdir(parents=True, mode=0o700)
    d.chmod(0o700)
    (d / "g.example.test" / "lock").write_text("1 0123456789abcdef\n")          # its instance gone
    (d / "h.example.test" / "lock").write_text(f"{int(time.time()) + 600} fedcba9876543210\n")  # ordering
    procs = []
    logs = []
    for i, (plain, tls) in enumerate(((PX, TX), (PY, TY))):
        conf = tmp / f"okena{i}.conf"
        conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s
    acme {d} ca=https://localhost:{CA}/dir trust={tmp}/ca.pem shared=on }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{plain} {{ route /* {{ to pool b }} }}
http 127.0.0.1:{tls} {{
    tls {{ acme f.example.test; acme g.example.test; acme h.example.test }}
    route /* {{ to pool b }}
}}
""")
        log = tmp / f"log{i}"
        logs.append(log)
        procs.append(subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w")))
    cafile = str(tmp / "ca.pem")
    try:
        def both(name):
            a, b = serial(TX, name, cafile), serial(TY, name, cafile)
            return a == b and a
        ok = A.until(lambda: both("f.example.test"), 20)
        check("both instances serve the CA's certificate, the same one", ok,
              (logs[0].read_text()[-500:], logs[1].read_text()[-500:], st.log[-5:]))
        check("  one order for it", orders(st, "f.example.test") == 1, [e for e in st.log if e[0] == "order"])
        fs = [s for s in SEEN if s[1] == "f.example.test"]
        check("  HTTP-01 answered by both (the other one from DIR/NAME/http-01)",
              len(fs) == 2 and all(s[2] for s in fs), fs)
        t = logs[0].read_text() + logs[1].read_text()
        ok = A.until(lambda: both("g.example.test"), 20)
        check("a stale lock: removed, ordered once, both serving it",
              ok and orders(st, "g.example.test") == 1 and "its lock was stale" in t + logs[0].read_text() + logs[1].read_text(),
              [e for e in st.log if e[0] == "order"])
        check("a fresh lock (another instance ordering): not ordered", orders(st, "h.example.test") == 0, st.log[-3:])
        # the other instance's certificate: its key, then it (as acme writes them), then the lock gone
        hk = ec.generate_private_key(ec.SECP256R1())
        hc = A.issue(k, c, hk.public_key(), ["h.example.test"], now - datetime.timedelta(hours=1), now + datetime.timedelta(days=30))
        (d / "h.example.test" / "key.pem").write_bytes(hk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                        serialization.NoEncryption()))
        (d / "h.example.test" / "cert.pem").write_bytes(hc.public_bytes(serialization.Encoding.PEM))
        (d / "h.example.test" / "lock").unlink()
        ok = A.until(lambda: serial(TX, "h.example.test", cafile) == hc.serial_number
                     and serial(TY, "h.example.test", cafile) == hc.serial_number, 10)
        check("  the certificate it left taken by both, not ordered", ok and orders(st, "h.example.test") == 0,
              (logs[0].read_text()[-400:], logs[1].read_text()[-400:], st.log[-6:],
               sorted(x.name for x in (d / "h.example.test").iterdir())))
        check("  each said it waited, then took it",
              A.until(lambda: all("h.example.test: another instance is ordering it" in g.read_text()
                                  and "h.example.test: renewed by another instance" in g.read_text() for g in logs), 3),
              (logs[0].read_text()[-400:], logs[1].read_text()[-400:]))
        # files changed under a running instance whose acme process starts again
        # (as a reload starts it): it sees they are not what is served, and reloads
        fk = ec.generate_private_key(ec.SECP256R1())
        fc = A.issue(k, c, fk.public_key(), ["f.example.test"], now - datetime.timedelta(hours=1), now + datetime.timedelta(days=30))
        (d / "f.example.test" / "key.pem").write_bytes(fk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                        serialization.NoEncryption()))
        (d / "f.example.test" / "cert.pem").write_bytes(fc.public_bytes(serialization.Encoding.PEM))
        def child_named(ppid, comm):
            for x in pathlib.Path("/proc").iterdir():
                try:
                    if x.name.isdigit() and (x / "comm").read_text().strip() == comm \
                            and (x / "stat").read_text().rsplit(")", 1)[1].split()[1] == str(ppid):
                        return int(x.name)
                except OSError:                     # (gone meanwhile)
                    pass
        acme_pid = child_named(procs[0].pid, "okena-acme")
        os.kill(acme_pid, 9)
        check("files newer than what is served, the acme process started again: reloaded, served",
              A.until(lambda: serial(TX, "f.example.test", cafile) == fc.serial_number, 10)
              and "its files are newer than the configuration served" in logs[0].read_text(), logs[0].read_text()[-400:])
        left = sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.name.startswith(("lock", "http-01")))
        check("the locks and challenges gone", A.until(lambda: not [p for p in d.rglob("*") if p.name.startswith(("lock", "http-01"))], 3),
              left)
    finally:
        for q in procs:
            q.terminate()
        for q in procs:
            try:
                q.wait(10)
            except subprocess.TimeoutExpired:
                q.kill()
    t = "\n".join(l for l in (logs[0].read_text() + logs[1].read_text()).splitlines()
                  if "acme process exited" not in l)       # (the one the test killed)
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited, restarting" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"acmefleet {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
