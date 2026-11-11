#!/usr/bin/env python3
"""A tls block's `versions` and `alpn`, through OpenSSL's s_client, on one
engine (argument): versions 1.3 refuses a TLS 1.2 client (protocol_version)
and serves 1.3; versions 1.2 serves 1.2 to a client offering 1.3 too;
alpn http/1.1 h2 prefers http/1.1; alpn h2 refuses a client that asks
http/1.1 only and gives h2; a listener without them is as before; versions 1.2
with http3 is refused by the checker."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import socket

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 42000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L13, L12, LH1, LH2, LD = (BASE + i for i in range(5))
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def sc(port, *opts):
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "a.test", *opts],
                       input=b"", capture_output=True, timeout=10)
    o = (r.stdout + r.stderr).decode(errors="replace")
    proto = next((x.split(":", 1)[1].strip() for x in o.splitlines() if x.strip().startswith("Protocol  :")), "")
    alpn = next((x.split(":", 1)[1].strip() for x in o.splitlines() if x.startswith("ALPN protocol:")), "")
    return proto, alpn, o


def main():
    if not shutil.which("openssl"):
        print("skip policy: no openssl")
        return
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-tlspol-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", "k.pem", "-out", "c.pem", "-subj", "/CN=a.test", "-days", "2"], check=True, capture_output=True, cwd=tmp)
    t = f"cert {tmp}/c.pem; key {tmp}/k.pem"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{L13} {{ tls {{ {t}; versions 1.3 }}; route /* {{ respond 404 }} }}
http 127.0.0.1:{L12} {{ tls {{ {t}; versions 1.2 }}; route /* {{ respond 404 }} }}
http 127.0.0.1:{LH1} {{ tls {{ {t}; alpn http/1.1 h2 }}; route /* {{ respond 404 }} }}
http 127.0.0.1:{LH2} {{ tls {{ {t}; alpn h2 }}; route /* {{ respond 404 }} }}
http 127.0.0.1:{LD} {{ tls {{ {t} }}; http2 on; route /* {{ respond 404 }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LD), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        pr, al, o = sc(L13, "-tls1_2")
        check("versions 1.3: a TLS 1.2 client refused, protocol_version", pr in ("", "TLSv1.2") and "protocol version" in o and "Cipher is (NONE)" in o, o[-300:])
        pr, al, o = sc(L13)
        check("  a TLS 1.3 client served", pr == "TLSv1.3", o[-300:])
        pr, al, o = sc(L12)
        check("versions 1.2: a client offering 1.3 too gets 1.2", pr == "TLSv1.2", o[-300:])
        pr, al, o = sc(LH1, "-alpn", "h2,http/1.1")
        check("alpn http/1.1 h2: http/1.1 preferred", al == "http/1.1", o[-300:])
        pr, al, o = sc(LH1, "-alpn", "h2")
        check("  h2 still when only it is asked", al == "h2", o[-300:])
        pr, al, o = sc(LH2, "-alpn", "http/1.1")
        check("alpn h2: a client asking http/1.1 only refused (no_application_protocol)", "no application protocol" in o, o[-300:])
        pr, al, o = sc(LH2, "-alpn", "http/1.1,h2")
        check("  h2 for one that asks it", al == "h2", o[-300:])
        pr, al, o = sc(LD, "-alpn", "h2,http/1.1")
        check("without them: h2 preferred, 1.3, as before", al == "h2" and pr == "TLSv1.3", o[-300:])
        pr, al, o = sc(LD, "-tls1_2", "-alpn", "http/1.1")
        check("  and 1.2 served, http/1.1 named back", pr == "TLSv1.2" and al == "http/1.1", o[-300:])
        pr, al, o = sc(LD, "-tls1_2", "-alpn", "h2,http/1.1")
        check("  TLS 1.2: h2 when offered", pr == "TLSv1.2" and al == "h2", o[-300:])
        pr, al, o = sc(LH2, "-tls1_2", "-alpn", "http/1.1")
        check("alpn h2 on TLS 1.2 too: http/1.1 only refused", "no application protocol" in o, o[-300:])
        pr, al, o = sc(LH1, "-tls1_2", "-alpn", "h2,http/1.1")
        check("alpn http/1.1 h2 on TLS 1.2 too: http/1.1", al == "http/1.1", o[-300:])
    finally:
        p.terminate()
        p.wait(10)
    bad = tmp / "bad.conf"
    bad.write_text(f"http 127.0.0.1:{LD} {{ tls {{ {t}; versions 1.2 }}; http3 on; route /* {{ respond 404 }} }}\n")
    r = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True)
    check("versions 1.2 with http3: refused", r.returncode == 2 and "QUIC is TLS 1.3 only" in r.stderr, r.stderr)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"policy {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
