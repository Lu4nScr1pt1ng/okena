#!/usr/bin/env python3
"""h2spec (summerwind/h2spec, the HTTP/2 conformance suite: RFC 9113 and
7541) against a live okena with `http2 on`, on one engine (argument):
over TLS (ALPN h2; h2spec negotiates TLS 1.2) every case must pass; by
prior knowledge on a plain listener the one failure allowed is "invalid
connection preface", which a listener that also serves HTTP/1.1 takes for
an HTTP/1.1 request. The binary is fetched once, at a pinned version and
checksum, into build/h2spec (or taken from $H2SPEC); without it (no
network) the suite is skipped."""
import hashlib
import io
import os
import pathlib
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
H2SPEC = pathlib.Path(os.environ.get("H2SPEC", ROOT / "build" / "h2spec" / "h2spec"))
URL = "https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz"
SHA256 = "157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318"
BASE = 28000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, PLAIN, TLS = BASE, BASE + 1, BASE + 2
ALLOWED_PLAIN = {"Sends invalid connection preface"}
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


def fetch():
    if H2SPEC.exists():
        return True
    try:
        data = urllib.request.urlopen(URL, timeout=30).read()
    except OSError:
        return False
    if hashlib.sha256(data).hexdigest() != SHA256:
        print("h2spec: the download does not match its checksum")
        return False
    H2SPEC.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        member = t.getmember("h2spec")
        H2SPEC.write_bytes(t.extractfile(member).read())
    H2SPEC.chmod(0o755)
    return True


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(512)

    def handle(c):
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, buf = buf.split(b"\r\n\r\n", 1)
                n = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        n = int(line.split(b":", 1)[1])
                while len(buf) < n:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                buf = buf[n:]
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def run(args):
    r = subprocess.run([str(H2SPEC), "-h", "127.0.0.1", *args], capture_output=True, text=True, timeout=120)
    summary = [l for l in r.stdout.splitlines() if "tests," in l]
    failed = sorted({l.strip()[2:].split(": ", 1)[1] for l in r.stdout.splitlines() if l.strip().startswith("× ")})
    return (summary[-1] if summary else r.stdout[-300:]), failed


def main():
    if not BIN.exists():
        print("build/okena missing")
        return 1
    if not fetch():
        print("skip h2spec: not available (no network; or set H2SPEC to the binary)")
        return 0
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h2spec-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost",
                    "-days", "2", "-out", tmp / "c.pem"], check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{PLAIN} {{
    http2 on
    route /* {{ to 127.0.0.1:{BACK} }}
}}
http 127.0.0.1:{TLS} {{
    http2 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.4)
        summary, failed = run(["-p", str(TLS), "-t", "-k"])
        check(f"h2spec over TLS: every case ({summary})", not failed, str(failed))
        summary, failed = run(["-p", str(PLAIN)])
        check(f"h2spec by prior knowledge ({summary})", set(failed) <= ALLOWED_PLAIN, str(failed))
        log.seek(0)
        text = log.read()
        check("no worker died", "killed" not in text and "exited with status" not in text, text[-300:])
    finally:
        p.terminate()
        p.wait(10)
    print(f"h2spec {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
