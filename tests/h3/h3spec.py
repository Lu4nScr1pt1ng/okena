#!/usr/bin/env python3
"""h3spec (github.com/kazu-yamamoto/h3spec) against okena: every QUIC and
HTTP/3 error case it sends answered with the error RFC 9000, 9001, 9114 and
9204 ask. Its binary is not part of the repository: put it at build/h3spec
(or OKENA_H3SPEC); without it this suite says so and passes."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
H3SPEC = pathlib.Path(os.environ.get("OKENA_H3SPEC", ROOT / "build" / "h3spec"))
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
PORT = 18600 + os.getpid() % 300


def main():
    if not H3SPEC.exists():
        print(f"h3spec {ENGINE}: skipped (no {H3SPEC})")
        return 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h3spec-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"],
                   check=True, capture_output=True)
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ overload off; workers 1; io_engine {ENGINE} }}\n"
                    f"http 127.0.0.1:{PORT} {{\n tls {{ cert {tmp}/c.pem key={tmp}/k.pem }}\n http2 on\n http3 on\n"
                    f" route /* {{ respond 200 \"ok\" }}\n}}\n")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        for _ in range(100):             # its TCP listener up: the QUIC one is too
            try:
                socket.create_connection(("127.0.0.1", PORT), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = subprocess.run([str(H3SPEC), "127.0.0.1", str(PORT), "-n"], capture_output=True, text=True, timeout=600)
    finally:
        p.terminate()
        p.wait(10)
    out = r.stdout + r.stderr
    summary = [x for x in out.splitlines() if "examples" in x]
    failed = [x.strip() for x in out.splitlines() if "[x]" in x]
    for x in failed:
        print("FAIL " + x)
    ok = bool(summary) and " 0 failures" in summary[-1]
    print(f"h3spec {ENGINE}: " + (summary[-1] if summary else "no summary") + ("" if ok else "\n" + out[-600:]))
    return 0 if ok else 1


sys.exit(main())
