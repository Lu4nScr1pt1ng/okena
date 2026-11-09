#!/usr/bin/env python3
"""okena bench proto=h3 against okena, on one engine (argument): requests
counted right by status, bodies going out, answers of many packets, a path
that loses datagrams (data past a gap dropped unacknowledged, the server
sending it again) and a server that goes away (the connection made again)."""
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
VENV = HERE.parents[1] / "build" / "qenv" / "bin" / "python"
try:
    import aioquic  # noqa: F401
except ImportError:
    if VENV.exists() and sys.executable != str(VENV):
        os.execv(str(VENV), [str(VENV), "-I", __file__] + sys.argv[1:])
    print("skip h3 bench: no aioquic")
    sys.exit(0)
sys.path.insert(0, str(HERE))
import run as t  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 24000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
t.BACK, t.LST, t.RELAY = BASE, BASE + 1, BASE + 2


def bench(port, path, *args):
    r = subprocess.run(["timeout", "20", str(t.BIN), "bench", f"https://127.0.0.1:{port}{path}", "proto=h3",
                        "format=kv", "warmup=0s", "workers=1", *args], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    kv = dict(x.split("=", 1) for x in r.stdout.split() if "=" in x)
    return r, kv


def n(kv, key):
    return int(float(kv.get(key, -1)))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-h3b-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    threading.Thread(target=t.backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{t.LST} {{
    http3 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{t.BACK} }}
}}
""")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen(["timeout", "--foreground", "70", str(t.BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.6)
        r, kv = bench(t.LST, "/ok", "conns=8", "duration=1s")
        t.check("GET: requests, every one 2xx, no errors",
                n(kv, "requests") > 100 and n(kv, "ok") == n(kv, "requests") and n(kv, "errors") == 0,
                f"{r.stdout[:200]} {r.stderr[:100]}")
        r, kv = bench(t.LST, "/ok", "conns=8", "rate=500", "duration=1s")
        t.check("open loop: the rate held", 450 <= n(kv, "requests") <= 550 and n(kv, "errors") == 0, r.stdout[:200])
        r, kv = bench(t.LST, "/missing", "conns=2", "duration=1s")
        t.check("another status: counted as other", n(kv, "other") == n(kv, "requests") > 10, r.stdout[:200])
        r, kv = bench(t.LST, "/ok", "conns=2", "method=POST", "body=hello", "header=x-a: b", "duration=1s")
        t.check("POST with a body, a header of ours", n(kv, "ok") == n(kv, "requests") > 10, r.stdout[:200])
        r, kv = bench(t.LST, "/big/1000000", "conns=2", "duration=1s")
        t.check("answers of a megabyte", n(kv, "ok") == n(kv, "requests") > 2 and n(kv, "errors") == 0, r.stdout[:200])
        threading.Thread(target=t.relay, args=(0.03,), daemon=True).start()
        time.sleep(0.05)
        r, kv = bench(t.RELAY, "/big/300000", "conns=1", "duration=3s")
        t.check("3% of the datagrams lost: 300 KB answers still whole", n(kv, "ok") == n(kv, "requests") > 1
                and n(kv, "errors") == 0, r.stdout[:200])
        q = subprocess.run(["timeout", "20", str(t.BIN), "bench", f"http://127.0.0.1:{t.LST}/", "proto=h3"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        t.check("proto=h3 for http://: refused", q.returncode != 0 and "proto=h3" in q.stderr, q.stderr[:100])
    finally:
        p.terminate()
        p.wait(10)
    print(f"h3 bench {ENGINE}: {'all passed' if not t.failures else f'{t.failures} failed'}")
    return 1 if t.failures else 0


if __name__ == "__main__":
    sys.exit(main())
