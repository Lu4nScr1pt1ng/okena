#!/usr/bin/env python3
"""QUIC packets steered to the worker that holds their connection, on one
engine (argument): okena with 4 workers, connections whose client address
changes (a NAT rebinding, a new port each time) during a download. The
kernel spreads datagrams over the workers' sockets by address, so without
the connection ID steering (qs_steer) a moved connection lands on a worker
that does not know it, which answers with a stateless reset."""
import asyncio
import os
import pathlib
import random
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
    print("skip h3 steering: no aioquic")
    sys.exit(0)
sys.path.insert(0, str(HERE))
import run as t  # noqa: E402

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 30000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
t.BACK, t.LST = BASE, BASE + 1
CONNS, MOVES = 8, (40, 120, 220)


async def one(i):
    port = BASE + 2 + i
    threading.Thread(target=t.rebind_relay, args=(port, [(m, "127.0.0.1") for m in MOVES]),
                     daemon=True).start()
    await asyncio.sleep(0.05)
    async with t.connect("127.0.0.1", port, configuration=t.config(), create_protocol=t.Client) as c:
        n = 300_000 + i
        r = await c.request("GET", f"/big/{n}")
        return r["body"] == bytes(random.Random(n).randbytes(n))


async def cases():
    ok = await asyncio.gather(*[one(i) for i in range(CONNS)])
    t.check(f"{CONNS} connections over 4 workers, each moving 3 times: every one finishes", all(ok), str(ok))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-steer-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    threading.Thread(target=t.backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 4; io_engine {ENGINE} }}
http 127.0.0.1:{t.LST} {{
    http3 on
    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}
    route /* {{ to 127.0.0.1:{t.BACK} }}
}}
""")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen(["timeout", "120", str(t.BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.6)
        asyncio.run(cases())
    finally:
        p.terminate()
        p.wait(10)
    print(f"h3 steering {ENGINE}: {'all passed' if not t.failures else f'{t.failures} failed'}")
    return 1 if t.failures else 0


if __name__ == "__main__":
    sys.exit(main())
