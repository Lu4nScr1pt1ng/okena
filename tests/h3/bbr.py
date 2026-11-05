#!/usr/bin/env python3
"""BBR (`quic_cc bbr`), on one engine (argument): downloads through a relay
that loses a tenth of the datagrams each way finish, bytes intact, and a
request on a clean path goes as ever. With the loss to itself the window
would collapse under a congestion control that takes losses for congestion."""
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
BASE = 31000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
t.BACK, t.LST, t.RELAY = BASE, BASE + 1, BASE + 2


async def get(port, n):
    async with t.connect("127.0.0.1", port, configuration=t.config(), create_protocol=t.Client) as c:
        r = await c.request("GET", f"/big/{n}")
        return r["body"] == bytes(random.Random(n).randbytes(n))


async def cases():
    t.check("clean path: 1 MB intact", await get(t.LST, 1_000_000))
    threading.Thread(target=t.relay, args=(0.1,), daemon=True).start()
    await asyncio.sleep(0.05)
    t0 = time.time()
    ok = [await get(t.RELAY, 300_000 + i) for i in range(4)]
    t.check("a tenth of the datagrams lost: 4 downloads of 300 KB intact", all(ok), str(ok))
    t.check("  and in good time", time.time() - t0 < 20, f"{time.time() - t0:.1f} s")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-bbr-"))
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=h3.test",
                    "-addext", "subjectAltName=DNS:h3.test", "-days", "2", "-out", tmp / "c.pem"],
                   check=True, capture_output=True)
    threading.Thread(target=t.backend, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; quic_cc bbr }}
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
    print(f"h3 bbr {ENGINE}: {'all passed' if not t.failures else f'{t.failures} failed'}")
    return 1 if t.failures else 0


if __name__ == "__main__":
    sys.exit(main())
