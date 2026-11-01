#!/usr/bin/env python3
"""A flood of QUIC Initial packets (tests/bench/h3.sh): real client
Initials (aioquic, each with a ClientHello and connection IDs of its own),
made beforehand, then sent round and round as fast as one socket goes for
the given time, never answered. A server that does the handshake for each
burns a signature and a key exchange a packet; one that sends Retry under
load answers most with a packet of its own and nothing more.

    h3flood.py HOST PORT SECONDS [INITIALS]   (prints datagrams sent)
"""
import os
import socket
import ssl
import sys
import time

VENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "build", "qenv", "bin", "python")
try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
except ImportError:
    if os.path.exists(VENV) and sys.executable != os.path.realpath(VENV):
        os.execv(VENV, [VENV, "-I", __file__] + sys.argv[1:])
    sys.exit("h3flood: needs aioquic (build/qenv)")


def initials(host, port, n):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    out = []
    for _ in range(n):
        c = QuicConnection(configuration=cfg)
        c.connect((host, port), now=time.time())
        out.extend(d for d, _ in c.datagrams_to_send(now=time.time()))
    return out


def main():
    host, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    pkts = initials(host, port, int(sys.argv[4]) if len(sys.argv) > 4 else 4000)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, port))
    s.setblocking(False)
    sent, end = 0, time.time() + secs
    while time.time() < end:
        for p in pkts:
            try:
                s.send(p)
                sent += 1
            except BlockingIOError:
                pass
    print(sent)


if __name__ == "__main__":
    main()
