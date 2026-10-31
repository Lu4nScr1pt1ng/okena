#!/usr/bin/env python3
"""WebSocket over HTTP/2 (RFC 8441), on one engine (argument): an HTTP/2
client opens an extended CONNECT stream (:protocol websocket), okena
asks an HTTP/1.1 backend for the upgrade (its own Sec-WebSocket-Key),
answers the stream with 200 when the backend switches, and then carries
the bytes both ways until the backend closes (END_STREAM). The backend
here checks the upgrade and echoes what it gets."""
import base64
import hashlib
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 27000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
failures = 0
heads = []

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
except ImportError:
    h2 = None


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    failures += not ok


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", BACK))
    s.listen(64)

    def handle(c):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            fields = {k.strip().lower(): v.strip() for k, v in (l.split(b":", 1) for l in lines[1:])}
            heads.append((lines[0], fields))
            if lines[0].startswith(b"GET /refuse"):
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
                return
            key = fields.get(b"sec-websocket-key", b"")
            accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            if lines[0].startswith(b"GET /close"):
                c.sendall(b"bye")
                return
            if rest:
                c.sendall(rest)
            while True:
                d = c.recv(65536)
                if not d:
                    return
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


class Client:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", LST), timeout=5)
        self.c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
        self.c.initiate_connection()
        self.c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1 << 20})
        self.c.increment_flow_control_window(1 << 24)
        self.flush()
        self.events = []

    def flush(self):
        d = self.c.data_to_send()
        if d:
            self.s.sendall(d)

    def pump(self, until, timeout=5):
        deadline = time.time() + timeout
        while not until() and time.time() < deadline:
            try:
                d = self.s.recv(1 << 16)
            except socket.timeout:
                break
            except OSError:
                self.events.append("eof")
                break
            if not d:
                self.events.append("eof")
                break
            for e in self.c.receive_data(d):
                self.events.append(e)
                if isinstance(e, h2.events.DataReceived):
                    self.c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
            self.flush()

    def of(self, kind, sid=None):
        return [e for e in self.events if isinstance(e, kind) and (sid is None or e.stream_id == sid)]

    def data(self, sid):
        return b"".join(e.data for e in self.of(h2.events.DataReceived, sid))


def connect(c, path, proto="websocket", method="CONNECT"):
    sid = c.c.get_next_available_stream_id()
    hdrs = [(":method", method), (":scheme", "http"), (":authority", "ws.test"), (":path", path)]
    if proto:
        hdrs.append((":protocol", proto))
    hdrs += [("sec-websocket-version", "13"), ("origin", "http://ws.test")]
    c.c.send_headers(sid, hdrs)
    c.flush()
    return sid


def raw_reset(path_headers):
    """A stream sent raw (the h2 package will not send some of these): the
    RST_STREAM code okena answers, or None."""
    import hpack
    s = socket.create_connection(("127.0.0.1", LST), timeout=3)
    block = hpack.Encoder().encode(path_headers)
    s.sendall(PREFACE + b"\0\0\0\4\0\0\0\0\0" + struct.pack(">I", len(block))[1:] + b"\x01\x04\0\0\0\1" + block)
    data, deadline = b"", time.time() + 2
    while time.time() < deadline:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        data += d
        i = 0
        while i + 9 <= len(data):
            n = int.from_bytes(data[i:i + 3], "big")
            if data[i + 3] == 3 and i + 13 <= len(data):
                s.close()
                return int.from_bytes(data[i + 9:i + 13], "big")
            i += 9 + n
    s.close()
    return None


def cases():
    c = Client()
    c.pump(lambda: c.of(h2.events.RemoteSettingsChanged), 3)
    st = c.of(h2.events.RemoteSettingsChanged)
    check("okena's SETTINGS allow extended CONNECT",
          st and any(k == 8 and v.new_value == 1 for k, v in st[0].changed_settings.items()), str(st))

    sid = connect(c, "/chat?room=1")
    c.pump(lambda: c.of(h2.events.ResponseReceived, sid), 3)
    resp = c.of(h2.events.ResponseReceived, sid)
    hdrs = dict(resp[0].headers) if resp else {}
    check("the backend's 101 is the stream's 200, without the handshake's fields",
          hdrs.get(b":status") == b"200" and b"upgrade" not in hdrs and b"sec-websocket-accept" not in hdrs,
          str(hdrs))
    line, fields = heads[-1] if heads else (b"", {})
    check("  the backend got an HTTP/1.1 upgrade: GET, Upgrade, a key, the client's fields",
          line == b"GET /chat?room=1 HTTP/1.1" and fields.get(b"upgrade", b"").lower() == b"websocket"
          and b"upgrade" in fields.get(b"connection", b"").lower()
          and len(base64.b64decode(fields.get(b"sec-websocket-key", b"") or b"==")) == 16
          and fields.get(b"sec-websocket-version") == b"13" and fields.get(b"host") == b"ws.test"
          and fields.get(b"origin") == b"http://ws.test", str((line, fields)))

    # a masked text frame, then many: echoed (the tunnel carries bytes)
    frame = b"\x81\x85\x37\xfa\x21\x3d" + bytes(a ^ b for a, b in zip(b"Hello", b"\x37\xfa\x21\x3d\x37"))
    c.c.send_data(sid, frame)
    c.flush()
    c.pump(lambda: len(c.data(sid)) >= len(frame), 3)
    check("bytes from the client come back through the backend", c.data(sid) == frame, repr(c.data(sid)))
    for i in range(20):                               # back and forth, each waits for its echo
        n = len(c.data(sid))
        msg = bytes([i]) * (100 + i)
        c.c.send_data(sid, msg)
        c.flush()
        c.pump(lambda: len(c.data(sid)) >= n + len(msg), 3)
    check("20 messages each echoed before the next", len(c.data(sid)) == len(frame) + sum(100 + i for i in range(20)),
          f"{len(c.data(sid))} bytes")

    big = os.urandom(1 << 20)                         # a megabyte, both ways at once
    start = len(c.data(sid))
    off = 0
    while off < len(big):
        w = min(c.c.local_flow_control_window(sid), 16384, len(big) - off)
        if w > 0:
            c.c.send_data(sid, big[off:off + w])
            off += w
            c.flush()
        else:
            c.pump(lambda: c.c.local_flow_control_window(sid) > 0, 3)
    c.pump(lambda: len(c.data(sid)) >= start + len(big), 10)
    check("a megabyte up and back", c.data(sid)[start:] == big, f"{len(c.data(sid)) - start} bytes back")

    sid2 = connect(c, "/close")                      # the backend closes: END_STREAM
    c.pump(lambda: c.of(h2.events.StreamEnded, sid2), 3)
    check("the backend closes: its last bytes, then END_STREAM",
          c.data(sid2) == b"bye" and c.of(h2.events.StreamEnded, sid2), repr(c.data(sid2)))

    sid3 = connect(c, "/refuse")                     # no switch: its answer as it is
    c.pump(lambda: c.of(h2.events.StreamEnded, sid3), 3)
    resp = c.of(h2.events.ResponseReceived, sid3)
    check("a backend that does not switch: its answer goes back (403)",
          resp and dict(resp[0].headers).get(b":status") == b"403" and c.data(sid3) == b"no", str(resp))
    c.s.close()

    base = [(":method", "CONNECT"), (":scheme", "http"), (":authority", "ws.test"), (":path", "/x")]
    check("CONNECT without :protocol: RST_STREAM PROTOCOL_ERROR", raw_reset(base[:1] + base[2:3]) == 1)
    check(":protocol other than websocket: RST_STREAM PROTOCOL_ERROR",
          raw_reset(base + [(":protocol", "smtp")]) == 1)
    check(":protocol on a GET: RST_STREAM PROTOCOL_ERROR",
          raw_reset([(":method", "GET")] + base[1:] + [(":protocol", "websocket")]) == 1)


def main():
    if h2 is None:
        print("skip websocket over h2: pip install h2")
        return 0
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ws2-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; io_engine {ENGINE} }}\nhttp 127.0.0.1:{LST} {{\n    http2 on\n"
                    f"    route /* {{ to 127.0.0.1:{BACK} }}\n}}\n")
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    try:
        time.sleep(0.4)
        cases()
        log.seek(0)
        text = log.read()
        check("no worker died", "killed" not in text and "exited with status" not in text, text[-300:])
    finally:
        p.terminate()
        p.wait(10)
    print(f"websocket over h2 {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
