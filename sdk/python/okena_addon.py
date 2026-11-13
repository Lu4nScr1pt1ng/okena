"""okena addon SDK for Python (protocol version 1, docs/ADDONS.md).

An addon is a program okena starts (`addon NAME { run ... }`) and calls at
phases of a request through shared memory. This module is the whole addon
side of the protocol, with no dependency beyond the standard library:

    import okena_addon as oa

    def on_request(req):
        if req.header("x-block"):
            return oa.Respond(403, [("content-type", "text/plain")], b"blocked\\n")
        return oa.Continue(set=[("x-checked", "yes")], remove=["x-debug"])

    oa.run(on_request)

`run` maps the memory okena gave (OKENA_ADDON_FD), says it is ready, then
answers calls until okena stops it. The handler runs on one thread; a call it
does not answer within the addon's `timeout` follows `on_error` in okena.
Python never polls: it sleeps on the bell between calls, so okena always rings.
"""
import mmap
import os
import struct

MAGIC = 0x314E4F4444414B4F
VERSION = 1

# header
H_NRINGS, H_RBYTES, H_HBYTES, H_STRIDE = 12, 16, 20, 24
H_BELL, H_WAKE0, H_PHASES, H_READY, H_EPOCH, H_SLEEP, H_NAME = 32, 36, 40, 48, 52, 60, 64
# ring pair
R_HEAD, R_TAIL = 0, 64

PHASE_REQUEST_HEADERS = 1
FLAG_TLS, FLAG_H2, FLAG_H3 = 1, 2, 4

OP_SET, OP_ADD, OP_REMOVE, OP_TARGET = 1, 2, 3, 4
ACTION_CONTINUE, ACTION_RESPOND = 0, 1

_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")
_CALL = struct.Struct("<IHHIIIHH16sHHHHII")	# up to the index
_FIELD = struct.Struct("<HHHH")
_ANSWER = struct.Struct("<IHHIHHII")


class Request:
    """A call: the request's head as okena forwards it (HTTP/1.1 form, also
    for HTTP/2 and HTTP/3 clients), and what okena knows of the client."""
    __slots__ = ("id", "phase", "flags", "head", "method", "target", "headers", "family", "client", "route")

    def header(self, name, default=None):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return default

    @property
    def path(self):
        return self.target.split("?", 1)[0]

    @property
    def client_ip(self):
        import ipaddress
        if self.family == 4:
            return str(ipaddress.IPv4Address(self.client[:4]))
        if self.family == 6:
            return str(ipaddress.IPv6Address(self.client))
        return ""


class Continue:
    """Let the request go on, its head changed first: `set` replaces every field
    of a name, `add` adds one more, `remove` takes them away, `target` is the
    new request target (a path, with its query). Content-Length,
    Transfer-Encoding, Connection and the like are okena's and stay as they are."""
    __slots__ = ("set", "add", "remove", "target")

    def __init__(self, set=(), add=(), remove=(), target=None):
        self.set, self.add, self.remove, self.target = set, add, remove, target


class Respond:
    """Answer the client here: status, fields, body. okena adds the
    Content-Length and the request id, and never asks the backend."""
    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers=(), body=b""):
        self.status, self.headers, self.body = status, headers, body if isinstance(body, bytes) else body.encode()


def _b(x):
    return x if isinstance(x, bytes) else str(x).encode("latin-1")


class Addon:
    def __init__(self, fd=None):
        fd = int(os.environ["OKENA_ADDON_FD"]) if fd is None else fd
        size = os.fstat(fd).st_size
        self.m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self.v = memoryview(self.m)
        if _U64.unpack_from(self.v, 0)[0] != MAGIC or _U32.unpack_from(self.v, 8)[0] != VERSION:
            raise RuntimeError("okena addon: not an okena addon memory, or another protocol version")
        self.nrings = _U32.unpack_from(self.v, H_NRINGS)[0]
        self.rbytes = _U32.unpack_from(self.v, H_RBYTES)[0]
        self.hbytes = _U32.unpack_from(self.v, H_HBYTES)[0]
        self.stride = _U64.unpack_from(self.v, H_STRIDE)[0]
        self.bell = _U32.unpack_from(self.v, H_BELL)[0]
        self.wake0 = _U32.unpack_from(self.v, H_WAKE0)[0]
        self.name = bytes(self.v[H_NAME:H_NAME + 64]).split(b"\0", 1)[0].decode()

    def _ring(self, r):
        base = self.hbytes + r * self.stride
        calls = base
        answers = base + self.hbytes + self.rbytes
        return calls, calls + self.hbytes, answers, answers + self.hbytes

    def ready(self):
        _U32.pack_into(self.v, H_SLEEP, 1)	# never polls: always rung
        _U32.pack_into(self.v, H_READY, 1)

    def run(self, handler):
        self.ready()
        while True:
            self.poll(handler)
            os.read(self.bell, 8)

    def poll(self, handler):
        """Answer every call waiting, once. Returns how many."""
        n = 0
        v = self.v
        mask = self.rbytes - 1
        for r in range(self.nrings):
            ch, cd, ah, ad = self._ring(r)
            head = _U64.unpack_from(v, ch + R_HEAD)[0]
            tail = _U64.unpack_from(v, ch + R_TAIL)[0]
            if head == tail:
                continue
            answered = False
            while tail != head:
                pos = tail & mask
                length = _U32.unpack_from(v, cd + pos)[0]
                kind = struct.unpack_from("<H", v, cd + pos + 4)[0]
                if length < 8 or length & 7 or length > head - tail:
                    tail = head		# not a record: what is left is dropped
                    break
                if kind == 1:
                    req = self._call(v, cd + pos)
                    try:
                        out = handler(req)
                    except Exception as e:		# the call goes unanswered: on_error
                        import sys
                        print(f"okena addon {self.name}: {e!r}", file=sys.stderr, flush=True)
                        out = None
                    if out is not None:
                        answered |= self._answer(ah, ad, req.id, out)
                    n += 1
                tail += length
            _U64.pack_into(v, ch + R_TAIL, tail)
            if answered:
                os.write(self.wake0 + r, _U64.pack(1))
        return n

    def _call(self, v, at):
        (length, kind, phase, cid, flags, hlen, nhdr, family, client,
         moff, mlen, toff, tlen, route, _rsv) = _CALL.unpack_from(v, at)
        idx = at + 56
        hat = idx + 8 * nhdr
        head = bytes(v[hat:hat + hlen])
        req = Request()
        req.id, req.phase, req.flags, req.head = cid, phase, flags, head
        req.family, req.client, req.route = family, client, route
        req.method = head[moff:moff + mlen].decode("latin-1")
        req.target = head[toff:toff + tlen].decode("latin-1")
        hs = []
        for i in range(nhdr):
            no, nl, vo, vl = _FIELD.unpack_from(v, idx + 8 * i)
            hs.append((head[no:no + nl].decode("latin-1"), head[vo:vo + vl].decode("latin-1")))
        req.headers = hs
        return req

    def _answer(self, ah, ad, cid, out):
        ops = []
        body = b""
        if isinstance(out, Respond):
            action, status = ACTION_RESPOND, out.status
            for k, val in out.headers:
                ops.append((OP_ADD, _b(k), _b(val)))
            body = out.body
        elif isinstance(out, Continue):
            action, status = ACTION_CONTINUE, 0
            for k, val in (out.set.items() if isinstance(out.set, dict) else out.set):
                ops.append((OP_SET, _b(k), _b(val)))
            for k, val in out.add:
                ops.append((OP_ADD, _b(k), _b(val)))
            for k in out.remove:
                ops.append((OP_REMOVE, _b(k), b""))
            if out.target is not None:
                ops.append((OP_TARGET, b"", _b(out.target)))
        else:
            raise TypeError("a handler returns okena_addon.Continue or okena_addon.Respond (or None: no answer)")
        rec = bytearray(_ANSWER.size)
        for op, k, val in ops:
            rec += struct.pack("<BBHH", op, 0, len(k), len(val)) + k + val
        rec += body
        size = (len(rec) + 7) & ~7
        rec += b"\0" * (size - len(rec))
        _ANSWER.pack_into(rec, 0, size, 1, action, cid, status, len(ops), len(body), 0)
        v = self.v
        head = _U64.unpack_from(v, ah + R_HEAD)[0]
        tail = _U64.unpack_from(v, ah + R_TAIL)[0]
        pos = head & (self.rbytes - 1)
        pad = self.rbytes - pos if self.rbytes - pos < size else 0
        if pad + size > self.rbytes - (head - tail):
            return False			# no room: okena gives up on it at its time
        if pad:
            struct.pack_into("<IHH", v, ad + pos, pad, 0, 0)
            head += pad
            pos = 0
        v[ad + pos:ad + pos + size] = rec
        _U64.pack_into(v, ah + R_HEAD, head + size)
        return True


def run(handler):
    """Serve calls with handler(Request) -> Continue | Respond | None, forever."""
    Addon().run(handler)
