#!/usr/bin/env python3
"""Encrypted Client Hello on one engine (argument), with a TLS 1.3 client of its
own (HPKE: X25519, HKDF-SHA256, AES-128-GCM): `okena ech new` makes the keys,
`okena ech print` the ECHConfigList; a ClientHelloOuter naming the public name
carries the inner one, sealed, its key share and groups taken from the outer
(ech_outer_extensions). Opened: the ServerHello's random ends with the accept
confirmation, the certificate is the inner name's, no retry_configs. Not
opened (an unknown config_id, a key not okena's): the public name's certificate
and retry_configs, the list okena prints. The second key (rotation) opens too;
an inner hello without its own ECH extension is refused; no ECH at all is as
before."""
import base64
import hashlib
import hmac
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("skip ech: no cryptography package")
    sys.exit(0)

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
PORT = 18990 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""), flush=True)
    fails += not ok


def extract(salt, ikm):
    return hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest() if salt else hmac.new(b"", ikm, hashlib.sha256).digest()


def expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def expand_label(secret, label, ctx, n):
    full = b"tls13 " + label
    return expand(secret, struct.pack(">H", n) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx, n)


SUITE_KEM = b"KEM\x00\x20"
SUITE = b"HPKE\x00\x20\x00\x01\x00\x01"


def l_extract(suite, salt, label, ikm):
    return hmac.new(salt, b"HPKE-v1" + suite + label + ikm, hashlib.sha256).digest()


def l_expand(suite, prk, label, info, n):
    return expand(prk, struct.pack(">H", n) + b"HPKE-v1" + suite + label + info, n)


def ext(kind, body):
    return struct.pack(">HH", kind, len(body)) + body


def sni(name):
    return ext(0, struct.pack(">HBH", 3 + len(name), 0, len(name)) + name)


def parse_configs(blob):
    """ECHConfigList: [(config bytes, id, pk, public name)]"""
    out, i = [], 2
    while i < len(blob):
        n = struct.unpack(">H", blob[i + 2:i + 4])[0]
        c = blob[i:i + 4 + n]
        cid, pk = c[4], c[9:41]
        name = c[49:49 + c[48]]
        out.append((c, cid, pk, name))
        i += 4 + n
    return out


def recv_exact(s, n):
    d = b""
    while len(d) < n:
        x = s.recv(n - len(d))
        if not x:
            raise EOFError(len(d))
        d += x
    return d


def record(s):
    h = recv_exact(s, 5)
    return h[0], h, recv_exact(s, struct.unpack(">H", h[3:5])[0])


def hello_body(random, sid, exts):
    return b"\x03\x03" + random + bytes([len(sid)]) + sid + struct.pack(">HH", 2, 0x1301) + b"\x01\x00" + struct.pack(">H", len(exts)) + exts


def msg(body):
    return b"\x01" + struct.pack(">I", len(body))[1:] + body


def handshake(config, inner_name=b"secret.test", outer_name=b"public.test", tamper=None, ech=True, inner_has_ech=True):
    """-> (accepted by the confirmation, the certificate's CN, EE's retry_configs or None)"""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    groups = ext(10, struct.pack(">HH", 2, 0x001d))
    keyshare = ext(51, struct.pack(">HHH", 36, 0x001d, 32) + pub)
    common = ext(13, struct.pack(">HHH", 4, 0x0403, 0x0804)) + ext(43, b"\x02\x03\x04")
    sid = os.urandom(32)
    r_in, r_out = os.urandom(32), os.urandom(32)
    if not ech:
        ch = msg(hello_body(r_out, sid, sni(outer_name) + groups + common + keyshare))
        th_ch = ch
    else:
        cbytes, cid, pk, pname = config
        # the inner hello: its own name, groups and key share taken from the outer
        inner_ext = (sni(inner_name) + ext(0xFD00, b"\x04\x00\x0a\x00\x33") + common
                     + (ext(0xFE0D, b"\x01") if inner_has_ech else b""))
        encoded = hello_body(r_in, b"", inner_ext) + b"\0" * 7          # (padding)
        full_inner_ext = sni(inner_name) + groups + keyshare + common + (ext(0xFE0D, b"\x01") if inner_has_ech else b"")
        th_ch = msg(hello_body(r_in, sid, full_inner_ext))
        plen = len(encoded) + 16
        cid_sent = tamper if tamper is not None else cid
        def outer(payload):
            e = struct.pack(">BHHB", 0, 1, 1, cid_sent) + struct.pack(">H", 32) + b"E" * 32 + struct.pack(">H", plen) + payload
            return sni(outer_name) + groups + keyshare + common + ext(0xFE0D, e)
        info = b"tls ech\0" + cbytes
        # the AAD holds the enc that is sent: the ephemeral key first
        sk_e = X25519PrivateKey.generate()
        enc_fixed = sk_e.public_key().public_bytes_raw()
        aad_body = hello_body(r_out, sid, outer(b"\0" * plen).replace(b"E" * 32, enc_fixed))
        dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk))
        eae = l_extract(SUITE_KEM, b"", b"eae_prk", dh)
        shared = l_expand(SUITE_KEM, eae, b"shared_secret", enc_fixed + pk, 32)
        ctx = b"\0" + l_extract(SUITE, b"", b"psk_id_hash", b"") + l_extract(SUITE, b"", b"info_hash", info)
        secret = l_extract(SUITE, shared, b"secret", b"")
        ct = AESGCM(l_expand(SUITE, secret, b"key", ctx, 16)).encrypt(l_expand(SUITE, secret, b"base_nonce", ctx, 12), encoded, aad_body)
        ch = msg(hello_body(r_out, sid, outer(ct).replace(b"E" * 32, enc_fixed)))
    s = socket.create_connection(("127.0.0.1", PORT), 5)
    s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch)
    kind, _, sh = record(s)
    if kind != 22:
        s.close()
        return "alert", sh, None
    # the confirmation: in the random's last 8 bytes, over the inner hello
    zeroed = sh[:6 + 24] + b"\0" * 8 + sh[6 + 32:]
    conf = expand_label(extract(None, r_in), b"ech accept confirmation", hashlib.sha256(th_ch + zeroed).digest(), 8)
    accepted = ech and sh[6 + 24:6 + 32] == conf
    th_first = th_ch if accepted else ch
    i = 4 + 2 + 32
    i += 1 + sh[i]
    i += 2 + 1
    end = i + 2 + struct.unpack(">H", sh[i:i + 2])[0]
    i += 2
    spub = None
    while i < end:
        k, n = struct.unpack(">HH", sh[i:i + 4])
        if k == 51:
            spub = sh[i + 8:i + 8 + 32]
        i += 4 + n
    shared = priv.exchange(X25519PublicKey.from_public_bytes(spub))
    th = hashlib.sha256(th_first + sh).digest()
    early = hmac.new(b"\0" * 32, b"\0" * 32, hashlib.sha256).digest()
    derived = expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    hs = hmac.new(derived, shared, hashlib.sha256).digest()
    shs = expand_label(hs, b"s hs traffic", th, 32)
    aead, iv, seq = AESGCM(expand_label(shs, b"key", b"", 16)), expand_label(shs, b"iv", b"", 12), 0
    data, msgs = b"", []
    try:
        while True:
            kind, head, body = record(s)
            if kind == 20:
                continue
            nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
            seq += 1
            plain = aead.decrypt(nonce, body, head).rstrip(b"\0")
            data += plain[:-1]
            while len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big"):
                n = int.from_bytes(data[1:4], "big")
                msgs.append((data[0], data[4:4 + n]))
                data = data[4 + n:]
            if any(t == 20 for t, _ in msgs):
                break
    except Exception as e:
        s.close()
        return accepted, f"undecryptable: {e!r}", None
    s.close()
    cn, retry = None, None
    for t, b in msgs:
        if t == 8:
            j = 2
            while j < len(b):
                k, n = struct.unpack(">HH", b[j:j + 4])
                if k == 0xFE0D:
                    retry = b[j + 4:j + 4 + n]
                j += 4 + n
        if t == 11:
            n0 = int.from_bytes(b[4:7], "big")
            der = b[7:7 + n0]
            c = x509.load_der_x509_certificate(der)
            cn = c.subject.rfc4514_string()
    return accepted, cn, retry


def hpke_ctx(pk, info):
    sk_e = X25519PrivateKey.generate()
    enc = sk_e.public_key().public_bytes_raw()
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk))
    shared = l_expand(SUITE_KEM, l_extract(SUITE_KEM, b"", b"eae_prk", dh), b"shared_secret", enc + pk, 32)
    ctx = b"\0" + l_extract(SUITE, b"", b"psk_id_hash", b"") + l_extract(SUITE, b"", b"info_hash", info)
    secret = l_extract(SUITE, shared, b"secret", b"")
    return enc, l_expand(SUITE, secret, b"key", ctx, 16), l_expand(SUITE, secret, b"base_nonce", ctx, 12)


def handshake_hrr(config):
    """ECH, then a HelloRetryRequest (no key share at first): -> (HRR confirmation right,
    final confirmation right, the certificate's CN)"""
    cbytes, cid, pk, pname = config
    info = b"tls ech\0" + cbytes
    enc, key, base = hpke_ctx(pk, info)
    groups = ext(10, struct.pack(">HH", 2, 0x001d))
    common = ext(13, struct.pack(">HHH", 4, 0x0403, 0x0804)) + ext(43, b"\x02\x03\x04")
    sid = os.urandom(32)

    def hello(r_in, r_out, keyshare, seq, enc_sent):
        inner_ext = sni(b"secret.test") + ext(0xFD00, b"\x04\x00\x0a\x00\x33") + common + ext(0xFE0D, b"\x01")
        encoded = hello_body(r_in, b"", inner_ext) + b"\0" * 5
        full_inner = msg(hello_body(r_in, sid, sni(b"secret.test") + groups + keyshare + common + ext(0xFE0D, b"\x01")))
        plen = len(encoded) + 16

        def outer(payload):
            e = struct.pack(">BHHB", 0, 1, 1, cid) + struct.pack(">H", len(enc_sent)) + enc_sent + struct.pack(">H", plen) + payload
            return sni(pname) + groups + keyshare + common + ext(0xFE0D, e)
        aad = hello_body(r_out, sid, outer(b"\0" * plen))
        nonce = base[:11] + bytes([base[11] ^ seq])
        ct = AESGCM(key).encrypt(nonce, encoded, aad)
        return msg(hello_body(r_out, sid, outer(ct))), full_inner

    r_in1 = os.urandom(32)
    ch1, inner1 = hello(r_in1, os.urandom(32), ext(51, b"\x00\x00"), 0, enc)
    s = socket.create_connection(("127.0.0.1", PORT), 5)
    s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(ch1)) + ch1)
    kind, _, hrr = record(s)
    if kind != 22:
        s.close()
        return "alert", hrr, None
    # its confirmation: over message_hash(ClientHelloInner1) and it, zeroed
    i = hrr.find(b"\xfe\x0d\x00\x08")
    conf_sent = hrr[i + 4:i + 12] if i > 0 else b""
    mh = b"\xfe\x00\x00\x20" + hashlib.sha256(inner1).digest()
    zeroed = hrr[:i + 4] + b"\0" * 8 + hrr[i + 12:]
    conf = expand_label(extract(None, r_in1), b"hrr ech accept confirmation", hashlib.sha256(mh + zeroed).digest(), 8)
    hrr_ok = i > 0 and conf == conf_sent
    # the second hello: a share now, the same context (sequence 1), no enc
    priv = X25519PrivateKey.generate()
    keyshare = ext(51, struct.pack(">HHH", 36, 0x001d, 32) + priv.public_key().public_bytes_raw())
    r_in2 = os.urandom(32)
    ch2, inner2 = hello(r_in2, os.urandom(32), keyshare, 1, b"")
    s.sendall(b"\x14\x03\x03\x00\x01\x01" + b"\x16\x03\x03" + struct.pack(">H", len(ch2)) + ch2)
    while True:
        kind, _, sh = record(s)
        if kind != 20:
            break
    if kind != 22:
        s.close()
        return hrr_ok, ("alert", sh), None
    zsh = sh[:6 + 24] + b"\0" * 8 + sh[6 + 32:]
    conf2 = expand_label(extract(None, r_in2), b"ech accept confirmation", hashlib.sha256(mh + hrr + inner2 + zsh).digest(), 8)
    final_ok = sh[6 + 24:6 + 32] == conf2
    # the flight, under the keys of that transcript: its certificate
    j = sh.find(b"\x00\x33\x00\x24\x00\x1d\x00\x20")
    spub = sh[j + 8:j + 40]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(spub))
    th = hashlib.sha256(mh + hrr + inner2 + sh).digest()
    early = hmac.new(b"\0" * 32, b"\0" * 32, hashlib.sha256).digest()
    hs = hmac.new(expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32), shared, hashlib.sha256).digest()
    shs = expand_label(hs, b"s hs traffic", th, 32)
    aead, iv, seq, data, cn = AESGCM(expand_label(shs, b"key", b"", 16)), expand_label(shs, b"iv", b"", 12), 0, b"", None
    try:
        while cn is None:
            kind, head, body = record(s)
            if kind == 20:
                continue
            nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
            seq += 1
            data += aead.decrypt(nonce, body, head).rstrip(b"\0")[:-1]
            while len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big"):
                n = int.from_bytes(data[1:4], "big")
                if data[0] == 11:
                    cn = x509.load_der_x509_certificate(data[4 + 7:4 + 7 + int.from_bytes(data[8:11], "big")]).subject.rfc4514_string()
                data = data[4 + n:]
    except Exception as e:
        cn = f"undecryptable: {e!r}"
    s.close()
    return hrr_ok, final_ok, cn


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ech-"))
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=tmp)
    for name in ("public", "secret"):
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{name}.key",
            "-out", f"{name}.crt", "-subj", f"/CN={name}.test", "-days", "2", "-addext", f"subjectAltName=DNS:{name}.test")
    q = subprocess.run([str(BIN), "ech", "new", str(tmp / "ech1.key")], capture_output=True, text=True, timeout=10)
    check("okena ech new: a key", q.returncode == 0 and (tmp / "ech1.key").exists()
          and oct((tmp / "ech1.key").stat().st_mode & 0o777) == "0o600", q.stderr)
    q2 = subprocess.run([str(BIN), "ech", "new", str(tmp / "ech1.key")], capture_output=True, text=True, timeout=10)
    check("  never over a file", q2.returncode != 0)
    run("genpkey", "-algorithm", "X25519", "-out", "ech2.key")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{
    workers 1; io_engine {ENGINE}
    ech public.test {tmp}/ech1.key {tmp}/ech2.key
}}
http 127.0.0.1:{PORT} {{
    tls {{
        cert {tmp}/public.crt key={tmp}/public.key
        cert {tmp}/secret.crt key={tmp}/secret.key
    }}
    route /* {{ respond 404 }}
}}
""")
    q = subprocess.run([str(BIN), "ech", "print", "-c", str(conf)], capture_output=True, text=True, timeout=10)
    blob = base64.b64decode(q.stdout.strip()) if q.returncode == 0 else b""
    cfgs = parse_configs(blob) if blob else []
    check("okena ech print: the ECHConfigList, both keys, the public name", len(cfgs) == 2
          and all(c[3] == b"public.test" for c in cfgs) and cfgs[0][1] != cfgs[1][1], (q.stdout, q.stderr))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        acc, cn, retry = handshake(cfgs[0])
        check("ECH opened: the confirmation in the random, the inner name's certificate, no retry_configs",
              acc is True and cn == "CN=secret.test" and retry is None, (acc, cn, retry))
        acc, cn, retry = handshake(cfgs[1])
        check("  sealed to the second key (rotation): opened too", acc is True and cn == "CN=secret.test", (acc, cn))
        acc, cn, retry = handshake(cfgs[0], tamper=(cfgs[0][1] + 77) % 256)
        check("not opened (an unknown config_id): the public name's certificate, retry_configs as printed",
              acc is False and cn == "CN=public.test" and retry == blob, (acc, cn, retry and retry[:16]))
        other = (cfgs[0][0], cfgs[0][1], X25519PrivateKey.generate().public_key().public_bytes_raw(), b"public.test")
        acc, cn, retry = handshake(other)
        check("  sealed to a key not okena's: the same", acc is False and cn == "CN=public.test" and retry == blob, (acc, cn))
        acc, cn, retry = handshake(cfgs[0], inner_has_ech=False)
        check("an inner hello that does not say it is one: refused (illegal_parameter)", acc == "alert" and cn[1] == 47, (acc, cn))
        hrr_ok, final_ok, cn = handshake_hrr(cfgs[0])
        check("ECH and a HelloRetryRequest: its confirmation, the second hello opened with the same context, the final one",
              hrr_ok is True and final_ok is True and cn == "CN=secret.test", (hrr_ok, final_ok, cn))
        acc, cn, retry = handshake(None, ech=False, outer_name=b"secret.test")
        check("no ECH: as before", acc is False and cn == "CN=secret.test" and retry is None, (acc, cn, retry))
        q = subprocess.run(["curl", "-q", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--resolve", f"public.test:{PORT}:127.0.0.1",
                            f"https://public.test:{PORT}/"], capture_output=True, text=True, timeout=10)
        check("  and an ordinary client", q.stdout == "404", q.stdout)
        q = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", "secret.test", "-tls1_3",
                            "-groups", "secp384r1:X25519", "-msg"], input=b"", capture_output=True, timeout=10)
        out = q.stdout.decode(errors="replace")
        check("a HelloRetryRequest without ECH (OpenSSL's first share for a group okena has not): it completes",
              out.count("ServerHello") >= 2 and "Cipher is TLS_AES_128_GCM_SHA256" in out, out[-500:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t and "exited" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"ech {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
