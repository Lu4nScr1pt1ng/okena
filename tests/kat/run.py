#!/usr/bin/env python3
"""Crypto known-answer and differential tests (build/kat).

Published vectors first (FIPS 180-4, RFC 4231, RFC 5869, RFC 8448's
TLS 1.3 key schedule, RFC 7748), then random inputs against reference
implementations (hashlib for SHA-3 and SHAKE, a FIPS 203 reference and
OpenSSL for ML-KEM-768): hashlib/hmac for SHA-256 (both block paths, every
length around the block boundaries), HMAC and HKDF, and `cryptography`
for X25519."""
import hashlib
import hmac
import os
import pathlib
import random
import subprocess
import sys

KAT = pathlib.Path(__file__).resolve().parents[2] / "build" / "kat"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mlkem_ref  # noqa: E402
failures = 0
checks = 0


def run(mode, data):
    out = subprocess.run([str(KAT)], input=mode + data, capture_output=True)
    return out.stdout.decode().strip() if out.returncode == 0 else f"exit {out.returncode}"


def check(name, got, want):
    global failures, checks
    checks += 1
    if got != want:
        failures += 1
        print(f"FAIL {name}: got {got} want {want}")


def le16(n):
    return n.to_bytes(2, "little")


def hkdf_ref(salt, ikm, info, n):
    prk = hmac.new(salt, ikm, "sha256").digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        out += t
        i += 1
    return out[:n]


def label_ref(secret, label, ctx, n):
    full = b"tls13 " + label
    info = n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_ref_expand(secret, info, n)


def hkdf_ref_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        out += t
        i += 1
    return out[:n]


def hkdf(salt, ikm, info, n):
    return run(b"k", le16(len(salt)) + salt + le16(len(ikm)) + ikm + le16(len(info)) + info + le16(n))


def label(secret, lab, ctx, n):
    return run(b"l", secret + bytes([len(lab)]) + lab + bytes([len(ctx)]) + ctx + le16(n))


# --- published vectors
for mode in (b"s", b"S"):
    check("FIPS 180-4 abc", run(mode, b"abc"),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    check("FIPS 180-4 448 bits", run(mode, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
check("RFC 4231 case 2", run(b"h", le16(4) + b"Jefe" + b"what do ya want for nothing?"),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
check("RFC 5869 case 1", hkdf(bytes(range(13)), b"\x0b" * 22, bytes(range(0xf0, 0xfa)), 42),
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
# RFC 8448 (simple 1-RTT): the handshake secret's server traffic secret
hs = bytes.fromhex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
th = bytes.fromhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
check("RFC 8448 s hs traffic", label(hs, b"s hs traffic", th, 32),
      "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
check("RFC 8448 server handshake key",
      label(bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), b"key", b"", 16),
      "3fce516009c21727d0f2e4e86ee403bc")
check("RFC 7748 vector 1",
      run(b"x", bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
          + bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
# RFC 7748 iterated: k = u = 9, 1 and 1000 iterations
k = u = (9).to_bytes(32, "little")
for i in range(1, 1001):
    r = bytes.fromhex(run(b"x", k + u))
    u, k = k, r
    if i == 1:
        check("RFC 7748 iterated x1", r.hex(), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
check("RFC 7748 iterated x1000", k.hex(), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

# --- differential
rng = random.Random(1)
sizes = list(range(0, 300)) + [rng.randrange(300, 400_000) for _ in range(20)]
for n in sizes:
    data = rng.randbytes(n)
    want = hashlib.sha256(data).hexdigest()
    check(f"sha256 SHA-NI length {n}", run(b"s", data), want)
    check(f"sha256 scalar length {n}", run(b"S", data), want)
for _ in range(200):
    key = rng.randbytes(rng.choice([0, 1, 31, 32, 63, 64, 65, 127, 128, rng.randrange(300)]))
    msg = rng.randbytes(rng.randrange(300))
    check(f"hmac key {len(key)} msg {len(msg)}", run(b"h", le16(len(key)) + key + msg),
          hmac.new(key, msg, "sha256").hexdigest())
for _ in range(150):
    salt, ikm, info = (rng.randbytes(rng.randrange(80)) for _ in range(3))
    n = rng.choice([1, 16, 31, 32, 33, 64, 100, rng.randrange(1, 8160)])
    check(f"hkdf out {n}", hkdf(salt, ikm, info, n), hkdf_ref(salt, ikm, info, n).hex())
for _ in range(100):
    secret = rng.randbytes(32)
    lab = rng.choice([b"key", b"iv", b"finished", b"derived", b"c hs traffic", b"s ap traffic"])
    ctx = rng.randbytes(rng.choice([0, 32, rng.randrange(64)]))
    n = rng.choice([12, 16, 32, 48])
    check(f"expand-label {lab.decode()} ctx {len(ctx)} out {n}", label(secret, lab, ctx, n), label_ref(secret, lab, ctx, n).hex())
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    raw = serialization.Encoding.Raw
    for _ in range(300):
        a = X25519PrivateKey.generate()
        b = X25519PrivateKey.generate()
        a_raw = a.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        b_pub = b.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        check("x25519 random pair", run(b"x", a_raw + b_pub), a.exchange(b.public_key()).hex())
    # the fixed-base key generation: the library's public key, and the ladder's
    for i in range(400):
        k = rng.randbytes(32) if i > 3 else (bytes(32), b"\xff" * 32, bytes(range(32)), b"\x08" + bytes(31))[i]
        pub = X25519PrivateKey.from_private_bytes(k).public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        got = run(b"u", k)
        check("x25519_base = the public key", got, pub.hex())
        if i % 20 == 0:
            check("x25519_base = x25519(k, 9)", got, run(b"x", k + (9).to_bytes(32, "little")))
    # P-256 ECDH (secp256r1): the shared X against the library, and invalid
    # peer points rejected
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PF
    for _ in range(200):
        a = _ec.generate_private_key(_ec.SECP256R1())
        b = _ec.generate_private_key(_ec.SECP256R1())
        k = a.private_numbers().private_value.to_bytes(32, "big")
        peer = b.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
        check("p256 ecdh shared x", run(b"D", k + peer), a.exchange(_ec.ECDH(), b.public_key()).hex())
    good = _ec.generate_private_key(_ec.SECP256R1()).public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    bad_pt = bytearray(good)
    bad_pt[40] ^= 1                                     # a Y bit flipped: off the curve
    k = rng.randbytes(32)
    check("p256 ecdh: off-curve peer rejected", run(b"D", k + bytes(bad_pt)), "FAIL")
    check("p256 ecdh: compressed peer rejected", run(b"D", k + b"\x02" + rng.randbytes(32) + bytes(32)), "FAIL")

    # ECDSA P-256 verification: library signatures accepted, tampered and
    # wrong-key rejected, an off-curve public key rejected
    import hashlib as _hl
    from cryptography.hazmat.primitives import hashes as _hashes
    for _ in range(100):
        sk = _ec.generate_private_key(_ec.SECP256R1())
        pub = sk.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
        msg = rng.randbytes(40)
        dg = _hl.sha256(msg).digest()
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        rr, ss = decode_dss_signature(sk.sign(msg, _ec.ECDSA(_hashes.SHA256())))
        sig = rr.to_bytes(32, "big") + ss.to_bytes(32, "big")
        check("p256 verify: valid signature", run(b"V", pub + dg + sig), "01")
        bd = bytearray(dg)
        bd[9] ^= 1
        check("p256 verify: tampered digest rejected", run(b"V", pub + bytes(bd) + sig), "00")
        other = _ec.generate_private_key(_ec.SECP256R1()).public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
        check("p256 verify: wrong key rejected", run(b"V", other + dg + sig), "00")
    sk = _ec.generate_private_key(_ec.SECP256R1())
    dg = _hl.sha256(b"m").digest()
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    rr, ss = decode_dss_signature(sk.sign(b"m", _ec.ECDSA(_hashes.SHA256())))
    offp = bytearray(sk.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint))
    offp[40] ^= 1
    check("p256 verify: off-curve public key rejected",
          run(b"V", bytes(offp) + dg + rr.to_bytes(32, "big") + ss.to_bytes(32, "big")), "00")

    # X.509: a certificate's ECDSA P-256/SHA-256 signature, verified under
    # its issuer's key (the basis of upstream TLS and mTLS chains)
    import struct as _struct
    from cryptography import x509 as _x509
    _ca = _ec.generate_private_key(_ec.SECP256R1())
    _leaf = _ec.generate_private_key(_ec.SECP256R1())
    import datetime as _dt
    def _cert(subject, signer_key, issuer):
        b = (_x509.CertificateBuilder()
             .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, subject)]))
             .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, issuer)]))
             .public_key(signer_key.public_key() if subject == issuer else _leaf.public_key())
             .serial_number(_x509.random_serial_number())
             .not_valid_before(_dt.datetime(2020, 1, 1))
             .not_valid_after(_dt.datetime(2030, 1, 1)))
        return b.sign(signer_key, _hashes.SHA256())
    ca_cert = _cert("ca", _ca, "ca")
    leaf_cert = (_x509.CertificateBuilder()
                 .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "leaf")]))
                 .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "ca")]))
                 .public_key(_leaf.public_key())
                 .serial_number(_x509.random_serial_number())
                 .not_valid_before(_dt.datetime(2020, 1, 1))
                 .not_valid_after(_dt.datetime(2030, 1, 1))
                 .sign(_ca, _hashes.SHA256()))
    capub = _ca.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    leafpub = _leaf.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    leaf_der = leaf_cert.public_bytes(_Enc.DER)
    ca_der = ca_cert.public_bytes(_Enc.DER)
    def _cv(issuer_cert, der):
        return run(b"C", _struct.pack("<H", len(issuer_cert)) + issuer_cert + _struct.pack("<H", len(der)) + der)
    check("x509: leaf verified under the issuer certificate", _cv(ca_der, leaf_der), "01")
    check("x509: wrong issuer rejected", _cv(leaf_der, leaf_der), "00")
    check("x509: self-signed CA verifies under itself", _cv(ca_der, ca_der), "01")
    _bad = bytearray(leaf_der)
    _bad[len(_bad) // 2] ^= 1
    check("x509: tampered certificate rejected", _cv(ca_der, bytes(_bad)), "00")
    # an RSA-signed certificate (an RSA CA, as real chains have)
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    _rsa_ca = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _rsa_ca_cert = (_x509.CertificateBuilder()
                    .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "rsa-ca")]))
                    .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "rsa-ca")]))
                    .public_key(_rsa_ca.public_key()).serial_number(_x509.random_serial_number())
                    .not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2030, 1, 1))
                    .add_extension(_x509.BasicConstraints(ca=True, path_length=None), True)
                    .sign(_rsa_ca, _hashes.SHA256()))
    _rsa_leaf = (_x509.CertificateBuilder()
                 .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "leaf")]))
                 .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "rsa-ca")]))
                 .public_key(_leaf.public_key()).serial_number(_x509.random_serial_number())
                 .not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2030, 1, 1))
                 .sign(_rsa_ca, _hashes.SHA256()))
    _rsa_ca_der = _rsa_ca_cert.public_bytes(_Enc.DER)
    _rsa_leaf_der = _rsa_leaf.public_bytes(_Enc.DER)
    check("x509: EC leaf under an RSA CA (sha256WithRSA)", _cv(_rsa_ca_der, _rsa_leaf_der), "01")
    check("x509: self-signed RSA CA verifies under itself", _cv(_rsa_ca_der, _rsa_ca_der), "01")
    check("x509: RSA CA, wrong issuer rejected", _cv(ca_der, _rsa_leaf_der), "00")
    _rbad = bytearray(_rsa_leaf_der); _rbad[len(_rbad) // 2] ^= 1
    check("x509: tampered RSA-signed certificate rejected", _cv(_rsa_ca_der, bytes(_rbad)), "00")

    # X.509 validity window: notBefore <= now <= notAfter (ASCII compare of
    # the normalised UTCTime/GeneralizedTime, the check a TLS client makes)
    def _tv(now, der):
        return run(b"T", now.encode() + _struct.pack("<H", len(der)) + der)
    check("x509 time: within the window", _tv("20250101000000", leaf_der), "01")
    check("x509 time: before notBefore rejected", _tv("20190101000000", leaf_der), "00")
    check("x509 time: after notAfter rejected", _tv("20310101000000", leaf_der), "00")
    check("x509 time: on the notBefore boundary", _tv("20200101000000", leaf_der), "01")
    # a cert whose dates land past 2050 exercise GeneralizedTime encoding
    _future = (_x509.CertificateBuilder()
               .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "leaf")]))
               .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "ca")]))
               .public_key(_leaf.public_key()).serial_number(_x509.random_serial_number())
               .not_valid_before(_dt.datetime(2049, 1, 1))
               .not_valid_after(_dt.datetime(2060, 1, 1))
               .sign(_ca, _hashes.SHA256())).public_bytes(_Enc.DER)
    check("x509 time: GeneralizedTime window", _tv("20550101000000", _future), "01")
    check("x509 time: before a GeneralizedTime window", _tv("20250101000000", _future), "00")

    # X.509 hostname matching: subjectAltName dNSName (with a leftmost
    # wildcard) is authoritative, else the subject commonName
    def _host(host, der):
        h = host.encode()
        return run(b"N", bytes([len(h)]) + h + _struct.pack("<H", len(der)) + der)
    def _san_cert(cn, names):
        b = (_x509.CertificateBuilder()
             .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, cn)]))
             .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, "ca")]))
             .public_key(_leaf.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2030, 1, 1)))
        if names is not None:
            b = b.add_extension(_x509.SubjectAlternativeName([_x509.DNSName(n) for n in names]), False)
        return b.sign(_ca, _hashes.SHA256()).public_bytes(_Enc.DER)
    _san = _san_cert("ignored", ["a.example.com", "*.wild.example.com"])
    check("x509 host: exact SAN match", _host("a.example.com", _san), "01")
    check("x509 host: SAN match is case-insensitive", _host("A.Example.COM", _san), "01")
    check("x509 host: wildcard matches one label", _host("x.wild.example.com", _san), "01")
    check("x509 host: wildcard does not match two labels", _host("x.y.wild.example.com", _san), "00")
    check("x509 host: wildcard does not match the bare domain", _host("wild.example.com", _san), "00")
    check("x509 host: unlisted name rejected", _host("evil.example.com", _san), "00")
    check("x509 host: CN ignored when a SAN is present", _host("ignored", _san), "00")
    _cnonly = _san_cert("host.example.com", None)
    check("x509 host: CN used when no SAN", _host("host.example.com", _cnonly), "01")
    check("x509 host: CN mismatch rejected", _host("other.example.com", _cnonly), "00")

    # X.509 chain: the server sends leaf first (and any intermediates); the
    # client verifies each link up to a trusted anchor key
    from cryptography.x509.oid import ExtendedKeyUsageOID as _ekuoid  # noqa: F401 (import style parity)
    def _issue(subject_key, subject_cn, issuer_key, issuer_cn, ca):
        b = (_x509.CertificateBuilder()
             .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, subject_cn)]))
             .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, issuer_cn)]))
             .public_key(subject_key.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2030, 1, 1))
             .add_extension(_x509.BasicConstraints(ca=ca, path_length=None), True))
        return b.sign(issuer_key, _hashes.SHA256())
    _root = _ec.generate_private_key(_ec.SECP256R1())
    _inter = _ec.generate_private_key(_ec.SECP256R1())
    _ee = _ec.generate_private_key(_ec.SECP256R1())
    root_c = _issue(_root, "root", _root, "root", True)
    inter_c = _issue(_inter, "inter", _root, "root", True)
    ee_c = _issue(_ee, "ee", _inter, "inter", False)
    rootpub = _root.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    interpub = _inter.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    def _entry(cert):
        der = cert.public_bytes(_Enc.DER)
        return len(der).to_bytes(3, "big") + der + b"\x00\x00"       # cert, empty extensions
    root_der = root_c.public_bytes(_Enc.DER)
    inter_der = inter_c.public_bytes(_Enc.DER)
    def _chain(anchor_cert, certs):
        lst = b"".join(_entry(c) for c in certs)
        return run(b"K", _struct.pack("<H", len(anchor_cert)) + anchor_cert + _struct.pack("<H", len(lst)) + lst)
    check("x509 chain: leaf + intermediate to the root", _chain(root_der, [ee_c, inter_c]), "01")
    check("x509 chain: single leaf directly under the anchor", _chain(inter_der, [ee_c]), "01")
    check("x509 chain: wrong anchor rejected", _chain(root_der, [ee_c]), "00")
    check("x509 chain: broken link rejected", _chain(root_der, [ee_c, root_c]), "00")
    _tamp = bytearray(ee_c.public_bytes(_Enc.DER)); _tamp[len(_tamp)//2] ^= 1
    _tchain = len(_tamp).to_bytes(3, "big") + bytes(_tamp) + b"\x00\x00" + _entry(inter_c)
    check("x509 chain: tampered leaf rejected",
          run(b"K", _struct.pack("<H", len(root_der)) + root_der + _struct.pack("<H", len(_tchain)) + _tchain), "00")
    # a mixed chain: an EC leaf under an RSA intermediate under an RSA root
    _rr = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _ri = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def _rc(subj_key, subj, iss_key, iss, ca):
        b = (_x509.CertificateBuilder()
             .subject_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, subj)]))
             .issuer_name(_x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, iss)]))
             .public_key(subj_key.public_key()).serial_number(_x509.random_serial_number())
             .not_valid_before(_dt.datetime(2020, 1, 1)).not_valid_after(_dt.datetime(2030, 1, 1))
             .add_extension(_x509.BasicConstraints(ca=ca, path_length=None), True))
        return b.sign(iss_key, _hashes.SHA256())
    _rroot = _rc(_rr, "rr", _rr, "rr", True)
    _rint = _rc(_ri, "ri", _rr, "rr", True)
    _ree = _rc(_ee, "ee", _ri, "ri", False)
    check("x509 chain: EC leaf, RSA intermediate, RSA root", _chain(_rroot.public_bytes(_Enc.DER), [_ree, _rint]), "01")
    check("x509 chain: RSA chain, wrong anchor rejected", _chain(root_der, [_ree, _rint]), "00")

    # Trust anchors from a PEM file: decode the first CERTIFICATE block,
    # take its key, and verify a chain under it (how a TLS client loads a
    # trust file for its upstreams)
    from cryptography.hazmat.primitives import serialization as _ser
    root_pem = root_c.public_bytes(_ser.Encoding.PEM)
    inter_pem = inter_c.public_bytes(_ser.Encoding.PEM)
    def _pem(pem, certs):
        lst = b"".join(_entry(c) for c in certs)
        return run(b"p", _struct.pack("<H", len(pem)) + pem + _struct.pack("<H", len(lst)) + lst)
    check("x509 pem: chain verified under a PEM trust anchor", _pem(root_pem, [ee_c, inter_c]), "01")
    check("x509 pem: single leaf under a PEM intermediate", _pem(inter_pem, [ee_c]), "01")
    check("x509 pem: wrong PEM anchor rejected", _pem(inter_pem, [ee_c, inter_c]), "00")
    # a PEM with surrounding comment text and CRLF line endings still parses
    _wrapped = b"# okena trust store\r\n" + root_pem.replace(b"\n", b"\r\n") + b"\r\ntrailing\r\n"
    check("x509 pem: tolerates comments and CRLF", _pem(_wrapped, [ee_c, inter_c]), "01")

    # TLS 1.2 PRF (RFC 5246 5): P_SHA256(secret, seed), the basis of the
    # 1.2 key material and Finished verify_data
    import hmac as _hmac
    def p_sha256_ref(secret, seed, n):
        out = b""
        a = seed
        while len(out) < n:
            a = _hmac.new(secret, a, "sha256").digest()
            out += _hmac.new(secret, a + seed, "sha256").digest()
        return out[:n]
    def _prf(secret, seed, n):
        return run(b"R", _struct.pack("<H", n) + _struct.pack("<H", len(secret)) + secret
                   + _struct.pack("<H", len(seed)) + seed)
    import os as _os
    for secret, seed, n in [(b"\x9b" * 48, b"master secret" + b"\xaa" * 64, 48),
                            (b"key", b"key expansion" + b"\x01" * 64, 40),
                            (_os.urandom(32), b"client finished" + _os.urandom(32), 12),
                            (_os.urandom(48), b"test label" + _os.urandom(30), 100)]:
        check(f"tls1.2 prf secret {len(secret)} seed {len(seed)} out {n}",
              _prf(secret, seed, n), p_sha256_ref(secret, seed, n).hex())

    # TLS 1.2 key schedule: master_secret, key_block and the Finished
    # verify_data, with the RFC 5246 seed orders
    pm, cr, sr, th = _os.urandom(32), _os.urandom(32), _os.urandom(32), _os.urandom(32)
    master = p_sha256_ref(pm, b"master secret" + cr + sr, 48)
    kb = p_sha256_ref(master, b"key expansion" + sr + cr, 40)
    cfin = p_sha256_ref(master, b"client finished" + th, 12)
    sfin = p_sha256_ref(master, b"server finished" + th, 12)
    got = run(b"r", pm + cr + sr + th)
    check("tls1.2 master_secret", got[:96], master.hex())
    check("tls1.2 key_block (order server|client random)", got[96:176], kb.hex())
    check("tls1.2 client Finished verify_data", got[176:200], cfin.hex())
    check("tls1.2 server Finished verify_data", got[200:224], sfin.hex())

    # TLS 1.2 AEAD record layer (RFC 5288): explicit nonce | ciphertext |
    # tag, GCM nonce salt|seq, aad seq|type|version|length
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    def tls12_rec_ref(key, salt, seq, ctype, pt):
        nonce = salt + seq.to_bytes(8, "big")
        aad = seq.to_bytes(8, "big") + bytes([ctype]) + b"\x03\x03" + len(pt).to_bytes(2, "big")
        ct = _AESGCM(key).encrypt(nonce, pt, aad)
        return seq.to_bytes(8, "big") + ct
    for ctype, pt in [(22, b"\x14\x00\x00\x0c" + b"\x11" * 12),  # a Finished
                      (23, b"GET / HTTP/1.1\r\n\r\n"), (23, b"")]:
        key, salt, seq = _os.urandom(16), _os.urandom(4), 7
        got = run(b"2", key + salt + seq.to_bytes(8, "little") + bytes([ctype])
                  + _struct.pack("<H", len(pt)) + pt)
        check(f"tls1.2 record type {ctype} len {len(pt)} (seal + open round-trip)",
              got, tls12_rec_ref(key, salt, seq, ctype, pt).hex())

    # RSA big-integer modular exponentiation (the core of RSA sign/verify)
    def modexp(n_limbs, base, exp, mod):
        base_le = base.to_bytes(n_limbs * 8, "little")
        mod_le = mod.to_bytes(n_limbs * 8, "little")
        exp_be = exp.to_bytes(max(1, (exp.bit_length() + 7) // 8), "big")
        inp = bytes([n_limbs]) + base_le + _struct.pack("<H", len(exp_be)) + exp_be + mod_le
        return run(b"X", inp)
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    for bits in (1024, 2048):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pn = k.private_numbers()
        mod = pn.public_numbers.n
        nl = bits // 64
        base = int.from_bytes(_os.urandom(bits // 8), 'big') % mod
        check(f"rsa modexp {bits} public (e=65537)",
              modexp(nl, base, 65537, mod), pow(base, 65537, mod).to_bytes(nl * 8, "little").hex())
        check(f"rsa modexp {bits} private (full d)",
              modexp(nl, base, pn.d, mod), pow(base, pn.d, mod).to_bytes(nl * 8, "little").hex())
    check("rsa modexp: base one", modexp(16, 1, 65537, (1 << 1024) - 159),
          pow(1, 65537, (1 << 1024) - 159).to_bytes(128, "little").hex())

    # RSA PKCS#1 v1.5 signature verification (for RSA certificate chains)
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    import hashlib as _hl
    def rsa_verify_in(n, e, sig, h):
        nb = (n.bit_length() + 7) // 8
        return _struct.pack("<H", nb) + n.to_bytes(nb, "big") + sig + _struct.pack("<I", e) + h
    for bits in (1024, 2048, 3072):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        n = k.public_key().public_numbers().n
        msg = b"okena rsa conformance " + bytes([bits & 0xff])
        h = _hl.sha256(msg).digest()
        sig = k.sign(msg, _pad.PKCS1v15(), _hashes.SHA256())
        check(f"rsa pkcs1 verify {bits}: valid", run(b"Y", rsa_verify_in(n, 65537, sig, h)), "01")
        bad = bytearray(h); bad[0] ^= 1
        check(f"rsa pkcs1 verify {bits}: tampered hash", run(b"Y", rsa_verify_in(n, 65537, sig, bytes(bad))), "00")
        bsig = bytearray(sig); bsig[len(bsig) // 2] ^= 1
        check(f"rsa pkcs1 verify {bits}: tampered signature", run(b"Y", rsa_verify_in(n, 65537, bytes(bsig), h)), "00")

    # RSA-PSS signature verification (rsa_pss_rsae_sha256, the TLS 1.3 scheme)
    for bits in (2048, 3072):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        n = k.public_key().public_numbers().n
        msg = b"okena pss " + bytes([bits & 0xff])
        h = _hl.sha256(msg).digest()
        sig = k.sign(msg, _pad.PSS(mgf=_pad.MGF1(_hashes.SHA256()), salt_length=32), _hashes.SHA256())
        check(f"rsa pss verify {bits}: valid", run(b"W", rsa_verify_in(n, 65537, sig, h)), "01")
        bad = bytearray(h); bad[5] ^= 1
        check(f"rsa pss verify {bits}: tampered hash", run(b"W", rsa_verify_in(n, 65537, sig, bytes(bad))), "00")
        bs = bytearray(sig); bs[len(bs) // 2] ^= 1
        check(f"rsa pss verify {bits}: tampered signature", run(b"W", rsa_verify_in(n, 65537, bytes(bs), h)), "00")

    # RSA-PSS signing: okena signs, a reference verifies with the public key
    from cryptography.hazmat.primitives.asymmetric import utils as _rsautil  # noqa: F401
    for bits in (2048, 3072):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pn = k.private_numbers()
        n = pn.public_numbers.n
        nb = bits // 8
        msg = b"okena pss sign " + bytes([bits & 0xff])
        h = _hl.sha256(msg).digest()
        sig = bytes.fromhex(run(b"z", _struct.pack("<H", nb) + n.to_bytes(nb, "big")
                                 + pn.d.to_bytes(nb, "big") + h))
        ok = True
        try:
            k.public_key().verify(sig, msg, _pad.PSS(mgf=_pad.MGF1(_hashes.SHA256()), salt_length=32),
                                  _hashes.SHA256())
        except Exception:
            ok = False
        check(f"rsa pss sign {bits}: verifies with a reference", ok, True)

    # RSASSA-PKCS1-v1_5 signing (rsa_pkcs1_sha256, a TLS 1.2 ServerKeyExchange)
    for bits in (2048, 3072):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pn = k.private_numbers()
        n = pn.public_numbers.n
        nb = bits // 8
        msg = b"okena pkcs1 sign " + bytes([bits & 0xff])
        h = _hl.sha256(msg).digest()
        sig = bytes.fromhex(run(b"U", _struct.pack("<H", nb) + n.to_bytes(nb, "big")
                                 + pn.d.to_bytes(nb, "big") + h))
        ok = True
        try:
            k.public_key().verify(sig, msg, _pad.PKCS1v15(), _hashes.SHA256())
        except Exception:
            ok = False
        check(f"rsa pkcs1 sign {bits}: verifies with a reference", ok, True)

    # RSA private key parsing (PKCS#1 RSAPrivateKey): modulus and private exponent
    from cryptography.hazmat.primitives import serialization as _ser2
    for bits in (2048, 3072):
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pn = k.private_numbers()
        der = k.private_bytes(_ser2.Encoding.DER, _ser2.PrivateFormat.TraditionalOpenSSL,
                              _ser2.NoEncryption())  # PKCS#1 RSAPrivateKey
        nb = bits // 8
        got = run(b"j", _struct.pack("<H", len(der)) + der)
        want = (pn.public_numbers.n.to_bytes(nb, "big") + pn.d.to_bytes(nb, "big")).hex()
        check(f"rsa key parse {bits}: n and d", got, want)

    # TLS client: a well-formed ClientHello (offering x25519 + secp256r1,
    # TLS_AES_128_GCM_SHA256, ecdsa_secp256r1_sha256, ALPN, SNI)
    def _parse_ch(sni):
        out = subprocess.run([str(KAT)], input=b"H" + sni, capture_output=True)
        rec = out.stdout.decode().strip()
        rec = bytes.fromhex(rec)
        d = {}
        d["rec"] = (rec[0], int.from_bytes(rec[1:3], "big"))   # type, version
        b = rec[5:][4:]                                        # handshake body
        d["ver"] = int.from_bytes(b[0:2], "big")
        off = 2 + 32
        d["sidlen"] = b[off]; off += 1 + b[off]
        cl = int.from_bytes(b[off:off+2], "big"); d["cipher"] = b[off+2:off+4].hex(); off += 2 + cl
        off += 2                                              # compression
        off += 2                                              # ext total len
        exts = {}
        while off < len(b):
            et = int.from_bytes(b[off:off+2], "big"); el = int.from_bytes(b[off+2:off+4], "big")
            exts[et] = b[off+4:off+4+el]; off += 4 + el
        d["exts"] = exts
        return d
    d = _parse_ch(b"okena.test")
    check("client hello: TLS record (handshake, version 0x0301)", d["rec"], (22, 0x0301))
    check("client hello: legacy_version 0x0303", d["ver"], 0x0303)
    check("client hello: session id 32 bytes (middlebox compat)", d["sidlen"], 32)
    check("client hello: cipher TLS_AES_128_GCM_SHA256", d["cipher"], "1301")
    check("client hello: supported_versions = TLS 1.3 + TLS 1.2",
          d["exts"].get(43), bytes([4, 3, 4, 3, 3]))
    check("client hello: supported_groups X25519MLKEM768, x25519, secp256r1",
          d["exts"].get(10), bytes([0, 6, 0x11, 0xEC, 0, 0x1D, 0, 0x17]))
    check("client hello: sig_algs ecdsa_secp256r1_sha256 + rsa_pss_rsae_sha256 + rsa_pkcs1_sha256",
          d["exts"].get(13), bytes([0, 6, 4, 3, 8, 4, 4, 1]))
    ks = d["exts"].get(51, b"")
    check("client hello: key_shares X25519MLKEM768 (1216) + x25519 (32) + secp256r1 (65)",
          ks[:2] == bytes([5, 0x2D]) and ks[2:6] == bytes([0x11, 0xEC, 4, 0xC0])
          and ks[1222:1226] == bytes([0, 0x1D, 0, 0x20]) and ks[1258:1262] == bytes([0, 0x17, 0, 0x41])
          and ks[1190:1222] == ks[1226:1258],          # the hybrid's x25519 half is the x25519 share
          True)
    check("client hello: the hybrid's ML-KEM key passes the modulus check",
          mlkem_ref.ek_valid(ks[6:6 + 1184]), True)
    check("client hello: ALPN http/1.1", d["exts"].get(16), bytes([0, 9, 8]) + b"http/1.1")
    sni = d["exts"].get(0, b"")
    check("client hello: SNI okena.test", sni[5:] if len(sni) >= 5 else b"", b"okena.test")

    # edge inputs: u with the top bit set (ignored), u = 0, u >= p
    for u in (bytes(31) + b"\x80", bytes(32), (2**255 - 19 + 5).to_bytes(32, "little"), b"\xff" * 32):
        a = X25519PrivateKey.generate()
        a_raw = a.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        try:
            want = a.exchange(X25519PublicKey.from_public_bytes(u)).hex()
        except Exception:
            want = None                         # the library refuses an all-zero result
        got = run(b"x", a_raw + u)
        if want is not None:
            check(f"x25519 edge u {u.hex()[:8]}..", got, want)
except ImportError:
    print("note: python cryptography not installed; X25519 checked on RFC 7748 only")

# --- AES-128-GCM: McGrew-Viega test cases 1 and 2, then the library
def seal(key, iv, aad, pt):
    return run(b"g", key + iv + le16(len(aad)) + aad + pt)


def gopen(key, iv, aad, ct):
    return run(b"G", key + iv + le16(len(aad)) + aad + ct)


check("GCM test case 1 (empty)", seal(bytes(16), bytes(12), b"", b""), "58e2fccefa7e3061367f1d57a4e7455a")
check("GCM test case 2", seal(bytes(16), bytes(12), b"", bytes(16)),
      "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf")
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    lens = list(range(0, 300)) + [rng.randrange(300, 60000) for _ in range(20)]
    for n in lens:
        key, iv = rng.randbytes(16), rng.randbytes(12)
        aad = rng.randbytes(rng.choice([0, 5, 13, 16, 17, 32, rng.randrange(80)]))
        pt = rng.randbytes(n)
        want = AESGCM(key).encrypt(iv, pt, aad)
        check(f"gcm seal {n} aad {len(aad)}", seal(key, iv, aad, pt), want.hex())
        if n % 7 == 0:
            check(f"gcm open {n}", gopen(key, iv, aad, want), pt.hex())
        if n % 3 == 0 or n > 299:            # the SSE paths too, where the CPU has VAES
            check(f"gcm seal {n} without VAES", run(b"vg", key + iv + le16(len(aad)) + aad + pt), want.hex())
            check(f"gcm open {n} without VAES", run(b"vG", key + iv + le16(len(aad)) + aad + want), pt.hex())
    key, iv, aad, pt = rng.randbytes(16), rng.randbytes(12), b"header", rng.randbytes(100)
    ct = bytearray(AESGCM(key).encrypt(iv, pt, aad))
    for name, k2, aad2, ct2 in [
        ("a flipped ciphertext bit", key, aad, bytes(ct[:10]) + bytes([ct[10] ^ 1]) + bytes(ct[11:])),
        ("a flipped tag bit", key, aad, bytes(ct[:-1]) + bytes([ct[-1] ^ 0x80])),
        ("other additional data", key, b"headeR", bytes(ct)),
        ("another key", rng.randbytes(16), aad, bytes(ct)),
    ]:
        check(f"gcm open refuses {name}", gopen(k2, iv, aad2, ct2), "FAIL")
except ImportError:
    print("note: python cryptography not installed; AES-GCM checked on the test cases only")

# --- P-256: field arithmetic, then keys and RFC 6979 signatures
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
R = 2**256


def limbs(v):
    return v.to_bytes(32, "little")


def num(hexs):
    return int.from_bytes(bytes.fromhex(hexs), "little")


edge = [0, 1, 2, P - 1, P - 2, 2**255, 2**224, 2**64 - 1]
for _ in range(120):
    a = rng.choice(edge + [rng.randrange(P)])
    b = rng.choice(edge + [rng.randrange(P)])
    check(f"p256 mont_mul {a:x} {b:x}", num(run(b"M", limbs(a) + limbs(b))), a * b * pow(R, -1, P) % P)
    check(f"p256 sqr {a:x}", num(run(b"Q", limbs(a))), a * a * pow(R, -1, P) % P)
    check(f"p256 add {a:x} {b:x}", num(run(b"a", limbs(a) + limbs(b))), (a + b) % P)
    check(f"p256 sub {a:x} {b:x}", num(run(b"b", limbs(a) + limbs(b))), (a - b) % P)
    if a:
        check(f"p256 inv {a:x}", num(run(b"I", limbs(a * R % P))), pow(a, -1, P) * R % P)
d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
sig = run(b"E", d.to_bytes(32, "big") + hashlib.sha256(b"sample").digest())
r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
s_ = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8


def der_int(v):
    b_ = v.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if b_[0] & 0x80:
        b_ = b"\0" + b_
    return bytes([2, len(b_)]) + b_


body = der_int(r) + der_int(s_)
check("RFC 6979 A.2.5 P-256 SHA-256 'sample'", sig, (bytes([0x30, len(body)]) + body).hex())
check("p256 refuses d = 0", run(b"E", bytes(32) + bytes(32)), "FAIL")
check("p256 refuses d = n", run(b"E", N.to_bytes(32, "big") + bytes(32)), "FAIL")
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    for i in range(150):
        k = ec.generate_private_key(ec.SECP256R1())
        dd = k.private_numbers().private_value.to_bytes(32, "big")
        pub = k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        check("p256 public key", run(b"P", dd), pub.hex())
        msg = rng.randbytes(rng.randrange(200))
        want = k.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        check("p256 RFC 6979 signature, byte for byte", run(b"E", dd + hashlib.sha256(msg).digest()), want.hex())
except (ImportError, TypeError):
    print("note: deterministic ECDSA not in this cryptography; P-256 checked on RFC 6979 only")

# --- SHA-512 against hashlib, around the 128-byte block and its padding
for n in list(range(0, 260)) + [1000, 4096, 65537]:
    m = rng.randbytes(n)
    check(f"sha-512 len {n}", run(b"8", m), hashlib.sha512(m).hexdigest())

# --- Ed25519 (RFC 8032): its test vectors, then the cryptography package
# (keys, deterministic signatures byte for byte, verification), and the
# refusals: a flipped bit, S >= L, a key that is not on the curve
ED_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
for sk, pk, msg, sig in ED_VECTORS:
    sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
    check("ed25519 RFC 8032 public key", run(b"A", sk), pk.hex())
    check("ed25519 RFC 8032 signature", run(b"F", sk + msg), sig.hex())
    check("ed25519 RFC 8032 verifies", run(b"f", pk + sig + msg), "01")
L_ED = 2**252 + 27742317777372353535851937790883648493
pk, sig = bytes.fromhex(ED_VECTORS[0][1]), bytes.fromhex(ED_VECTORS[0][3])
s_val = int.from_bytes(sig[32:], "little")
check("ed25519: S + L (not canonical) refused", run(b"f", pk + sig[:32] + (s_val + L_ED).to_bytes(32, "little")), "00")
off_curve = bytearray(pk)
off_curve[0] ^= 1                               # almost surely not a point
check("ed25519: a key off the curve refused", run(b"f", bytes(off_curve) + sig), "00")
check("ed25519: a key with y >= p refused",
      run(b"f", (2**255 - 19 + 1).to_bytes(32, "little") + sig), "00")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as _ser
    for i in range(60):
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())
        pub = key.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        msg = rng.randbytes(rng.randrange(300))
        sig = key.sign(msg)
        check("ed25519 public key", run(b"A", seed), pub.hex())
        check("ed25519 signature, byte for byte", run(b"F", seed + msg), sig.hex())
        check("ed25519 verifies", run(b"f", pub + sig + msg), "01")
        bad = bytearray(sig)
        bad[rng.randrange(64)] ^= 1 << rng.randrange(8)
        check("ed25519 flipped bit refused", run(b"f", pub + bytes(bad) + msg), "00")
except ImportError:
    print("note: no cryptography package; Ed25519 checked on RFC 8032 only")

# --- ChaCha20-Poly1305 (RFC 8439): the published key stream, then the
# cryptography package for ChaCha20 at every length around its two-block
# step, Poly1305 on extreme keys and messages (h near p, all carries), and
# the AEAD sealing, opening, and refusing a forged tag
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    sun = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
           b"sunscreen would be it.")
    check("chacha20 RFC 8439 2.4.2", run(b"c", bytes(range(32)) + bytes.fromhex("000000000000004a00000000")
                                         + le16(1) + b"\0\0" + sun)[:32], "6e2e359a2568f98041ba0728dd0d6981")
    for n in list(range(0, 260, 7)) + [16384, 16391]:
        k, nc, ctr, d = rng.randbytes(32), rng.randbytes(12), rng.randrange(1 << 28), rng.randbytes(n)
        want = Cipher(algorithms.ChaCha20(k, ctr.to_bytes(4, "little") + nc), mode=None).encryptor().update(d)
        check(f"chacha20 len {n}", run(b"c", k + nc + ctr.to_bytes(4, "little") + d), want.hex())
    edge_keys = [b"\xff" * 32, bytes(16) + b"\xff" * 16, b"\xff" * 16 + bytes(16), bytes(32)]
    edge_msgs = [b"\xff" * 16 * k for k in (1, 2, 3, 16, 64)] + [bytes(64), (b"\xfb" + b"\xff" * 15) * 3]
    for k in edge_keys + [rng.randbytes(32) for _ in range(10)]:
        for m in edge_msgs + [rng.randbytes(16 * rng.randrange(1, 40)) for _ in range(3)]:
            check("poly1305", run(b"e", k + m), Poly1305.generate_tag(k, m).hex())
    for n in (0, 1, 15, 16, 17, 64, 129, 1000, 16384):
        for al in (0, 5, 13, 16):
            k, iv, aad, pt = rng.randbytes(32), rng.randbytes(12), rng.randbytes(al), rng.randbytes(n)
            ct = ChaCha20Poly1305(k).encrypt(iv, pt, aad)
            head = k + iv + le16(al) + aad
            check(f"chacha20-poly1305 seal {n}/{al}", run(b"y", head + pt), ct.hex())
            check(f"chacha20-poly1305 open {n}/{al}", run(b"Z", head + ct), pt.hex())
            forged = bytearray(ct)
            forged[rng.randrange(len(ct))] ^= 1 << rng.randrange(8)
            check(f"chacha20-poly1305 forged {n}/{al}", run(b"Z", head + bytes(forged)), "FAIL")
except ImportError:
    print("note: no cryptography package; ChaCha20-Poly1305 checked on RFC 8439 only")

# --- Keccak (FIPS 202): SHA3-256, SHA3-512, SHAKE128/256 against hashlib,
# every length around the block boundaries (rates 72, 136, 168)
for n in list(range(0, 180)) + [271, 272, 273, 335, 336, 337, 1184, 1216]:
    m = rng.randbytes(n)
    check(f"sha3-256 len {n}", run(b"3", m), hashlib.sha3_256(m).hexdigest())
    check(f"sha3-512 len {n}", run(b"5", m), hashlib.sha3_512(m).hexdigest())
    out = rng.choice([1, 32, 64, 128, 135, 136, 137, 167, 168, 169, 504, 1000])
    check(f"shake128 len {n} out {out}", run(b"6", le16(out) + m), hashlib.shake_128(m).hexdigest(out))
    check(f"shake256 len {n} out {out}", run(b"7", le16(out) + m), hashlib.shake_256(m).hexdigest(out))

# four-way Keccak (AVX2): four one-block sponges side by side, two output
# blocks of each, against hashlib (SHAKE128 with two bytes after the
# prefix, as SampleNTT; SHAKE256 with one, as ML-KEM's PRF)
import struct  # noqa: E402
for rate, f, n in ((168, hashlib.shake_128, 2), (136, hashlib.shake_256, 1)):
    for t in range(25):
        pre, lanes, want = rng.randbytes(32), b"", b""
        for k in range(4):
            sfx = rng.randbytes(n)
            lanes += struct.pack("<Q", int.from_bytes(sfx, "little") | (0x1F << (8 * n)))
            want += f(pre + sfx).digest(2 * rate)
        check(f"keccak x4 rate {rate}", run(b"4", bytes([rate]) + pre + lanes), want.hex())

# --- ML-KEM-768 (FIPS 203) encapsulation: against tests/kat/mlkem_ref.py
# (written from the standard) byte for byte, the modulus check, and against
# OpenSSL's decapsulation where it has ML-KEM

for i in range(40):
    ek, dk = mlkem_ref.keygen(rng.randbytes(32), rng.randbytes(32))
    m = rng.randbytes(32)
    k, c = mlkem_ref.encaps(ek, m)
    got = run(b"q", ek + m)
    check("ml-kem-768 encaps = reference (ciphertext | secret)", got, (c + k).hex())
    if i < 5:
        check("ml-kem-768 reference decaps closes the loop", mlkem_ref.decaps(dk, bytes.fromhex(got[:2 * 1088])).hex(), k.hex())
# key generation and decapsulation (okena's client side), and implicit
# rejection: a ciphertext changed by one bit decapsulates to J(z | c)
for i in range(20):
    d, z = rng.randbytes(32), rng.randbytes(32)
    ek, dk = mlkem_ref.keygen(d, z)
    check("ml-kem-768 keygen = reference (ek | dk)", run(b"L", d + z), (ek + dk).hex())
    k, c = mlkem_ref.encaps(ek, rng.randbytes(32))
    check("ml-kem-768 decaps = reference", run(b"O", dk + c), k.hex())
    bad = bytearray(c)
    bad[rng.randrange(1088)] ^= 1 << rng.randrange(8)
    check("ml-kem-768 implicit rejection: J(z | c)", run(b"O", dk + bytes(bad)), mlkem_ref.J(z + bytes(bad)).hex())
# an encapsulation key with a coefficient not below q is refused
ek, _ = mlkem_ref.keygen(rng.randbytes(32), rng.randbytes(32))
for pos in (0, 1, 383, 384 * 2 + 190):
    bad = bytearray(ek)
    if pos % 3 == 1:                    # the high nibble of this byte and the next byte
        bad[pos] |= 0xF0
        bad[pos + 1] = 0xFF
    else:
        bad[pos] = 0xFF
        bad[pos + 1] |= 0x0F
    want_valid = mlkem_ref.ek_valid(bytes(bad))
    check(f"ml-kem-768 modulus check (byte {pos})", run(b"q", bytes(bad) + bytes(32)) == "exit 2",
          not want_valid)
try:
    import shutil
    import tempfile
    if shutil.which("openssl") and b"ML-KEM-768" in subprocess.run(
            ["openssl", "list", "-kem-algorithms"], capture_output=True).stdout:
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            for i in range(5):
                subprocess.run(["openssl", "genpkey", "-algorithm", "ML-KEM-768", "-out", dp / "dk.pem"],
                               check=True, capture_output=True)
                der = subprocess.run(["openssl", "pkey", "-in", dp / "dk.pem", "-pubout", "-outform", "DER"],
                                     check=True, capture_output=True).stdout
                got = bytes.fromhex(run(b"q", der[-1184:] + rng.randbytes(32)))
                (dp / "ct").write_bytes(got[:1088])
                subprocess.run(["openssl", "pkeyutl", "-decap", "-inkey", dp / "dk.pem", "-in", dp / "ct",
                                "-secret", dp / "ss"], check=True, capture_output=True)
                check("ml-kem-768 encaps to an OpenSSL key, OpenSSL decapsulates the same secret",
                      (dp / "ss").read_bytes().hex(), got[1088:].hex())
            # the other way: OpenSSL encapsulates to a key okena generated
            # (its seed form, d | z, is what OpenSSL imports)
            for i in range(3):
                seed = rng.randbytes(64)
                ek = bytes.fromhex(run(b"L", seed))[:1184]
                (dp / "ek.raw").write_bytes(ek)
                # SubjectPublicKeyInfo for ML-KEM-768: the 22-byte prefix, then ek
                spki = bytes.fromhex("308204b2300b0609608648016503040402038204a100") + ek
                (dp / "ek.der").write_bytes(spki)
                subprocess.run(["openssl", "pkeyutl", "-encap", "-pubin", "-inkey", dp / "ek.der", "-keyform", "DER",
                                "-out", dp / "ct2", "-secret", dp / "ss2"], check=True, capture_output=True)
                dk = bytes.fromhex(run(b"L", seed))[1184:]
                check("ml-kem-768: OpenSSL encapsulates to okena's key, okena decapsulates the same secret",
                      run(b"O", dk + (dp / "ct2").read_bytes()), (dp / "ss2").read_bytes().hex())
    else:
        print("note: no ML-KEM in this openssl; ML-KEM checked against the reference only")
except (OSError, subprocess.CalledProcessError, ValueError) as e:
    check("ml-kem-768 against openssl", repr(e), "")

print(f"kat: {'all passed' if not failures else f'{failures} failed'} ({checks} checks)")
sys.exit(1 if failures else 0)
