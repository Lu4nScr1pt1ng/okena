#!/usr/bin/env python3
"""tlsfuzzer conformance against a live okena. okena terminates TLS on an
http listener and proxies to a tiny HTTP backend, so tlsfuzzer's TLS stack
(tlslite-ng) drives real handshakes end to end: a TLS 1.3 and a TLS 1.2
sanity exchange (ClientHello .. Finished, a GET, the HTTP response, close),
and a few negative probes that must draw the right alert.

Skipped unless tlsfuzzer and tlslite are importable (pip install tlsfuzzer).
The HTTP response is proxied as more than one record, so the conversations
accept application_data until the connection closes."""
import atexit
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"

try:
    from tlsfuzzer.runner import Runner
    from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator
    from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectChangeCipherSpec, ExpectFinished, ExpectAlert, \
        ExpectApplicationData, ExpectClose, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket, ExpectServerHelloDone, \
        ExpectServerKeyExchange
    from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType, SignatureScheme, ECPointFormat
    from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        ECPointFormatsExtension
    from tlsfuzzer.helpers import key_share_gen, SIG_ALL
except ImportError as e:
    print(f"skip tlsfuzzer: {e} (pip install tlsfuzzer tlslite-ng)")
    sys.exit(0)

BASE = 36000 + os.getpid() % 60 * 10
BACK, LST = BASE, BASE + 1
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*a):
    subprocess.run(a, check=True, capture_output=True, cwd=tmp)


def backend(port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=_serve, args=(c,), daemon=True).start()


def _serve(c):
    try:
        c.recv(4096)
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nhi\n")
    except OSError:
        pass
    finally:
        c.close()


def run(name, conversation):
    runner = Runner(conversation)
    try:
        runner.run()
        return True
    except Exception:
        return False


def tls13_handshake(host, port):
    groups = [GroupName.secp256r1, GroupName.x25519]
    node = conv = Connect(host, port)
    ext = {
        ExtensionType.key_share: ClientKeyShareExtension().create(
            [key_share_gen(g) for g in groups]),
        ExtensionType.supported_versions: SupportedVersionsExtension().create([(3, 4), (3, 3)]),
        ExtensionType.supported_groups: SupportedGroupsExtension().create(groups),
        ExtensionType.signature_algorithms: SignatureAlgorithmsExtension().create(
            [SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.rsa_pss_rsae_sha256]),
        ExtensionType.signature_algorithms_cert: SignatureAlgorithmsCertExtension().create(SIG_ALL),
    }
    node = node.add_child(ClientHelloGenerator(
        [CipherSuite.TLS_AES_128_GCM_SHA256], extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    return conv, node


def with_http(conv, node):
    """send a GET and accept NewSessionTickets + application_data until close"""
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\r\n\r\n"))
    nst = ExpectNewSessionTicket()
    node = node.add_child(nst)
    nst.add_child(nst)                                  # 0+ NewSessionTickets
    app = ExpectApplicationData()
    nst.next_sibling = app
    app.add_child(app)                                  # 1+ application_data records
    app.next_sibling = ExpectClose()                    # okena closes (HTTP/1.0)
    return conv


def tls12_handshake(host, port, cipher, sig):
    groups = [GroupName.secp256r1, GroupName.x25519]
    node = conv = Connect(host, port)
    ext = {
        ExtensionType.supported_groups: SupportedGroupsExtension().create(groups),
        ExtensionType.ec_point_formats: ECPointFormatsExtension().create([ECPointFormat.uncompressed]),
        ExtensionType.signature_algorithms: SignatureAlgorithmsExtension().create(sig),
        ExtensionType.signature_algorithms_cert: SignatureAlgorithmsCertExtension().create(SIG_ALL),
    }
    node = node.add_child(ClientHelloGenerator(
        [cipher, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    return conv, node


def main():
    if not shutil.which("openssl"):
        print("skip tlsfuzzer: openssl not found")
        return 0
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "s.key")
    sh("openssl", "req", "-new", "-x509", "-key", "s.key", "-subj", "/CN=localhost",
       "-addext", "subjectAltName=DNS:localhost", "-days", "2", "-out", "s.pem")
    threading.Thread(target=backend, args=(BACK,), daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2 }}
http 127.0.0.1:{LST} {{
    tls {{ cert {tmp / 's.pem'}; key {tmp / 's.key'} }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    if r.returncode != 0:
        print("skip tlsfuzzer: no kTLS" if "kernel TLS" in r.stderr else f"FAIL config: {r.stderr[-200:]}")
        return 0 if "kernel TLS" in r.stderr else 1
    log = open(tmp / "okena.log", "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    time.sleep(0.3)

    host = "127.0.0.1"
    conv, node = tls13_handshake(host, LST)
    check("tlsfuzzer: TLS 1.3 handshake and HTTP response", run("tls13", with_http(conv, node)))

    conv, node = tls12_handshake(host, LST, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                 [SignatureScheme.ecdsa_secp256r1_sha256])
    check("tlsfuzzer: TLS 1.2 ECDHE-ECDSA handshake and HTTP response", run("tls12", with_http(conv, node)))

    # negative: a ClientHello with no cipher the server accepts -> handshake_failure
    node = conv = Connect(host, LST)
    ext = {
        ExtensionType.key_share: ClientKeyShareExtension().create([key_share_gen(GroupName.secp256r1)]),
        ExtensionType.supported_versions: SupportedVersionsExtension().create([(3, 4)]),
        ExtensionType.supported_groups: SupportedGroupsExtension().create([GroupName.secp256r1]),
        ExtensionType.signature_algorithms: SignatureAlgorithmsExtension().create(
            [SignatureScheme.ecdsa_secp256r1_sha256]),
        ExtensionType.signature_algorithms_cert: SignatureAlgorithmsCertExtension().create(SIG_ALL),
    }
    node = node.add_child(ClientHelloGenerator([CipherSuite.TLS_CHACHA20_POLY1305_SHA256], extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal, AlertDescription.handshake_failure))
    node.add_child(ExpectClose())
    check("tlsfuzzer: a ClientHello with no shared cipher is refused", run("no-cipher", conv))

    print(f"tlsfuzzer: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
