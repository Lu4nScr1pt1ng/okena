#!/usr/bin/env python3
"""tls { cert; key }: certificates and keys made by openssl, loaded and
checked by okena check (exit code and message for each refusal)."""
import atexit
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


def okena_check(cert, key, extra=""):
    conf = tmp / "okena.conf"
    conf.write_text(f"""http 127.0.0.1:18443 {{
    tls {{ cert {cert}; key {key} }}
    route /* {{ to 127.0.0.1:1 }}{extra}
}}
""")
    r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# keys and certificates
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ec.key")
sh("openssl", "req", "-new", "-x509", "-key", "ec.key", "-subj", "/CN=okena.test", "-days", "2", "-out", "ec.pem")
sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "p8.key")
sh("openssl", "req", "-new", "-x509", "-key", "p8.key", "-subj", "/CN=p8.test", "-days", "2", "-out", "p8.pem")
# a chain: CA, then a leaf signed by it
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key")
sh("openssl", "req", "-new", "-x509", "-key", "ca.key", "-subj", "/CN=ca", "-days", "2", "-out", "ca.pem")
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=leaf", "-out", "leaf.csr")
sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
   "-days", "2", "-out", "leaf.pem")
(tmp / "chain.pem").write_text((tmp / "leaf.pem").read_text() + (tmp / "ca.pem").read_text())
# an RSA certificate (served to clients that do not offer ECDSA)
sh("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rsa.key",
   "-subj", "/CN=rsa", "-days", "2", "-out", "rsa.pem")
sh("openssl", "ecparam", "-genkey", "-name", "secp384r1", "-noout", "-out", "p384.key")
sh("openssl", "req", "-new", "-x509", "-key", "p384.key", "-subj", "/CN=p384", "-days", "2", "-out", "p384.pem")
sh("openssl", "pkcs8", "-topk8", "-in", "ec.key", "-out", "enc.key", "-passout", "pass:secret")
pem = (tmp / "ec.pem").read_text().splitlines()
(tmp / "broken.pem").write_text("\n".join(pem[:2] + ["!!!not base64!!!"] + pem[2:]) + "\n")

code, out = okena_check(tmp / "ec.pem", tmp / "ec.key")
check("an EC P-256 certificate and its SEC 1 key", code == 0, out.strip())
code, out = okena_check(tmp / "p8.pem", tmp / "p8.key")
check("a PKCS #8 key", code == 0, out.strip())
code, out = okena_check(tmp / "chain.pem", tmp / "leaf.key")
check("a chain, the leaf first, with the leaf's key", code == 0, out.strip())
code, out = okena_check(tmp / "rsa.pem", tmp / "rsa.key")
check("an RSA certificate and its key (for legacy clients)", code == 0, out.strip())
for name, cert, key, want in [
    ("a key that does not belong to the certificate", "ec.pem", "p8.key", "does not belong to the certificate"),
    ("the chain with the CA's key", "chain.pem", "ca.key", "does not belong to the certificate"),
    ("a P-384 certificate", "p384.pem", "p384.key", "not on P-256"),
    ("an encrypted key", "ec.pem", "enc.key", "encrypted key is not supported"),
    ("broken base64", "broken.pem", "ec.key", "base64 is broken"),
    ("a missing certificate file", "nope.pem", "ec.key", "cannot read"),
    ("a key file that is a certificate", "ec.pem", "ec.pem", "no EC PRIVATE KEY or PRIVATE KEY block"),
]:
    code, out = okena_check(tmp / cert, tmp / key)
    check(f"refused: {name}", code != 0 and want in out, out.strip().splitlines()[0] if out.strip() else "")
conf = tmp / "nokey.conf"
conf.write_text(f"http 127.0.0.1:18443 {{\n    tls {{ cert {tmp / 'ec.pem'} }}\n    route /* {{ to 127.0.0.1:1 }}\n}}\n")
r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
check("refused: a tls block without its key", r.returncode != 0 and "needs its certificate and its key" in r.stderr,
      r.stderr.strip().splitlines()[0] if r.stderr else "")
# tls on a tcp listener: kTLS or nothing (its bytes never pass through okena)
conf = tmp / "tcp.conf"
conf.write_text(f"tcp 127.0.0.1:18444 {{\n    tls {{ cert {tmp / 'ec.pem'}; key {tmp / 'ec.key'} }}\n    to 127.0.0.1:1\n}}\n")
r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
check("okena check accepts tls on a tcp listener", r.returncode == 0, (r.stdout + r.stderr).strip())
r = subprocess.run([str(BIN), "-c", str(conf)], capture_output=True, text=True, timeout=10,
                   env=dict(__import__("os").environ, OKENA_KTLS="off"))
check("without kTLS, tls on a tcp listener is refused at the start", r.returncode != 0
      and "needs kernel TLS" in r.stderr, r.stderr.strip()[:160])

# several certificates: each names its key
for name, block, want in [
    ("two certs with key=", f"cert {tmp / 'ec.pem'} key={tmp / 'ec.key'}; cert {tmp / 'p8.pem'} key={tmp / 'p8.key'}", None),
    ("two certs, one without key=", f"cert {tmp / 'ec.pem'} key={tmp / 'ec.key'}; cert {tmp / 'p8.pem'}; key {tmp / 'p8.key'}",
     "each names its key"),
    ("a key line no cert uses", f"cert {tmp / 'ec.pem'} key={tmp / 'ec.key'}; key {tmp / 'p8.key'}", "belongs to none"),
    ("a key= that does not match its cert", f"cert {tmp / 'ec.pem'} key={tmp / 'p8.key'}", "does not belong to the certificate"),
]:
    c = tmp / "multi.conf"
    c.write_text(f"http 127.0.0.1:18443 {{\n    tls {{ {block} }}\n    route /* {{ to 127.0.0.1:1 }}\n}}\n")
    r = subprocess.run([str(BIN), "check", str(c)], capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    if want is None:
        check(f"tls: {name}", r.returncode == 0, out)
    else:
        check(f"tls refused: {name}", r.returncode != 0 and want in out, out.splitlines()[0] if out else "")

# okena { ticket_keys FILE }: one key a line, 32 bytes of base64, at most two
import base64, os
good = tmp / "tickets.key"
good.write_text(base64.b64encode(os.urandom(32)).decode() + "\n" + base64.b64encode(os.urandom(32)).decode() + "\n")
for name, text, want in [
    ("two keys", good.read_text(), None),
    ("not base64", "!!!!\n", "not 32 bytes of base64"),
    ("16 bytes, not 32", base64.b64encode(os.urandom(16)).decode() + "\n", "not 32 bytes of base64"),
    ("three keys", good.read_text() + base64.b64encode(os.urandom(32)).decode() + "\n", "at most two keys"),
    ("an empty file", "\n\n", "no key in this file"),
]:
    f = tmp / "tk.key"
    f.write_text(text)
    c = tmp / "tk.conf"
    c.write_text(f"okena {{ ticket_keys {f} }}\nhttp 127.0.0.1:18443 {{\n    tls {{ cert {tmp / 'ec.pem'}; key {tmp / 'ec.key'} }}\n"
                 "    route /* { to 127.0.0.1:1 }\n}\n")
    r = subprocess.run([str(BIN), "check", str(c)], capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    if want is None:
        check(f"ticket_keys: {name}", r.returncode == 0, out)
    else:
        check(f"ticket_keys refused: {name}", r.returncode != 0 and want in out, out.splitlines()[0] if out else "")

print(f"tls: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
