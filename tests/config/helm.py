#!/usr/bin/env python3
"""contrib/helm/okena: `helm lint`, and `helm template` with its values as they
come and turned the other ways (a DaemonSet, the cluster's default class, a
GatewayClass, okena settings and configuration of one's own): every manifest
reads as YAML, and the okena.conf it makes passes `okena check`. helm comes
from $HELM or build/helm/helm (install it there yourself: helm v3, e.g.
https://get.helm.sh/helm-v3.16.3-linux-amd64.tar.gz, sha256
f5355c79190951eed23c5432a3b920e071f4c00a64f75e077de0dd4cb7b294ea); without
it the suite is skipped."""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
CHART = ROOT / "contrib" / "helm" / "okena"
HELM = pathlib.Path(os.environ.get("HELM", ROOT / "build" / "helm" / "helm"))
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


def helm(*a):
    env = dict(os.environ, HELM_CACHE_HOME="/tmp/okena-helm-cache", HELM_CONFIG_HOME="/tmp/okena-helm-config",
               HELM_DATA_HOME="/tmp/okena-helm-data")
    return subprocess.run([str(HELM), *a], capture_output=True, text=True, timeout=60, env=env)


def main():
    try:
        import yaml
    except ImportError:
        print("skip helm: no yaml module")
        return 0
    if not HELM.exists():
        print(f"skip helm: no helm at {HELM} (set HELM to one)")
        return 0
    r = helm("lint", str(CHART), "--strict")
    check("helm lint --strict", r.returncode == 0, r.stdout + r.stderr)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-helm-"))
    cases = {
        "as it comes": ([], "Deployment"),
        "a DaemonSet, the default class, a GatewayClass": (["--set", "kind=DaemonSet", "--set", "ingressClass.default=true",
                                                           "--set", "gatewayClass.create=true"], "DaemonSet"),
        "settings and configuration of one's own": ([
            "--set-string", "okena=workers 2\nprofile latency\ncache_memory 128MiB\n",
            "--set-string", "extraConfig=pool db { server 10.0.0.5:5432 }\ntcp :5432 { to pool db }\n"], "Deployment"),
    }
    for name, (extra, workload) in cases.items():
        r = helm("template", "edge", str(CHART), "--namespace", "ingress", *extra)
        if r.returncode != 0:
            check(f"{name}: helm template", False, r.stderr)
            continue
        docs = [d for d in yaml.safe_load_all(r.stdout) if d]
        kinds = sorted(d["kind"] for d in docs)
        want = {"ServiceAccount", "ClusterRole", "ClusterRoleBinding", "ConfigMap", "Service", "IngressClass", workload}
        check(f"{name}: the manifests ({', '.join(kinds)})", want <= set(kinds), kinds)
        conf = next(d for d in docs if d["kind"] == "ConfigMap")["data"]["okena.conf"]
        f = tmp / "okena.conf"
        (tmp / "gw").mkdir(exist_ok=True)
        # (outside a pod: the API server and the service account's files said)
        if not (tmp / "ca.crt").exists():
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-keyout", tmp / "ca.key", "-out", tmp / "ca.crt", "-subj", "/CN=ca", "-days", "1"],
                           check=True, capture_output=True)
            (tmp / "token").write_text("t\n")
        conf2 = conf.replace("/var/lib/okena/gateway", str(tmp / "gw")).replace("/run/okena/", str(tmp) + "/")
        conf2 = conf2.replace("gateway kubernetes ", f"gateway kubernetes api=127.0.0.1:6443 ca={tmp}/ca.crt token={tmp}/token ")
        f.write_text(conf2)
        c = subprocess.run([str(BIN), "check", str(f)], capture_output=True, text=True)
        check(f"{name}: its okena.conf passes okena check", c.returncode == 0, conf + c.stdout + c.stderr)
        if "ingressClass.default=true" in extra:
            ic = next(d for d in docs if d["kind"] == "IngressClass")
            check("  the IngressClass says it is the default, and okena takes classless ones",
                  ic["metadata"]["annotations"]["ingressclass.kubernetes.io/is-default-class"] == "true"
                  and "ingress_default=on" in conf, conf)
            check("  a GatewayClass of okena's controller",
                  any(d["kind"] == "GatewayClass" and d["spec"]["controllerName"] == "okena.dev/gateway-controller"
                      for d in docs))
    print(f"helm: {'all passed' if not fails else f'{fails} failed'}")
    return 1 if fails else 0


sys.exit(main())
