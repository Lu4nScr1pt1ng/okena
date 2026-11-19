# okena Helm chart

okena as the cluster's Ingress controller, and the implementation of a
GatewayClass when the Gateway API's CRDs are installed.

```sh
helm install edge oci://ghcr.io/lu4nscr1pt1ng/charts/okena \
    --namespace ingress --create-namespace
```

(or `helm install edge contrib/helm/okena ...` from a clone of the repository).
Then any Ingress with `ingressClassName: okena` is served: its hosts, paths,
the TLS certificates of its `spec.tls` Secrets (cert-manager's too), and the
common ingress-nginx annotations (rewrite-target, ssl-redirect, canary-*,
auth-url, CORS, limits...; docs/CONFIG.md lists them).

**Gateway API.** Install its CRDs, then let okena own a GatewayClass:

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
helm upgrade edge oci://ghcr.io/lu4nscr1pt1ng/charts/okena -n ingress --reuse-values --set gatewayClass.create=true
```

Gateways of class `okena` and their HTTPRoutes, GRPCRoutes, TLSRoutes,
TCPRoutes and UDPRoutes are served, and their status is written back.

| Value | Default | What |
|---|---|---|
| `image.repository`, `image.tag` | `ghcr.io/lu4nscr1pt1ng/okena`, the chart's appVersion | |
| `kind` | `Deployment` | or `DaemonSet` (one a node) |
| `replicas` | 2 | for a Deployment |
| `ingressClass.name` | `okena` | the class served |
| `ingressClass.default` | false | also the Ingresses that name no class |
| `gatewayClass.create` | false | a GatewayClass of okena's controller (needs the CRDs) |
| `service.type` | `LoadBalancer` | with `externalTrafficPolicy: Local` (the client's address reaches okena) |
| `statusAddress` | | what Ingresses' and Gateways' status shows; empty: the Service's load balancer |
| `zone` | | `node` (the pod's topology label, Kubernetes 1.33+) or a zone's name: a Service's endpoints in that zone first |
| `okena` | `workers auto` | lines for the `okena { }` block |
| `extraConfig` | | configuration after the generated part (pools and listeners of your own) |
| `seccompProfile` | `RuntimeDefault` | see below |
| `resources` | 100m, 64Mi; 512Mi at most | |

**io_uring.** `RuntimeDefault` blocks io_uring and okena runs on epoll (and
says so in its log). For io_uring, put `okena.seccomp.json` (in the release
archive, or docker/okena.seccomp.json) on each node as
`/var/lib/kubelet/seccomp/okena.json`, then:

```sh
--set seccompProfile.type=Localhost --set seccompProfile.localhostProfile=okena.json
```

The pod runs as user 65532 with no capabilities and a read-only root, on the
ports 8080, 8443 and 9464 (metrics, `/ready`, `/live`); the Service maps 80
and 443 to them. A pod that stops is taken out of rotation first and drains
its connections. See docs/CONFIG.md, "Kubernetes Gateway API".
