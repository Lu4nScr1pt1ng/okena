# okena Helm chart

okena as the cluster's Ingress controller, and the implementation of a
GatewayClass when the Gateway API's CRDs are installed.

```sh
helm install edge contrib/helm/okena --namespace ingress --create-namespace
```

| Value | Default | What |
|---|---|---|
| `kind` | `Deployment` | or `DaemonSet` |
| `replicas` | 2 | for a Deployment |
| `ingressClass.name` | `okena` | the class served |
| `ingressClass.default` | false | also the Ingresses that name no class |
| `gatewayClass.create` | false | a GatewayClass of okena's controller |
| `service.type` | `LoadBalancer` | with `externalTrafficPolicy: Local` |
| `okena` | `workers auto` | lines for the `okena { }` block |
| `extraConfig` | | configuration after the generated part |
| `seccompProfile` | `RuntimeDefault` | io_uring needs a Localhost profile allowing it (docker/okena.seccomp.json); without it okena runs on epoll |

The pod runs as user 65532 with no capabilities, a read-only root and the
ports 8080, 8443 and 9464 (metrics, `/ready`, `/live`); the Service maps 80
and 443 to them. See docs/CONFIG.md, "Kubernetes Gateway API".
