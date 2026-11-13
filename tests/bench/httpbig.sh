#!/bin/bash
# HTTP/1.1 downloads of large bodies: okena, HAProxy 3.2, nginx 1.27 (its
# responses streamed, proxy_buffering off, as the others do) and Envoy 1.40,
# each in a container on the host network on the same two cores, in front of
# the same backend (l4bench httpbig: keep-alive, GET /SIZE answered with SIZE
# bytes). The
# load: h2load --h1, CONNS connections, closed loop, DUR seconds. Output:
# Gbit/s of bodies, and requests/s, a row each, markdown.
#
#   tests/bench/httpbig.sh            (needs gcc, docker and the images)
#   SIZES="65536 1048576" CONNS=64 ONLY="okena envoy"
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (9-10 idle), the backend on 4-5 and 12-13, the load on the others.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA_IMAGE=${OKENA_IMAGE:-okena:bench}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
CADDY_IMAGE=${CADDY_IMAGE:-caddy:2.10-alpine}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-traefik:v3.5}
H2LOAD_IMAGE=${H2LOAD_IMAGE:-okena-h2load-h3}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
BACK_CPUS=${BACK_CPUS:-4,5,12,13}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-6}
CONNS=${CONNS:-64}
SIZES=${SIZES:-65536 1048576}
REPEAT=${REPEAT:-3}
ONLY=${ONLY:-direct okena haproxy nginx envoy caddy traefik}
OKENA_EXTRA=${OKENA_EXTRA:-}
B=29600
W=$(mktemp -d)
chmod 755 "$W"
BPID=
trap 'docker rm -f okb-okena okb-haproxy okb-nginx okb-envoy okb-caddy okb-traefik >/dev/null 2>&1 || true; [ -n "$BPID" ] && kill $BPID 2>/dev/null; rm -rf "$W"' EXIT

gcc -O2 -pthread -o "$W/l4bench" "$ROOT/tests/bench/l4bench.c"
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null
port() { case $1 in direct) echo $B ;; okena) echo 29610 ;; haproxy) echo 29611 ;; nginx) echo 29612 ;; envoy) echo 29613 ;; caddy) echo 29614 ;; traefik) echo 29615 ;; esac; }

cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY; $OKENA_EXTRA }
pool b { server 127.0.0.1:$B }
http 127.0.0.1:29610 { route /* { to pool b } }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 200000
defaults
	mode http
	timeout connect 5s
	timeout client 60s
	timeout server 60s
	http-reuse always
frontend f
	bind 127.0.0.1:29611
	default_backend b
backend b
	server s 127.0.0.1:$B
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
events { worker_connections 65536; }
http {
	access_log off;
	keepalive_requests 1000000;
	upstream b { server 127.0.0.1:$B; keepalive 1024; keepalive_requests 1000000; }
	server {
		listen 127.0.0.1:29612 reuseport backlog=65535;
		location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; proxy_buffering off; }
	}
}
EOF
cat > "$W/envoy.yaml" <<EOF
static_resources:
  listeners:
  - address: { socket_address: { address: 127.0.0.1, port_value: 29613 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h
          generate_request_id: false
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: b, timeout: 0s }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              dynamic_stats: false
  clusters:
  - name: b
    type: STATIC
    circuit_breakers:
      thresholds:
      - { max_connections: 1000000, max_pending_requests: 1000000, max_requests: 1000000 }
    load_assignment:
      cluster_name: b
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: $B } } }
EOF
cat > "$W/Caddyfile" <<EOF
{
	admin off
	auto_https off
	persist_config off
	servers {
		protocols h1
	}
}
http://127.0.0.1:29614 {
	bind 127.0.0.1
	reverse_proxy 127.0.0.1:$B {
		transport http {
			keepalive 120s
			keepalive_idle_conns 1024
			keepalive_idle_conns_per_host 1024
		}
	}
}
EOF
cat > "$W/traefik.yml" <<EOF
global: { checkNewVersion: false, sendAnonymousUsage: false }
log: { level: ERROR }
entryPoints:
  web: { address: "127.0.0.1:29615" }
serversTransport: { maxIdleConnsPerHost: 1024 }
providers: { file: { filename: /w/traefik-dyn.yml } }
EOF
cat > "$W/traefik-dyn.yml" <<EOF
http:
  routers:
    r: { entryPoints: [web], rule: "PathPrefix(\`/\`)", service: s }
  services:
    s: { loadBalancer: { servers: [ { url: "http://127.0.0.1:$B" } ] } }
EOF
chmod 644 "$W"/*.conf "$W"/*.cfg "$W"/*.yaml "$W"/Caddyfile

start() {
	case $1 in
	okena) docker run -d --rm --name okb-okena --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" "$OKENA_IMAGE" >/dev/null ;;
	haproxy) docker run -d --rm --name okb-haproxy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okb-nginx --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okb-envoy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W:/w:ro" "$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	caddy) docker run -d --rm --name okb-caddy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$CADDY_IMAGE" caddy run --config /w/Caddyfile --adapter caddyfile >/dev/null ;;
	traefik) docker run -d --rm --name okb-traefik --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$TRAEFIK_IMAGE" --configFile=/w/traefik.yml >/dev/null ;;
	esac
	sleep 2
}
stop() { [ "$1" = direct ] || docker rm -f "okb-$1" >/dev/null; }
# one run: requests/s, 0 when not 99% of them 200
one() {
	docker run --rm --network host --cpuset-cpus "$LOAD_CPUS" "$H2LOAD_IMAGE" --h1 -t8 -c"$CONNS" -D"$DUR" \
		"http://127.0.0.1:$1/$2" 2>&1 |
		awk '/^finished in/ { gsub(",", ""); r = $4 } /^status codes:/ { ok = $3 + 0 } /^requests:/ { n = $2 + 0 }
		     END { if (ok < n * 0.99) r = 0; printf "%d\n", r }'
}

echo "| Path ($NPROXY cores) | body | Gbit/s | requests/s |"
echo "|---|---|---|---|"
taskset -c "$BACK_CPUS" "$W/l4bench" httpbig $B 16777216 & BPID=$!
sleep 0.3
for size in $SIZES; do
	for p in $ONLY; do
		[ "$p" = direct ] || start "$p"
		r=$(for i in $(seq "$REPEAT"); do one "$(port "$p")" "$size"; done | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }')
		printf '| %s | %s | %s | %s |\n' "$p" "$(numfmt --to=iec "$size")B" \
			"$(awk -v r="$r" -v s="$size" 'BEGIN { printf "%.1f", r * s * 8 / 1e9 }')" "$r"
		stop "$p"
	done
done
