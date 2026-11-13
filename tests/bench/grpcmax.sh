#!/bin/bash
# gRPC, the most each proxy does: okena, Envoy, HAProxy, nginx, Caddy and Traefik, each in a
# container on the same two cores, gRPC over h2c on both sides, in front of
# the same backend (tests/bench/grpc, Go grpc-go, an echo). The load is h2load
# posting one unary call after another (a 64-byte message in its gRPC frame,
# content-type application/grpc, te: trailers) on H2_CONNS connections of
# H2_STREAMS streams; it sees HTTP statuses only, so each proxy is first
# checked with grpcbench to end calls with grpc-status 0 (its errors column).
# With RATES, latency at those rates too: grpcbench (open loop, from the
# schedule), REPEAT times a point, the median of each percentile.
# Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/grpcmax.sh          (needs go, docker and the images)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (9-10 idle), the backend on 4-5 and 12-13, the load on the others.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GB=$ROOT/build/grpcbench
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
DUR=${DUR:-10}
H2_CONNS=${H2_CONNS:-64}
H2_STREAMS=${H2_STREAMS:-16}
ONLY=${ONLY:-direct okena envoy haproxy nginx caddy traefik}
RATES=${RATES:-}		# unary calls a second: latency at each (grpcbench, open loop)
REPEAT=${REPEAT:-3}		# each point, the median of each percentile
MOSTRUN=${MOSTRUN:-1}
B=28700 OK=28701 EN=28702 HA=28703 NG=28704 CA=28705 TR=28706
W=$(mktemp -d)
chmod 755 "$W"
BPID=
trap 'docker rm -f okg-okena okg-envoy okg-haproxy okg-nginx okg-caddy okg-traefik >/dev/null 2>&1 || true; [ -n "$BPID" ] && kill $BPID 2>/dev/null; rm -rf "$W"' EXIT

(cd "$ROOT/tests/bench/grpc" && go build -o "$GB" .)
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null
GOMAXPROCS=4 taskset -c "$BACK_CPUS" "$GB" server -addr 127.0.0.1:$B & BPID=$!

# a unary call: the gRPC frame (no compression, length) and 64 bytes
python3 -c 'import sys; sys.stdout.buffer.write(b"\0" + (64).to_bytes(4, "big") + b"x" * 64)' > "$W/call.bin"
cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY }
pool g { server 127.0.0.1:$B; protocol h2 }
http 127.0.0.1:$OK {
	http2 on
	route /* { to pool g }
}
EOF
cat > "$W/envoy.yaml" <<EOF
static_resources:
  listeners:
  - address: { socket_address: { address: 127.0.0.1, port_value: $EN } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: g
          codec_type: AUTO
          generate_request_id: false
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: g, timeout: 0s }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              dynamic_stats: false
  clusters:
  - name: g
    type: STATIC
    circuit_breakers:
      thresholds:
      - { max_connections: 1000000, max_pending_requests: 1000000, max_requests: 1000000 }
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: { http2_protocol_options: {} }
    load_assignment:
      cluster_name: g
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: $B } } }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 200000
defaults
	mode http
	timeout connect 5s
	timeout client 30s
	timeout server 30s
	http-reuse always
frontend f
	bind 127.0.0.1:$HA proto h2
	default_backend b
backend b
	server s 127.0.0.1:$B proto h2
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
events { worker_connections 65536; }
http {
	access_log off;
	keepalive_requests 1000000;
	upstream g { server 127.0.0.1:$B; keepalive 1024; keepalive_requests 1000000; }
	server {
		listen 127.0.0.1:$NG reuseport backlog=65535;
		http2 on;
		location / { grpc_pass grpc://g; }
	}
}
EOF
cat > "$W/Caddyfile" <<EOF
{
	admin off
	auto_https off
	persist_config off
	servers {
		protocols h1 h2c
	}
}
http://127.0.0.1:$CA {
	bind 127.0.0.1
	reverse_proxy h2c://127.0.0.1:$B {
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
  web: { address: "127.0.0.1:$TR" }
serversTransport: { maxIdleConnsPerHost: 1024 }
providers: { file: { filename: /w/traefik-dyn.yml } }
EOF
cat > "$W/traefik-dyn.yml" <<EOF
http:
  routers:
    r: { entryPoints: [web], rule: "PathPrefix(\`/\`)", service: s }
  services:
    s: { loadBalancer: { servers: [ { url: "h2c://127.0.0.1:$B" } ] } }
EOF
chmod 644 "$W"/*

start() {
	case $1 in
	okena) docker run -d --rm --name okg-okena --network host --cpuset-cpus "$PROXY_CPUS" \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" "$OKENA_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okg-envoy --network host --cpuset-cpus "$PROXY_CPUS" -v "$W:/w:ro" \
		"$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	haproxy) docker run -d --rm --name okg-haproxy --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okg-nginx --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	caddy) docker run -d --rm --name okg-caddy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$CADDY_IMAGE" caddy run --config /w/Caddyfile --adapter caddyfile >/dev/null ;;
	traefik) docker run -d --rm --name okg-traefik --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$TRAEFIK_IMAGE" --configFile=/w/traefik.yml >/dev/null ;;
	esac
	sleep 2
}
stop() { [ "$1" = direct ] || docker rm -f "okg-$1" >/dev/null; }
port() { case $1 in direct) echo $B ;; okena) echo $OK ;; envoy) echo $EN ;; haproxy) echo $HA ;; nginx) echo $NG ;; caddy) echo $CA ;; traefik) echo $TR ;; esac; }

# grpcbench, 2000 calls a second for 2 s: its errors (grpc-status not 0, or none)
check() {
	taskset -c "$LOAD_CPUS" "$GB" load -addr "127.0.0.1:$1" -mode unary -rate 2000 -conns 8 -dur 2s -warmup 0s 2>&1 |
		awk '{ for (i = 1; i < NF; i++) if ($i == "errors") print $(i + 1) }'
}
# h2load: calls a second, counted only over h2c and with 99% of them 200
most() {
	docker run --rm --network host --cpuset-cpus "$LOAD_CPUS" -v "$W:/w:ro" "$H2LOAD_IMAGE" -t8 \
		-c"$H2_CONNS" -m"$H2_STREAMS" -D"$DUR" -d /w/call.bin -H "content-type: application/grpc" \
		-H "te: trailers" "http://127.0.0.1:$1/bench.B/Unary" 2>&1 |
		awk '/^finished in/ { gsub(",", ""); r = $4 } /^status codes:/ { ok = $3 + 0 }
		     /^requests:/ { n = $2 + 0 } /Application protocol: *h2c/ { proto = "h2c" }
		     END { if (proto != "h2c" || ok < n * 0.99) r = 0; printf "%d", r }'
}

# lat PORT RATE: "p50 p99 p99.9 max errors" (us)
lat() {
	local i
	for i in $(seq "$REPEAT"); do
		taskset -c "$LOAD_CPUS" "$GB" load -addr "127.0.0.1:$1" -mode unary -rate "$2" -conns 64 -dur "${DUR}s" 2>/dev/null |
			awk '{ for (i = 1; i < NF; i++) v[$i] = $(i + 1) } END { print v["p50"], v["p99"], v["p99.9"], v["max"], v["errors"] }'
	done | awk '{ for (i = 1; i <= NF; i++) c[i, NR] = $i } END { for (i = 1; i <= 5; i++) {
		n = 0; for (j = 1; j <= NR; j++) a[++n] = c[i, j]
		for (x = 1; x <= n; x++) for (y = x + 1; y <= n; y++) if (a[y] + 0 < a[x] + 0) { t = a[x]; a[x] = a[y]; a[y] = t }
		printf "%s ", a[int((n + 1) / 2)] } print "" }'
}

if [ "$MOSTRUN" = 1 ]; then
echo "| Proxy ($NPROXY cores) | gRPC unary calls/s | per core | errors (grpcbench, 4000 calls) |"
echo "|---|---|---|---|"
for p in $ONLY; do
	[ "$p" = direct ] || start "$p"
	e=$(check "$(port "$p")")
	m=$(most "$(port "$p")")
	if [ "$p" = direct ]; then
		printf '| straight to the backend | %s | | %s |\n' "$m" "$e"
	else
		printf '| %s | %s | %s | %s |\n' "$p" "$m" $(( m / NPROXY )) "$e"
	fi
	stop "$p"
done
fi
if [ -n "$RATES" ]; then
	echo
	echo "| Path | rate | p50 / p99 / p99.9 / max (us) | errors |"
	echo "|---|---|---|---|"
	for p in $ONLY; do
		[ "$p" = direct ] || start "$p"
		for r in $RATES; do
			read -ra v < <(lat "$(port "$p")" "$r")
			printf '| %s | %s/s | %s / %s / %s / %s | %s |\n' "$p" "$r" "${v[0]}" "${v[1]}" "${v[2]}" "${v[3]}" "${v[4]}"
		done
		stop "$p"
	done
fi
