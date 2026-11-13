#!/bin/bash
# L4, TCP and UDP: okena, HAProxy 3.2 (TCP only: UDP is not in its open
# source edition), nginx 1.27 (`stream`), Envoy 1.40 (tcp_proxy,
# udp_proxy) and Traefik 3.5 (TCP and UDP routers; Caddy has no L4 without a plugin), each in a container on the host network on the same two
# cores, in front of the same backends (tests/bench/l4bench.c: an echo, a
# sink, a UDP echo). The load, from l4bench on cores of its own:
#
#   ping 1      one TCP connection, a 64-byte message and its echo, closed
#               loop: latency
#   ping 256    256 connections, a message in flight on each at all times:
#               messages/s and latency
#   bulk        8 connections writing 64 KiB at a time to the sink: Gbit/s
#   bulk256     the same on 256 connections
#   connect     8 threads, a new connection per 64-byte exchange: per second
#   udp 1, 256  the same as ping with datagrams (lost: none back in 200 ms)
#
# REPEAT times each point, the median (by the first number). Output:
# markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/l4max.sh            (needs gcc, docker and the images)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (9-10 idle), the backends on 4-5 and 12-13, the load on the others.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA_IMAGE=${OKENA_IMAGE:-okena:bench}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-traefik:v3.5}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
BACK_CPUS=${BACK_CPUS:-4,5,12,13}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-6}
REPEAT=${REPEAT:-3}
ONLY=${ONLY:-direct okena haproxy nginx envoy traefik}
TESTS=${TESTS:-ping1 ping256 bulk bulk256 connect udp1 udp256}
W=$(mktemp -d)
chmod 755 "$W"
BENCH=$W/l4bench
PIDS=
trap 'docker rm -f okl4-okena okl4-haproxy okl4-nginx okl4-envoy okl4-traefik >/dev/null 2>&1 || true; for p in $PIDS; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT

gcc -O2 -pthread -o "$BENCH" "$ROOT/tests/bench/l4bench.c"
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null
# the backends: echo 29000, sink 29001, UDP echo 29002
taskset -c "$BACK_CPUS" "$BENCH" echo 29000 4 & PIDS="$PIDS $!"
taskset -c "$BACK_CPUS" "$BENCH" sink 29001 4 & PIDS="$PIDS $!"
taskset -c "$BACK_CPUS" "$BENCH" uecho 29002 4 & PIDS="$PIDS $!"

# ports: proxy base + 0 echo, + 1 sink, + 2 UDP echo
base() { case $1 in direct) echo 29000 ;; okena) echo 29100 ;; haproxy) echo 29200 ;; nginx) echo 29300 ;; envoy) echo 29400 ;; traefik) echo 29500 ;; esac; }

cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY; ${OKENA_EXTRA:-} }
tcp 127.0.0.1:29100 { to 127.0.0.1:29000 }
tcp 127.0.0.1:29101 { to 127.0.0.1:29001 }
udp 127.0.0.1:29102 { to 127.0.0.1:29002 }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 200000
defaults
	mode tcp
	timeout connect 5s
	timeout client 60s
	timeout server 60s
listen e
	bind 127.0.0.1:29200
	server s 127.0.0.1:29000
listen k
	bind 127.0.0.1:29201
	server s 127.0.0.1:29001
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
events { worker_connections 65536; }
stream {
	server { listen 127.0.0.1:29300 reuseport backlog=65535; proxy_pass 127.0.0.1:29000; }
	server { listen 127.0.0.1:29301 reuseport backlog=65535; proxy_pass 127.0.0.1:29001; }
	server { listen 127.0.0.1:29302 udp reuseport; proxy_pass 127.0.0.1:29002; proxy_timeout 60s; }
}
EOF
cluster() {
	cat <<EOF
  - name: $1
    type: STATIC
    circuit_breakers:
      thresholds:
      - { max_connections: 1000000, max_pending_requests: 1000000, max_requests: 1000000 }
    load_assignment:
      cluster_name: $1
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: $2 } } }
EOF
}
tcpl() {
	cat <<EOF
  - name: $1
    address: { socket_address: { address: 127.0.0.1, port_value: $2 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: $1
          cluster: $3
EOF
}
{
	echo "static_resources:"
	echo "  listeners:"
	tcpl e 29400 echo
	tcpl k 29401 sink
	cat <<EOF
  - name: u
    address: { socket_address: { protocol: UDP, address: 127.0.0.1, port_value: 29402 } }
    listener_filters:
    - name: envoy.filters.udp_listener.udp_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig
        stat_prefix: u
        idle_timeout: 60s
        matcher:
          on_no_match:
            action:
              name: route
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route
                cluster: uecho
EOF
	echo "  clusters:"
	cluster echo 29000
	cluster sink 29001
	cluster uecho 29002
} > "$W/envoy.yaml"
cat > "$W/traefik.yml" <<EOF
global: { checkNewVersion: false, sendAnonymousUsage: false }
log: { level: ERROR }
entryPoints:
  e: { address: "127.0.0.1:29500" }
  k: { address: "127.0.0.1:29501" }
  u: { address: "127.0.0.1:29502/udp", udp: { timeout: 60s } }
providers: { file: { filename: /w/traefik-dyn.yml } }
EOF
cat > "$W/traefik-dyn.yml" <<EOF
tcp:
  routers:
    e: { entryPoints: [e], rule: "HostSNI(\`*\`)", service: e }
    k: { entryPoints: [k], rule: "HostSNI(\`*\`)", service: k }
  services:
    e: { loadBalancer: { servers: [ { address: "127.0.0.1:29000" } ] } }
    k: { loadBalancer: { servers: [ { address: "127.0.0.1:29001" } ] } }
udp:
  routers:
    u: { entryPoints: [u], service: u }
  services:
    u: { loadBalancer: { servers: [ { address: "127.0.0.1:29002" } ] } }
EOF
chmod 644 "$W"/*.conf "$W"/*.cfg "$W"/*.yaml

start() {
	case $1 in
	okena) docker run -d --rm --name okl4-okena --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" "$OKENA_IMAGE" >/dev/null ;;
	haproxy) docker run -d --rm --name okl4-haproxy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okl4-nginx --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okl4-envoy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W:/w:ro" "$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	traefik) docker run -d --rm --name okl4-traefik --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$TRAEFIK_IMAGE" --configFile=/w/traefik.yml >/dev/null ;;
	esac
	sleep 2
}
stop() { [ "$1" = direct ] || docker rm -f "okl4-$1" >/dev/null; }

L() { timeout $((DUR + 20)) taskset -c "$LOAD_CPUS" "$BENCH" "$@"; }
one() {	# test port: one line of l4bench's output
	case $1 in
	ping1) L ping 127.0.0.1 "$2" 1 1 "$DUR" 64 ;;
	ping256) L pingep 127.0.0.1 "$2" 256 8 "$DUR" 64 ;;
	bulk) L blast 127.0.0.1 $(($2 + 1)) 8 8 "$DUR" ;;
	bulk256) L blast 127.0.0.1 $(($2 + 1)) 256 8 "$DUR" ;;
	connect) L cps 127.0.0.1 "$2" 8 "$DUR" ;;
	udp1) L uping 127.0.0.1 $(($2 + 2)) 1 1 "$DUR" 64 ;;
	udp256) L uping 127.0.0.1 $(($2 + 2)) 256 8 "$DUR" 64 ;;
	esac
}
# the median of REPEAT runs, by the first number
med() {
	local i
	for i in $(seq "$REPEAT"); do one "$1" "$2" || echo "0 failed"; done |
		sort -n | awk '{ l[NR] = $0 } END { print l[int((NR + 1) / 2)] }'
}
# l4bench's line as a row: "rate | p50 / p99 / p99.9 / max | lost"
cells() {
	awk '/Gbit/ { print $1 " Gbit/s | | "; next }
	     { printf "%s/s | %s / %s / %s / %s | %s\n", $1, $4, $7, $10, $13, ($(NF - 1) == "lost" ? $NF : "") }'
}

echo "| Path ($NPROXY cores) | test | rate | p50 / p99 / p99.9 / max (µs) | lost |"
echo "|---|---|---|---|---|"
for p in $ONLY; do
	[ "$p" = direct ] || start "$p"
	b=$(base "$p")
	for t in $TESTS; do
		case $p:$t in haproxy:udp*) continue ;; esac
		printf '| %s | %s | %s |\n' "$p" "$t" "$(med "$t" "$b" | cells)"
	done
	stop "$p"
done
