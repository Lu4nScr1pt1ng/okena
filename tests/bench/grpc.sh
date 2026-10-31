#!/bin/bash
# gRPC against Envoy, open loop: okena and Envoy (official image, host
# network) on the same two cores in front of the same gRPC backend (Go,
# grpc-go, tests/bench/grpc), plain HTTP/2 both sides, loaded by the same
# program on cores of its own. Unary calls, and messages of server-
# streaming calls held open; each at fixed rates, straight to the backend
# first: what a proxy adds is its latency minus that (at the top rates the
# load program itself is near its limit, and the difference is noise or
# below zero). Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/grpc.sh           (needs go, network once for its modules,
#                                  and docker for Envoy)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (siblings 9-10 left idle), the backend on 4-5 (12-13 idle), the load on
# the four other physical cores, both threads of each.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
GB=$ROOT/build/grpcbench
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
PROXY_CPUS=${PROXY_CPUS:-1,2}
BACK_CPUS=${BACK_CPUS:-4,5}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-10s}
CONNS=${CONNS:-8}
UNARY_RATES=${UNARY_RATES:-5000 20000 40000}
STREAM_RATES=${STREAM_RATES:-5000 20000 80000}
W=$(mktemp -d)
chmod 755 "$W"
BPID= OKPID=
trap 'docker rm -f okb-envoy >/dev/null 2>&1 || true; for p in $OKPID $BPID; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT

(cd "$ROOT/tests/bench/grpc" && go build -o "$GB" .)
GOMAXPROCS=2 taskset -c "$BACK_CPUS" "$GB" server -addr 127.0.0.1:28500 & BPID=$!
cat > "$W/okena.conf" <<EOF
okena { workers 2 }
http 127.0.0.1:28501 {
	http2 on
	route /* { to pool grpc }
}
pool grpc {
	protocol h2
	server 127.0.0.1:28500
}
EOF
cat > "$W/envoy.yaml" <<EOF
static_resources:
  listeners:
  - address: { socket_address: { address: 127.0.0.1, port_value: 28502 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: grpc
          codec_type: HTTP2
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: grpc, timeout: 0s }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: grpc
    type: STATIC
    circuit_breakers:             # the defaults (1024) would refuse, not queue
      thresholds:
      - { max_connections: 1000000, max_pending_requests: 1000000, max_requests: 1000000 }
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: { http2_protocol_options: {} }
    load_assignment:
      cluster_name: grpc
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: 28500 } } }
EOF
chmod 644 "$W"/*

# load PORT MODE RATE: "rate p50 p99 p99.9 max errors" (latency in us)
load() {
	GOMAXPROCS=8 taskset -c "$LOAD_CPUS" "$GB" load -addr "127.0.0.1:$1" -mode "$2" -rate "$3" \
		-conns "$CONNS" -dur "$DUR" 2>/dev/null |
		awk '{ printf "%s %s %s %s %s %s\n", $2, $4, $8, $10, $12, $15 }'
}
declare -A BASE
baseline() {
	local m r v
	for m in unary stream; do
		local rates=$UNARY_RATES
		[ "$m" = stream ] && rates=$STREAM_RATES
		for r in $rates; do
			read -ra v < <(load 28500 "$m" "$r")
			BASE[$m.$r.p50]=${v[1]} BASE[$m.$r.p99]=${v[2]}
			printf '| %s, %s/s | direct | %s | %s / %s / %s / %s | | %s |\n' "$m" "$r" "${v[0]}" "${v[1]}" "${v[2]}" "${v[3]}" "${v[4]}" "${v[5]}"
		done
	done
}
scenarios() {	# label port
	local m r v
	for m in unary stream; do
		local rates=$UNARY_RATES
		[ "$m" = stream ] && rates=$STREAM_RATES
		for r in $rates; do
			read -ra v < <(load "$2" "$m" "$r")
			printf '| %s, %s/s | %s | %s | %s / %s / %s / %s | %+d / %+d | %s |\n' "$m" "$r" "$1" "${v[0]}" \
				"${v[1]}" "${v[2]}" "${v[3]}" "${v[4]}" $((${v[1]} - ${BASE[$m.$r.p50]})) \
				$((${v[2]} - ${BASE[$m.$r.p99]})) "${v[5]}"
		done
	done
}

echo "| Scenario | Path | rate | p50 / p99 / p99.9 / max (us) | added p50 / p99 | errors |"
echo "|---|---|---|---|---|---|"
sleep 0.5
baseline
taskset -c "$PROXY_CPUS" "$OKENA" -c "$W/okena.conf" 2> "$W/okena.log" & OKPID=$!
sleep 1
scenarios "okena, 2 cores" 28501
kill $OKPID; wait $OKPID 2>/dev/null || true; OKPID=

docker run -d --rm --name okb-envoy --network host --cpuset-cpus "$PROXY_CPUS" \
	-v "$W:/w:ro" "$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency 2 -l warn >/dev/null
sleep 2
scenarios "Envoy $(docker run --rm --entrypoint envoy "$ENVOY_IMAGE" --version | grep -o '/1\.[0-9.]*/' | tr -d /), 2 threads" 28502
docker rm -f okb-envoy >/dev/null
