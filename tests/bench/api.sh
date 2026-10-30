#!/bin/bash
# okena against HAProxy in front of a real API: fasm2crud (an HTTP/1.1 JSON
# API in assembly, PostgreSQL behind it). The same backend, the same load,
# cores pinned; each scenario also run straight to the backend, so what a
# proxy adds shows. Output: markdown table rows for docs/BENCHMARK.md.
#
# The backend must be running (outside this script):
#   cd ../fasm2Crud && docker compose up -d postgres migrate
#   API_PORT=28080 API_WORKERS=2 API_RATE=0 API_DB_HOST=10.231.0.10 ... \
#       taskset -c 3,4 ./build/fasm2crud
#
#   tests/bench/api.sh        (docker for HAProxy, wrk, openssl, curl)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2,
# the backend on 3-4, wrk on 5-7 and 13-15, PostgreSQL wherever it is.
# wrk is a closed-loop generator: its latencies are not corrected for
# coordinated omission.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
BACKEND=${BACKEND:-127.0.0.1:28080}
PROXY_CPUS=${PROXY_CPUS:-1,2}
WRK_CPUS=${WRK_CPUS:-5,6,7,13,14,15}
DUR=${DUR:-10s}
CONNS=${CONNS:-64}
W=$(mktemp -d)
chmod 755 "$W"				# HAProxy reads it as its own non-root user
OKPID=
trap 'docker rm -f okb-haproxy >/dev/null 2>&1 || true; [ -n "$OKPID" ] && kill $OKPID 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"

curl -q -sf "http://$BACKEND/readyz" >/dev/null || { echo "the backend at $BACKEND is not ready" >&2; exit 1; }

# an account, its token and a note
EMAIL="bench$$-$RANDOM@okena.test"
J='Content-Type: application/json'
curl -q -sf -X POST "http://$BACKEND/v1/auth/register" -H "$J" \
	-d "{\"email\":\"$EMAIL\",\"password\":\"bench-password-1\"}" >/dev/null
TOKEN=$(curl -q -sf -X POST "http://$BACKEND/v1/auth/login" -H "$J" \
	-d "{\"email\":\"$EMAIL\",\"password\":\"bench-password-1\"}" | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
NOTE=$(curl -q -sf -i -X POST "http://$BACKEND/v1/notes" -H "$J" -H "Authorization: Bearer $TOKEN" \
	-d '{"title":"bench","body":"a note read by the benchmark"}' | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}')
cat > post.lua <<EOF
wrk.method = "POST"
wrk.body = '{"title":"bench write","body":"one more note"}'
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Authorization"] = "Bearer $TOKEN"
EOF

openssl ecparam -genkey -name prime256v1 -noout -out key.pem 2>/dev/null
openssl req -new -x509 -key key.pem -subj /CN=bench.test -addext subjectAltName=DNS:bench.test \
	-days 2 -out cert.pem 2>/dev/null
cat cert.pem key.pem > combined.pem
chmod 644 ./*.pem
cat > x25519.cnf <<'EOF'
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Groups = X25519
EOF

# wrk: "req/s p50 p99 non2xx" (latency in microseconds)
wrk_run() {
	local url=$1; shift
	taskset -c "$WRK_CPUS" wrk -t6 -c"$CONNS" -d"$DUR" --latency "$@" "$url" > wrk.out 2>&1 || true
	local rps p50 p99 bad
	rps=$(awk '/Requests\/sec/ {print int($2)}' wrk.out)
	p50=$(awk '$1=="50%" {print $2}' wrk.out)
	p99=$(awk '$1=="99%" {print $2}' wrk.out)
	bad=$(awk '/Non-2xx/ {print $NF} /Socket errors/ {s=$0} END {}' wrk.out)
	echo "${rps:-0} $(to_us "${p50:-?}") $(to_us "${p99:-?}") ${bad:-0}"
}
to_us() {
	case "$1" in
		*us) echo "${1%us}" ;;
		*ms) awk -v v="${1%ms}" 'BEGIN { printf "%.0f", v * 1000 }' ;;
		*s) awk -v v="${1%s}" 'BEGIN { printf "%.0f", v * 1000000 }' ;;
		*) echo "?" ;;
	esac
}
row() { printf '| %s | %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4 / $5" "$6"; }

# scenario name, url path, scheme+port per server, extra wrk args
scenarios() {	# $1 = server label, $2 = http base, $3 = https base (or -), $4 = tcp base (or -)
	local s=$1 h=$2 t=$3 l=$4 r a b n
	read -r r a b n < <(wrk_run "$h/healthz")
	row "GET /healthz, keep-alive" "$s" "$r" "$a" "$b" "$n"
	read -r r a b n < <(wrk_run "$h$NOTE" -H "Authorization: Bearer $TOKEN")
	row "GET a note (token + PostgreSQL), keep-alive" "$s" "$r" "$a" "$b" "$n"
	read -r r a b n < <(wrk_run "$h/v1/notes" -s post.lua)
	row "POST a note (PostgreSQL write), keep-alive" "$s" "$r" "$a" "$b" "$n"
	if [ "$l" != - ]; then
		read -r r a b n < <(wrk_run "$l/healthz")
		row "GET /healthz through TCP (L4)" "$s" "$r" "$a" "$b" "$n"
	fi
	if [ "$t" != - ]; then
		read -r r a b n < <(wrk_run "$t/healthz")
		row "HTTPS GET /healthz, keep-alive" "$s" "$r" "$a" "$b" "$n"
		read -r r a b n < <(wrk_run "$t$NOTE" -H "Authorization: Bearer $TOKEN")
		row "HTTPS GET a note, keep-alive" "$s" "$r" "$a" "$b" "$n"
		read -r r a b n < <(OPENSSL_CONF=$W/x25519.cnf wrk_run "$t/healthz" -H "Connection: close")
		row "HTTPS, a new connection per request (x25519, ECDSA)" "$s" "$r" "$a" "$b" "$n"
		read -r r a b n < <(wrk_run "$t/healthz" -H "Connection: close")
		row "HTTPS, a new connection per request (X25519MLKEM768)" "$s" "$r" "$a" "$b" "$n"
	fi
}

cat > okena.conf <<EOF
tcp 127.0.0.1:28100 { to $BACKEND }
http 127.0.0.1:28101 { route /* { to $BACKEND } }
http 127.0.0.1:28102 {
	tls { cert $W/cert.pem; key $W/key.pem }
	route /* { to $BACKEND }
}
EOF
cat > haproxy.cfg <<EOF
global
	nbthread 2
	maxconn 100000
	ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
defaults
	timeout connect 5s
	timeout client 30s
	timeout server 30s
frontend f_tcp
	mode tcp
	bind 127.0.0.1:28200
	default_backend b_tcp
backend b_tcp
	mode tcp
	server s1 $BACKEND
frontend f_http
	mode http
	bind 127.0.0.1:28201
	bind 127.0.0.1:28202 ssl crt /w/combined.pem alpn http/1.1
	default_backend b_http
backend b_http
	mode http
	http-reuse always
	server s1 $BACKEND
EOF

chmod 644 okena.conf haproxy.cfg post.lua x25519.cnf
echo "| Scenario | Server | req/s | p50 / p99 (us) | non-2xx |"
echo "|---|---|---|---|---|"
scenarios "fasm2crud direct" "http://$BACKEND" - -

taskset -c "$PROXY_CPUS" "$OKENA" -c "$W/okena.conf" 2> okena.log &
OKPID=$!
sleep 1
scenarios "okena, 2 cores" http://127.0.0.1:28101 https://127.0.0.1:28102 http://127.0.0.1:28100
kill $OKPID; wait $OKPID 2>/dev/null || true; OKPID=

docker run -d --rm --name okb-haproxy --network host --cpuset-cpus "$PROXY_CPUS" \
	-v "$W:/w:ro" "$HAPROXY_IMAGE" haproxy -f /w/haproxy.cfg >/dev/null
sleep 1.5
scenarios "HAProxy 3.2, 2 threads" http://127.0.0.1:28201 https://127.0.0.1:28202 http://127.0.0.1:28200
docker rm -f okb-haproxy >/dev/null
