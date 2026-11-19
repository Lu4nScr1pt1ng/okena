#!/usr/bin/env sh
# A short check of a built binary, for CI and releases (the full suites are
# `make test`): its version, every example accepted by `okena check`, and a
# request proxied on each I/O engine.
#   scripts/smoke.sh [BINARY]
set -eu
BIN="${1:-build/okena}"
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$T"' EXIT

"$BIN" version

# the examples, with the files they name made up here
mkdir -p "$T/www"
echo '<h1>ok</h1>' > "$T/www/index.html"
echo "user:c0ffee:$(printf 'c0ffeepass' | sha256sum | cut -d' ' -f1)" > "$T/proxy.users"
printf '{"keys":[{"kty":"oct","kid":"k1","alg":"HS256","k":"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA"}]}' > "$T/jwks.json"
for f in examples/*.conf docker/okena.conf; do
	sed -e "s#/srv/www#$T/www#; s#/etc/okena/proxy.users#$T/proxy.users#; s#/etc/okena/jwks.json#$T/jwks.json#" "$f" > "$T/c.conf"
	"$BIN" check "$T/c.conf" >/dev/null || { echo "FAIL $f"; "$BIN" check "$T/c.conf"; exit 1; }
	echo "ok   okena check $f"
done

# a request through it, on each engine
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$T/www" >/dev/null 2>&1 &
for engine in io_uring epoll; do
	cat > "$T/run.conf" <<C
okena { workers 1; io_engine $engine; drain delay=0s timeout=1s }
pool app { server 127.0.0.1:18081 }
http 127.0.0.1:18080 { route /* { to pool app } }
C
	"$BIN" -c "$T/run.conf" 2> "$T/log" &
	pid=$!
	got=""
	for i in $(seq 1 50); do
		got=$(curl -fs http://127.0.0.1:18080/ 2>/dev/null || true)
		[ -n "$got" ] && break
		sleep 0.1
	done
	kill "$pid"; wait "$pid" 2>/dev/null || true
	case "$got" in
	*'<h1>ok</h1>'*) echo "ok   a request proxied, io_engine $engine" ;;
	*) echo "FAIL proxied on $engine"; cat "$T/log"; exit 1 ;;
	esac
done
echo "smoke: all passed"
