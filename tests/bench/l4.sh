#!/usr/bin/env sh
# Added latency of the L4 proxy: the same closed-loop ping-pong, straight
# to an echo backend and through okena. Cores are kept apart: backend 4-7,
# okena 0-3, client 8-15.
set -eu
cd "$(dirname "$0")/../.."
mkdir -p build
gcc -O2 -pthread -o build/l4bench tests/bench/l4bench.c
taskset -c 4-7 build/l4bench echo 17000 4 & echo_pid=$!
taskset -c 0-3 build/okena tcp 127.0.0.1:17500 to 127.0.0.1:17000 2>/dev/null & okena_pid=$!
trap 'kill $echo_pid $okena_pid 2>/dev/null' EXIT
sleep 0.5
for conns in 1 256; do
	threads=1; [ "$conns" -gt 1 ] && threads=8
	printf 'direct, %s conn(s):  ' "$conns"
	taskset -c 8-15 build/l4bench ping 127.0.0.1 17000 "$conns" "$threads" 5 64
	printf 'okena,  %s conn(s):  ' "$conns"
	taskset -c 8-15 build/l4bench ping 127.0.0.1 17500 "$conns" "$threads" 5 64
done
