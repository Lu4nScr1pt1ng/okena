#!/bin/bash
# The XDP balancer against Katran's: packets a second on one core, flows in
# the table (est) and every packet a new flow (new). Katran's balancer.bpf.c
# at KATRAN_REV, built with the clang and loaded with the libbpf of the
# container (tests/bench/xdp/), its maps filled as its control plane does;
# katran-noflood: the same with MAX_CONN_RATE out of reach, so it remembers
# every new flow as okena does below its own bound.
#
#   tests/bench/xdp.sh            (needs docker, the pktgen module: modprobe
#                                  pktgen; a --privileged container with
#                                  --pid host, to pin the NAPI threads)
#   MODES="est new" WHO="base okena katran katran-noflood okena-drop" SECS=5 GENS="2 10 3"
#   LB_CPU=4 PEER_CPU=6 FLOWS=1024
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KATRAN_REV=04a473356295c805993164c7ca20414f46222cb8
W=$ROOT/build/xdpbench
IMAGE=okena-xdpbench
[ -d /proc/net/pktgen ] || { echo "xdp bench: no pktgen (sudo modprobe pktgen)" >&2; exit 1; }
[ -x "$ROOT/build/okena" ] || { echo "xdp bench: build okena first (make)" >&2; exit 1; }
mkdir -p "$W"
if [ ! -d "$W/katran" ]; then
	git clone -q https://github.com/facebookincubator/katran.git "$W/katran"
fi
git -C "$W/katran" checkout -q "$KATRAN_REV"
docker build -q -t $IMAGE "$ROOT/tests/bench/xdp" >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/o:ro" -v "$W:/b" $IMAGE sh -c '
	set -e
	mkdir -p /b/stub/gnu; : > /b/stub/gnu/stubs-32.h	# (glibc headers ask for it with -target bpf)
	I="-I /b/stub -I /usr/include/x86_64-linux-gnu"
	K="$I -I /b/katran -I /b/katran/katran/lib/linux_includes -D__KERNEL__ -O2 -g -target bpf
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types"
	clang $K -c /b/katran/katran/lib/bpf/balancer.bpf.c -o /b/balancer.bpf.o
	clang $K -DMAX_CONN_RATE=4000000000 -c /b/katran/katran/lib/bpf/balancer.bpf.c -o /b/balancer-noflood.bpf.o
	clang $I -O2 -g -target bpf -c /o/tests/bench/xdp/base.bpf.c -o /b/base.bpf.o
	gcc -O2 -Wall -o /b/kload /o/tests/bench/xdp/kload.c -lbpf'
for mode in ${MODES:-est new}; do
	docker run --rm --privileged --pid host --network none \
		-e MODE=$mode -e WHO -e SECS -e GENS -e LB_CPU -e PEER_CPU -e FLOWS \
		-v "$W:/b:ro" -v "$ROOT/build/okena:/okena:ro" -v "$ROOT/tests/bench/xdp/lab.sh:/lab.sh:ro" \
		$IMAGE bash /lab.sh
done
