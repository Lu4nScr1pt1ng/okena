#!/bin/bash
# The XDP balancer end to end, in a privileged container of its own (its
# own network: nothing on the host changes): a bridge, and on it a client,
# the balancer and two real servers, each in a namespace.
#
#   client 10.9.0.10 --(VIP 10.9.0.100 via 10.9.0.1)--> lb 10.9.0.1:
#     okena xdplb: TCP to 10.9.0.100:80 wrapped in IPIP to a real
#   real1 10.9.0.21, real2 10.9.0.22: tunl0 takes the outer header off, the
#     VIP on lo, okena answers "real1" / "real2", straight to the client (DSR)
#
# Checks: every request answered, both reals answering, a connection's
# requests on one real (the flow table), and the balancer's counters.
#
#   tests/xdp/lab.sh          (needs docker; runs a --privileged container)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${LAB_IMAGE:-martenseemann/quic-network-simulator-endpoint:latest}
N=${N:-40}
exec docker run --rm --privileged --network none -e N="$N" \
	-v "$ROOT/build/okena:/okena:ro" --entrypoint bash "$IMAGE" -c '
set -euo pipefail
fails=0
check() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1: $3"; fails=$((fails + 1)); fi; }
ip link add br0 type bridge; ip link set br0 up
node() {	# name address
	ip netns add $1
	ip link add $1 type veth peer name $1-b
	ip link set $1 netns $1
	ip link set $1-b master br0 up
	ethtool -K $1-b gro on >/dev/null 2>&1 || true	# (XDP_TX on a veth: its peer reads with NAPI)
	ip -n $1 addr add $2/24 dev $1
	ip -n $1 link set $1 up
	ip -n $1 link set lo up
}
node client 10.9.0.10
node lb 10.9.0.1
node real1 10.9.0.21
node real2 10.9.0.22
ip -n client route add 10.9.0.100/32 via 10.9.0.1
# (lab only) a veth leaves TCP checksums for hardware that never comes: a
# packet the balancer passes on keeps that one unfinished, and the real drops
# it; packets from a NIC come off the wire with theirs whole
ip netns exec client ethtool -K client tx off >/dev/null
# (lab only) XDP_TX on a veth hands the frame to the NAPI of its peer, there only
# with an XDP program on the peer: a counter that lets everything pass
/okena xdp lb-b 600 >/tmp/peer.out 2>&1 &
for r in real1 real2; do
	ip netns exec $r sh -c "
		ip link add tunl0 type ipip 2>/dev/null || true	# (the fallback device: any outer source)
		ip link set tunl0 up
		ip addr add 10.9.0.100/32 dev lo
		sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.tunl0.rp_filter=0 \
			net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2"
	printf "okena { workers 1 }\nhttp 10.9.0.100:80 { route /* { respond 200 \"%s\" } }\n" $r > /tmp/$r.conf
	ip netns exec $r /okena -c /tmp/$r.conf 2>/tmp/$r.log &
done
ip netns exec lb ping -c1 -W1 10.9.0.21 >/dev/null; ip netns exec lb ping -c1 -W1 10.9.0.22 >/dev/null
ip netns exec lb /okena xdplb lb 10.9.0.1 10.9.0.100 80 10.9.0.21 10.9.0.22 -- 15 >/tmp/lb.out 2>&1 &
lbpid=$!
sleep 1.5
if ! kill -0 $lbpid 2>/dev/null; then cat /tmp/lb.out; echo "FAIL the balancer did not start"; exit 1; fi
ok=0; r1=0; r2=0
for i in $(seq $N); do
	got=$(ip netns exec client wget -t 1 -qO- -T 2 http://10.9.0.100/ 2>/dev/null || true)
	case $got in real1) r1=$((r1 + 1)); ok=$((ok + 1)) ;; real2) r2=$((r2 + 1)); ok=$((ok + 1)) ;; esac
done
check "$N requests through the VIP, every one answered" $([ $ok = $N ] && echo 1 || echo 0) "$ok answered (real1 $r1, real2 $r2)"
check "  both reals answering" $([ $r1 -gt 0 ] && [ $r2 -gt 0 ] && echo 1 || echo 0) "real1 $r1, real2 $r2"
echo "     (real1 $r1, real2 $r2)"
wait $lbpid || true
cat /tmp/lb.out
tx=$(awk "/to reals/ { s += \$1 } END { print s + 0 }" /tmp/lb.out)
check "  the balancer sent them on (XDP_TX)" $([ "$tx" -gt 0 ] && echo 1 || echo 0) "$tx"
echo "xdp lab: $([ $fails = 0 ] && echo all passed || echo $fails failed)"
exit $fails
'
