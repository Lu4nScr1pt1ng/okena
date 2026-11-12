#!/bin/bash
# `mode xdp` from okena.conf, end to end, in a privileged container of its own
# network (nothing on the host changes): a bridge, and on it a client, okena
# with a VIP balanced in XDP, and three real servers, each in a namespace.
#
#   okena.conf:  okena { xdp lb }
#                pool web { server 10.9.0.21:80; ...; health tcp every=200ms fall=2 rise=2 }
#                tcp 10.9.0.100:80 { mode xdp; to pool web }
#
# Checks: requests through the VIP all answered, spread over the reals,
# straight back from them (DSR); a real stopped: taken out of the ring by
# the health checks, its share to the others, no request lost after; back:
# taken in again; okena-xdp killed: restarted, the balancer serving meanwhile.
#
#   tests/xdp/vip.sh          (needs docker; runs a --privileged container)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${LAB_IMAGE:-martenseemann/quic-network-simulator-endpoint:latest}
exec docker run --rm --privileged --network none \
	-v "$ROOT/build/okena:/okena:ro" --entrypoint bash "$IMAGE" -c '
set -uo pipefail
fails=0
check() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1: $3"; fails=$((fails + 1)); fi; }
ip link add br0 type bridge; ip link set br0 up
node() {	# name address
	ip netns add $1
	ip link add $1 type veth peer name $1-b
	ip link set $1 netns $1
	ip link set $1-b master br0 up
	ip -n $1 addr add $2/24 dev $1
	ip -n $1 link set $1 up
	ip -n $1 link set lo up
}
node client 10.9.0.10
node lb 10.9.0.1
for i in 1 2 3; do node real$i 10.9.0.2$i; done
ip -n client route add 10.9.0.100/32 via 10.9.0.1
# (lab only) a veth leaves TCP checksums for hardware that never comes; a NIC
# hands frames over with theirs whole
ip netns exec client ethtool -K client tx off >/dev/null
# (lab only) XDP_TX on a veth reaches the NAPI of its peer only when the peer
# runs an XDP program too: a counter that lets everything pass
/okena xdp lb-b 3600 >/tmp/peer.out 2>&1 &
real_start() {
	ip netns exec real$1 /okena -c /tmp/real$1.conf 2>>/tmp/real$1.log &
	echo $! > /tmp/real$1.pid
}
for i in 1 2 3; do
	ip netns exec real$i sh -c "
		ip link add tunl0 type ipip 2>/dev/null || true
		ip link set tunl0 up
		ip addr add 10.9.0.100/32 dev lo
		sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.tunl0.rp_filter=0 \
			net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2"
	printf "okena { workers 1 }\nhttp :80 { route /* { respond 200 \"real%s\" } }\n" $i > /tmp/real$i.conf
	real_start $i
done
cat > /tmp/lb.conf <<EOF
okena { workers 1; xdp lb }
pool web {
	server 10.9.0.21:80
	server 10.9.0.22:80
	server 10.9.0.23:80
	health tcp every=200ms fall=2 rise=2
}
tcp 10.9.0.100:80 { mode xdp; to pool web }
http 10.9.0.1:9000 { route /* { respond 200 } }
EOF
for i in 1 2 3; do ip netns exec lb ping -c1 -W1 10.9.0.2$i >/dev/null; done
ip netns exec lb /okena -c /tmp/lb.conf 2>/tmp/lb.log &
sleep 2
grep -q "VIPs balanced in the driver" /tmp/lb.log && ok=1 || ok=0
check "okena.conf: the VIP balanced in XDP" $ok "$(tail -5 /tmp/lb.log)"
ask() {		# N requests: "answered real1 real2 real3"
	local n=$1 a=0 c1=0 c2=0 c3=0 got
	for k in $(seq $n); do
		got=$(ip netns exec client wget -t 1 -qO- -T 2 http://10.9.0.100/ 2>/dev/null || true)
		case $got in real1) c1=$((c1+1)); a=$((a+1)) ;; real2) c2=$((c2+1)); a=$((a+1)) ;; real3) c3=$((c3+1)); a=$((a+1)) ;; esac
	done
	echo "$a $c1 $c2 $c3"
}
read a c1 c2 c3 < <(ask 60)
check "60 requests through the VIP, every one answered" $([ $a = 60 ] && echo 1 || echo 0) "$a (real1 $c1, real2 $c2, real3 $c3)"
check "  spread over the three reals" $([ $c1 -gt 0 ] && [ $c2 -gt 0 ] && [ $c3 -gt 0 ] && echo 1 || echo 0) "real1 $c1, real2 $c2, real3 $c3"
echo "     (real1 $c1, real2 $c2, real3 $c3)"
# a real goes: the health checks take it out of the ring
kill $(cat /tmp/real2.pid); sleep 1.5
read a c1 c2 c3 < <(ask 40)
check "real2 stopped: every request answered by the others" $([ $a = 40 ] && [ $c2 = 0 ] && echo 1 || echo 0) "$a (real1 $c1, real2 $c2, real3 $c3)"
# back: in again
real_start 2; sleep 1.5
read a c1 c2 c3 < <(ask 60)
check "real2 back: in the ring again" $([ $a = 60 ] && [ $c2 -gt 0 ] && echo 1 || echo 0) "$a (real1 $c1, real2 $c2, real3 $c3)"
# okena-xdp killed: the balancer serves meanwhile, it is started again
pkill -x okena-xdp 2>/dev/null || kill $(ps -eo pid,comm | awk "\$2 == \"okena-xdp\" { print \$1 }")
read a c1 c2 c3 < <(ask 20)
check "okena-xdp killed: still served (the maps stay)" $([ $a = 20 ] && echo 1 || echo 0) "$a"
sleep 2
ps -eo comm | grep -qx okena-xdp && ok=1 || ok=0
check "  and started again" $ok "$(tail -3 /tmp/lb.log)"
echo "xdp vip: $([ $fails = 0 ] && echo all passed || echo $fails failed)"
exit $fails
'
