#!/bin/bash
# `mode xdp` over both IP families and both encapsulations, end to end, in a
# privileged container of its own network (nothing on the host changes): a
# bridge, dual stack, and on it a client, okena with six VIPs balanced in
# XDP, and two real servers, each in a namespace.
#
#   VIP                 reals   outer header        the real takes it off with
#   10.9.0.100:80       IPv4    IPv4 in IPv4        tunl0
#   [fd00::100]:80      IPv6    IPv6 in IPv6        ip6tnl0
#   10.9.0.101:80       IPv6    IPv4 in IPv6        ip6tnl0 (mode any)
#   [fd00::101]:80      IPv4    IPv6 in IPv4        sit0
#   10.9.0.102:80       IPv4    GUE over IPv4       fou port 6080 gue, tunl0
#   [fd00::102]:80      IPv6    GUE over IPv6       fou port 6080 gue -6, ip6tnl0
#
# Checks: each VIP's requests all answered, by both reals, straight back
# from them (DSR); GUE's source ports differ by flow (a real's RSS spreads
# them); a configuration naming port= without encap=gue is refused.
#
#   tests/xdp/encap.sh        (needs docker; runs a --privileged container;
#                              the reals' GUE needs fou: modprobe fou fou6)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[ -d /sys/module/fou ] && [ -d /sys/module/fou6 ] ||
	{ echo "xdp encap: the reals take GUE off with fou (sudo modprobe fou fou6)" >&2; exit 1; }
IMAGE=${LAB_IMAGE:-martenseemann/quic-network-simulator-endpoint:latest}
exec docker run --rm --privileged --network none -e N \
	-v "$ROOT/build/okena:/okena:ro" --entrypoint bash "$IMAGE" -c '
set -uo pipefail
fails=0
check() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1: $3"; fails=$((fails + 1)); fi; }
ip link add br0 type bridge; ip link set br0 up
node() {	# name, last byte of its addresses
	ip netns add $1
	ip link add $1 type veth peer name $1-b
	ip link set $1 netns $1
	ip link set $1-b master br0 up
	ip -n $1 addr add 10.9.0.$2/24 dev $1
	ip -n $1 addr add fd00::$2/64 dev $1 nodad
	ip -n $1 link set $1 up
	ip -n $1 link set lo up
}
node client 10
node lb 1
for i in 1 2; do node real$i 2$i; done
for v in 100 101 102; do
	ip -n client route add 10.9.0.$v/32 via 10.9.0.1
	ip -n client -6 route add fd00::$v/128 via fd00::1
done
# (lab only) a veth leaves TCP checksums for hardware that never comes
ip netns exec client ethtool -K client tx off >/dev/null
# (lab only) XDP_TX on a veth reaches the NAPI of its peer only when the peer
# runs an XDP program too: a counter that lets everything pass
/okena xdp lb-b 3600 >/tmp/peer.out 2>&1 &
for i in 1 2; do
	ip netns exec real$i sh -c "
		ip link add tunl0 type ipip 2>/dev/null || true
		ip link add sit0 type sit 2>/dev/null || true
		ip link add ip6tnl0 type ip6tnl 2>/dev/null || true
		ip -6 tunnel change ip6tnl0 mode any
		for d in tunl0 sit0 ip6tnl0; do ip link set \$d up; done
		ip fou add port 6080 gue
		ip fou add port 6080 gue -6
		for v in 100 101 102; do
			ip addr add 10.9.0.\$v/32 dev lo
			ip -6 addr add fd00::\$v/128 dev lo nodad
		done
		sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
			net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2
		for d in tunl0 sit0 ip6tnl0; do sysctl -qw net.ipv4.conf.\$d.rp_filter=0; done"
	printf "okena { workers 1 }\nhttp 0.0.0.0:80 [::]:80 { route /* { respond 200 \"real%s\" } }\n" $i > /tmp/real$i.conf
	ip netns exec real$i /okena -c /tmp/real$i.conf 2>>/tmp/real$i.log &
done
cat > /tmp/lb.conf <<EOF
okena { workers 1; xdp lb }
pool v4 { server 10.9.0.21:80; server 10.9.0.22:80 }
pool v6 { server [fd00::21]:80; server [fd00::22]:80 }
tcp 10.9.0.100:80 { mode xdp; to pool v4 }
tcp [fd00::100]:80 { mode xdp; to pool v6 }
tcp 10.9.0.101:80 { mode xdp; to pool v6 }
tcp [fd00::101]:80 { mode xdp; to pool v4 }
tcp 10.9.0.102:80 { mode xdp encap=gue; to pool v4 }
tcp [fd00::102]:80 { mode xdp encap=gue port=6080; to pool v6 }
http 10.9.0.1:9000 { route /* { respond 200 } }
EOF
for i in 1 2; do
	ip netns exec lb ping -c1 -W1 10.9.0.2$i >/dev/null
	ip netns exec lb ping -6 -c1 -W1 fd00::2$i >/dev/null
done
# the kernel gives XDP a next hop only where it forwards (bpf_fib_lookup)
ip netns exec lb sysctl -qw net.ipv4.conf.lb.forwarding=1 net.ipv6.conf.lb.forwarding=1
ip netns exec lb /okena -c /tmp/lb.conf 2>/tmp/lb.log &
sleep 2
grep -q "6 VIPs balanced in the driver" /tmp/lb.log && ok=1 || ok=0
check "okena.conf: six VIPs, both families, balanced in XDP" $ok "$(tail -5 /tmp/lb.log)"
ask() {		# URL N: "answered real1 real2"
	local a=0 c1=0 c2=0 got
	for k in $(seq $2); do
		got=$(ip netns exec client wget -t 1 -qO- -T 2 "$1" 2>/dev/null || true)
		case $got in real1) c1=$((c1+1)); a=$((a+1)) ;; real2) c2=$((c2+1)); a=$((a+1)) ;; esac
	done
	echo "$a $c1 $c2"
}
via() {		# label URL
	read a c1 c2 < <(ask "$2" ${N:-30})
	check "$1: ${N:-30} requests, every one answered, by both reals" \
		$([ $a = ${N:-30} ] && [ $c1 -gt 0 ] && [ $c2 -gt 0 ] && echo 1 || echo 0) "$a (real1 $c1, real2 $c2)"
}
via "IPv4 in IPv4  (10.9.0.100)" http://10.9.0.100/
via "IPv6 in IPv6  (fd00::100)" "http://[fd00::100]/"
via "IPv4 in IPv6  (10.9.0.101)" http://10.9.0.101/
via "IPv6 in IPv4  (fd00::101)" "http://[fd00::101]/"
via "GUE over IPv4 (10.9.0.102)" http://10.9.0.102/
via "GUE over IPv6 (fd00::102)" "http://[fd00::102]/"
# GUE: a source port a flow, from its hash
ip netns exec real1 sh -c "timeout 3 tcpdump -nli real1 -c 20 udp dst port 6080 2>/dev/null" > /tmp/gue.txt &
dump=$!
sleep 0.5
ask http://10.9.0.102/ 12 >/dev/null
wait $dump
ports=$(grep -o "10.9.0.1.[0-9]* >" /tmp/gue.txt | sort -u | wc -l)
check "GUE: source ports from the flows (a real spreads them by RSS)" $([ "$ports" -gt 1 ] && echo 1 || echo 0) "$ports distinct in $(wc -l < /tmp/gue.txt) packets"
# port= is GUE'"'"'s
printf "okena { xdp lb }\npool p { server 10.9.0.21:80 }\ntcp 10.9.0.103:80 { mode xdp port=7000; to pool p }\n" > /tmp/bad.conf
out=$(ip netns exec lb /okena -c /tmp/bad.conf 2>&1 || true)
echo "$out" | grep -q "with .encap=gue." && ok=1 || ok=0
check "port= without encap=gue: refused" $ok "$out"
echo "xdp encap: $([ $fails = 0 ] && echo all passed || echo $fails failed)"
exit $fails
'
