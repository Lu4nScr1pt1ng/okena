#!/bin/bash
# ICMP through the XDP balancer, end to end, IPv4 and IPv6, in a privileged
# container of its own network (nothing on the host changes):
#
#   client (MTU 1500) ----+
#   lb, real1, real2  ----+ br0 (MTU 1500)
#   rt --(1400 on rt'"'"'s side, 1500 on far'"'"'s: the bottleneck in the middle)-- far
#
# Checks:
# * ping to a VIP: answered by the balancer itself (lb's kernel does not
#   hold the VIP: only the XDP program can answer);
# * an upload of full-size packets from client: with the outer header they
#   would not fit the way to the reals; the balancer answers "fragmentation
#   needed" / "packet too big", client's kernel takes the smaller MTU, the
#   upload completes;
# * a download to far: the reals' full-size answers do not fit rt's link to
#   far; rt's ICMP goes to the VIP, the balancer carries it to the real of
#   that flow, the real's kernel takes the smaller MTU, the download
#   completes (path MTU discovery through the balancer).
#
#   tests/xdp/icmp.sh         (needs docker; runs a --privileged container)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${LAB_IMAGE:-martenseemann/quic-network-simulator-endpoint:latest}
exec docker run --rm --privileged --network none \
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
node rt 5
for i in 1 2; do node real$i 2$i; done
# far, behind rt: rt'"'"'s link to it takes 1400 bytes, far'"'"'s own 1500 (so far
# asks for full-size segments, and only rt, in the middle, finds them too big)
ip netns add far
ip link add far type veth peer name rt-far
ip link set far netns far; ip link set rt-far netns rt
ip -n far link set far up; ip -n rt link set rt-far mtu 1400 up; ip -n far link set lo up
ip -n far addr add 10.9.1.10/24 dev far; ip -n far addr add fd01::10/64 dev far nodad
ip -n rt addr add 10.9.1.1/24 dev rt-far; ip -n rt addr add fd01::1/64 dev rt-far nodad
ip -n far route add default via 10.9.1.1; ip -n far -6 route add default via fd01::1
ip netns exec rt sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
for n in client rt; do
	ip -n $n route add 10.9.0.100/32 via 10.9.0.1
	ip -n $n -6 route add fd00::100/128 via fd00::1
done
for n in real1 real2 lb; do
	ip -n $n route add 10.9.1.0/24 via 10.9.0.5
	ip -n $n -6 route add fd01::/64 via fd00::5
done
# (lab only) veths leave TCP checksums for hardware that never comes; and
# without segmentation offload the packets are the MTU, as from a NIC
for n in client far; do ip netns exec $n ethtool -K $n tx off >/dev/null; done
# (lab only) XDP_TX on a veth reaches the NAPI of its peer only when the peer
# runs an XDP program too: a counter that lets everything pass
/okena xdp lb-b 3600 >/tmp/peer.out 2>&1 &
body=$(head -c 4000 /dev/zero | tr "\\0" x)
for i in 1 2; do
	ip netns exec real$i sh -c "
		ip link add tunl0 type ipip 2>/dev/null || true
		ip link add ip6tnl0 type ip6tnl 2>/dev/null || true
		ip -6 tunnel change ip6tnl0 mode any
		ip link set tunl0 up; ip link set ip6tnl0 up
		ip addr add 10.9.0.100/32 dev lo
		ip -6 addr add fd00::100/128 dev lo nodad
		sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
			net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2
		for d in tunl0 ip6tnl0; do sysctl -qw net.ipv4.conf.\$d.rp_filter=0; done"
	printf "okena { workers 1 }\nhttp 0.0.0.0:80 [::]:80 { route /* { respond 200 \"%s\" } }\n" $body > /tmp/real$i.conf
	ip netns exec real$i /okena -c /tmp/real$i.conf 2>>/tmp/real$i.log &
done
cat > /tmp/lb.conf <<EOF
okena { workers 1; xdp lb }
pool v4 { server 10.9.0.21:80; server 10.9.0.22:80 }
pool v6 { server [fd00::21]:80; server [fd00::22]:80 }
tcp 10.9.0.100:80 { mode xdp; to pool v4 }
tcp [fd00::100]:80 { mode xdp; to pool v6 }
EOF
for i in 1 2; do
	ip netns exec lb ping -c1 -W1 10.9.0.2$i >/dev/null
	ip netns exec lb ping -6 -c1 -W1 fd00::2$i >/dev/null
done
ip netns exec lb ping -c1 -W1 10.9.0.5 >/dev/null; ip netns exec lb ping -6 -c1 -W1 fd00::5 >/dev/null
ip netns exec lb sysctl -qw net.ipv4.conf.lb.forwarding=1 net.ipv6.conf.lb.forwarding=1
ip netns exec lb /okena -c /tmp/lb.conf 2>/tmp/lb.log &
sleep 2
grep -q "2 VIPs balanced in the driver" /tmp/lb.log && ok=1 || ok=0
check "two VIPs, IPv4 and IPv6, balanced in XDP" $ok "$(tail -5 /tmp/lb.log)"
# ping
ip netns exec client ping -c2 -i0.2 -W1 10.9.0.100 >/dev/null 2>&1 && ok=1 || ok=0
check "ping 10.9.0.100: answered by the balancer" $ok ""
ip netns exec client ping -6 -c2 -i0.2 -W1 fd00::100 >/dev/null 2>&1 && ok=1 || ok=0
check "ping fd00::100: answered by the balancer" $ok ""
# an upload of full-size packets: too big with the outer header
head -c 300000 /dev/zero > /tmp/up
up() {	# URL: the answer (the real'"'"'s body) when the upload went through
	ip netns exec client wget -t 1 -qO- -T 5 --post-file=/tmp/up "$1" 2>/dev/null | head -c 10
}
[ "$(up http://10.9.0.100/)" = xxxxxxxxxx ] && ok=1 || ok=0
mtu=$(ip -n client route get 10.9.0.100 | grep -o "mtu [0-9]*" || true)
check "upload to 10.9.0.100: fragmentation needed from the balancer, done" \
	$([ $ok = 1 ] && [ "$mtu" = "mtu 1480" ] && echo 1 || echo 0) "answered $ok, client route: $mtu"
[ "$(up "http://[fd00::100]/")" = xxxxxxxxxx ] && ok=1 || ok=0
mtu=$(ip -n client -6 route get fd00::100 | grep -o "mtu [0-9]*" || true)
check "upload to fd00::100: packet too big from the balancer, done" \
	$([ $ok = 1 ] && [ "$mtu" = "mtu 1460" ] && echo 1 || echo 0) "answered $ok, client route: $mtu"
# a download to far: rt'"'"'s ICMP about the reals'"'"' answers, carried to them
down() { ip netns exec far wget -t 1 -qO- -T 5 "$1" 2>/dev/null | wc -c; }
got=$(down http://10.9.0.100/)
pm=$(for i in 1 2; do ip -n real$i route get 10.9.1.10 from 10.9.0.100 2>/dev/null | grep -o "mtu [0-9]*"; done | head -1)
check "download from 10.9.0.100 to far (MTU 1400): rt'"'"'s ICMP reached the real" \
	$([ "$got" = 4000 ] && [ "$pm" = "mtu 1400" ] && echo 1 || echo 0) "$got bytes, real route: $pm"
got=$(down "http://[fd00::100]/")
pm=$(for i in 1 2; do ip -n real$i -6 route get fd01::10 from fd00::100 2>/dev/null | grep -o "mtu [0-9]*"; done | head -1)
check "download from fd00::100 to far (MTU 1400): rt'"'"'s ICMPv6 reached the real" \
	$([ "$got" = 4000 ] && [ "$pm" = "mtu 1400" ] && echo 1 || echo 0) "$got bytes, real route: $pm"
echo "xdp icmp: $([ $fails = 0 ] && echo all passed || echo $fails failed)"
exit $fails
'
