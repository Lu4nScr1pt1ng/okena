#!/bin/bash
# Inside the bench's container (tests/bench/xdp.sh starts it): packets a
# second through an XDP balancer on one core.
#
#   pktgen (gen, CPUs $GENS) -> xg0 ==veth== xl0 (lb: the balancer, its NAPI
#   a thread pinned to $LB_CPU) -> IPIP, XDP_TX -> xg0 (xdp_drop, on $PEER_CPU)
#
# The veth hands the balancer skbs it turns into XDP buffers (a copy): the
# same for every balancer, and `base` (XDP_TX and nothing else) says what
# that path costs alone. A balancer's number is the XDP_TX count of xl0, a
# second at a time, the median; its core must be busy all the time (else
# the generator, not the balancer, set the number: it says so).
#
#   MODE=est   FLOWS UDP flows over and over (in the flow table)
#   MODE=new   source address and port drawn for each packet (all new)
set -uo pipefail
GENS=${GENS:-2 10 3} LB_CPU=${LB_CPU:-4} PEER_CPU=${PEER_CPU:-6}
SECS=${SECS:-5} FLOWS=${FLOWS:-1024} MODE=${MODE:-est}
WHO=${WHO:-base okena katran katran-noflood}
B=/b
ip netns add gen; ip netns add lb
ip link add xg0 type veth peer name xl0
ip link set xg0 netns gen; ip link set xl0 netns lb
ip -n gen addr add 10.9.0.10/24 dev xg0; ip -n gen link set xg0 up
ip -n lb addr add 10.9.0.1/24 dev xl0; ip -n lb link set xl0 up; ip -n lb link set lo up
mac() { ip -n $1 -o link show $2 | grep -o 'link/ether [0-9a-f:]*' | cut -d' ' -f2; }
GMAC=$(mac gen xg0) LMAC=$(mac lb xl0)
# the reals: behind xg0 (what reaches it is dropped there)
for r in 21 22 23; do ip -n lb neigh add 10.9.0.$r lladdr $GMAC dev xl0 nud permanent; done
REALS="10.9.0.21 10.9.0.22 10.9.0.23"
ip netns exec gen $B/kload attach $B/base.bpf.o xdp_drop xg0 >/dev/null || exit 1
# a NAPI as a thread, on a core of its own (the veth makes it when a program
# is attached; --pid host shows its thread)
napi() {	# netns iface cpu
	ip netns exec $1 sh -c "echo 0 > /sys/class/net/$2/threaded; echo 1 > /sys/class/net/$2/threaded"
	for p in $(ps -eo pid,comm | awk -v n="napi/$2-" 'index($2, n) == 1 { print $1 }'); do
		taskset -pc $3 $p >/dev/null
	done
}
napi gen xg0 $PEER_CPU
pktgen() {
	ip netns exec gen sh -c "
		echo reset > /proc/net/pktgen/pgctrl
		n=0
		for c in $GENS; do
			echo add_device xg0@\$n > /proc/net/pktgen/kpktgend_\$c
			f=/proc/net/pktgen/xg0@\$n
			echo 'count 0' > \$f; echo 'pkt_size 60' > \$f; echo 'clone_skb 0' > \$f
			echo 'dst 10.9.0.100' > \$f; echo 'dst_mac $LMAC' > \$f
			echo 'udp_dst_min 53' > \$f; echo 'udp_dst_max 53' > \$f
			if [ $MODE = new ]; then
				echo 'src_min 10.9.1.1' > \$f; echo 'src_max 10.9.255.255' > \$f
				echo 'udp_src_min 1024' > \$f; echo 'udp_src_max 65000' > \$f
				echo 'flag UDPSRC_RND' > \$f; echo 'flag IPSRC_RND' > \$f
			else
				echo src_min 10.9.1.\$((n + 1)) > \$f; echo src_max 10.9.1.\$((n + 1)) > \$f
				echo 'udp_src_min 1024' > \$f; echo 'udp_src_max $((1023 + FLOWS))' > \$f
			fi
			n=\$((n + 1))
		done"
}
xdp_tx() { ip netns exec lb ethtool -S xl0 | awk '$1 == "rx_queue_0_xdp_tx:" { print $2 }'; }
busy() { awk -v c=cpu$LB_CPU '$1 == c { print $2 + $3 + $4 + $7 + $8, $2 + $3 + $4 + $5 + $6 + $7 + $8 }' /proc/stat; }
run() {		# label
	napi lb xl0 $LB_CPU
	pktgen
	ip netns exec gen sh -c 'echo start > /proc/net/pktgen/pgctrl' &
	local pg=$! a b r=() u0 t0 u1 t1
	sleep 1
	read u0 t0 < <(busy)
	for s in $(seq $SECS); do
		a=$(xdp_tx); sleep 1; b=$(xdp_tx); r+=($((b - a)))
	done
	read u1 t1 < <(busy)
	ip netns exec gen sh -c 'echo stop > /proc/net/pktgen/pgctrl'
	wait $pg 2>/dev/null
	local med=$(printf '%s\n' "${r[@]}" | sort -n | sed -n "$(( (SECS + 1) / 2 ))p")
	local pct=$(( 100 * (u1 - u0) / (t1 - t0) ))
	local note=""; [ $pct -lt 97 ] && note="  (its core ${pct}% busy: the generator set this)"
	printf '%-15s %-4s %9s packets/s   (each second: %s)%s\n' "$1" $MODE "$med" "${r[*]}" "$note"
}
detach() { ip -n lb link set xl0 xdp off 2>/dev/null; ip -n lb link set xl0 xdpgeneric off 2>/dev/null; true; }
for w in $WHO; do
	case $w in
	base)
		ip netns exec lb $B/kload attach $B/base.bpf.o xdp_tx xl0 >/dev/null || exit 1
		run base ;;
	okena)
		cat > /tmp/lb.conf <<EOF
okena { workers 1; xdp xl0 }
pool p { server 10.9.0.21:53; server 10.9.0.22:53; server 10.9.0.23:53 }
udp 10.9.0.100:53 { mode xdp; to pool p }
EOF
		ip netns exec lb /okena -c /tmp/lb.conf 2>/tmp/lb.log &
		ok=$!
		for i in $(seq 50); do grep -q 'balanced in the driver' /tmp/lb.log && break; sleep 0.1; done
		grep -q 'balanced in the driver' /tmp/lb.log || { cat /tmp/lb.log; exit 1; }
		run okena
		kill $ok; wait $ok 2>/dev/null ;;
	katran|katran-noflood)
		o=$B/balancer.bpf.o; [ $w = katran-noflood ] && o=$B/balancer-noflood.bpf.o
		ip netns exec lb $B/kload katran $o xl0 $GMAC 10.9.0.100 53 17 $((1 << 20)) $REALS >/dev/null || exit 1
		run $w ;;
	esac
	detach
done
