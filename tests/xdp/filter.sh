#!/bin/bash
# The XDP pre-filter in front of okena's other engines, end to end, IPv4 and
# IPv6, in a privileged container of its own network (nothing on the host
# changes): a bridge, okena on lb with an HTTP listener (no VIP: the
# program only filters), and clients ka, kb, kc (kb, kc on fd01::/64 too;
# "a", "b" would read as `ip link` keywords).
#
#   okena { xdp lb; drop 10.9.0.11 fd00::10; syn_rate 1/m burst=3 }
#
# Checks: b (dropped) gets nothing, not even a ping, a and c do; a's IPv6
# address (dropped) gets nothing while its IPv4 one does; a's SYNs:
# three new connections, then none (the rate refills one a minute); c,
# another IPv4 source, has its own three; on IPv6 a /64 is one source: b and
# c, both in fd01::/64, share theirs; a reload that drops c, not b: b in,
# c out, at once.
#
#   tests/xdp/filter.sh       (needs docker; runs a --privileged container)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=${LAB_IMAGE:-martenseemann/quic-network-simulator-endpoint:latest}
exec docker run --rm --privileged --network none \
	-v "$ROOT/build/okena:/okena:ro" --entrypoint bash "$IMAGE" -c '
set -uo pipefail
fails=0
check() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1: $3"; fails=$((fails + 1)); fi; }
ip link add br0 type bridge; ip link set br0 up
node() {	# name, last byte of its addresses, its IPv6 prefix
	ip netns add $1
	ip link add $1 type veth peer name $1-b
	ip link set $1 netns $1
	ip link set $1-b master br0 up
	ip -n $1 addr add 10.9.0.$2/24 dev $1
	ip -n $1 addr add $3::$2/64 dev $1 nodad
	ip -n $1 link set $1 up
	ip -n $1 link set lo up
}
node lb 1 fd00
ip -n lb addr add fd01::1/64 dev lb nodad
node ka 10 fd00
node kb 11 fd01
node kc 12 fd01
cat > /tmp/lb.conf <<EOF
okena { workers 1; xdp lb; drop 10.9.0.11 fd00::10; syn_rate 1/m burst=3 }
http 10.9.0.1:80 [fd00::1]:80 [fd01::1]:80 { route /* { respond 200 "lb" } }
EOF
ip netns exec lb /okena -c /tmp/lb.conf 2>/tmp/lb.log &
for i in $(seq 50); do grep -q "balanced in the driver" /tmp/lb.log && break; sleep 0.1; done
grep -q "drop. before anything; SYNs a source at most .syn_rate." /tmp/lb.log && ok=1 || ok=0
check "the pre-filter on lb (no VIP)" $ok "$(tail -5 /tmp/lb.log)"
get() { ip netns exec $1 wget -t 1 -T 1 -qO- "$2" 2>/dev/null; }	# one SYN, no retry in time
n_ok() {	# node URL tries: how many answered
	local n=0
	for i in $(seq $3); do [ "$(get $1 "$2")" = lb ] && n=$((n + 1)); done
	echo $n
}
# drop: nothing reaches, not even ICMP
ip netns exec kb ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=0 || ok=1
check "b (drop 10.9.0.11): its ping dropped" $ok ""
[ "$(get kb http://10.9.0.1/)" = "" ] && ok=1 || ok=0
check "  and its connection" $ok ""
ip netns exec ka ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=1 || ok=0
check "a: its ping answered" $ok ""
# syn_rate: three, then none
got=$(n_ok ka http://10.9.0.1/ 6)
check "a: syn_rate 1/m burst=3: three connections of six" $([ $got = 3 ] && echo 1 || echo 0) "$got"
got=$(n_ok kc http://10.9.0.1/ 4)
check "c, another IPv4 source: its own three" $([ $got = 3 ] && echo 1 || echo 0) "$got"
# IPv6: fd00::10 (ka) dropped, fd01::11 (kb) not; a /64 is one source
ip netns exec kb ping -6 -c1 -W1 fd01::1 >/dev/null 2>&1 && ok=1 || ok=0
check "fd01::11 (not in drop): its ping answered" $ok ""
got=$(n_ok kb "http://[fd01::1]/" 2)
got2=$(n_ok kc "http://[fd01::1]/" 3)
check "b and c in fd01::/64: three between them" $([ $((got + got2)) = 3 ] && echo 1 || echo 0) "b $got, c $got2"
ip netns exec ka ping -6 -c1 -W1 fd00::1 >/dev/null 2>&1 && ok=0 || ok=1
check "a from fd00::10 (drop fd00::10): its ping dropped, while its IPv4 one was not" $ok ""
# a reload: c dropped, b no longer
sed -i "s/drop 10.9.0.11 fd00::10/drop 10.9.0.12/" /tmp/lb.conf
kill -HUP $(ps -eo pid,args | awk "\$2 == \"/okena\" && \$3 == \"-c\" { print \$1; exit }")
for i in $(seq 50); do
	ip netns exec kb ping -c1 -W0.2 10.9.0.1 >/dev/null 2>&1 && break
done
ip netns exec kb ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=1 || ok=0
check "reload, b no longer dropped: its ping answered" $ok "$(tail -3 /tmp/lb.log)"
ip netns exec kc ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=0 || ok=1
check "  c dropped now" $ok ""
ip netns exec ka ping -6 -c1 -W1 fd00::1 >/dev/null 2>&1 && ok=1 || ok=0
check "  fd00::10 no longer dropped" $ok ""
# a list from a file, 70000 prefixes, then another 70000 in its place: more
# gone than one pass takes (XC_STALE_N)
gen() { awk -v b=$1 -v keep=$2 "BEGIN { print keep; for (i = 0; i < 70000; i++) printf \"10.%d.%d.%d/32\n\", b + int(i / 65536), int(i / 256) % 256, i % 256 }"; }
gen 100 10.9.0.11 > /tmp/drop.txt
sed -i "s|drop 10.9.0.12|drop file:/tmp/drop.txt|" /tmp/lb.conf
sup=$(ps -eo pid,args | awk "\$2 == \"/okena\" && \$3 == \"-c\" { print \$1; exit }")
kill -HUP $sup
for i in $(seq 100); do ip netns exec kb ping -c1 -W0.1 10.9.0.1 >/dev/null 2>&1 || break; sleep 0.1; done
ip netns exec kb ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=0 || ok=1
ip netns exec kc ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok2=1 || ok2=0
check "drop file: with 70001 lines: b dropped again, c not" $([ $ok = 1 ] && [ $ok2 = 1 ] && echo 1 || echo 0) "b dropped $ok, c answered $ok2"
gen 200 10.9.0.12 > /tmp/drop.txt
t0=$(date +%s%N)
kill -HUP $sup
for i in $(seq 200); do ip netns exec kb ping -c1 -W0.1 10.9.0.1 >/dev/null 2>&1 && break; sleep 0.1; done
t1=$(date +%s%N)
ip netns exec kb ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok=1 || ok=0
ip netns exec kc ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && ok2=0 || ok2=1
check "  another 70001 in its place: b in, c out ($(( (t1 - t0) / 1000000 )) ms)" $([ $ok = 1 ] && [ $ok2 = 1 ] && echo 1 || echo 0) "b answered $ok, c dropped $ok2"
ps -eo comm | grep -qx okena-xdp && ok=1 || ok=0
check "  okena-xdp still there" $ok "$(tail -3 /tmp/lb.log)"
echo "xdp filter: $([ $fails = 0 ] && echo all passed || echo $fails failed)"
exit $fails
'
