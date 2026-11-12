; The XDP balancer: L4, in the driver, before the kernel's stack sees a packet.
;
; TCP and UDP to a VIP, IPv4 or IPv6 (its address, port and protocol in
; VIPS4 / VIPS6) go to a real server, IPv4 or IPv6, wrapped in an outer
; header of the real's family: IP in IP (IPv4 in IPv4, IPv6 in IPv4 (41),
; IPv4 in IPv6 (4), IPv6 in IPv6), or GUE (variant 1: UDP, then the packet)
; when the VIP says so. The real takes the outer header off (tunl0, sit0,
; ip6tnl0, or a fou port) and answers the client itself: direct server
; return. Everything else passes to the kernel.
;
; A flow keeps its real while it lives in LRU4 / LRU6 (an LRU list a CPU:
; no lock between CPUs); a new one takes the real its hash names in the
; VIP's ring (RING: MAGLEV_M entries a VIP, the same table as the
; user-space maglev, so every instance agrees). The same hash is GUE's
; source port and IPv6's flow label: a real's RSS spreads the flows over
; its queues.
;
; The next hop comes from the kernel (bpf_fib_lookup): no gateway to
; configure, and a real on another interface is redirected there. Each CPU
; keeps what the kernel said for a real (NH, direct mapped by the real's
; number, tagged by its address and family and the interface in) for the
; rest of a time step (2^30 ns, about a second): a change of route or
; neighbour is seen within one, and the kernel's tables are not walked for
; every packet.
;
; ICMP: an echo request to a VIP's address is answered here; an error about
; a VIP's packet (unreachable, time exceeded, IPv6's packet too big: what
; the reals' answers earn on their way, sent to the VIP) goes to the real of
; the flow it is about, so path MTU discovery works through the balancer. A
; client's packet the outer header would make too large for the way out
; (the route's MTU, kept with the next hop) is answered with ICMP: IPv4's
; fragmentation needed, IPv6's packet too big, giving the MTU left.
;
; The pre-filter, for every packet on the interface (okena's other engines'
; listeners too), before anything else: a source in DROP4 / DROP6 (`drop`,
; longest prefix) is dropped; TCP SYNs over `syn_rate` from one source (an
; IPv4 address, an IPv6 /64) are dropped, by GCRA (SYNS: the theoretical
; arrival time, one u64 a source, shared by the CPUs: a race between two
; may let one more through, never fewer).
;
; A flood of new flows (more than CTL[CTL_FLOOD] in a time step on one CPU)
; is routed by the ring alone, not remembered: the flows LRU holds are not
; pushed out by it, and the flood is cheaper (as Katran does).
;
; Maps, by number (the control plane makes them in this order):
XL_VIPS4	:= 0		; hash: {address, port, protocol, 0} (8 bytes) -> XVV_*
XL_RING		:= 1		; array: VIP number * MAGLEV_M + slot -> u32 real number
XL_REALS	:= 2		; array: real number -> XR_*
XL_LRU4		:= 3		; LRU hash: flow (16 bytes) -> u32 real number
XL_STATS	:= 4		; per-CPU array of u64: XS_*
XL_CTL		:= 5		; array of 16 bytes: CTL_*
XL_NH		:= 6		; per-CPU array: real number mod XL_NH_N -> the next hop (NH_*)
XL_VIPS6	:= 7		; hash: {address (16), port, protocol, 0} (20 bytes) -> XVV_*
XL_LRU6		:= 8		; LRU hash: flow (40 bytes) -> u32 real number
XL_DROP4	:= 9		; LPM trie: {prefix length, address (4)} -> u32 generation
XL_DROP6	:= 10		; LPM trie: {prefix length, address (16)} -> u32 generation
XL_SYNS		:= 11		; LRU hash: source (8 bytes) -> u64 its theoretical arrival time
XL_NH_N		:= 1024
CTL_SRC4	:= 0		; the outer IPv4 header's source (0: none)
CTL_FLOOD	:= 1		; u32 new flows remembered a time step, each CPU (0: all)
CTL_SRC6	:= 2		; the outer IPv6 header's source (:: none)
CTL_FILTER	:= 3		; u32 FF_*: what the pre-filter does
CTL_SYN		:= 4		; u64 ns between SYNs of a source, u64 how far ahead (burst)
CTL_GEN		:= 5		; u32 the drop lists' generation (okena-xdp's; the program
				; ignores it)
CTL_N		:= 6
FF_DROP4	:= 1
FF_DROP6	:= 2
FF_SYN		:= 4
CTL_L		:= 16
XL_FLOOD_N	:= 125000	; (Katran's MAX_CONN_RATE)
; a VIP (VIPS4 / VIPS6's value)
XVV_NUM		:= 0		; its number (its ring)
XVV_FLAGS	:= 4		; XVF_*; GUE's port (network order) in the high half
XVV_L		:= 8
XVF_GUE		:= 1
; a real (REALS' value)
XR_ADDR		:= 0		; 16 bytes: IPv4 in the first 4
XR_FAMILY	:= 16		; u32: 4, 6, 0 when it is down
XR_L		:= 20
XS_TX		:= 0		; packets sent on to a real
XS_MISS		:= 1		; flows not in LRU (new, or forgotten)
XS_DROP		:= 2		; no real, no route, no room, no source: dropped
XS_FLOOD	:= 3		; new flows past CTL_FLOOD: routed, not remembered
XS_WINDOW	:= 4		; (not a count: the time step, high half; its new flows, low)
XS_ICMP		:= 5		; echo requests answered, errors carried to a real
XS_TOOBIG	:= 6		; too big for the outer header: ICMP sent back
XS_FILTERED	:= 7		; from a source `drop` names: dropped
XS_SYN		:= 8		; SYNs over `syn_rate`: dropped
XS_N		:= 9
; a next hop (NH's value)
NH_DMAC		:= 0
NH_SMAC		:= 6
NH_IFINDEX	:= 12		; out
NH_IN		:= 16		; the tag: the interface in,
NH_STAMP	:= 20		; the time step it was found in,
NH_ADDR		:= 24		; the real's address (16) and
NH_FAMILY	:= 40		; family
NH_MTU		:= 44		; the route's MTU (0: not known)
NH_L		:= 48

; the frame (offsets from BR10)
XF_TAU		:= -312		; u64: CTL_SYN's burst
XF_IVL		:= -304		; u64: CTL_SYN's interval
XF_NOW		:= -296		; u64: now (ns)
XF_SVAL		:= -288		; u64: a SYNS value
XF_SKEY		:= -280		; 8 bytes: a SYNS key
XF_LPM		:= -272		; 20 bytes: a DROP key
XF_ICMP		:= -248		; u32: 1 for an ICMP error carried to its flow's real
XF_MTU		:= -244		; u32: the route's MTU, then what is left of it
XF_SRC6		:= -240		; 16 bytes: the outer IPv6 source
XF_RADDR	:= -224		; 16 bytes: the real's address
XF_VIP6		:= -208		; 20 bytes: daddr, dport, protocol, 0
XF_FLOW6	:= -184		; 40 bytes: saddr, daddr, sport, dport, protocol, 0 x3
XF_RFAM		:= -144		; u32: the real's family
XF_VFLAGS	:= -140		; u32: the VIP's XVV_FLAGS
XF_VNUM		:= -136		; u32: the VIP's number
XF_FAM		:= -132		; u32: the packet's family, 4 or 6
XF_TOS		:= -128		; u32: its TOS / traffic class
XF_ILEN		:= -124		; u32: its length (the IP header's)
XF_HASH		:= -120		; u32: the flow's hash
XF_STAMP	:= -116		; u32: the time step (ns shr 30)
XF_FIB		:= -112		; struct bpf_fib_lookup, 64 bytes
XF_LRU		:= -44		; u32: 1 when the real came from LRU
XF_SRC		:= -40		; u32 the outer IPv4 source
XF_KEY		:= -36		; u32 a key (CTL, STATS, NH)
XF_RING		:= -32		; u32 the ring's key
XF_REAL		:= -28		; u32 the real's number
XF_FLOW		:= -24		; 16 bytes: saddr, daddr, sport, dport, protocol, 0 x3
XF_VIP		:= -8		; 8 bytes: daddr, dport, protocol, 0
; struct bpf_fib_lookup
FIB_FAMILY	:= 0
FIB_TOT_LEN	:= 6		; (in: the length to check; out: the MTU)
FIB_IFINDEX	:= 8
FIB_SRC		:= 16
FIB_DST		:= 32
FIB_SMAC	:= 52
FIB_DMAC	:= 58
FIB_FRAG_NEEDED	:= 8		; BPF_FIB_LKUP_RET_FRAG_NEEDED
ETH_L		:= 14
IP_L		:= 20
IP6_L		:= 40
UDP_L		:= 8
ICMP_L		:= 8

; a per-CPU counter (XS_*) up by one; clobbers BR0-BR5
macro xl_count n*
	local no
	e_st32	BR10, XF_KEY, n
	e_ldmap	BR1, XL_STATS
	e_mov	BR2, BR10
	e_addi	BR2, XF_KEY
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, no
	e_ldx64	BR1, BR0, 0
	e_addi	BR1, 1
	e_stx64	BR0, 0, BR1
no:
end macro

; BR1 = map number's value for the key at BR10 + off (BR0 = its pointer)
macro xl_lookup map*, off*
	e_ldmap	BR1, map
	e_mov	BR2, BR10
	e_addi	BR2, off
	e_call	BPF_FUNC_map_lookup_elem
end macro

; The outer headers, the real's family o (4, 6), GUE or not (g): room made
; in front, Ethernet to the next hop (XF_FIB), the outer IP header, the UDP
; one; then on to .send. The inner packet is untouched.
macro xl_encap o*, g*
	local L, ol, inner4
	if o = 4
		ol = IP_L
	else
		ol = IP6_L
	end if
	L = ol + g * UDP_L
	e_mov	BR1, BR6
	e_movi	BR2, -L
	e_call	BPF_FUNC_xdp_adjust_head
	e_jnei	BR0, 0, .drop
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + L
	e_jgt	BR1, BR8, .drop
	; Ethernet: the next hop's (2 bytes at a time: the stack wants its
	; accesses aligned, and the addresses are 2-byte aligned there)
	repeat 3, h:0
		e_ldx16	BR1, BR10, XF_FIB + FIB_DMAC + h * 2
		e_stx16	BR7, h * 2, BR1
		e_ldx16	BR1, BR10, XF_FIB + FIB_SMAC + h * 2
		e_stx16	BR7, 6 + h * 2, BR1
	end repeat
	if o = 4
		e_st16	BR7, 12, 0x0008
	else
		e_st16	BR7, 12, 0xDD86
	end if
	; what follows the outer IP header: UDP, or the packet (4: IPv4, 41: IPv6)
	if g
		e_movi	BR3, 17
	else
		e_movi	BR3, 4
		e_ldx32	BR1, BR10, XF_FAM
		e_jeqi	BR1, 4, inner4
		e_movi	BR3, 41
	inner4:
	end if
	if o = 4
		e_ldx32	BR1, BR10, XF_ILEN		; its length, plus ours
		e_addi	BR1, L
		e_be	BR1, 16
		e_ldx32	BR2, BR10, XF_TOS
		e_st8	BR7, ETH_L, 0x45
		e_stx8	BR7, ETH_L + 1, BR2
		e_stx16	BR7, ETH_L + 2, BR1
		e_st32	BR7, ETH_L + 4, 0		; id, no fragment flags
		e_st8	BR7, ETH_L + 8, 64		; TTL
		e_stx8	BR7, ETH_L + 9, BR3
		e_st16	BR7, ETH_L + 10, 0
		e_ldx32	BR1, BR10, XF_SRC
		e_stx32	BR7, ETH_L + 12, BR1
		e_ldx32	BR1, BR10, XF_RADDR
		e_stx32	BR7, ETH_L + 16, BR1
		; its checksum: the 16-bit words summed (in either byte order), folded
		e_movi	BR1, 0
		repeat 10, w:0
			e_ldx16	BR2, BR7, ETH_L + w * 2
			e_add	BR1, BR2
		end repeat
		e_mov	BR2, BR1
		e_rshi	BR2, 16
		e_andi	BR1, 0xFFFF
		e_add	BR1, BR2
		e_mov	BR2, BR1
		e_rshi	BR2, 16
		e_add	BR1, BR2
		e_xori	BR1, 0xFFFF
		e_stx16	BR7, ETH_L + 10, BR1
	else
		; version 6, the packet's traffic class, the flow's hash as label
		e_ldx32	BR1, BR10, XF_TOS
		e_lshi	BR1, 20
		e_ldx32	BR2, BR10, XF_HASH
		e_andi	BR2, 0xFFFFF
		e_or	BR1, BR2
		e_ori	BR1, 0x60000000
		e_be	BR1, 32
		e_stx32	BR7, ETH_L, BR1
		e_ldx32	BR1, BR10, XF_ILEN		; the payload: the packet (and UDP)
		e_addi	BR1, g * UDP_L
		e_be	BR1, 16
		e_stx16	BR7, ETH_L + 4, BR1
		e_stx8	BR7, ETH_L + 6, BR3
		e_st8	BR7, ETH_L + 7, 64		; hop limit
		repeat 4, q:0
			e_ldx32	BR1, BR10, XF_SRC6 + q * 4
			e_stx32	BR7, ETH_L + 8 + q * 4, BR1
			e_ldx32	BR1, BR10, XF_RADDR + q * 4
			e_stx32	BR7, ETH_L + 24 + q * 4, BR1
		end repeat
	end if
	if g
		; GUE, variant 1 (the packet right after UDP: no GUE header); the
		; source port from the flow's hash, 49152 and up; no checksum
		; (the inner packet has its own)
		e_ldx32	BR1, BR10, XF_HASH
		e_andi	BR1, 0x3FFF
		e_ori	BR1, 0xC000
		e_be	BR1, 16
		e_stx16	BR7, ETH_L + ol, BR1
		e_ldx32	BR1, BR10, XF_VFLAGS
		e_rshi	BR1, 16
		e_stx16	BR7, ETH_L + ol + 2, BR1
		e_ldx32	BR1, BR10, XF_ILEN
		e_addi	BR1, UDP_L
		e_be	BR1, 16
		e_stx16	BR7, ETH_L + ol + 4, BR1
		e_st16	BR7, ETH_L + ol + 6, 0
	end if
	e_ja	.send
end macro

; XF_FIB filled for the real (its family, our source, the interface in)
macro xl_fib_fill
	local v6, done
	repeat 8, q:0
		e_st64	BR10, XF_FIB + q * 8, 0
	end repeat
	e_ldx32	BR1, BR6, XDP_MD_IFINDEX
	e_stx32	BR10, XF_FIB + FIB_IFINDEX, BR1
	e_ldx32	BR1, BR10, XF_RFAM
	e_jeqi	BR1, 6, v6
	e_st8	BR10, XF_FIB + FIB_FAMILY, 2	; AF_INET
	e_ldx32	BR1, BR10, XF_SRC
	e_stx32	BR10, XF_FIB + FIB_SRC, BR1
	e_ldx32	BR1, BR10, XF_RADDR
	e_stx32	BR10, XF_FIB + FIB_DST, BR1
	e_ja	done
v6:
	e_st8	BR10, XF_FIB + FIB_FAMILY, 10	; AF_INET6
	repeat 2, q:0
		e_ldx64	BR1, BR10, XF_SRC6 + q * 8
		e_stx64	BR10, XF_FIB + FIB_SRC + q * 8, BR1
		e_ldx64	BR1, BR10, XF_RADDR + q * 8
		e_stx64	BR10, XF_FIB + FIB_DST + q * 8, BR1
	end repeat
done:
end macro

; Ethernet back to where the frame came from: its source and destination
; swapped (via the stack at XF_VIP6: the old header may be overwritten
; next); the old header at BR7 + at
macro xl_eth_back at*, type*
	repeat 3, h:0
		e_ldx16	BR1, BR7, at + h * 2
		e_stx16	BR10, XF_VIP6 + h * 2, BR1
		e_ldx16	BR1, BR7, at + 6 + h * 2
		e_stx16	BR10, XF_VIP6 + 6 + h * 2, BR1
	end repeat
	repeat 3, h:0
		e_ldx16	BR1, BR10, XF_VIP6 + 6 + h * 2
		e_stx16	BR7, h * 2, BR1
		e_ldx16	BR1, BR10, XF_VIP6 + h * 2
		e_stx16	BR7, 6 + h * 2, BR1
	end repeat
	e_st16	BR7, 12, type
end macro

; BR1 = the ones' complement sum of n 16-bit words at BR7 + at, added to
; BR1, folded to 16 bits (not complemented); clobbers BR2
macro xl_sum at*, n*
	repeat n, w:0
		e_ldx16	BR2, BR7, at + w * 2
		e_add	BR1, BR2
	end repeat
	e_mov	BR2, BR1
	e_rshi	BR2, 16
	e_andi	BR1, 0xFFFF
	e_add	BR1, BR2
	e_mov	BR2, BR1
	e_rshi	BR2, 16
	e_andi	BR1, 0xFFFF
	e_add	BR1, BR2
end macro

; a SYN from the source at XF_SKEY: on to .synd when over `syn_rate`;
; clobbers BR0-BR5
macro xl_syn_rate
	local fresh, ok, later
	e_call	BPF_FUNC_ktime_get_ns
	e_stx64	BR10, XF_NOW, BR0
	e_st32	BR10, XF_KEY, CTL_SYN
	xl_lookup XL_CTL, XF_KEY
	e_jeqi	BR0, 0, ok
	e_ldx64	BR1, BR0, 0
	e_stx64	BR10, XF_IVL, BR1
	e_ldx64	BR1, BR0, 8
	e_stx64	BR10, XF_TAU, BR1
	xl_lookup XL_SYNS, XF_SKEY
	e_jeqi	BR0, 0, fresh
	e_ldx64	BR1, BR0, 0			; its theoretical arrival time
	e_ldx64	BR2, BR10, XF_NOW
	e_ldx64	BR3, BR10, XF_TAU
	e_mov	BR4, BR2			; too early: now + burst before it
	e_add	BR4, BR3
	e_jlt	BR4, BR1, .synd
	e_jge	BR1, BR2, later			; the next: one interval after it, or now
	e_mov	BR1, BR2
later:
	e_ldx64	BR4, BR10, XF_IVL
	e_add	BR1, BR4
	e_stx64	BR0, 0, BR1
	e_ja	ok
fresh:
	e_ldx64	BR1, BR10, XF_NOW
	e_ldx64	BR2, BR10, XF_IVL
	e_add	BR1, BR2
	e_stx64	BR10, XF_SVAL, BR1
	e_ldmap	BR1, XL_SYNS
	e_mov	BR2, BR10
	e_addi	BR2, XF_SKEY
	e_mov	BR3, BR10
	e_addi	BR3, XF_SVAL
	e_movi	BR4, 0
	e_call	BPF_FUNC_map_update_elem
ok:
end macro

rodata
	align 8
xl_prog:
	e_mov	BR6, BR1			; the context
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L
	e_jgt	BR1, BR8, .pass
	e_ldx16	BR1, BR7, 12
	e_jeqi	BR1, 0x0008, .v4		; (0x0800, read little endian)
	e_jeqi	BR1, 0xDD86, .v6		; (0x86DD)
	e_ja	.pass
.v4:
	e_mov	BR1, BR7			; IPv4
	e_addi	BR1, ETH_L + IP_L
	e_jgt	BR1, BR8, .pass
	; the pre-filter: what it does (BR9 holds it), the source's prefix
	e_st32	BR10, XF_KEY, CTL_FILTER
	xl_lookup XL_CTL, XF_KEY
	e_movi	BR9, 0
	e_jeqi	BR0, 0, @f
	e_ldx32	BR9, BR0, 0
@@:
	e_mov	BR1, BR9
	e_andi	BR1, FF_DROP4
	e_jeqi	BR1, 0, .v4_kept
	e_st32	BR10, XF_LPM, 32
	e_ldx32	BR1, BR7, ETH_L + 12
	e_stx32	BR10, XF_LPM + 4, BR1
	xl_lookup XL_DROP4, XF_LPM
	e_jnei	BR0, 0, .filtered
.v4_kept:
	e_mov	BR1, BR7			; the ports
	e_addi	BR1, ETH_L + IP_L + 4
	e_jgt	BR1, BR8, .pass
	e_ldx8	BR1, BR7, ETH_L
	e_jnei	BR1, 0x45, .pass		; no options
	e_ldx16	BR1, BR7, ETH_L + 6
	e_andi	BR1, 0xFF3F			; a fragment (MF, or an offset): passes
	e_jnei	BR1, 0, .pass
	e_st32	BR10, XF_ICMP, 0
	e_ldx8	BR2, BR7, ETH_L + 9		; the protocol
	e_jeqi	BR2, 6, .tcp4
	e_jeqi	BR2, 1, .icmp4
	e_jnei	BR2, 17, .pass
	e_ja	.l4
.tcp4:	; a SYN (no ACK), over the source's rate?
	e_mov	BR1, BR9
	e_andi	BR1, FF_SYN
	e_jeqi	BR1, 0, .l4
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP_L + 14
	e_jgt	BR1, BR8, .l4
	e_ldx8	BR1, BR7, ETH_L + IP_L + 13
	e_andi	BR1, 0x12
	e_jnei	BR1, 0x02, .l4
	e_ldx32	BR1, BR7, ETH_L + 12		; the key: the address
	e_stx32	BR10, XF_SKEY, BR1
	e_st32	BR10, XF_SKEY + 4, -1
	xl_syn_rate
	e_movi	BR2, 6
.l4:
	e_ldx32	BR1, BR7, ETH_L + 16		; the VIP's key
	e_stx32	BR10, XF_VIP, BR1
	e_ldx16	BR1, BR7, ETH_L + IP_L + 2
	e_stx16	BR10, XF_VIP + 4, BR1
	e_stx8	BR10, XF_VIP + 6, BR2
	e_st8	BR10, XF_VIP + 7, 0
	e_ldx32	BR1, BR7, ETH_L + 12		; the flow's
	e_stx32	BR10, XF_FLOW, BR1
	e_ldx32	BR1, BR7, ETH_L + 16
	e_stx32	BR10, XF_FLOW + 4, BR1
	e_ldx32	BR1, BR7, ETH_L + IP_L		; both ports
	e_stx32	BR10, XF_FLOW + 8, BR1
	e_stx8	BR10, XF_FLOW + 12, BR2
	e_st8	BR10, XF_FLOW + 13, 0
	e_st16	BR10, XF_FLOW + 14, 0
	e_st32	BR10, XF_FAM, 4
	e_ldx16	BR1, BR7, ETH_L + 2		; its length, its TOS
	e_be	BR1, 16
	e_stx32	BR10, XF_ILEN, BR1
	e_ldx8	BR1, BR7, ETH_L + 1
	e_stx32	BR10, XF_TOS, BR1
.hash4:	; the flow's hash: its source and ports (the VIP's are the same for all)
	e_ldx32	BR1, BR10, XF_FLOW
	e_mul32i BR1, 0x9E3779B1
	e_ldx32	BR2, BR10, XF_FLOW + 8
	e_mul32i BR2, 0x85EBCA77
	e_xor32	BR1, BR2
	e_mov32	BR2, BR1
	e_rsh32i BR2, 15
	e_xor32	BR1, BR2
	e_stx32	BR10, XF_HASH, BR1
	xl_lookup XL_VIPS4, XF_VIP
	e_jeqi	BR0, 0, .pass			; not a VIP
	e_ja	.vip
.icmp4:
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP_L + ICMP_L
	e_jgt	BR1, BR8, .pass
	e_ldx8	BR1, BR7, ETH_L + IP_L		; its type
	e_jeqi	BR1, 8, .echo4
	e_jeqi	BR1, 3, .error4			; unreachable (and fragmentation needed)
	e_jnei	BR1, 11, .pass			; time exceeded
.error4:	; about a packet a real sent from the VIP: the flow's other way
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP_L + ICMP_L + IP_L + 4
	e_jgt	BR1, BR8, .pass
	e_ldx8	BR1, BR7, ETH_L + IP_L + ICMP_L
	e_jnei	BR1, 0x45, .pass
	e_ldx8	BR2, BR7, ETH_L + IP_L + ICMP_L + 9
	e_jeqi	BR2, 6, @f
	e_jnei	BR2, 17, .pass
@@:
	e_ldx32	BR1, BR7, ETH_L + IP_L + ICMP_L + 12	; the VIP: its source
	e_stx32	BR10, XF_VIP, BR1
	e_stx32	BR10, XF_FLOW + 4, BR1
	e_ldx16	BR1, BR7, ETH_L + IP_L + ICMP_L + IP_L	; and source port
	e_stx16	BR10, XF_VIP + 4, BR1
	e_stx16	BR10, XF_FLOW + 10, BR1
	e_stx8	BR10, XF_VIP + 6, BR2
	e_st8	BR10, XF_VIP + 7, 0
	e_ldx32	BR1, BR7, ETH_L + IP_L + ICMP_L + 16	; the client: its destination
	e_stx32	BR10, XF_FLOW, BR1
	e_ldx16	BR1, BR7, ETH_L + IP_L + ICMP_L + IP_L + 2
	e_stx16	BR10, XF_FLOW + 8, BR1
	e_stx8	BR10, XF_FLOW + 12, BR2
	e_st8	BR10, XF_FLOW + 13, 0
	e_st16	BR10, XF_FLOW + 14, 0
	e_st32	BR10, XF_FAM, 4
	e_ldx16	BR1, BR7, ETH_L + 2		; this packet's length, TOS
	e_be	BR1, 16
	e_stx32	BR10, XF_ILEN, BR1
	e_ldx8	BR1, BR7, ETH_L + 1
	e_stx32	BR10, XF_TOS, BR1
	e_st32	BR10, XF_ICMP, 1
	xl_count XS_ICMP
	e_ja	.hash4
.echo4:	; to a VIP's address (VIPS4 has it with port 0, protocol 1): answered
	e_ldx32	BR1, BR7, ETH_L + 16
	e_stx32	BR10, XF_VIP, BR1
	e_st32	BR10, XF_VIP + 4, 0x00010000	; port 0, protocol 1
	xl_lookup XL_VIPS4, XF_VIP
	e_jeqi	BR0, 0, .pass
	xl_eth_back 0, 0x0008
	e_ldx32	BR1, BR7, ETH_L + 12		; the addresses swapped
	e_ldx32	BR2, BR7, ETH_L + 16
	e_stx32	BR7, ETH_L + 12, BR2
	e_stx32	BR7, ETH_L + 16, BR1
	e_st8	BR7, ETH_L + 8, 64		; TTL
	e_st16	BR7, ETH_L + 10, 0
	e_movi	BR1, 0
	xl_sum	ETH_L, 10
	e_xori	BR1, 0xFFFF
	e_stx16	BR7, ETH_L + 10, BR1
	e_st8	BR7, ETH_L + IP_L, 0		; echo reply: its checksum less 0x0800
	e_ldx16	BR1, BR7, ETH_L + IP_L + 2
	e_addi	BR1, 0x0008			; (read little endian)
	e_mov	BR2, BR1
	e_rshi	BR2, 16
	e_andi	BR1, 0xFFFF
	e_add	BR1, BR2
	e_stx16	BR7, ETH_L + IP_L + 2, BR1
	xl_count XS_ICMP
	e_movi	BR0, XDP_TX
	e_exit
.v6:
	e_mov	BR1, BR7			; IPv6
	e_addi	BR1, ETH_L + IP6_L
	e_jgt	BR1, BR8, .pass
	e_st32	BR10, XF_KEY, CTL_FILTER	; the pre-filter
	xl_lookup XL_CTL, XF_KEY
	e_movi	BR9, 0
	e_jeqi	BR0, 0, @f
	e_ldx32	BR9, BR0, 0
@@:
	e_mov	BR1, BR9
	e_andi	BR1, FF_DROP6
	e_jeqi	BR1, 0, .v6_kept
	e_st32	BR10, XF_LPM, 128
	repeat 4, q:0
		e_ldx32	BR1, BR7, ETH_L + 8 + q * 4
		e_stx32	BR10, XF_LPM + 4 + q * 4, BR1
	end repeat
	xl_lookup XL_DROP6, XF_LPM
	e_jnei	BR0, 0, .filtered
.v6_kept:
	e_mov	BR1, BR7			; the ports
	e_addi	BR1, ETH_L + IP6_L + 4
	e_jgt	BR1, BR8, .pass
	e_st32	BR10, XF_ICMP, 0
	e_ldx8	BR2, BR7, ETH_L + 6		; the next header: TCP, UDP, ICMPv6
	e_jeqi	BR2, 6, .tcp6			; (any extension header passes)
	e_jeqi	BR2, 58, .icmp6
	e_jnei	BR2, 17, .pass
	e_ja	.l4v6
.tcp6:	; a SYN (no ACK), over the source's /64's rate?
	e_mov	BR1, BR9
	e_andi	BR1, FF_SYN
	e_jeqi	BR1, 0, .l4v6
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP6_L + 14
	e_jgt	BR1, BR8, .l4v6
	e_ldx8	BR1, BR7, ETH_L + IP6_L + 13
	e_andi	BR1, 0x12
	e_jnei	BR1, 0x02, .l4v6
	e_ldx32	BR1, BR7, ETH_L + 8		; the key: the /64
	e_stx32	BR10, XF_SKEY, BR1
	e_ldx32	BR1, BR7, ETH_L + 12
	e_stx32	BR10, XF_SKEY + 4, BR1
	xl_syn_rate
	e_movi	BR2, 6
.l4v6:
	repeat 4, q:0				; the VIP's key
		e_ldx32	BR1, BR7, ETH_L + 24 + q * 4
		e_stx32	BR10, XF_VIP6 + q * 4, BR1
	end repeat
	e_ldx16	BR1, BR7, ETH_L + IP6_L + 2
	e_stx16	BR10, XF_VIP6 + 16, BR1
	e_stx8	BR10, XF_VIP6 + 18, BR2
	e_st8	BR10, XF_VIP6 + 19, 0
	repeat 8, q:0				; the flow's: both addresses,
		e_ldx32	BR1, BR7, ETH_L + 8 + q * 4
		e_stx32	BR10, XF_FLOW6 + q * 4, BR1
	end repeat
	e_ldx32	BR1, BR7, ETH_L + IP6_L		; both ports
	e_stx32	BR10, XF_FLOW6 + 32, BR1
	e_stx8	BR10, XF_FLOW6 + 36, BR2
	e_st8	BR10, XF_FLOW6 + 37, 0
	e_st16	BR10, XF_FLOW6 + 38, 0
	e_st32	BR10, XF_FAM, 6
	e_ldx16	BR1, BR7, ETH_L + 4		; its length (the payload's, and ours)
	e_be	BR1, 16
	e_addi	BR1, IP6_L
	e_stx32	BR10, XF_ILEN, BR1
	e_ldx8	BR1, BR7, ETH_L			; its traffic class (4 bits in each byte)
	e_andi	BR1, 0x0F
	e_lshi	BR1, 4
	e_ldx8	BR3, BR7, ETH_L + 1
	e_rshi	BR3, 4
	e_or	BR1, BR3
	e_stx32	BR10, XF_TOS, BR1
.hash6:	; the flow's hash: its source, word by word, and ports
	e_ldx32	BR1, BR10, XF_FLOW6
	e_mul32i BR1, 0x9E3779B1
	repeat 3, q:1
		e_ldx32	BR2, BR10, XF_FLOW6 + q * 4
		e_xor32	BR1, BR2
		e_mul32i BR1, 0x9E3779B1
	end repeat
	e_ldx32	BR2, BR10, XF_FLOW6 + 32
	e_mul32i BR2, 0x85EBCA77
	e_xor32	BR1, BR2
	e_mov32	BR2, BR1
	e_rsh32i BR2, 15
	e_xor32	BR1, BR2
	e_stx32	BR10, XF_HASH, BR1
	xl_lookup XL_VIPS6, XF_VIP6
	e_jeqi	BR0, 0, .pass			; not a VIP
	e_ja	.vip
.icmp6:
	e_ldx8	BR1, BR7, ETH_L + IP6_L		; its type
	e_jeqi	BR1, 128, .echo6
	e_jeqi	BR1, 1, .error6			; unreachable
	e_jeqi	BR1, 2, .error6			; packet too big
	e_jnei	BR1, 3, .pass			; time exceeded
.error6:	; about a packet a real sent from the VIP: the flow's other way
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP6_L + ICMP_L + IP6_L + 4
	e_jgt	BR1, BR8, .pass
	e_ldx8	BR2, BR7, ETH_L + IP6_L + ICMP_L + 6
	e_jeqi	BR2, 6, @f
	e_jnei	BR2, 17, .pass
@@:
	repeat 4, q:0				; the VIP: its source, the client: its
		e_ldx32	BR1, BR7, ETH_L + IP6_L + ICMP_L + 8 + q * 4	; destination
		e_stx32	BR10, XF_VIP6 + q * 4, BR1
		e_stx32	BR10, XF_FLOW6 + 16 + q * 4, BR1
		e_ldx32	BR1, BR7, ETH_L + IP6_L + ICMP_L + 24 + q * 4
		e_stx32	BR10, XF_FLOW6 + q * 4, BR1
	end repeat
	e_ldx16	BR1, BR7, ETH_L + IP6_L + ICMP_L + IP6_L	; the VIP's port
	e_stx16	BR10, XF_VIP6 + 16, BR1
	e_stx16	BR10, XF_FLOW6 + 34, BR1
	e_ldx16	BR1, BR7, ETH_L + IP6_L + ICMP_L + IP6_L + 2
	e_stx16	BR10, XF_FLOW6 + 32, BR1
	e_stx8	BR10, XF_VIP6 + 18, BR2
	e_st8	BR10, XF_VIP6 + 19, 0
	e_stx8	BR10, XF_FLOW6 + 36, BR2
	e_st8	BR10, XF_FLOW6 + 37, 0
	e_st16	BR10, XF_FLOW6 + 38, 0
	e_st32	BR10, XF_FAM, 6
	e_ldx16	BR1, BR7, ETH_L + 4		; this packet's length, class
	e_be	BR1, 16
	e_addi	BR1, IP6_L
	e_stx32	BR10, XF_ILEN, BR1
	e_st32	BR10, XF_TOS, 0
	e_st32	BR10, XF_ICMP, 1
	xl_count XS_ICMP
	e_ja	.hash6
.echo6:	; to a VIP's address (VIPS6 has it with port 0, protocol 58): answered
	repeat 4, q:0
		e_ldx32	BR1, BR7, ETH_L + 24 + q * 4
		e_stx32	BR10, XF_VIP6 + q * 4, BR1
	end repeat
	e_st32	BR10, XF_VIP6 + 16, 0x003A0000	; port 0, protocol 58
	xl_lookup XL_VIPS6, XF_VIP6
	e_jeqi	BR0, 0, .pass
	xl_eth_back 0, 0xDD86
	repeat 4, q:0				; the addresses swapped
		e_ldx32	BR1, BR7, ETH_L + 8 + q * 4
		e_ldx32	BR2, BR7, ETH_L + 24 + q * 4
		e_stx32	BR7, ETH_L + 8 + q * 4, BR2
		e_stx32	BR7, ETH_L + 24 + q * 4, BR1
	end repeat
	e_st8	BR7, ETH_L + 7, 64		; hop limit
	e_st8	BR7, ETH_L + IP6_L, 129		; echo reply: its checksum plus 0x0100
	e_ldx16	BR1, BR7, ETH_L + IP6_L + 2	; (the pseudo header's sum is the same)
	e_addi	BR1, 0xFFFE			; (- 0x0001 read little endian)
	e_mov	BR2, BR1
	e_rshi	BR2, 16
	e_andi	BR1, 0xFFFF
	e_add	BR1, BR2
	e_stx16	BR7, ETH_L + IP6_L + 2, BR1
	xl_count XS_ICMP
	e_movi	BR0, XDP_TX
	e_exit
.vip:	; BR0 = the VIP
	e_ldx32	BR1, BR0, XVV_NUM
	e_stx32	BR10, XF_VNUM, BR1
	e_ldx32	BR1, BR0, XVV_FLAGS
	e_stx32	BR10, XF_VFLAGS, BR1
	e_call	BPF_FUNC_ktime_get_ns
	e_rshi	BR0, 30
	e_stx32	BR10, XF_STAMP, BR0
	e_ldx32	BR1, BR10, XF_FAM
	e_jeqi	BR1, 6, .lru6
	xl_lookup XL_LRU4, XF_FLOW
	e_ja	.lru
.lru6:
	xl_lookup XL_LRU6, XF_FLOW6
.lru:
	e_jeqi	BR0, 0, .new
	e_ldx32	BR1, BR0, 0
	e_stx32	BR10, XF_REAL, BR1
	e_st32	BR10, XF_LRU, 1
	e_ja	.real
.new:
	e_st32	BR10, XF_LRU, 0
	e_ldx32	BR1, BR10, XF_HASH		; its slot in the VIP's ring
	e_mod32i BR1, MAGLEV_M
	e_ldx32	BR2, BR10, XF_VNUM
	e_mul32i BR2, MAGLEV_M
	e_add32	BR1, BR2
	e_stx32	BR10, XF_RING, BR1
	xl_lookup XL_RING, XF_RING
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR1, BR0, 0
	e_stx32	BR10, XF_REAL, BR1
	xl_count XS_MISS
	e_ldx32	BR1, BR10, XF_ICMP		; an ICMP error: the ring's real, not kept
	e_jnei	BR1, 0, .real
	; this CPU's new flows in this time step, against CTL_FLOOD (BR8: the
	; packet's end is read again after adjust_head)
	e_st32	BR10, XF_KEY, CTL_FLOOD
	xl_lookup XL_CTL, XF_KEY
	e_jeqi	BR0, 0, .remember
	e_ldx32	BR8, BR0, 0
	e_jeqi	BR8, 0, .remember		; no bound
	e_st32	BR10, XF_KEY, XS_WINDOW
	xl_lookup XL_STATS, XF_KEY
	e_jeqi	BR0, 0, .remember
	e_ldx32	BR1, BR0, 4
	e_ldx32	BR2, BR10, XF_STAMP
	e_jeq	BR1, BR2, .window
	e_stx32	BR0, 4, BR2			; a new time step
	e_st32	BR0, 0, 0
.window:
	e_ldx32	BR1, BR0, 0
	e_addi	BR1, 1
	e_stx32	BR0, 0, BR1
	e_jle	BR1, BR8, .remember
	xl_count XS_FLOOD
	e_ja	.real
.remember:	; it keeps this real
	e_mov	BR3, BR10
	e_addi	BR3, XF_REAL
	e_movi	BR4, 0
	e_ldx32	BR1, BR10, XF_FAM
	e_jeqi	BR1, 6, .remember6
	e_ldmap	BR1, XL_LRU4
	e_mov	BR2, BR10
	e_addi	BR2, XF_FLOW
	e_call	BPF_FUNC_map_update_elem
	e_ja	.real
.remember6:
	e_ldmap	BR1, XL_LRU6
	e_mov	BR2, BR10
	e_addi	BR2, XF_FLOW6
	e_call	BPF_FUNC_map_update_elem
.real:
	xl_lookup XL_REALS, XF_REAL
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR1, BR0, XR_FAMILY		; 0: it is down
	e_jnei	BR1, 0, .real_up
	e_ldx32	BR2, BR10, XF_LRU		; a flow's real gone: a new flow, once
	e_jeqi	BR2, 0, .drop
	e_ja	.new
.real_up:
	e_stx32	BR10, XF_RFAM, BR1
	e_ldx64	BR2, BR0, XR_ADDR
	e_stx64	BR10, XF_RADDR, BR2
	e_ldx64	BR2, BR0, XR_ADDR + 8
	e_stx64	BR10, XF_RADDR + 8, BR2
	; the outer header's source, of the real's family
	e_jeqi	BR1, 6, .src6
	e_st32	BR10, XF_KEY, CTL_SRC4
	xl_lookup XL_CTL, XF_KEY
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR1, BR0, 0
	e_jeqi	BR1, 0, .drop			; the interface has no IPv4 address
	e_stx32	BR10, XF_SRC, BR1
	e_ja	.nh
.src6:
	e_st32	BR10, XF_KEY, CTL_SRC6
	xl_lookup XL_CTL, XF_KEY
	e_jeqi	BR0, 0, .drop
	e_ldx64	BR1, BR0, 0
	e_ldx64	BR2, BR0, 8
	e_stx64	BR10, XF_SRC6, BR1
	e_stx64	BR10, XF_SRC6 + 8, BR2
	e_or	BR1, BR2
	e_jeqi	BR1, 0, .drop			; nor an IPv6 one
.nh:	; the next hop: this CPU's, while it is the real's, for this interface
	; in, from this time step
	e_ldx32	BR1, BR10, XF_REAL
	e_andi	BR1, XL_NH_N - 1
	e_stx32	BR10, XF_KEY, BR1
	xl_lookup XL_NH, XF_KEY
	e_jeqi	BR0, 0, .drop
	e_ldx64	BR1, BR0, NH_ADDR
	e_ldx64	BR2, BR10, XF_RADDR
	e_jne	BR1, BR2, .fib
	e_ldx64	BR1, BR0, NH_ADDR + 8
	e_ldx64	BR2, BR10, XF_RADDR + 8
	e_jne	BR1, BR2, .fib
	e_ldx32	BR1, BR0, NH_FAMILY
	e_ldx32	BR2, BR10, XF_RFAM
	e_jne	BR1, BR2, .fib
	e_ldx32	BR1, BR0, NH_STAMP
	e_ldx32	BR2, BR10, XF_STAMP
	e_jne	BR1, BR2, .fib
	e_ldx32	BR1, BR0, NH_IN
	e_ldx32	BR2, BR6, XDP_MD_IFINDEX
	e_jne	BR1, BR2, .fib
	repeat 3, h:0
		e_ldx16	BR1, BR0, NH_DMAC + h * 2
		e_stx16	BR10, XF_FIB + FIB_DMAC + h * 2, BR1
		e_ldx16	BR1, BR0, NH_SMAC + h * 2
		e_stx16	BR10, XF_FIB + FIB_SMAC + h * 2, BR1
	end repeat
	e_ldx32	BR1, BR0, NH_IFINDEX
	e_stx32	BR10, XF_FIB + FIB_IFINDEX, BR1
	e_ldx32	BR1, BR0, NH_MTU
	e_stx32	BR10, XF_MTU, BR1
	e_ja	.encap
.fib:	; from the kernel's tables: first the route's MTU (asked about a length
	; no MTU takes: FRAG_NEEDED says it, since 5.12; else 0, not known),
	; then the next hop
	xl_fib_fill
	e_st16	BR10, XF_FIB + FIB_TOT_LEN, 0xFFFF
	e_mov	BR1, BR6
	e_mov	BR2, BR10
	e_addi	BR2, XF_FIB
	e_movi	BR3, 64
	e_movi	BR4, 0
	e_call	BPF_FUNC_fib_lookup
	e_st32	BR10, XF_MTU, 0
	e_jnei	BR0, FIB_FRAG_NEEDED, .route
	e_ldx16	BR1, BR10, XF_FIB + FIB_TOT_LEN
	e_jeqi	BR1, 0xFFFF, .route
	e_stx32	BR10, XF_MTU, BR1
.route:
	xl_fib_fill
	e_mov	BR1, BR6
	e_mov	BR2, BR10
	e_addi	BR2, XF_FIB
	e_movi	BR3, 64
	e_movi	BR4, 0
	e_call	BPF_FUNC_fib_lookup
	e_jnei	BR0, 0, .drop			; no route, or no neighbour yet
	xl_lookup XL_NH, XF_KEY			; kept (XF_KEY: its slot still)
	e_jeqi	BR0, 0, .encap
	repeat 3, h:0
		e_ldx16	BR1, BR10, XF_FIB + FIB_DMAC + h * 2
		e_stx16	BR0, NH_DMAC + h * 2, BR1
		e_ldx16	BR1, BR10, XF_FIB + FIB_SMAC + h * 2
		e_stx16	BR0, NH_SMAC + h * 2, BR1
	end repeat
	e_ldx32	BR1, BR10, XF_FIB + FIB_IFINDEX
	e_stx32	BR0, NH_IFINDEX, BR1
	e_ldx32	BR1, BR6, XDP_MD_IFINDEX
	e_stx32	BR0, NH_IN, BR1
	e_ldx32	BR1, BR10, XF_STAMP
	e_stx32	BR0, NH_STAMP, BR1
	repeat 2, q:0
		e_ldx64	BR1, BR10, XF_RADDR + q * 8
		e_stx64	BR0, NH_ADDR + q * 8, BR1
	end repeat
	e_ldx32	BR1, BR10, XF_RFAM
	e_stx32	BR0, NH_FAMILY, BR1
	e_ldx32	BR1, BR10, XF_MTU
	e_stx32	BR0, NH_MTU, BR1
.encap:	; the outer headers: the real's family, GUE or not
	e_ldx32	BR1, BR10, XF_VFLAGS
	e_andi	BR1, XVF_GUE
	e_ldx32	BR2, BR10, XF_RFAM
	; too large with them for the way out? (an ICMP error never is)
	e_movi	BR4, IP_L			; their length
	e_jeqi	BR2, 4, @f
	e_movi	BR4, IP6_L
@@:
	e_jeqi	BR1, 0, @f
	e_addi	BR4, UDP_L
@@:
	e_ldx32	BR3, BR10, XF_MTU
	e_jeqi	BR3, 0, .fits			; not known
	e_ldx32	BR5, BR10, XF_ICMP
	e_jnei	BR5, 0, .fits
	e_ldx32	BR5, BR10, XF_ILEN
	e_add	BR5, BR4
	e_jle	BR5, BR3, .fits
	e_sub	BR3, BR4			; what is left for the client
	e_stx32	BR10, XF_MTU, BR3
	e_ldx32	BR5, BR10, XF_FAM
	e_jeqi	BR5, 6, .toobig6
	e_ja	.toobig4
.fits:
	e_jeqi	BR2, 6, .out6
	e_jnei	BR1, 0, .gue4
	xl_encap 4, 0
.gue4:
	xl_encap 4, 1
.out6:
	e_jnei	BR1, 0, .gue6
	xl_encap 6, 0
.gue6:
	xl_encap 6, 1
.send:	; out the way it came, or to the interface the route says
	e_ldx32	BR9, BR10, XF_FIB + FIB_IFINDEX
	xl_count XS_TX
	e_ldx32	BR1, BR6, XDP_MD_IFINDEX
	e_jne	BR1, BR9, .redirect
	e_movi	BR0, XDP_TX
	e_exit
.redirect:
	e_mov	BR1, BR9
	e_movi	BR2, 0
	e_call	BPF_FUNC_redirect
	e_exit
.toobig4:	; ICMP fragmentation needed back to the client, with its packet's
	; IP header and 8 bytes: its packet cut to those, room made in front
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR2, BR7
	e_sub	BR2, BR8
	e_addi	BR2, ETH_L + IP_L + 8		; (- its length: negative)
	e_mov	BR1, BR6
	e_call	BPF_FUNC_xdp_adjust_tail
	e_jnei	BR0, 0, .drop
	e_mov	BR1, BR6
	e_movi	BR2, -(IP_L + ICMP_L)
	e_call	BPF_FUNC_xdp_adjust_head
	e_jnei	BR0, 0, .drop
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP_L + ICMP_L + IP_L + 8
	e_jgt	BR1, BR8, .drop
	xl_eth_back IP_L + ICMP_L, 0x0008	; (the old Ethernet header is there)
	O = ETH_L + IP_L + ICMP_L		; its packet
	e_st8	BR7, ETH_L, 0x45
	e_st8	BR7, ETH_L + 1, 0xC0		; (internetwork control)
	e_st16	BR7, ETH_L + 2, 0x3800		; 56, big endian
	e_st32	BR7, ETH_L + 4, 0
	e_st8	BR7, ETH_L + 8, 64
	e_st8	BR7, ETH_L + 9, 1		; ICMP
	e_st16	BR7, ETH_L + 10, 0
	e_ldx32	BR1, BR7, O + 16		; from the VIP, to the client
	e_stx32	BR7, ETH_L + 12, BR1
	e_ldx32	BR1, BR7, O + 12
	e_stx32	BR7, ETH_L + 16, BR1
	e_movi	BR1, 0
	xl_sum	ETH_L, 10
	e_xori	BR1, 0xFFFF
	e_stx16	BR7, ETH_L + 10, BR1
	e_st16	BR7, ETH_L + IP_L, 0x0403	; type 3, code 4
	e_st32	BR7, ETH_L + IP_L + 2, 0	; the checksum, unused
	e_ldx32	BR1, BR10, XF_MTU
	e_be	BR1, 16
	e_stx16	BR7, ETH_L + IP_L + 6, BR1	; the next hop's MTU
	e_movi	BR1, 0
	xl_sum	ETH_L + IP_L, (ICMP_L + IP_L + 8) / 2
	e_xori	BR1, 0xFFFF
	e_stx16	BR7, ETH_L + IP_L + 2, BR1
	xl_count XS_TOOBIG
	e_movi	BR0, XDP_TX
	e_exit
.toobig6:	; ICMPv6 packet too big back to the client, with its packet's
	; IPv6 header and 8 bytes
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR2, BR7
	e_sub	BR2, BR8
	e_addi	BR2, ETH_L + IP6_L + 8
	e_mov	BR1, BR6
	e_call	BPF_FUNC_xdp_adjust_tail
	e_jnei	BR0, 0, .drop
	e_mov	BR1, BR6
	e_movi	BR2, -(IP6_L + ICMP_L)
	e_call	BPF_FUNC_xdp_adjust_head
	e_jnei	BR0, 0, .drop
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP6_L + ICMP_L + IP6_L + 8
	e_jgt	BR1, BR8, .drop
	xl_eth_back IP6_L + ICMP_L, 0xDD86
	O = ETH_L + IP6_L + ICMP_L
	e_st32	BR7, ETH_L, 0x60		; version 6 (big endian 0x60000000)
	e_st16	BR7, ETH_L + 4, 0x3800		; 56
	e_st8	BR7, ETH_L + 6, 58
	e_st8	BR7, ETH_L + 7, 64
	repeat 4, q:0				; from the VIP, to the client
		e_ldx32	BR1, BR7, O + 24 + q * 4
		e_stx32	BR7, ETH_L + 8 + q * 4, BR1
		e_ldx32	BR1, BR7, O + 8 + q * 4
		e_stx32	BR7, ETH_L + 24 + q * 4, BR1
	end repeat
	e_st16	BR7, ETH_L + IP6_L, 0x0002	; type 2, code 0
	e_st16	BR7, ETH_L + IP6_L + 2, 0
	e_ldx32	BR1, BR10, XF_MTU
	e_be	BR1, 32
	e_stx32	BR7, ETH_L + IP6_L + 4, BR1	; the MTU
	; the checksum: the pseudo header (the addresses, 56, 58), the message
	e_movi	BR1, 0x3800 + 0x3A00		; (56 and 58, big endian, read little)
	xl_sum	ETH_L + 8, 16
	xl_sum	ETH_L + IP6_L, (ICMP_L + IP6_L + 8) / 2
	e_xori	BR1, 0xFFFF
	e_stx16	BR7, ETH_L + IP6_L + 2, BR1
	xl_count XS_TOOBIG
	e_movi	BR0, XDP_TX
	e_exit
.filtered:
	xl_count XS_FILTERED
	e_movi	BR0, XDP_DROP
	e_exit
.synd:
	xl_count XS_SYN
	e_movi	BR0, XDP_DROP
	e_exit
.drop:
	xl_count XS_DROP
	e_movi	BR0, XDP_DROP
	e_exit
.pass:
	e_movi	BR0, XDP_PASS
	e_exit
xl_prog_len = $ - xl_prog
end rodata
