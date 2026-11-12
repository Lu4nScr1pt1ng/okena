; The XDP balancer: L4, in the driver, before the kernel's stack sees a packet.
;
; IPv4 TCP and UDP to a VIP (its address, port and protocol in the VIPS map)
; go to a real server, wrapped in IPIP (the real takes the outer header off
; and answers the client itself: direct server return); everything else
; passes to the kernel. A flow keeps its real while it lives in LRU (an LRU
; list a CPU: no lock between CPUs); a new one takes the real its hash
; names in the VIP's ring (RING: MAGLEV_M entries a VIP, the same table as
; the user-space maglev, so every instance agrees). The next hop's address
; comes from the kernel (bpf_fib_lookup): no gateway to configure, and a
; real on another interface is redirected there.
;
; Maps, by number (the control plane makes them in this order):
XL_VIPS		:= 0		; hash: VIP key (8 bytes) -> u32 VIP number
XL_RING		:= 1		; array: VIP number * MAGLEV_M + slot -> u32 real number
XL_REALS	:= 2		; array: real number -> u32 its address (network order)
XL_LRU		:= 3		; LRU hash: flow (16 bytes) -> u32 real number
XL_STATS	:= 4		; per-CPU array of u64: XS_*
XL_CTL		:= 5		; array: 0 -> u32 the outer header's source (network order)
XS_TX		:= 0		; packets sent on to a real
XS_MISS		:= 1		; flows not in LRU (new, or forgotten)
XS_DROP		:= 2		; no real, no route, no room: dropped
XS_N		:= 4

; the frame (offsets from BR10)
XF_FIB		:= -112		; struct bpf_fib_lookup, 64 bytes
XF_SRC		:= -40		; u32 the outer source
XF_KEY		:= -36		; u32 a key (CTL, STATS)
XF_RING		:= -32		; u32 the ring's key
XF_REAL		:= -28		; u32 the real's number
XF_FLOW		:= -24		; 16 bytes: saddr, daddr, sport, dport, protocol, 0 x3
XF_VIP		:= -8		; 8 bytes: daddr, dport, protocol, 0
; struct bpf_fib_lookup
FIB_FAMILY	:= 0
FIB_IFINDEX	:= 8
FIB_SRC		:= 16
FIB_DST		:= 32
FIB_SMAC	:= 52
FIB_DMAC	:= 58
ETH_L		:= 14
IP_L		:= 20

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

rodata
	align 8
xl_prog:
	e_mov	BR6, BR1			; the context
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7			; Ethernet, IPv4, the ports
	e_addi	BR1, ETH_L + IP_L + 4
	e_jgt	BR1, BR8, .pass
	e_ldx16	BR1, BR7, 12
	e_jnei	BR1, 0x0008, .pass		; (0x0800, read little endian)
	e_ldx8	BR1, BR7, ETH_L
	e_jnei	BR1, 0x45, .pass		; IPv4, no options
	e_ldx16	BR1, BR7, ETH_L + 6
	e_andi	BR1, 0xFF3F			; a fragment (MF, or an offset): passes
	e_jnei	BR1, 0, .pass
	e_ldx8	BR2, BR7, ETH_L + 9		; the protocol
	e_jeqi	BR2, 6, .l4
	e_jnei	BR2, 17, .pass
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
	e_ldmap	BR1, XL_VIPS
	e_mov	BR2, BR10
	e_addi	BR2, XF_VIP
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .pass			; not a VIP
	e_ldx32	BR9, BR0, 0			; its number
	e_ldmap	BR1, XL_LRU
	e_mov	BR2, BR10
	e_addi	BR2, XF_FLOW
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .new
	e_ldx32	BR1, BR0, 0
	e_stx32	BR10, XF_REAL, BR1
	e_ja	.real
.new:
	; the flow's hash: its source and ports (the VIP's are the same for all)
	e_ldx32	BR1, BR10, XF_FLOW
	e_mul32i BR1, 0x9E3779B1
	e_ldx32	BR2, BR10, XF_FLOW + 8
	e_mul32i BR2, 0x85EBCA77
	e_xor32	BR1, BR2
	e_mov32	BR2, BR1
	e_rsh32i BR2, 15
	e_xor32	BR1, BR2
	e_mod32i BR1, MAGLEV_M
	e_mov32	BR2, BR9
	e_mul32i BR2, MAGLEV_M
	e_add32	BR1, BR2
	e_stx32	BR10, XF_RING, BR1
	e_ldmap	BR1, XL_RING
	e_mov	BR2, BR10
	e_addi	BR2, XF_RING
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR1, BR0, 0
	e_stx32	BR10, XF_REAL, BR1
	e_ldmap	BR1, XL_LRU			; remembered: it keeps this real
	e_mov	BR2, BR10
	e_addi	BR2, XF_FLOW
	e_mov	BR3, BR10
	e_addi	BR3, XF_REAL
	e_movi	BR4, 0
	e_call	BPF_FUNC_map_update_elem
	xl_count XS_MISS
.real:
	e_ldmap	BR1, XL_REALS
	e_mov	BR2, BR10
	e_addi	BR2, XF_REAL
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR9, BR0, 0			; the real's address
	e_jeqi	BR9, 0, .drop			; (a slot with no real)
	e_st32	BR10, XF_KEY, 0			; the outer source
	e_ldmap	BR1, XL_CTL
	e_mov	BR2, BR10
	e_addi	BR2, XF_KEY
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .drop
	e_ldx32	BR1, BR0, 0
	e_stx32	BR10, XF_SRC, BR1
	; the next hop, from the kernel's tables
	repeat 8, q:0
		e_st64	BR10, XF_FIB + q * 8, 0
	end repeat
	e_st8	BR10, XF_FIB + FIB_FAMILY, 2	; AF_INET
	e_ldx32	BR1, BR6, XDP_MD_IFINDEX
	e_stx32	BR10, XF_FIB + FIB_IFINDEX, BR1
	e_ldx32	BR1, BR10, XF_SRC
	e_stx32	BR10, XF_FIB + FIB_SRC, BR1
	e_stx32	BR10, XF_FIB + FIB_DST, BR9
	e_mov	BR1, BR6
	e_mov	BR2, BR10
	e_addi	BR2, XF_FIB
	e_movi	BR3, 64
	e_movi	BR4, 0
	e_call	BPF_FUNC_fib_lookup
	e_jnei	BR0, 0, .drop			; no route, or no neighbour yet
	; room for the outer header
	e_mov	BR1, BR6
	e_movi	BR2, -IP_L
	e_call	BPF_FUNC_xdp_adjust_head
	e_jnei	BR0, 0, .drop
	e_ldx32	BR7, BR6, XDP_MD_DATA
	e_ldx32	BR8, BR6, XDP_MD_DATA_END
	e_mov	BR1, BR7
	e_addi	BR1, ETH_L + IP_L + IP_L
	e_jgt	BR1, BR8, .drop
	; Ethernet: the next hop's (2 bytes at a time: the stack wants its
	; accesses aligned, and the addresses are 2-byte aligned there)
	repeat 3, h:0
		e_ldx16	BR1, BR10, XF_FIB + FIB_DMAC + h * 2
		e_stx16	BR7, h * 2, BR1
		e_ldx16	BR1, BR10, XF_FIB + FIB_SMAC + h * 2
		e_stx16	BR7, 6 + h * 2, BR1
	end repeat
	e_st16	BR7, 12, 0x0008
	; the outer IPv4 header (the inner one starts at ETH_L + IP_L)
	e_ldx16	BR1, BR7, ETH_L + IP_L + 2	; the inner length, plus ours
	e_be	BR1, 16
	e_addi	BR1, IP_L
	e_be	BR1, 16
	e_ldx8	BR2, BR7, ETH_L + IP_L + 1	; its TOS
	e_st8	BR7, ETH_L, 0x45
	e_stx8	BR7, ETH_L + 1, BR2
	e_stx16	BR7, ETH_L + 2, BR1
	e_st32	BR7, ETH_L + 4, 0		; id, no fragment flags
	e_st8	BR7, ETH_L + 8, 64		; TTL
	e_st8	BR7, ETH_L + 9, 4		; IPIP
	e_st16	BR7, ETH_L + 10, 0
	e_ldx32	BR1, BR10, XF_SRC
	e_stx32	BR7, ETH_L + 12, BR1
	e_stx32	BR7, ETH_L + 16, BR9
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
	; out the way it came, or to the interface the route says
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
.drop:
	xl_count XS_DROP
	e_movi	BR0, XDP_DROP
	e_exit
.pass:
	e_movi	BR0, XDP_PASS
	e_exit
xl_prog_len = $ - xl_prog
end rodata
