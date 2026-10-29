; The client's address: what per_source limits and the PROXY protocol
; need. Shared by both engines.
;
; Only listeners that use one of them pay for it: their sessions get a
; side record (256 bytes, reserved address space, touched only for them)
; with the client's address, the local one, the per-source slot and the
; PROXY header to send.
;
; per_source counts connections per client address for the whole
; instance in a shared table. An entry is one quadword, a 40-bit keyed
; hash of (listener address, client address) and a 24-bit count, updated
; with lock cmpxchg: an atomic per connection opened or closed, never per
; byte. The key is random per start, so clients cannot aim at collisions.
; A full neighbourhood fails open (the connection is let in, uncounted)
; rather than refusing everyone. Two first connections of one client at
; the same instant may land in two entries; the limit is then a little
; loose for that client, never tight for others.

P_PEER		= 0		; sockaddr of the client (28 bytes)
P_LOCAL		= 32		; local sockaddr (28 bytes)
P_SLOT		= 60		; d: per-source entry, -1 = not counted
P_HLEN		= 64		; d: PROXY header length (0 = none)
P_HOFF		= 68		; d: bytes of it sent
P_HDR		= 72		; the header (v1 at most 107 bytes)
P_SIZE		= 256
P_SHIFT		= 8

SRC_BITS	= 20		; 1M entries, 8 MiB of address space
SRC_PROBE	= 16

bss
	align 8
	g_peer_base	dq ?
	g_src_tbl	dq ?		; shared
	g_src_seed	rq 2
	g_ip_a:		rb 16		; scratch: normalized addresses
	g_ip_b:		rb 16
end bss

; Supervisor, once: the shared table and its random key.
peer_global_init:
	xor	edi,edi
	mov	esi,8 shl SRC_BITS
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_src_tbl],rax
	lea	rdi,[g_src_seed]
	mov	esi,16
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	ret

; Worker: the side records. eax = 0 or -errno.
peer_worker_init:
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,P_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_peer_base],rax
	xor	eax,eax
.done:
	ret

; ebx = session. rax = its side record.
peer_ptr:
	mov	eax,ebx
	shl	rax,P_SHIFT
	add	rax,[g_peer_base]
	ret

; rsi = sockaddr (AF_INET or AF_INET6), rdi = 16-byte output.
; eax = 4 or 6, edx = port (host order). An IPv4-mapped IPv6 address
; (a dual-stack socket) is an IPv4 address.
peer_normalize:
	movzx	edx,word [rsi+2]
	xchg	dl,dh
	cmp	word [rsi],AF_INET
	jne	.v6
	mov	eax,[rsi+4]
	mov	[rdi],eax
	xor	eax,eax
	mov	[rdi+4],eax
	mov	[rdi+8],rax
	mov	eax,4
	ret
.v6:
	mov	rax,[rsi+8]
	mov	rcx,[rsi+16]
	test	rax,rax
	jnz	.plain
	mov	r8,0xFFFF0000
	mov	r9,rcx
	mov	r10,0xFFFFFFFF
	and	r9,r10
	cmp	r9,r8
	jne	.plain
	shr	rcx,32				; ::ffff:a.b.c.d
	mov	[rdi],ecx
	xor	eax,eax
	mov	[rdi+4],eax
	mov	[rdi+8],rax
	mov	eax,4
	ret
.plain:
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	eax,6
	ret

; --------------------------------------------------------- per_source

; ebx = session (its P_PEER filled), r13d = listener.
; CF when the client is over the listener's limit (nothing counted then).
src_acquire:
	push	rbx
	push	r12
	push	r14
	push	r15
	call	peer_ptr
	mov	r12,rax
	mov	dword [r12+P_SLOT],-1
	; key: hash of the listener's address and the client's address
	lea	rdi,[g_ip_a]
	lea	rsi,[r12+P_PEER]
	call	peer_normalize
	imul	r8,r13,LS_SIZE
	lea	r8,[g_listeners+r8]
	mov	rax,[g_src_seed]
	mov	rcx,[g_ip_a]
	call	.mix
	mov	rcx,[g_ip_a+8]
	call	.mix
	mov	rcx,[r8+LS_SA]			; family, port and the start of the address
	call	.mix
	mov	rcx,[r8+LS_SA+8]
	call	.mix
	mov	rcx,[r8+LS_SA+16]
	call	.mix
	mov	rcx,[g_src_seed+8]
	call	.mix
	mov	r14,rax				; hash
	mov	r15,rax
	shr	r15,24
	or	r15,1				; 40-bit key, never 0
	mov	r9d,[r8+LS_PER_SOURCE]		; limit
	mov	r10d,2				; attempts (a lost race retries)
.attempt:
	mov	rdi,-1				; first reusable entry
	xor	ecx,ecx
.probe:
	cmp	ecx,SRC_PROBE
	jae	.claim
	mov	rax,r14
	add	rax,rcx
	and	eax,(1 shl SRC_BITS) - 1
	mov	rdx,[g_src_tbl]
	lea	rdx,[rdx+rax*8]
.read:
	mov	rax,[rdx]
	mov	rsi,rax
	shr	rsi,24
	cmp	rsi,r15
	je	.mine
	test	eax,0xFFFFFF
	jnz	.next				; someone else's, in use
	cmp	rdi,-1
	jne	.next
	mov	rdi,rdx				; free or stale: take it if ours is absent
.next:
	inc	ecx
	jmp	.probe
.mine:
	mov	r11d,eax
	and	r11d,0xFFFFFF
	test	r11d,r11d
	jz	.claim_here			; our key, count 0: take it
	cmp	r11d,r9d
	jae	.over
	lea	rsi,[rax+1]
	lock	cmpxchg [rdx],rsi
	jne	.read
	jmp	.counted
.claim_here:
	mov	rdi,rdx
.claim:
	cmp	rdi,-1
	je	.full
	mov	rdx,rdi
	mov	rax,[rdx]
	test	eax,0xFFFFFF
	jnz	.retry				; taken meanwhile
	test	r9d,r9d
	jz	.over				; a limit of 0 lets nobody in
	mov	rsi,r15
	shl	rsi,24
	inc	rsi
	lock	cmpxchg [rdx],rsi
	jne	.retry
.counted:
	sub	rdx,[g_src_tbl]
	shr	rdx,3
	mov	[r12+P_SLOT],edx
	clc
	jmp	.out
.retry:
	dec	r10d
	jnz	.attempt
.full:
	inc	qword [g_st_src_open]		; fail open
	clc
	jmp	.out
.over:
	stc
.out:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret
; rax = state, rcx = word: rax = mixed (keyed by the seed in the state)
.mix:
	xor	rax,rcx
	mov	rcx,0x9E3779B97F4A7C15
	imul	rax,rcx
	mov	rcx,rax
	shr	rcx,29
	xor	rax,rcx
	rol	rax,17
	ret

; ebx = session: release its per-source entry, if counted.
src_release:
	call	peer_ptr
	mov	ecx,[rax+P_SLOT]
	cmp	ecx,-1
	je	.done
	mov	dword [rax+P_SLOT],-1
	mov	rdx,[g_src_tbl]
	lock	dec qword [rdx+rcx*8]
.done:
	ret

; ------------------------------------------------------ PROXY protocol

; ebx = session, r13d = listener: build the header into the side record
; (P_PEER and P_LOCAL filled).
pp_build:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	peer_ptr
	mov	r12,rax
	mov	dword [r12+P_HOFF],0
	lea	rdi,[g_ip_a]
	lea	rsi,[r12+P_PEER]
	call	peer_normalize
	mov	r14d,eax			; family
	mov	r15d,edx			; client port
	lea	rdi,[g_ip_b]
	lea	rsi,[r12+P_LOCAL]
	call	peer_normalize
	mov	ebx,edx				; local port
	; both sides have one family: a dual-stack socket sees IPv4 clients
	; as mapped addresses on a mapped local address, both normalized
	imul	rax,r13,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PP_V2
	jnz	.v2
	; v1: "PROXY TCP4 src dst sport dport\r\n"
	lea	rdi,[r12+P_HDR]
	mov	dword [rdi],'PROX'
	mov	dword [rdi+4],'Y TC'
	mov	byte [rdi+8],'P'
	mov	byte [rdi+9],'4'
	cmp	r14d,4
	je	@f
	mov	byte [rdi+9],'6'
@@:
	mov	byte [rdi+10],' '
	add	rdi,11
	lea	rsi,[g_ip_a]
	mov	edx,r14d
	call	fmt_ip
	mov	byte [rdi],' '
	inc	rdi
	lea	rsi,[g_ip_b]
	mov	edx,r14d
	call	fmt_ip
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,r15d
	call	fmt_u
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,ebx
	call	fmt_u
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r12+P_HDR]
	sub	rdi,rax
	mov	[r12+P_HLEN],edi
	jmp	.out
.v2:
	lea	rdi,[r12+P_HDR]
	mov	rax,0x510A0D000A0D0A0D		; \r\n\r\n\0\r\nQ

	mov	[rdi],rax
	mov	dword [rdi+8],0x0A544955	; "UIT\n"
	mov	byte [rdi+12],0x21		; version 2, PROXY
	cmp	r14d,4
	jne	.v2_6
	mov	byte [rdi+13],0x11		; TCP over IPv4
	mov	word [rdi+14],0x0C00		; 12, big endian
	mov	eax,[g_ip_a]
	mov	[rdi+16],eax
	mov	eax,[g_ip_b]
	mov	[rdi+20],eax
	mov	eax,r15d
	xchg	al,ah
	mov	[rdi+24],ax
	mov	eax,ebx
	xchg	al,ah
	mov	[rdi+26],ax
	mov	dword [r12+P_HLEN],28
	jmp	.out
.v2_6:
	mov	byte [rdi+13],0x21		; TCP over IPv6
	mov	word [rdi+14],0x2400		; 36
	mov	rax,[g_ip_a]
	mov	[rdi+16],rax
	mov	rax,[g_ip_a+8]
	mov	[rdi+24],rax
	mov	rax,[g_ip_b]
	mov	[rdi+32],rax
	mov	rax,[g_ip_b+8]
	mov	[rdi+40],rax
	mov	eax,r15d
	xchg	al,ah
	mov	[rdi+48],ax
	mov	eax,ebx
	xchg	al,ah
	mov	[rdi+50],ax
	mov	dword [r12+P_HLEN],52
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = output, eax = value. rdi = after it.
fmt_u:
	sub	rsp,24
	lea	rsi,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	ecx
	add	dl,'0'
	dec	rsi
	mov	[rsi],dl
	test	eax,eax
	jnz	@b
	lea	rcx,[rsp+24]
	sub	rcx,rsi
	rep	movsb
	add	rsp,24
	ret

; rdi = output, rsi = 16 address bytes, edx = 4 or 6. rdi = after it.
; IPv6 as eight hex groups (valid, and simplest to read back).
fmt_ip:
	push	rbx
	push	r12
	mov	rbx,rsi
	xor	r12d,r12d
	cmp	edx,4
	jne	.v6
.octet:
	movzx	eax,byte [rbx+r12]
	call	fmt_u
	inc	r12d
	cmp	r12d,4
	je	.done
	mov	byte [rdi],'.'
	inc	rdi
	jmp	.octet
.v6:
	movzx	eax,word [rbx+r12*2]
	xchg	al,ah
	call	fmt_hex
	inc	r12d
	cmp	r12d,8
	je	.done
	mov	byte [rdi],':'
	inc	rdi
	jmp	.v6
.done:
	pop	r12
	pop	rbx
	ret

; rdi = output, eax = 16-bit value: lowercase hex, no leading zeros.
fmt_hex:
	mov	ecx,12
	xor	edx,edx				; started
.digit:
	mov	r8d,eax
	shr	r8d,cl
	and	r8d,15
	test	edx,edx
	jnz	.emit
	test	r8d,r8d
	jnz	.emit
	test	ecx,ecx
	jnz	.skip
.emit:
	mov	edx,1
	cmp	r8d,10
	jb	@f
	add	r8d,'a' - '0' - 10
@@:
	add	r8d,'0'
	mov	[rdi],r8b
	inc	rdi
.skip:
	sub	ecx,4
	jns	.digit
	ret

; ebx = session, r13d = listener, edi = client fd (a normal descriptor):
; the local address, from the listener or (bound to every address) from
; the socket itself.
peer_local:
	push	rbx
	call	peer_ptr
	mov	rbx,rax
	imul	rcx,r13,LS_SIZE
	lea	rcx,[g_listeners+rcx]
	test	dword [rcx+LS_FLAGS],LSF_WILDCARD
	jnz	.ask
	lea	rsi,[rcx+LS_SA]
	lea	rdi,[rbx+P_LOCAL]
	mov	ecx,28
	rep	movsb
	pop	rbx
	ret
.ask:
	sub	rsp,8
	mov	dword [rsp],28
	lea	rsi,[rbx+P_LOCAL]
	mov	rdx,rsp
	mov	eax,SYS_getsockname
	syscall
	add	rsp,8
	pop	rbx
	ret
