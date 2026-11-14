; PROXY protocol received: `proxy_protocol accept [FROM...]` on a tcp or
; http listener. A load balancer in front (an AWS NLB, HAProxy, another
; okena) writes the client's address before the first byte of the
; connection; from then on that client is the session's peer, for logs,
; X-Forwarded-For, allow/deny, limits, per_source, hashing and a PROXY
; header sent on.
;
; The header is looked at with MSG_PEEK and then taken to its last byte
; and no further, so what follows stays in the socket: the request, the
; ClientHello (kTLS needs the socket's own bytes) or an L4 stream reach
; their code as on any connection, which never knows. Most often it is all
; there when the connection is accepted (TCP_DEFER_ACCEPT), and costs two
; system calls and no wait on the ring. Otherwise every byte seen belongs
; to the header (it is not whole yet), so they are taken, and the next
; look waits on the ring (or epoll) for more: never a busy loop. The
; header timeout bounds all of it, and anything that is not a header
; closes the connection.
;
; Both versions (RFC-less spec, haproxy.org proxy-protocol.txt): v1 text
; ("PROXY TCP4 a b p q\r\n", 107 bytes at most, UNKNOWN keeps the
; connection's addresses) and v2 binary (LOCAL keeps them; AF_INET and
; AF_INET6 taken, UNSPEC and UNIX kept as LOCAL; TLVs skipped).
;
; FROM lists who may send one (as trusted_proxies takes them); a peer
; outside it is served as a direct client and must not send one. Without
; FROM every peer must.

HS_PP_IN	:= 53				; reading the PROXY header (H_STATE)
PP_PEEK		:= 536				; a first look: v1, and v2 with its addresses and common TLVs
PP_MAX		:= 4096				; a longer v2 header is refused
assert PP_MAX <= H_IN_CAP

bss
	align 8
	g_pp_src	rb 16			; what the last whole header said
	g_pp_dst	rb 16
	g_pp_kind	dd ?			; 4, 6, or 0: keep the connection's addresses
	g_pp_sport	dd ?			; (host order)
	g_pp_dport	dd ?
	g_pp_local	db ?			; P_LOCAL came from a header (peer_admit)
end bss

rodata
	pp_v2_sig	db 13,10,13,10,0,13,10,'QUIT',10
	pp_v1_sig	db 'PROXY '
end rodata

; ebx = session (P_PEER filled), r13d = listener: CF when the connection
; must send a PROXY header before anything else. Keeps rbx, r12-r15.
pp_in_wanted:
	imul	rax,r13,LS_SIZE
	lea	rax,[g_listeners+rax]
	test	dword [rax+LS_FLAGS],LSF_PP_IN
	jz	.no
	cmp	dword [rax+LS_PCOUNT],0
	je	.yes				; from everyone
	push	r14
	mov	r14,rax
	call	peer_ptr
	lea	rsi,[rax+P_PEER]
	lea	rdi,[g_ip_a]
	call	peer_normalize
	mov	edx,eax
	lea	rsi,[g_ip_a]
	mov	r8d,[r14+LS_PFIRST]
	mov	r9d,r8d
	add	r9d,[r14+LS_PCOUNT]
	call	trust_match_range		; CF: one of the senders
	pop	r14
	ret
.yes:
	stc
	ret
.no:
	clc
	ret

; ebx = session, r13d = listener: a new connection that starts with a
; PROXY header. Its admission (per_source, the header sent on) waits for
; the address the header gives. Both engines.
pp_in_start:
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN	; on the http machinery meanwhile,
	or	dword [rax+S_FLAGS],SF_TLS_HS	; as a tcp session's handshake is
	h_rec
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	[r15+H_FLAGS],eax
	mov	[r15+H_UTLS],eax
	mov	dword [r15+H_STATE],HS_PP_IN
	mov	edi,ebx
	mov	esi,PH_HEAD
	call	ph_arm
	h_rec
	call	pp_look_now			; usually all there already
	cmp	rax,-EAGAIN
	jne	pp_in_recv
; nothing (more) yet: look again when something comes
pp_in_wait:
	h_rec
	call	pp_room
	mov	ecx,SIDE_CLIENT
	jmp	h_recv_peek

; ebx = session, r15 = record: rdi = where the next look goes (after what
; is known of the header), esi = how far to look (to the header's end when
; its length is known). Keeps rbx, r12-r15.
pp_room:
	mov	rdi,[r15+H_BUF]
	mov	esi,[r15+H_INLEN]
	call	pp_parse			; (not whole: 0, edx = its length if known)
	mov	ecx,PP_PEEK
	test	edx,edx
	cmovnz	ecx,edx
	sub	ecx,[r15+H_INLEN]
	mov	esi,ecx
	mov	edi,[r15+H_INLEN]
	add	rdi,[r15+H_BUF]
	ret

; ebx = session, r15 = record: a look at once (MSG_DONTWAIT). rax = bytes
; or -errno.
pp_look_now:
	call	pp_room
	mov	edx,esi
	mov	rsi,rdi
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	mov	r10d,MSG_PEEK or MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	ret

; ebx = session, r15 = record, eax = header bytes to take from the socket
; (seen by a look, so there): into IN after the others. CF when the socket
; gave fewer. Keeps rbx, r12-r15.
pp_take:
	push	rax
	mov	edx,eax
	mov	esi,[r15+H_INLEN]
	add	rsi,[r15+H_BUF]
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	pop	rdx
	cmp	rax,rdx
	jne	.short
	add	[r15+H_INLEN],edx
	clc
	ret
.short:
	stc
	ret

; ebx = session, rax = bytes the look found after what is known of the
; header (http_recv_plain in HS_PP_IN, or the first look).
pp_in_recv:
	test	rax,rax
	jle	.close				; the client left, or an error
	h_rec
	push	rax
	mov	edi,ebx
	call	idle_touch
	h_rec
	mov	rdi,[r15+H_BUF]
	mov	esi,[r15+H_INLEN]
	add	esi,[rsp]
	call	pp_parse
	pop	rcx
	h_rec
	test	eax,eax
	js	.close				; not a PROXY header
	jz	.more
	sub	eax,[r15+H_INLEN]		; whole: its bytes still in the socket
	call	pp_take
	jc	.close
	jmp	pp_in_done
.more:
	; not whole: every byte seen is the header's. Take them, wait for more
	mov	eax,ecx
	call	pp_take
	jc	.close
	cmp	dword [r15+H_INLEN],PP_MAX
	jae	.close
	jmp	pp_in_wait
.close:
	mov	edi,ebx
	jmp	session_close

; ebx = session: its header taken (g_pp_*). The connection goes on as
; accept would have sent it, with the header's addresses.
pp_in_done:
	push	r13
	mov	edi,ebx
	call	ph_disarm
	h_rec
	mov	dword [r15+H_STATE],0
	mov	dword [r15+H_INLEN],0
	call	session_ptr
	and	dword [rax+S_FLAGS],not SF_TLS_HS
	mov	r13d,[rax+S_LST]
	call	pp_apply
	call	peer_admit_pp			; per_source, the PROXY header sent on
	jc	.over
	imul	rax,r13,LS_SIZE
	pop	r13
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	je	http_start
	call	tcp_tls_wanted
	test	rax,rax
	jnz	tcp_tls_start			; TLS first, then the upstream
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING	; as accept leaves it: the connect's
	mov	edi,ebx					; completion is told apart by it
	cmp	dword [g_engine],ENGINE_EPOLL
	je	ep_connect
	jmp	session_connect
.over:
	inc	qword [g_st_l_source+r13*8]
	dec	qword [g_st_l_accepted+r13*8]	; refused, not admitted
	pop	r13
	mov	edi,ebx
	jmp	session_close

; ebx = session: the header's addresses into its side record (P_PEER, the
; client; P_LOCAL, where it connected). Sets g_pp_local.
pp_apply:
	mov	byte [g_pp_local],0
	mov	ecx,[g_pp_kind]
	test	ecx,ecx
	jz	.out				; LOCAL, UNKNOWN: the connection's own
	mov	byte [g_pp_local],1
	call	peer_ptr
	push	rbx
	mov	rbx,rax
	lea	rdi,[rbx+P_PEER]
	lea	rsi,[g_pp_src]
	mov	edx,[g_pp_sport]
	call	.sockaddr
	lea	rdi,[rbx+P_LOCAL]
	lea	rsi,[g_pp_dst]
	mov	edx,[g_pp_dport]
	call	.sockaddr
	pop	rbx
.out:
	ret
; rdi = sockaddr (28 bytes), rsi = address, edx = port, ecx = 4 or 6
.sockaddr:
	xor	eax,eax
	mov	[rdi],rax
	mov	[rdi+8],rax
	mov	[rdi+16],rax
	mov	[rdi+24],eax
	xchg	dl,dh
	mov	[rdi+2],dx
	cmp	ecx,4
	jne	.v6
	mov	word [rdi],AF_INET
	mov	eax,[rsi]
	mov	[rdi+4],eax
	ret
.v6:
	mov	word [rdi],AF_INET6
	mov	rax,[rsi]
	mov	[rdi+8],rax
	mov	rax,[rsi+8]
	mov	[rdi+16],rax
	ret

; rdi = bytes, esi = how many: a PROXY header at their start?
;   eax = -1  no (or a malformed one)
;   eax = 0   not whole yet; edx = its whole length when known, else 0
;   eax = N   whole, N bytes long; g_pp_* say what it says
; Keeps rbx, r12-r15.
pp_parse:
	xor	edx,edx
	test	esi,esi
	jz	.more
	cmp	byte [rdi],'P'
	je	.v1
	cmp	byte [rdi],13
	jne	.bad
; v2: 12 bytes of signature, version and command, family, length (BE)
	mov	ecx,12
	cmp	esi,ecx
	cmovb	ecx,esi
	xor	eax,eax
@@:
	mov	r8b,[rdi+rax]
	cmp	r8b,[pp_v2_sig+rax]
	jne	.bad
	inc	eax
	cmp	eax,ecx
	jb	@b
	cmp	esi,16
	jb	.more
	movzx	eax,byte [rdi+12]
	mov	ecx,eax
	and	eax,0xF0
	cmp	eax,0x20
	jne	.bad				; version 2 only
	and	ecx,15
	cmp	ecx,1
	ja	.bad				; LOCAL (0) or PROXY (1)
	movzx	edx,word [rdi+14]
	xchg	dl,dh
	add	edx,16				; the whole header
	cmp	edx,PP_MAX
	ja	.bad
	cmp	esi,edx
	jb	.more				; (edx: how long it will be)
	mov	dword [g_pp_kind],0
	test	ecx,ecx
	jz	.whole				; LOCAL: a health check of the balancer's own
	movzx	eax,byte [rdi+13]
	shr	eax,4
	cmp	eax,1
	je	.v2_inet
	cmp	eax,2
	jne	.whole				; UNSPEC, UNIX: as LOCAL
	cmp	edx,16+36
	jb	.bad
	mov	rax,[rdi+16]
	mov	qword [g_pp_src],rax
	mov	rax,[rdi+24]
	mov	qword [g_pp_src+8],rax
	mov	rax,[rdi+32]
	mov	qword [g_pp_dst],rax
	mov	rax,[rdi+40]
	mov	qword [g_pp_dst+8],rax
	movzx	eax,word [rdi+48]
	movzx	ecx,word [rdi+50]
	mov	r8d,6
	jmp	.v2_ports
.v2_inet:
	cmp	edx,16+12
	jb	.bad
	mov	eax,[rdi+16]
	mov	dword [g_pp_src],eax
	mov	eax,[rdi+20]
	mov	dword [g_pp_dst],eax
	movzx	eax,word [rdi+24]
	movzx	ecx,word [rdi+26]
	mov	r8d,4
.v2_ports:
	xchg	al,ah
	xchg	cl,ch
	mov	[g_pp_sport],eax
	mov	[g_pp_dport],ecx
	mov	[g_pp_kind],r8d
.whole:
	mov	eax,edx
	ret
.more:
	xor	eax,eax
	ret
.bad:
	mov	eax,-1
	ret
; v1: "PROXY " then TCP4, TCP6 or UNKNOWN, a line of 107 bytes at most
.v1:
	mov	ecx,6
	cmp	esi,ecx
	cmovb	ecx,esi
	xor	eax,eax
@@:
	mov	r8b,[rdi+rax]
	cmp	r8b,[pp_v1_sig+rax]
	jne	.bad
	inc	eax
	cmp	eax,ecx
	jb	@b
	mov	ecx,107
	cmp	esi,ecx
	cmovb	ecx,esi
	xor	eax,eax				; its LF
@@:
	cmp	eax,ecx
	jae	.v1_nolf
	cmp	byte [rdi+rax],10
	je	@f
	inc	eax
	jmp	@b
.v1_nolf:
	cmp	esi,107
	jae	.bad				; too long to be one
	jmp	.more
@@:
	cmp	eax,7
	jb	.bad
	cmp	byte [rdi+rax-1],13
	jne	.bad
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	lea	r12,[rdi+6]			; the fields
	lea	r13,[rdi+rax-1]			; their end (the CR)
	lea	r14d,[rax+1]			; the header's length
	mov	dword [g_pp_kind],0
	mov	rax,r13
	sub	rax,r12
	cmp	rax,7
	jb	.v1_proto
	cmp	dword [r12],'UNKN'
	jne	.v1_proto
	cmp	word [r12+4],'OW'
	jne	.v1_proto
	cmp	byte [r12+6],'N'
	je	.v1_whole			; anything after UNKNOWN is ignored
.v1_proto:
	cmp	rax,5
	jb	.v1_bad
	cmp	dword [r12],'TCP4'
	mov	r15d,4
	je	@f
	cmp	dword [r12],'TCP6'
	mov	r15d,6
	jne	.v1_bad
@@:
	cmp	byte [r12+4],' '
	jne	.v1_bad
	add	r12,5
	call	.v1_field			; the source
	jc	.v1_bad
	lea	rdx,[g_pp_src]
	call	.v1_addr
	jc	.v1_bad
	call	.v1_field			; the destination
	jc	.v1_bad
	lea	rdx,[g_pp_dst]
	call	.v1_addr
	jc	.v1_bad
	call	.v1_field
	jc	.v1_bad
	call	.v1_port
	jc	.v1_bad
	mov	[g_pp_sport],eax
	call	.v1_field
	jc	.v1_bad
	cmp	rbx,r13
	jne	.v1_bad				; nothing after the last port
	call	.v1_port
	jc	.v1_bad
	mov	[g_pp_dport],eax
	mov	[g_pp_kind],r15d
.v1_whole:
	mov	eax,r14d
	jmp	.v1_out
.v1_bad:
	mov	eax,-1
.v1_out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; r12 = a field's first byte: rdi/esi = it, up to a space or r13; r12
; past its space, rbx = where it ended. CF when empty.
.v1_field:
	mov	rdi,r12
	mov	rbx,r12
@@:
	cmp	rbx,r13
	jae	@f
	cmp	byte [rbx],' '
	je	@f
	inc	rbx
	jmp	@b
@@:
	mov	rsi,rbx
	sub	rsi,rdi
	jz	.v1_empty
	lea	r12,[rbx+1]
	clc
	ret
.v1_empty:
	stc
	ret
; rdi/esi = an address of the family r15d, rdx = 16 bytes out. CF: not one.
.v1_addr:
	cmp	r15d,4
	jne	parse_ipv6_text
	push	rdx
	call	parse_ipv4_text
	pop	rdx
	jc	@f
	mov	[rdx],eax
@@:
	ret
; rdi/esi = a port: eax, CF when it is not 0..65535 in digits.
.v1_port:
	cmp	esi,5
	ja	.v1_empty
	xor	eax,eax
	xor	ecx,ecx
@@:
	movzx	edx,byte [rdi+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.v1_empty
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,esi
	jb	@b
	cmp	eax,65535
	ja	.v1_empty
	clc
	ret
