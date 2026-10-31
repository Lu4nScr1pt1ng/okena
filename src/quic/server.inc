; QUIC server (RFC 9000, 9001, 9002; version 2: RFC 9369), for `http3 on`.
;
; Every http listener with http3 has, besides its TCP sockets, one UDP
; socket per worker on the same address (SO_REUSEPORT: the kernel hashes
; a client's address and port to one of them, so its packets keep coming
; to the worker that holds its connection). A worker reads its sockets in
; batches (recvmmsg) when they are readable (epoll, or a multishot poll on
; the ring), and sends what its connections have at the end of each loop
; iteration, in batches (sendmmsg).
;
; A connection is a session (SF_QC) with no socket of its own: its 256 KiB
; buffer holds its state (QC_*), its TLS handshake (TS with TF_QUIC, and
; the QT block), the keys of the three levels, the packet number spaces
; and the crypto streams. Its connection IDs (ours, 8 random bytes; and
; until the handshake is done the client's original one) name it in a
; per-worker hash.
;
; The handshake: Initial CRYPTO frames reassemble the ClientHello, which
; goes to tls_hello; its ServerHello goes back in Initial packets, the
; rest of the flight in Handshake packets (at most three times what the
; client sent until its address is validated by a Handshake packet), and
; the client Finished, from Handshake CRYPTO frames, completes it:
; HANDSHAKE_DONE. Lost packets are found by a probe timeout (PTO), which
; sends again the crypto data not acknowledged.

QS_MAX		:= 16				; UDP sockets a worker reads
QRX_N		:= 32				; datagrams a recvmmsg takes
QRX_SZ		:= 2048
QTX_N		:= 64				; datagrams a sendmmsg sends
QTX_SZ		:= 1472
QUIC_DGRAM	:= 1350				; the largest datagram okena sends
QH_BITS		:= 14				; connection ID hash: 16384 entries
QH_N		:= 1 shl QH_BITS
QDIRTY_MAX	:= 512
EK_QUIC		:= 5				; epoll data: a QUIC socket (slot in the low bits)
IORING_POLL_ADD_MULTI := 1
SF_QC		:= 65536			; S_FLAGS: a QUIC connection

; levels (and packet number spaces)
QL_INIT		:= 0
QL_HS		:= 1
QL_APP		:= 2

; a connection's buffer
QC_LINK		:= 0				; d: next in the worker's list (+ 1), 0 = none
QC_PLINK	:= 4				; d: previous
QC_SOCK		:= 8				; d: the socket slot it came on
QC_VER		:= 12				; d
QC_STATE	:= 16				; d: QCS_*
QC_FLAGS	:= 20				; d: QF_*
QC_PEER		:= 24				; its address (28)
QC_PEERLEN	:= 52				; d
QC_SCID		:= 56				; ours (8)
QC_DCIDLEN	:= 64				; d: the client's (what our packets carry)
QC_DCID		:= 68				; (20)
QC_ODCIDLEN	:= 88				; d: the client's first Destination Connection ID
QC_ODCID	:= 92				; (20)
QC_RXB		:= 112				; q: bytes received (the 3x rule before validation)
QC_TXB		:= 120				; q: bytes sent
QC_PTO_AT	:= 128				; q: µs, 0 = none
QC_PTOCNT	:= 136				; d
QC_DIRTY	:= 140				; d: in the flush list
QC_SRTT		:= 144				; q: µs
QC_RTTVAR	:= 152				; q
QC_CLOSE_AT	:= 160				; q: closing: when it goes
QC_ERR		:= 168				; q: the error CONNECTION_CLOSE carries
QC_CS_LEN	:= 176				; d * 3: crypto data to send, a level each
QC_CS_SENT	:= 188				; d * 3: sent so far (back to what is lost)
QC_CR_END	:= 200				; d * 3: crypto received in order
QC_PROBE	:= 212				; d * 3: a PING to send
QC_GEN		:= 224				; d: the session's generation
QC_ACKED_ALL	:= 228				; d * 3: 1 once all crypto sent is acknowledged
QC_FIELDS_END	:= 512

QCS_HS		:= 1				; handshaking
QCS_EST		:= 2				; established
QCS_CLOSING	:= 3				; CONNECTION_CLOSE sent or received: going

QF_VALID	:= 1				; address validated (a Handshake packet came)
QF_INIT_GONE	:= 2				; Initial keys discarded
QF_HELLO	:= 4				; tls_hello answered
QF_DONE		:= 8				; the handshake is complete
QF_HDONE	:= 16				; HANDSHAKE_DONE to send
QF_CLOSE	:= 32				; CONNECTION_CLOSE to send
QF_APP_ERR	:= 64				; ... of the application (0x1d)

; packet number spaces
QC_PS		:= QC_FIELDS_END
PS_NEXT		:= 0				; q: our next packet number
PS_LARGEST	:= 8				; q: the largest received, -1 none
PS_LTIME	:= 16				; q: when (µs)
PS_ACKQ		:= 24				; d: ack-eliciting packets not acknowledged yet
PS_NR		:= 28				; d: ranges received
PS_R		:= 32				; PS_RMAX of (hi q, lo q), the highest first
PS_RMAX		:= 12
PS_SIZE		:= 256

; sent packets, a ring a space
QC_SP		:= QC_PS + 3 * PS_SIZE
SP_N		:= 128
SP_PN		:= 0				; q
SP_TIME		:= 8				; q
SP_FL		:= 16				; d: SPF_*
SP_COFF		:= 20				; d: its crypto data
SP_CLEN		:= 24				; d
SP_SIZE		:= 32
SPF_SENT	:= 1				; a packet is recorded here
SPF_ACKEL	:= 2				; ack-eliciting
SPF_ACKED	:= 4
SPF_HDONE	:= 8				; it carried HANDSHAKE_DONE

QC_TS		:= QC_SP + 3 * SP_N * SP_SIZE	; the TLS state (TS_SIZE)
QC_QT		:= QC_TS + 2048			; QUIC's TLS block (QT_SIZE)
QC_KEYS		:= QC_QT + 2048			; 6 * QK: rx, tx a level
QC_CRX		:= 32768			; crypto received: Initial (CH_MAX)
QC_CRX_HS	:= QC_CRX + CH_MAX		; Handshake (2048)
QC_CRX_HSCAP	:= 2048
QC_CRBM		:= QC_CRX_HS + QC_CRX_HSCAP	; which bytes came: Initial
QC_CRBM_HS	:= QC_CRBM + CH_MAX / 8
QC_TLSOUT	:= 65536			; tls_hello's out: ServerHello | the flight
QC_TLSROOM	:= 65536
QC_STREAMS	:= 131072			; streams (http3.inc)
assert QC_KEYS + 6 * QK_SIZE <= QC_CRX
assert QC_CRBM_HS + QC_CRX_HSCAP / 8 <= QC_TLSOUT
assert TS_SIZE <= 2048
assert QT_SIZE <= 2048

bss
	align 16
	g_qfd		rd MAX_LISTENERS * MAX_WORKERS	; supervisor: the UDP sockets
	g_qs_n		dd ?
	g_qs_fd		rd QS_MAX
	g_qs_lst	rd QS_MAX
	g_qnow		dq ?				; µs (CLOCK_MONOTONIC)
	g_qc_head	dd ?				; connections (+ 1)
	g_qc_count	dd ?
	g_qdirty_n	dd ?
	g_qdirty	rq QDIRTY_MAX			; session | generation << 32
	g_qtx_n		dd ?
	g_qtx_fds	rd QTX_N
	g_qtmp:	rb 64
	align 16
	g_qh:	rb QH_N * 16			; key (q), session + 1 (d), generation (d)
	g_qrx_mm:	rb QRX_N * 64
	g_qrx_iov:	rb QRX_N * 16
	g_qrx_sa:	rb QRX_N * 32
	g_qtx_mm:	rb QTX_N * 64
	g_qtx_iov:	rb QTX_N * 16
	g_qtx_sa:	rb QTX_N * 32
	g_qrx_buf:	rb QRX_N * QRX_SZ
	g_qtx_buf:	rb QTX_N * QTX_SZ
end bss

rodata
	align 8
	ts_qtick	dq 0, 10000000			; 10 ms
	; our transport parameters past the connection IDs: max_idle_timeout
	; 30 s, max_udp_payload_size 1472, initial_max_data 1 MiB, stream data
	; 256 KiB (bidi local and remote) and 64 KiB (uni), 100 bidi streams,
	; 16 uni, no active migration
	qtp_fixed	db 0x01,4, 0x80,0x00,0x75,0x30
			db 0x03,2, 0x45,0xC0
			db 0x04,4, 0x80,0x10,0x00,0x00
			db 0x05,4, 0x80,0x04,0x00,0x00
			db 0x06,4, 0x80,0x04,0x00,0x00
			db 0x07,4, 0x80,0x01,0x00,0x00
			db 0x08,2, 0x40,100
			db 0x09,1, 16
			db 0x0C,0
	qtp_fixed.len = $ - qtp_fixed
end rodata

; ------------------------------------------------------------- helpers

; rsi = cursor, rdx = end: rax = a varint, rsi past it; CF when truncated.
; Keeps rdx and everything but rax, rcx, rsi.
qv_read:
	cmp	rsi,rdx
	jae	.short
	movzx	eax,byte [rsi]
	mov	ecx,eax
	shr	ecx,6
	and	eax,0x3F
	mov	r11d,1
	shl	r11d,cl				; its length: 1, 2, 4 or 8
	lea	rcx,[rsi+r11]
	cmp	rcx,rdx
	ja	.short
	inc	rsi
	dec	r11d
	jz	.done
@@:
	shl	rax,8
	movzx	ecx,byte [rsi]
	or	rax,rcx
	inc	rsi
	dec	r11d
	jnz	@b
.done:
	clc
	ret
.short:
	stc
	ret

; rdi = out, rax = value (< 2^62): its shortest varint, rdi past it.
; Keeps everything but rax, rcx, rdi.
qv_write:
	cmp	rax,64
	jb	.one
	cmp	rax,16384
	jb	.two
	cmp	rax,1 shl 30
	jb	.four
	mov	rcx,0xC000000000000000
	or	rax,rcx
	bswap	rax
	mov	[rdi],rax
	add	rdi,8
	ret
.four:
	or	eax,0x80000000
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	ret
.two:
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	ret
.one:
	mov	[rdi],al
	inc	rdi
	ret

; ebx = connection session: r14 = its buffer, r15 = its QC (the same).
macro qc_regs
	mov	r14d,ebx
	shl	r14,HB_SHIFT
	add	r14,[g_hbuf_base]
	mov	r15,r14
end macro

; ecx = level, edx = 0 rx / 1 tx: rax = that QK. Keeps the rest.
macro qc_key level*, dir*
	lea	eax,[level*2+dir]
	imul	eax,eax,QK_SIZE
	lea	rax,[r15+QC_KEYS+rax]
end macro

; µs now, into g_qnow
qs_clock:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000
	mov	rcx,rax
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	r8d,1000
	div	r8
	add	rax,rcx
	mov	[g_qnow],rax
	add	rsp,24
	ret

; ---------------------------------------------------- sockets (supervisor)

; Before the workers fork: a UDP socket per worker for every listener
; with http3, bound where its TCP sockets are. eax < 0 on a failure (the
; listener's address is logged).
qs_open_all:
	push	rbx
	push	r12
	push	r13
	xor	r12d,r12d			; listener
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.done
	imul	rbx,r12,LS_SIZE
	lea	rbx,[g_listeners+rbx]
	test	dword [rbx+LS_FLAGS],LSF_H3
	jz	.next
	xor	r13d,r13d			; worker
.socket:
	call	.open
	test	eax,eax
	js	.failed
	mov	ecx,r12d
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,r13d
	mov	[g_qfd+rcx*4],eax
	inc	r13d
	cmp	r13d,[g_workers]
	jb	.socket
.next:
	inc	r12d
	jmp	.listener
.done:
	xor	eax,eax
.failed:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rbx = listener: eax = a bound socket, or -errno
.open:
	movzx	edi,word [rbx+LS_SA]		; the family its TCP sockets got
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC or SOCK_NONBLOCK
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.ret
	push	rax
	cmp	word [rbx+LS_SA],AF_INET6
	jne	@f
	mov	edi,eax
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	lea	r10,[zero_int]
	cmp	dword [rbx+LS_FAMILY],0
	je	.v6only
	lea	r10,[one_int]
.v6only:
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rax,[rsp]
@@:
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rdi,[rsp]
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEPORT
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rdi,[rsp]
	lea	rsi,[rbx+LS_SA]
	mov	edx,[rbx+LS_SALEN]
	mov	eax,SYS_bind
	syscall
	pop	rcx
	test	eax,eax
	js	.ret
	mov	eax,ecx
.ret:
	ret

; ----------------------------------------------------- sockets (worker)

; This worker's sockets, watched; the batches' headers. After the engine
; is up (epoll set, or the ring), before seccomp.
qs_worker_init:
	push	rbx
	push	r12
	mov	dword [g_qs_n],0
	mov	dword [g_qc_head],0
	mov	dword [g_qc_count],0
	mov	dword [g_qdirty_n],0
	mov	dword [g_qtx_n],0
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.headers
	imul	rax,rbx,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3
	jz	.next
	mov	eax,ebx
	imul	eax,eax,MAX_WORKERS
	add	eax,[g_worker_id]
	mov	eax,[g_qfd+rax*4]
	mov	ecx,[g_qs_n]
	cmp	ecx,QS_MAX
	jae	.next
	mov	[g_qs_fd+rcx*4],eax
	mov	[g_qs_lst+rcx*4],ebx
	inc	dword [g_qs_n]
	mov	edi,ecx
	call	qs_watch
.next:
	inc	ebx
	jmp	.listener
.headers:
	cmp	dword [g_qs_n],0
	je	.out
	; receive slots: name, iovec, one buffer each
	xor	ecx,ecx
@@:
	mov	rax,rcx
	shl	rax,6
	lea	rdx,[g_qrx_mm+rax]
	mov	r8,rcx
	shl	r8,5
	lea	r8,[g_qrx_sa+r8]
	mov	[rdx],r8			; msg_name
	mov	dword [rdx+8],28		; msg_namelen
	mov	r8,rcx
	shl	r8,4
	lea	r8,[g_qrx_iov+r8]
	mov	[rdx+16],r8			; msg_iov
	mov	qword [rdx+24],1
	imul	r9,rcx,QRX_SZ
	lea	r9,[g_qrx_buf+r9]
	mov	[r8],r9
	mov	qword [r8+8],QRX_SZ
	inc	ecx
	cmp	ecx,QRX_N
	jb	@b
	; the timer: a QUIC tick every 10 ms (io_uring; epoll waits that long)
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.out
	call	qs_arm_timer
.out:
	pop	r12
	pop	rbx
	ret

; edi = socket slot: watch it (epoll: level-triggered; io_uring: a multishot poll)
qs_watch:
	mov	esi,edi
	mov	edi,[g_qs_fd+rdi*4]
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	.ring
	mov	edx,esi
	mov	rcx,EK_QUIC shl 56
	or	rdx,rcx
	mov	esi,EPOLLIN
	jmp	ep_add
.ring:
	push	rdi
	push	rsi
	call	ring_get_sqe
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	mov	[rax+SQE_FD],edi
	mov	dword [rax+SQE_OP_FLAGS],EPOLLIN
	mov	dword [rax+SQE_LEN],IORING_POLL_ADD_MULTI
	mov	rcx,OP_QPOLL shl 56
	or	rcx,rsi
	mov	[rax+SQE_USER_DATA],rcx
	ret

qs_arm_timer:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[ts_qtick]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],IORING_TIMEOUT_MULTISHOT
	mov	rcx,OP_QTIMER shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

; io_uring: a socket is readable (ebx = slot, r15d = cqe flags)
on_qpoll:
	push	r15
	mov	edi,ebx
	call	qs_readable
	pop	r15
	test	r15d,IORING_CQE_F_MORE
	jnz	.out
	mov	edi,ebx				; the multishot poll ended: again
	jmp	qs_watch
.out:
	ret

on_qtimer:
	test	r15d,IORING_CQE_F_MORE
	jnz	qs_tick
	call	qs_arm_timer
	jmp	qs_tick

; ------------------------------------------------------------- receive

; edi = socket slot: every datagram waiting there
qs_readable:
	push	rbx
	push	r12
	push	r13
	mov	r12d,edi
.batch:
	xor	ecx,ecx				; names: room again
@@:
	mov	rax,rcx
	shl	rax,6
	mov	dword [g_qrx_mm+rax+8],28
	inc	ecx
	cmp	ecx,QRX_N
	jb	@b
	mov	edi,[g_qs_fd+r12*4]
	lea	rsi,[g_qrx_mm]
	mov	edx,QRX_N
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	mov	eax,SYS_recvmmsg
	syscall
	test	eax,eax
	jle	.done
	mov	r13d,eax
	push	r13
	call	qs_clock
	pop	r13
	xor	ebx,ebx
.dgram:
	cmp	ebx,r13d
	jae	.more
	mov	rax,rbx
	shl	rax,6
	mov	edx,[g_qrx_mm+rax+56]		; msg_len
	mov	r8d,[g_qrx_mm+rax+8]		; msg_namelen
	imul	rsi,rbx,QRX_SZ
	lea	rsi,[g_qrx_buf+rsi]
	mov	rcx,rbx
	shl	rcx,5
	lea	rcx,[g_qrx_sa+rcx]
	mov	edi,r12d
	push	rbx
	push	r13
	call	qs_datagram
	pop	r13
	pop	rbx
	inc	ebx
	jmp	.dgram
.more:
	cmp	r13d,QRX_N
	je	.batch				; maybe more waiting
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; One datagram: edi = socket slot, rsi = bytes, edx = length, rcx = the
; sender's address, r8d = its length.
QD_SLOT		:= 0
QD_BUF		:= 8
QD_END		:= 16
QD_SA		:= 24
QD_SALEN	:= 32
QD_LEN		:= 36
QD_VER		:= 40
QD_SIZE		:= 48
qs_datagram:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,QD_SIZE
	mov	[rsp+QD_SLOT],edi
	mov	[rsp+QD_BUF],rsi
	lea	rax,[rsi+rdx]
	mov	[rsp+QD_END],rax
	mov	[rsp+QD_SA],rcx
	mov	[rsp+QD_SALEN],r8d
	mov	[rsp+QD_LEN],edx
	mov	r12,rsi				; the packet's start
	mov	ebx,NIL				; no connection yet
.packet:
	mov	rax,[rsp+QD_END]
	sub	rax,r12
	cmp	rax,7
	jb	.out
	movzx	eax,byte [r12]
	test	eax,0x80
	jz	.short
	test	eax,0x40			; the fixed bit
	jz	.out
	; long header: version, dcid, scid
	mov	r13d,[r12+1]
	bswap	r13d				; version
	mov	[rsp+QD_VER],r13d
	cmp	r13d,QUIC_V1
	je	@f
	cmp	r13d,QUIC_V2
	je	@f
	test	r13d,r13d
	jz	.out				; a Version Negotiation: not for a server
	cmp	r12,[rsp+QD_BUF]
	jne	.out
	cmp	dword [rsp+QD_LEN],1200
	jb	.out
	mov	rdi,rsp
	call	qs_send_vn
	jmp	.out
@@:
	lea	rsi,[r12+5]
	mov	rdx,[rsp+QD_END]
	movzx	ecx,byte [rsi]			; dcid
	cmp	ecx,20
	ja	.out
	inc	rsi
	mov	r8,rsi				; dcid
	mov	r9d,ecx
	add	rsi,rcx
	cmp	rsi,rdx
	jae	.out
	movzx	ecx,byte [rsi]			; scid
	cmp	ecx,20
	ja	.out
	inc	rsi
	mov	r10,rsi
	mov	r11d,ecx
	add	rsi,rcx
	cmp	rsi,rdx
	ja	.out
	; the type: v1 Initial 0, 0-RTT 1, Handshake 2, Retry 3; v2 rotates them
	movzx	ebp,byte [r12]
	shr	ebp,4
	and	ebp,3
	cmp	r13d,QUIC_V2
	jne	@f
	dec	ebp
	and	ebp,3
@@:
	cmp	ebp,3
	je	.out				; Retry: never to a server
	push	r8
	push	r9
	push	r10
	push	r11
	cmp	ebp,0
	jne	.no_token
	call	qv_read				; Initial: the token
	jc	.pop_out
	add	rsi,rax
	cmp	rsi,rdx
	ja	.pop_out
.no_token:
	call	qv_read				; the length: packet number and payload
	jc	.pop_out
	lea	r13,[rsi+rax]			; the packet's end
	cmp	r13,rdx
	ja	.pop_out
	mov	r15,rsi				; the packet number's start
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	cmp	ebp,1
	je	.next_packet			; 0-RTT: not taken (no early data)
	; its connection
	cmp	ebx,NIL
	jne	.have
	mov	rdi,r8
	mov	esi,r9d
	call	qh_find
	mov	ebx,eax
	cmp	ebx,NIL
	jne	.have
	test	ebp,ebp
	jnz	.out				; Handshake for nobody
	cmp	dword [rsp+QD_LEN],1200		; a client's first datagram is padded
	jb	.out
	cmp	r9d,8
	jb	.out
	mov	rdi,rsp				; a new connection
	call	qc_new				; r8/r9 dcid, r10/r11 scid
	cmp	eax,NIL
	je	.out
	mov	ebx,eax
.have:
	mov	edi,ebx
	mov	esi,ebp
	cmp	esi,2
	jne	@f
	mov	esi,QL_HS
@@:
	mov	rdx,r12
	mov	rcx,r13
	sub	rcx,r12				; the packet's length
	mov	r8,r15
	sub	r8,r12				; its packet number's offset
	mov	r9d,[rsp+QD_LEN]
	call	qc_packet
	mov	dword [rsp+QD_LEN],0		; (the datagram is counted once)
.next_packet:
	mov	r12,r13
	jmp	.packet
.pop_out:
	add	rsp,32
	jmp	.out
.short:
	test	eax,0x40
	jz	.out
	mov	rax,[rsp+QD_END]
	sub	rax,r12
	cmp	rax,1 + 8 + 20
	jb	.out
	lea	rdi,[r12+1]			; our connection IDs: 8 bytes
	mov	esi,8
	call	qh_find
	cmp	eax,NIL
	je	.out				; (a stateless reset would go here)
	cmp	ebx,NIL
	je	@f
	cmp	eax,ebx
	jne	.out				; coalesced with another connection's
@@:
	mov	edi,eax
	mov	esi,QL_APP
	mov	rdx,r12
	mov	rcx,[rsp+QD_END]
	sub	rcx,r12
	mov	r8d,9
	mov	r9d,[rsp+QD_LEN]
	call	qc_packet
.out:
	add	rsp,QD_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = the datagram's frame (QD_*): a Version Negotiation back, listing
; v2 and v1 (RFC 9000 17.2.1)
qs_send_vn:
	push	rbx
	push	r12
	mov	r12,rdi
	call	qtx_slot			; rax = buffer, edx = slot
	test	rax,rax
	jz	.out
	mov	rbx,rax
	mov	rsi,[r12+QD_BUF]
	rdtsc
	or	al,0x80
	mov	[rbx],al
	mov	dword [rbx+1],0			; version 0
	lea	rdi,[rbx+5]
	movzx	ecx,byte [rsi+5]		; their dcid
	lea	r8,[rsi+6]			; (its bytes)
	lea	r9,[r8+rcx]
	movzx	eax,byte [r9]			; their scid: our dcid
	mov	[rdi],al
	inc	rdi
	push	rcx
	push	rsi
	lea	rsi,[r9+1]
	mov	ecx,eax
	rep	movsb
	pop	rsi
	pop	rcx
	mov	[rdi],cl			; their dcid: our scid
	inc	rdi
	mov	rsi,r8
	rep	movsb
	mov	dword [rdi],0xCF43336B		; 6b3343cf, 00000001
	mov	dword [rdi+4],0x01000000
	add	rdi,8
	sub	rdi,rbx
	mov	ecx,edi
	mov	edi,[r12+QD_SLOT]
	mov	rsi,[r12+QD_SA]
	mov	r8d,[r12+QD_SALEN]
	call	qtx_commit
.out:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ the hash

; rdi = connection ID, esi = its length: eax = its connection, or NIL.
; Keeps rbx, rbp, r12-r15.
qh_find:
	call	qh_key				; rax = key, rdx = first slot
.probe:
	mov	ecx,[g_qh+rdx+8]
	test	ecx,ecx
	jz	.none
	cmp	ecx,-1
	je	.skip
	cmp	[g_qh+rdx],rax
	jne	.skip
	dec	ecx				; still that session?
	mov	r8d,ecx
	shl	r8,S_SHIFT
	add	r8,[g_sess_base]
	mov	r9d,[r8+S_GEN]
	cmp	r9d,[g_qh+rdx+12]
	jne	.skip
	cmp	dword [r8+S_STATE],ST_OPEN
	jne	.skip
	mov	eax,ecx
	ret
.skip:
	add	edx,16
	and	edx,QH_N * 16 - 1
	jmp	.probe
.none:
	mov	eax,NIL
	ret

; rdi = connection ID, esi = length: rax = its key, rdx = its home slot's offset
qh_key:
	xor	eax,eax
	cmp	esi,8
	jb	@f
	mov	rax,[rdi]
	jmp	.mixed
@@:
	; shorter: byte by byte
	mov	ecx,esi
@@:
	test	ecx,ecx
	jz	.mixed
	dec	ecx
	shl	rax,8
	movzx	edx,byte [rdi+rcx]
	or	rax,rdx
	jmp	@b
.mixed:
	mov	rcx,rsi
	shl	rcx,56
	xor	rax,rcx
	mov	rdx,rax
	mov	rcx,0x9E3779B97F4A7C15
	imul	rdx,rcx
	shr	rdx,64 - QH_BITS
	shl	edx,4
	ret

; rdi = connection ID, esi = length, ebx = session: in
qh_add:
	call	qh_key
.probe:
	mov	ecx,[g_qh+rdx+8]
	test	ecx,ecx
	jz	.here
	cmp	ecx,-1
	je	.here
	add	edx,16
	and	edx,QH_N * 16 - 1
	jmp	.probe
.here:
	mov	[g_qh+rdx],rax
	lea	ecx,[rbx+1]
	mov	[g_qh+rdx+8],ecx
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	mov	[g_qh+rdx+12],ecx
	ret

; rdi = connection ID, esi = length, ebx = session: out
qh_del:
	call	qh_key
.probe:
	mov	ecx,[g_qh+rdx+8]
	test	ecx,ecx
	jz	.out
	cmp	[g_qh+rdx],rax
	jne	.skip
	dec	ecx
	cmp	ecx,ebx
	jne	.skip
	mov	dword [g_qh+rdx+8],-1		; a tombstone
	ret
.skip:
	add	edx,16
	and	edx,QH_N * 16 - 1
	jmp	.probe
.out:
	ret

; ------------------------------------------------------ connections

; A new connection for a client's first Initial: rdi = the datagram's
; frame (QD_*, its version at QD_VER), r8/r9d = its dcid, r10/r11d = its scid.
; eax = the session, or NIL.
qc_new:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rdi
	push	r8
	push	r9
	push	r10
	push	r11
	call	session_alloc
	cmp	eax,NIL
	je	.none
	mov	ebx,eax
	mov	r12d,[rbp+QD_SLOT]
	mov	r12d,[g_qs_lst+r12*4]		; its listener
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_QC
	mov	dword [rax+S_CLIENT],-1
	mov	[rax+S_LST],r12d
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	imul	rcx,r12,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	mov	[rax+S_POOL],ecx
	mov	ecx,[rax+S_GEN]
	push	rcx
	inc	dword [g_ls_active+r12*4]
	inc	dword [g_active]
	mov	edi,ebx
	call	idle_append
	qc_regs
	mov	rdi,r15				; the fields, the spaces, the logs: zero
	mov	ecx,QC_TS / 8
	xor	eax,eax
	rep	stosq
	mov	rdi,r15
	add	rdi,QC_TS
	mov	ecx,(QC_CRX - QC_TS) / 8
	rep	stosq
	lea	rdi,[r15+QC_CRBM]		; which crypto bytes came
	mov	ecx,(CH_MAX / 8 + QC_CRX_HSCAP / 8) / 8
	rep	stosq
	pop	rcx
	mov	[r15+QC_GEN],ecx
	mov	eax,[rbp+QD_SLOT]
	mov	[r15+QC_SOCK],eax
	mov	eax,[rbp+QD_VER]
	mov	[r15+QC_VER],eax
	mov	dword [r15+QC_STATE],QCS_HS
	mov	rsi,[rbp+QD_SA]			; the client's address
	lea	rdi,[r15+QC_PEER]
	mov	ecx,28
	rep	movsb
	mov	eax,[rbp+QD_SALEN]
	mov	[r15+QC_PEERLEN],eax
	mov	rax,-1
	mov	[r15+QC_PS+0*PS_SIZE+PS_LARGEST],rax
	mov	[r15+QC_PS+1*PS_SIZE+PS_LARGEST],rax
	mov	[r15+QC_PS+2*PS_SIZE+PS_LARGEST],rax
	mov	qword [r15+QC_SRTT],333000	; RFC 9002: the initial RTT
	mov	qword [r15+QC_RTTVAR],166500
	; connection IDs: ours random, the client's as it chose them
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	mov	[r15+QC_DCIDLEN],r11d
	lea	rdi,[r15+QC_DCID]
	mov	rsi,r10
	mov	ecx,r11d
	rep	movsb
	mov	[r15+QC_ODCIDLEN],r9d
	lea	rdi,[r15+QC_ODCID]
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	; Initial keys from the client's dcid: rx are the client's
	qc_key	QL_INIT, 0
	mov	rdi,rax
	qc_key	QL_INIT, 1
	mov	rsi,rax
	lea	rdx,[r15+QC_ODCID]
	mov	ecx,[r15+QC_ODCIDLEN]
	mov	r8d,[r15+QC_VER]
	call	quic_initial
	; TLS: QUIC mode, our transport parameters
	lea	rax,[r15+QC_QT]
	mov	[r15+QC_TS+TS_QT],rax
	mov	dword [r15+QC_TS+TS_FLAGS],TF_QUIC
	call	qc_tp_build
	; named by both IDs, listed
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	call	qh_add
	lea	rdi,[r15+QC_ODCID]
	mov	esi,[r15+QC_ODCIDLEN]
	call	qh_add
	mov	eax,[g_qc_head]
	mov	[r15+QC_LINK],eax
	mov	dword [r15+QC_PLINK],0
	test	eax,eax
	jz	@f
	dec	eax
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	lea	ecx,[rbx+1]
	mov	[rax+QC_PLINK],ecx
@@:
	lea	eax,[rbx+1]
	mov	[g_qc_head],eax
	inc	dword [g_qc_count]
	mov	eax,ebx
	jmp	.out
.none:
	add	rsp,32
	mov	eax,NIL
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r15 = connection: QT_TPS = our transport parameters
qc_tp_build:
	lea	rdi,[r15+QC_QT+QT_TPS]
	mov	byte [rdi],0x00			; original_destination_connection_id
	mov	eax,[r15+QC_ODCIDLEN]
	mov	[rdi+1],al
	add	rdi,2
	lea	rsi,[r15+QC_ODCID]
	mov	ecx,eax
	rep	movsb
	mov	word [rdi],0x080F		; initial_source_connection_id, 8 bytes
	add	rdi,2
	mov	rax,[r15+QC_SCID]
	mov	[rdi],rax
	add	rdi,8
	lea	rsi,[qtp_fixed]
	mov	ecx,qtp_fixed.len
	rep	movsb
	lea	rax,[r15+QC_QT+QT_TPS]
	sub	rdi,rax
	mov	[r15+QC_QT+QT_TPSLEN],edi
	ret

; ebx = connection: on the flush list (sends at the iteration's end)
qc_dirty:
	push	r15
	qc_regs
	cmp	dword [r15+QC_DIRTY],0
	jne	.out
	mov	eax,[g_qdirty_n]
	cmp	eax,QDIRTY_MAX
	jae	.now
	mov	dword [r15+QC_DIRTY],1
	inc	dword [g_qdirty_n]
	mov	ecx,[r15+QC_GEN]
	shl	rcx,32
	or	rcx,rbx
	mov	[g_qdirty+rax*8],rcx
.out:
	pop	r15
	ret
.now:
	pop	r15
	jmp	qc_send

; ------------------------------------------------------------ packets

; edi = connection, esi = level, rdx = the packet, rcx = its length (to
; its end, for a short header the datagram's), r8d = its packet number's
; offset, r9d = the datagram's length (0 when already counted)
QP_LEVEL	:= 0
QP_PKT		:= 8
QP_PAY		:= 16
QP_END		:= 24
QP_PN		:= 32
QP_ACKEL	:= 40
QP_PNOFF	:= 44
QP_SIZE		:= 48
qc_packet:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,QP_SIZE
	mov	ebx,edi
	qc_regs
	mov	[rsp+QP_LEVEL],esi
	mov	[rsp+QP_PKT],rdx
	mov	[rsp+QP_PNOFF],r8d
	mov	dword [rsp+QP_ACKEL],0
	add	[r15+QC_RXB],r9
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	je	.out
	mov	r12d,esi
	cmp	r12d,QL_INIT
	jne	@f
	test	dword [r15+QC_FLAGS],QF_INIT_GONE
	jnz	.out
@@:
	cmp	r12d,QL_APP
	jne	@f
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.out				; no 1-RTT keys yet
@@:
	cmp	r12d,QL_HS
	jne	@f
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.out
@@:
	; open it
	mov	r13,rdx				; the packet
	mov	r14d,ecx			; its length
	imul	eax,r12d,PS_SIZE
	mov	r8,[r15+QC_PS+rax+PS_LARGEST]
	lea	eax,[r12*2]
	imul	eax,eax,QK_SIZE
	lea	rdi,[r15+QC_KEYS+rax]
	mov	rsi,r13
	mov	edx,r14d
	mov	ecx,[rsp+QP_PNOFF]
	call	quic_open
	cmp	eax,-1
	je	.out				; not ours, or damaged: dropped
	mov	[rsp+QP_PN],rdx
	movzx	ecx,byte [r13]
	and	ecx,3
	inc	ecx				; packet number length
	add	ecx,[rsp+QP_PNOFF]
	lea	rsi,[r13+rcx]			; the payload
	mov	[rsp+QP_PAY],rsi
	lea	rdx,[rsi+rax]
	mov	[rsp+QP_END],rdx
	mov	edi,[rsp+QP_LEVEL]
	mov	rsi,[rsp+QP_PN]
	call	qc_seen
	jc	.out				; a duplicate: once is enough
	mov	edi,ebx
	call	idle_touch
	; a Handshake packet: the client's address is good, Initial is over
	cmp	dword [rsp+QP_LEVEL],QL_HS
	jne	@f
	or	dword [r15+QC_FLAGS],QF_VALID or QF_INIT_GONE
@@:
	; frames
	mov	rsi,[rsp+QP_PAY]
.frame:
	mov	rdx,[rsp+QP_END]
	cmp	rsi,rdx
	jae	.frames_done
	call	qv_read
	jc	.encoding
	test	rax,rax
	jz	.padding
	cmp	rax,1
	je	.ping
	cmp	rax,2
	je	.ack
	cmp	rax,3
	je	.ack
	cmp	rax,6
	je	.crypto
	cmp	rax,0x1C
	je	.close
	cmp	rax,0x1D
	je	.close
	cmp	dword [rsp+QP_LEVEL],QL_APP
	jne	.violation			; anything else needs 1-RTT
	mov	rdi,rsp				; the application's frames
	call	qc_app_frame			; rsi past it, CF: an error (QC_ERR set)
	jc	.error
	jmp	.frame
.padding:
	cmp	rsi,rdx
	jae	.frames_done
	cmp	byte [rsi],0
	jne	.frame
	inc	rsi
	jmp	.padding
.ping:
	mov	dword [rsp+QP_ACKEL],1
	jmp	.frame
.ack:
	push	rax
	mov	edi,[rsp+8+QP_LEVEL]
	pop	rcx
	call	qc_on_ack			; rsi past the frame, CF on a bad one
	jc	.encoding
	jmp	.frame
.crypto:
	mov	dword [rsp+QP_ACKEL],1
	call	qv_read				; offset
	jc	.encoding
	mov	r8,rax
	call	qv_read				; length
	jc	.encoding
	lea	rcx,[rsi+rax]
	cmp	rcx,rdx
	ja	.encoding
	push	rcx
	mov	edi,[rsp+8+QP_LEVEL]
	mov	rdx,rax				; length
	mov	rcx,r8				; offset
	call	qc_crypto_in			; CF: the connection fails (QC_ERR set)
	pop	rsi
	jc	.error
	qc_regs
	jmp	.frame
.close:
	; the peer closes: we go, silently (draining)
	mov	dword [r15+QC_STATE],QCS_CLOSING
	mov	rax,[g_qnow]
	add	rax,[r15+QC_SRTT]
	add	rax,[r15+QC_SRTT]
	add	rax,[r15+QC_SRTT]
	mov	[r15+QC_CLOSE_AT],rax
	and	dword [r15+QC_FLAGS],not QF_CLOSE
	jmp	.out
.encoding:
	mov	qword [r15+QC_ERR],7		; FRAME_ENCODING_ERROR
	jmp	.error
.violation:
	mov	qword [r15+QC_ERR],0x0A		; PROTOCOL_VIOLATION
.error:
	call	qc_fail
	jmp	.out
.frames_done:
	; recorded as received; acknowledged when it asks for it
	mov	edi,[rsp+QP_LEVEL]
	mov	rsi,[rsp+QP_PN]
	call	qc_received
	cmp	dword [rsp+QP_ACKEL],0
	je	.out
	imul	eax,[rsp+QP_LEVEL],PS_SIZE
	inc	dword [r15+QC_PS+rax+PS_ACKQ]
	call	qc_dirty
.out:
	add	rsp,QP_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ------------------------------------------------ received, acknowledged

; edi = level, rsi = packet number (r15 = connection): CF when it came already
qc_seen:
	imul	eax,edi,PS_SIZE
	lea	rdx,[r15+QC_PS+rax]
	mov	ecx,[rdx+PS_NR]
	lea	r8,[rdx+PS_R]
.range:
	test	ecx,ecx
	jz	.new
	cmp	rsi,[r8]
	ja	.next
	cmp	rsi,[r8+8]
	jae	.dup
.next:
	add	r8,16
	dec	ecx
	jmp	.range
.new:
	clc
	ret
.dup:
	stc
	ret

; edi = level, rsi = packet number: into its space's ranges (highest
; first, merged; the lowest dropped past PS_RMAX)
qc_received:
	imul	eax,edi,PS_SIZE
	lea	rdx,[r15+QC_PS+rax]
	cmp	rsi,[rdx+PS_LARGEST]
	jle	@f
	cmp	qword [rdx+PS_LARGEST],-1
	je	.larger
	cmp	rsi,[rdx+PS_LARGEST]
	jbe	@f
.larger:
	mov	[rdx+PS_LARGEST],rsi
	mov	rax,[g_qnow]
	mov	[rdx+PS_LTIME],rax
@@:
	mov	ecx,[rdx+PS_NR]
	lea	r8,[rdx+PS_R]
	xor	r9d,r9d				; index
.find:
	cmp	r9d,ecx
	jae	.append
	mov	rax,[r8]			; hi
	lea	r10,[rax+1]
	cmp	rsi,r10
	je	.extend_hi			; just above it
	ja	.insert				; above it, with a gap: a new range before
	mov	r10,[r8+8]			; lo
	dec	r10
	cmp	rsi,r10
	je	.extend_lo
	add	r8,16
	inc	r9d
	jmp	.find
.extend_hi:
	mov	[r8],rsi
	ret
.extend_lo:
	mov	[r8+8],rsi
	; does it touch the next one (lower)?
	inc	r9d
	cmp	r9d,ecx
	jae	.done
	mov	rax,[r8+16]
	inc	rax
	cmp	rax,rsi
	jne	.done
	mov	rax,[r8+24]			; merge: lo of the next
	mov	[r8+8],rax
	; remove the next: shift the rest down
	lea	rdi,[r8+16]
	lea	rsi,[r8+32]
	mov	eax,ecx
	sub	eax,r9d
	dec	eax
	shl	eax,4
	mov	ecx,eax
	rep	movsb
	dec	dword [rdx+PS_NR]
.done:
	ret
.insert:
	cmp	ecx,PS_RMAX
	jb	@f
	dec	ecx				; full: the lowest goes
	mov	[rdx+PS_NR],ecx
	cmp	r9d,ecx
	ja	.done
@@:
	; shift [r9, n) up one, then this one at r9
	push	rsi
	mov	eax,ecx
	sub	eax,r9d
	shl	eax,4
	lea	rsi,[r8+rax-1]
	lea	rdi,[r8+rax+15]
	mov	ecx,eax
	std
	rep	movsb
	cld
	pop	rsi
	mov	[r8],rsi
	mov	[r8+8],rsi
	inc	dword [rdx+PS_NR]
	ret
.append:
	cmp	ecx,PS_RMAX
	jae	.done				; lower than all we keep
	mov	[r8],rsi
	mov	[r8+8],rsi
	inc	dword [rdx+PS_NR]
	ret

; An ACK frame (rcx = 2 or 3): edi = level, rsi past its type, rdx = the
; payload's end (r15 = connection). Every packet of ours it covers is
; acknowledged; an RTT sample from the largest. rsi past the frame, CF
; when it does not parse.
QA_LEVEL	:= 0
QA_TYPE		:= 4
QA_LARGEST	:= 8
QA_HI		:= 16
QA_SPACE	:= 24
QA_NEWLY	:= 32
QA_SIZE		:= 48
qc_on_ack:
	push	rbx
	push	r12
	push	r13
	sub	rsp,QA_SIZE
	mov	[rsp+QA_LEVEL],edi
	mov	[rsp+QA_TYPE],ecx
	mov	dword [rsp+QA_NEWLY],0
	call	qv_read				; largest acknowledged
	jc	.bad
	mov	[rsp+QA_LARGEST],rax
	mov	r12,rax				; the range's top
	call	qv_read				; ack delay
	jc	.bad
	call	qv_read				; range count
	jc	.bad
	mov	r13,rax
	call	qv_read				; first range
	jc	.bad
	cmp	rax,r12
	ja	.bad
	mov	rbx,r12
	sub	rbx,rax				; its bottom
	call	.mark				; [rbx, r12]
.ranges:
	test	r13,r13
	jz	.ecn
	dec	r13
	call	qv_read				; gap
	jc	.bad
	lea	rcx,[rax+2]
	cmp	rcx,rbx
	ja	.bad
	mov	r12,rbx
	sub	r12,rcx				; the next top
	call	qv_read				; its length
	jc	.bad
	cmp	rax,r12
	ja	.bad
	mov	rbx,r12
	sub	rbx,rax
	call	.mark
	jmp	.ranges
.ecn:
	cmp	dword [rsp+QA_TYPE],3
	jne	.done
	call	qv_read
	jc	.bad
	call	qv_read
	jc	.bad
	call	qv_read
	jc	.bad
.done:
	; anything newly acknowledged: the probe count starts over, the
	; timer follows what is still out
	cmp	dword [rsp+QA_NEWLY],0
	je	.ok
	mov	dword [r15+QC_PTOCNT],0
	push	rsi
	push	rdx
	call	qc_pto_arm
	pop	rdx
	pop	rsi
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	lea	rsp,[rsp+QA_SIZE]
	pop	r13
	pop	r12
	pop	rbx
	ret
; [rbx, r12] acknowledged: the packets of ours in that window
.mark:
	push	rsi
	push	rdx
	imul	eax,[rsp+16+8+QA_LEVEL],PS_SIZE
	mov	r8,[r15+QC_PS+rax+PS_NEXT]
	cmp	r12,r8
	jae	.mark_out			; (acks what we never sent: ignored)
	mov	rcx,r12
	sub	rcx,rbx
	cmp	rcx,SP_N
	jb	@f
	lea	rbx,[r12-SP_N+1]		; only the ring's window
@@:
	mov	r9d,[rsp+16+8+QA_LEVEL]
	imul	r9d,r9d,SP_N * SP_SIZE
	lea	r9,[r15+QC_SP+r9]
	mov	r10,r12
.mark_one:
	cmp	r10,rbx
	jl	.mark_out
	mov	eax,r10d
	and	eax,SP_N - 1
	shl	eax,5				; SP_SIZE
	lea	r11,[r9+rax]
	cmp	[r11+SP_PN],r10
	jne	.mark_next
	mov	eax,[r11+SP_FL]
	test	eax,SPF_SENT
	jz	.mark_next
	test	eax,SPF_ACKED
	jnz	.mark_next
	or	dword [r11+SP_FL],SPF_ACKED
	mov	dword [rsp+16+8+QA_NEWLY],1
	; an RTT sample from the largest acknowledged, when it asked for one
	cmp	r10,[rsp+16+8+QA_LARGEST]
	jne	.mark_next
	test	eax,SPF_ACKEL
	jz	.mark_next
	mov	rax,[g_qnow]
	sub	rax,[r11+SP_TIME]
	call	qc_rtt_sample
.mark_next:
	dec	r10
	jmp	.mark_one
.mark_out:
	pop	rdx
	pop	rsi
	ret

; rax = an RTT sample (µs): smoothed RTT and its variation (RFC 9002 5.3)
qc_rtt_sample:
	test	rax,rax
	jg	@f
	mov	eax,1
@@:
	mov	rcx,[r15+QC_SRTT]
	cmp	rcx,333000
	jne	.update
	cmp	qword [r15+QC_RTTVAR],166500
	jne	.update
	mov	[r15+QC_SRTT],rax		; the first sample
	shr	rax,1
	mov	[r15+QC_RTTVAR],rax
	ret
.update:
	mov	rdx,rcx
	sub	rdx,rax
	jns	@f
	neg	rdx
@@:
	; rttvar = 3/4 rttvar + 1/4 |srtt - sample|; srtt = 7/8 srtt + 1/8 sample
	mov	r8,[r15+QC_RTTVAR]
	lea	r8,[r8*3]
	add	r8,rdx
	shr	r8,2
	mov	[r15+QC_RTTVAR],r8
	lea	r8,[rcx*8]
	sub	r8,rcx
	add	r8,rax
	shr	r8,3
	mov	[r15+QC_SRTT],r8
	ret

; r15 = connection: the probe timer for what is still out, ack-eliciting
; and not acknowledged (crypto at Initial/Handshake, anything at 1-RTT);
; off when nothing is
qc_pto_arm:
	mov	qword [r15+QC_PTO_AT],0
	xor	ecx,ecx				; level
.level:
	cmp	ecx,3
	jae	.none
	mov	eax,ecx
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	edx,SP_N
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	je	.out_there
	add	r8,SP_SIZE
	dec	edx
	jnz	.slot
	inc	ecx
	jmp	.level
.out_there:
	call	qc_pto_period
	add	rax,[g_qnow]
	mov	[r15+QC_PTO_AT],rax
.none:
	ret

; rax = the probe timeout (µs): srtt + max(4 rttvar, 1 ms) + 25 ms,
; doubled for every probe in a row
qc_pto_period:
	mov	rax,[r15+QC_RTTVAR]
	shl	rax,2
	cmp	rax,1000
	jae	@f
	mov	eax,1000
@@:
	add	rax,[r15+QC_SRTT]
	add	rax,25000
	mov	ecx,[r15+QC_PTOCNT]
	cmp	ecx,8
	jbe	@f
	mov	ecx,8
@@:
	shl	rax,cl
	ret

; ------------------------------------------------------------ crypto

; edi = level, rsi = the bytes, rdx = their length, rcx = their offset
; (r15 = connection, ebx = session). Reassembled; complete messages go
; to the handshake. CF when the connection fails (QC_ERR set).
qc_crypto_in:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12d,edi
	cmp	r12d,QL_APP
	je	.ok				; (post-handshake messages: none expected)
	lea	r13,[r15+QC_CRX]
	lea	r14,[r15+QC_CRBM]
	mov	eax,CH_MAX
	cmp	r12d,QL_HS
	jne	@f
	lea	r13,[r15+QC_CRX_HS]
	lea	r14,[r15+QC_CRBM_HS]
	mov	eax,QC_CRX_HSCAP
@@:
	lea	r8,[rcx+rdx]
	cmp	r8,rax
	ja	.exceeded
	; the bytes, and their marks
	lea	rdi,[r13+rcx]
	push	rcx
	mov	rcx,rdx
	rep	movsb
	pop	rcx
	mov	r9,rcx
.mark:
	cmp	r9,r8
	jae	.advance
	mov	rax,r9
	shr	rax,3
	mov	r10d,r9d
	and	r10d,7
	bts	dword [r14+rax],r10d
	inc	r9
	jmp	.mark
.advance:
	mov	r9d,[r15+QC_CR_END+r12*4]
	mov	r10d,r9d
.adv:
	mov	eax,r9d
	shr	eax,3
	mov	ecx,r9d
	and	ecx,7
	movzx	eax,byte [r14+rax]
	bt	eax,ecx
	jnc	@f
	inc	r9d
	jmp	.adv
@@:
	mov	[r15+QC_CR_END+r12*4],r9d
	cmp	r9d,r10d
	je	.ok				; nothing new in order
	cmp	r12d,QL_INIT
	jne	.handshake
	test	dword [r15+QC_FLAGS],QF_HELLO
	jnz	.ok				; (a retransmission)
	; the ClientHello, whole or not yet
	mov	eax,[r15+QC_SOCK]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_TLS]
	test	eax,eax
	jz	.internal
	dec	eax
	imul	rax,rax,TL_SIZE
	lea	rsi,[g_tls+rax]
	lea	rdi,[r15+QC_TS]
	mov	rdx,r13
	mov	ecx,r9d
	lea	r8,[r15+QC_TLSOUT]
	mov	r9d,QC_TLSROOM
	call	tls_hello
	cmp	eax,TH_MORE
	je	.ok
	cmp	eax,TH_SEND
	jne	.tls_failed
	; the flight: ServerHello for Initial, the rest for Handshake; the
	; keys of both levels from the secrets
	mov	ecx,[r15+QC_QT+QT_SHLEN]
	mov	[r15+QC_CS_LEN+0],ecx
	sub	edx,ecx
	mov	[r15+QC_CS_LEN+4],edx
	or	dword [r15+QC_FLAGS],QF_HELLO
	qc_key	QL_HS, 0
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_CHS]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_HS, 1
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_SHS]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_APP, 0
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_CAP]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_APP, 1
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_SAP]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	; the secrets are done with (the handshake's own are in its TS)
	lea	rdi,[r15+QC_QT]
	mov	ecx,128
	call	secure_zero
	jmp	.ok
.handshake:
	test	dword [r15+QC_FLAGS],QF_DONE
	jnz	.ok
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.ok
	lea	rdi,[r15+QC_TS]
	mov	rsi,r13
	mov	ecx,r9d
	call	quic_tls_finished
	cmp	eax,TH_MORE
	je	.ok
	cmp	eax,TH_DONE
	jne	.bad_finished
	; complete: HANDSHAKE_DONE goes, the handshake data needs no more sending
	or	dword [r15+QC_FLAGS],QF_DONE or QF_HDONE
	mov	dword [r15+QC_STATE],QCS_EST
	mov	eax,[r15+QC_CS_LEN+4]
	mov	[r15+QC_CS_SENT+4],eax
	mov	dword [r15+QC_ACKED_ALL+4],1
	mov	eax,[r15+QC_CS_LEN+0]
	mov	[r15+QC_CS_SENT+0],eax
	call	qc_established			; http3.inc: the control streams
.ok:
	clc
	jmp	.out
.exceeded:
	mov	qword [r15+QC_ERR],0x0D		; CRYPTO_BUFFER_EXCEEDED
	jmp	.fail
.bad_finished:
	mov	qword [r15+QC_ERR],0x100 + 51	; crypto error: decrypt_error
	jmp	.fail
.tls_failed:
	movzx	eax,byte [r15+QC_TLSOUT+6]	; the alert it would have sent
	add	eax,0x100
	mov	[r15+QC_ERR],rax
	jmp	.fail
.internal:
	mov	qword [r15+QC_ERR],1		; INTERNAL_ERROR
.fail:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r15 = connection, ebx = session: it fails with QC_ERR: CONNECTION_CLOSE
; goes (at the highest level we can), then it closes
qc_fail:
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	je	.out
	mov	dword [r15+QC_STATE],QCS_CLOSING
	or	dword [r15+QC_FLAGS],QF_CLOSE
	call	qc_pto_period
	lea	rax,[rax*2+rax]
	add	rax,[g_qnow]
	mov	[r15+QC_CLOSE_AT],rax
	jmp	qc_dirty
.out:
	ret

; ------------------------------------------------------------- sending

; ebx = connection: every packet it has to send, a level at a time
qc_send:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	qc_regs
	xor	r12d,r12d
.level:
	cmp	r12d,3
	jae	.done
	mov	r13d,32				; at most this many packets a level a call
.more:
	mov	ecx,r12d
	call	qc_build
	test	eax,eax
	jz	.next
	dec	r13d
	jnz	.more
.next:
	inc	r12d
	jmp	.level
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ecx = level (ebx, r15 = connection): one packet of what it has at that
; level, into the send batch. eax = 1 when one went, 0 when nothing did.
QB_LEVEL	:= 0
QB_BUF		:= 8
QB_PN		:= 16
QB_HDR		:= 24
QB_LENAT	:= 28				; where the long header's length goes, 0 short
QB_ACKEL	:= 32
QB_MAX		:= 36				; the datagram's room
QB_CRYPTO	:= 40				; d, d: crypto offset and length in it
QB_HDONE	:= 48
QB_FLAGS	:= 52
QB_SIZE		:= 64
qc_build:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,QB_SIZE
	mov	[rsp+QB_LEVEL],ecx
	mov	r12d,ecx
	xor	eax,eax
	mov	[rsp+QB_ACKEL],eax
	mov	[rsp+QB_CRYPTO],eax
	mov	[rsp+QB_CRYPTO+4],eax
	mov	[rsp+QB_HDONE],eax
	; keys for it?
	cmp	r12d,QL_INIT
	jne	@f
	test	dword [r15+QC_FLAGS],QF_INIT_GONE
	jnz	.nothing
	jmp	.keys_ok
@@:
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.nothing
.keys_ok:
	; anything to say?
	mov	r13d,0
	imul	eax,r12d,PS_SIZE
	cmp	dword [r15+QC_PS+rax+PS_ACKQ],0
	je	@f
	or	r13d,1				; an ACK
@@:
	cmp	r12d,QL_APP
	je	.app_wants
	mov	eax,[r15+QC_CS_SENT+r12*4]
	cmp	eax,[r15+QC_CS_LEN+r12*4]
	jae	@f
	or	r13d,2				; crypto data
@@:
	jmp	.probe_wants
.app_wants:
	test	dword [r15+QC_FLAGS],QF_HDONE
	jz	@f
	or	r13d,4
@@:
	call	qc_app_pending			; http3.inc: stream data, flow control
	test	eax,eax
	jz	.probe_wants
	or	r13d,16
.probe_wants:
	cmp	dword [r15+QC_PROBE+r12*4],0
	je	@f
	or	r13d,8
@@:
	test	dword [r15+QC_FLAGS],QF_CLOSE
	jz	@f
	call	qc_close_level			; eax = the level CONNECTION_CLOSE goes at
	cmp	eax,r12d
	jne	@f
	mov	r13d,32				; closing: that is all it says
@@:
	test	r13d,r13d
	jz	.nothing
	mov	[rsp+QB_FLAGS],r13d
	; room: a datagram, and before validation three times what came
	mov	eax,QUIC_DGRAM
	test	dword [r15+QC_FLAGS],QF_VALID
	jnz	@f
	mov	rcx,[r15+QC_RXB]
	lea	rcx,[rcx*2+rcx]
	sub	rcx,[r15+QC_TXB]
	jle	.nothing
	cmp	rcx,rax
	jae	@f
	mov	eax,ecx
	cmp	eax,128
	jb	.nothing
@@:
	mov	[rsp+QB_MAX],eax
	call	qtx_slot
	test	rax,rax
	jz	.nothing
	mov	[rsp+QB_BUF],rax
	mov	rdi,rax
	; the header
	imul	eax,r12d,PS_SIZE
	mov	rcx,[r15+QC_PS+rax+PS_NEXT]
	mov	[rsp+QB_PN],rcx
	inc	qword [r15+QC_PS+rax+PS_NEXT]
	cmp	r12d,QL_APP
	je	.short
	; long: the type bits of the version (v1: Initial 0, Handshake 2; v2: 1, 3)
	mov	eax,r12d
	add	eax,eax				; 0 or 2
	cmp	dword [r15+QC_VER],QUIC_V2
	jne	@f
	inc	eax
@@:
	shl	eax,4
	or	eax,0xC3			; long, fixed bit, a 4-byte packet number
	mov	[rdi],al
	mov	eax,[r15+QC_VER]
	bswap	eax
	mov	[rdi+1],eax
	add	rdi,5
	mov	ecx,[r15+QC_DCIDLEN]
	mov	[rdi],cl
	inc	rdi
	lea	rsi,[r15+QC_DCID]
	rep	movsb
	mov	byte [rdi],8
	mov	rax,[r15+QC_SCID]
	mov	[rdi+1],rax
	add	rdi,9
	cmp	r12d,QL_INIT
	jne	@f
	mov	byte [rdi],0			; no token
	inc	rdi
@@:
	mov	rax,rdi
	sub	rax,[rsp+QB_BUF]
	mov	[rsp+QB_LENAT],eax
	add	rdi,2				; the length: two bytes, after
	jmp	.pn
.short:
	mov	byte [rdi],0x43			; fixed bit, key phase 0, a 4-byte number
	inc	rdi
	mov	ecx,[r15+QC_DCIDLEN]
	lea	rsi,[r15+QC_DCID]
	rep	movsb
	mov	dword [rsp+QB_LENAT],0
.pn:
	mov	eax,[rsp+QB_PN]
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	mov	rax,rdi
	sub	rax,[rsp+QB_BUF]
	mov	[rsp+QB_HDR],eax
	; the frames
	mov	r14,[rsp+QB_BUF]
	mov	eax,[rsp+QB_MAX]
	sub	eax,16				; the tag
	add	r14,rax				; their limit
	test	dword [rsp+QB_FLAGS],32
	jnz	.close
	imul	eax,r12d,PS_SIZE
	cmp	dword [r15+QC_PS+rax+PS_NR],0
	je	@f
	mov	ecx,r12d
	call	qc_ack_write			; rdi past it
@@:
	test	dword [rsp+QB_FLAGS],2
	jz	.no_crypto
	; CRYPTO: as much as fits
	mov	eax,[r15+QC_CS_SENT+r12*4]
	mov	ecx,[r15+QC_CS_LEN+r12*4]
	sub	ecx,eax				; left
	mov	rdx,r14
	sub	rdx,rdi
	sub	rdx,1 + 4 + 2			; type, offset, length
	jle	.no_crypto
	cmp	rcx,rdx
	jbe	@f
	mov	ecx,edx
@@:
	mov	[rsp+QB_CRYPTO],eax
	mov	[rsp+QB_CRYPTO+4],ecx
	mov	byte [rdi],6
	or	eax,0x80000000			; offset: 4-byte varint
	bswap	eax
	mov	[rdi+1],eax
	mov	eax,ecx
	or	eax,0x4000			; length: 2-byte varint
	xchg	al,ah
	mov	[rdi+5],ax
	add	rdi,7
	mov	eax,[rsp+QB_CRYPTO]
	lea	rsi,[r15+QC_TLSOUT+rax]
	cmp	r12d,QL_HS
	jne	@f
	mov	edx,[r15+QC_CS_LEN+0]		; Handshake data follows the ServerHello
	add	rsi,rdx
@@:
	rep	movsb
	mov	eax,[rsp+QB_CRYPTO+4]
	add	[r15+QC_CS_SENT+r12*4],eax
	mov	dword [rsp+QB_ACKEL],1
.no_crypto:
	test	dword [rsp+QB_FLAGS],4
	jz	@f
	mov	byte [rdi],0x1E			; HANDSHAKE_DONE
	inc	rdi
	and	dword [r15+QC_FLAGS],not QF_HDONE
	mov	dword [rsp+QB_HDONE],1
	mov	dword [rsp+QB_ACKEL],1
@@:
	test	dword [rsp+QB_FLAGS],16
	jz	@f
	mov	rsi,r14				; stream frames, as far as they fit
	call	qc_app_write			; rdi past them; eax = 1 when any
	or	[rsp+QB_ACKEL],eax
@@:
	test	dword [rsp+QB_FLAGS],8
	jz	.frames_end
	mov	dword [r15+QC_PROBE+r12*4],0
	cmp	dword [rsp+QB_ACKEL],0
	jne	.frames_end
	mov	byte [rdi],1			; PING: something to acknowledge
	inc	rdi
	mov	dword [rsp+QB_ACKEL],1
	jmp	.frames_end
.close:
	mov	al,0x1C				; CONNECTION_CLOSE: error, frame type, no reason
	test	dword [r15+QC_FLAGS],QF_APP_ERR
	jz	@f
	cmp	r12d,QL_APP
	jne	@f
	mov	al,0x1D				; the application's: no frame type
@@:
	mov	[rdi],al
	inc	rdi
	push	rax
	mov	rax,[r15+QC_ERR]
	call	qv_write
	pop	rax
	cmp	al,0x1D
	je	@f
	mov	byte [rdi],0
	inc	rdi
@@:
	mov	byte [rdi],0
	inc	rdi
	and	dword [r15+QC_FLAGS],not QF_CLOSE
	mov	dword [rsp+QB_ACKEL],0
.frames_end:
	; a datagram with an ack-eliciting Initial: 1200 bytes at least
	cmp	r12d,QL_INIT
	jne	.padded
	cmp	dword [rsp+QB_ACKEL],0
	je	.padded
	mov	rax,[rsp+QB_BUF]
	add	rax,1200 - 16
	cmp	rdi,rax
	jae	.padded
	mov	rcx,rax
	sub	rcx,rdi
	push	rdi
	xor	eax,eax
	rep	stosb
	pop	rdi
	mov	rdi,[rsp+QB_BUF]
	add	rdi,1200 - 16
.padded:
	; the payload's length; the long header's length field
	mov	r9,rdi
	sub	r9,[rsp+QB_BUF]
	sub	r9d,[rsp+QB_HDR]		; payload
	mov	eax,[rsp+QB_LENAT]
	test	eax,eax
	jz	@f
	lea	ecx,[r9+4+16]			; packet number, payload, tag
	or	ecx,0x4000
	xchg	cl,ch
	mov	rdx,[rsp+QB_BUF]
	mov	[rdx+rax],cx
@@:
	; recorded, sealed, queued
	mov	eax,[rsp+QB_PN]
	and	eax,SP_N - 1
	shl	eax,5
	mov	ecx,r12d
	imul	ecx,ecx,SP_N * SP_SIZE
	lea	rdx,[r15+QC_SP+rcx]
	add	rdx,rax
	mov	rax,[rsp+QB_PN]
	mov	[rdx+SP_PN],rax
	mov	rax,[g_qnow]
	mov	[rdx+SP_TIME],rax
	mov	eax,SPF_SENT
	cmp	dword [rsp+QB_ACKEL],0
	je	@f
	or	eax,SPF_ACKEL
@@:
	cmp	dword [rsp+QB_HDONE],0
	je	@f
	or	eax,SPF_HDONE
@@:
	mov	[rdx+SP_FL],eax
	mov	eax,[rsp+QB_CRYPTO]
	mov	[rdx+SP_COFF],eax
	mov	eax,[rsp+QB_CRYPTO+4]
	mov	[rdx+SP_CLEN],eax
	cmp	r12d,QL_APP
	jne	@f
	mov	rdi,rdx				; the stream frames it carried (http3.inc)
	mov	rsi,[rsp+QB_PN]
	call	qc_app_sent
@@:
	imul	eax,r12d,PS_SIZE
	mov	dword [r15+QC_PS+rax+PS_ACKQ],0
	lea	eax,[r12*2+1]
	imul	eax,eax,QK_SIZE
	lea	rdi,[r15+QC_KEYS+rax]
	mov	rsi,[rsp+QB_BUF]
	mov	edx,[rsp+QB_HDR]
	mov	ecx,4
	mov	r8,[rsp+QB_PN]
	call	quic_seal			; eax = the packet's length
	add	[r15+QC_TXB],rax
	mov	ecx,eax
	mov	edi,[r15+QC_SOCK]
	lea	rsi,[r15+QC_PEER]
	mov	r8d,[r15+QC_PEERLEN]
	call	qtx_commit
	cmp	dword [rsp+QB_ACKEL],0
	je	@f
	cmp	qword [r15+QC_PTO_AT],0
	jne	@f
	call	qc_pto_period
	add	rax,[g_qnow]
	mov	[r15+QC_PTO_AT],rax
@@:
	mov	eax,1
	jmp	.out
.nothing:
	xor	eax,eax
.out:
	add	rsp,QB_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = the level CONNECTION_CLOSE goes at: the highest with keys
qc_close_level:
	mov	eax,QL_APP
	test	dword [r15+QC_FLAGS],QF_DONE
	jnz	.out
	mov	eax,QL_HS
	test	dword [r15+QC_FLAGS],QF_HELLO
	jnz	.out
	mov	eax,QL_INIT
.out:
	ret

; ecx = level, rdi = where: an ACK frame of its ranges; rdi past it
qc_ack_write:
	imul	eax,ecx,PS_SIZE
	lea	r8,[r15+QC_PS+rax]
	mov	byte [rdi],2
	inc	rdi
	mov	rax,[r8+PS_R]			; largest
	call	qv_write
	mov	rax,[g_qnow]			; ack delay, in units of 8 µs
	sub	rax,[r8+PS_LTIME]
	jns	@f
	xor	eax,eax
@@:
	shr	rax,3
	call	qv_write
	mov	eax,[r8+PS_NR]
	dec	eax
	call	qv_write			; range count
	mov	rax,[r8+PS_R]
	sub	rax,[r8+PS_R+8]
	call	qv_write			; first range
	mov	r9d,1
	lea	r10,[r8+PS_R]
.range:
	cmp	r9d,[r8+PS_NR]
	jae	.done
	mov	rax,[r10+8]			; previous lo
	sub	rax,[r10+16]			; - this hi
	sub	rax,2
	call	qv_write			; gap
	mov	rax,[r10+16]
	sub	rax,[r10+24]
	call	qv_write			; length
	add	r10,16
	inc	r9d
	jmp	.range
.done:
	ret

; ------------------------------------------------------- the send batch

; rax = the next datagram's buffer (0 when the batch cannot take one even
; after a flush), edx = its slot
qtx_slot:
	mov	edx,[g_qtx_n]
	cmp	edx,QTX_N
	jb	@f
	push	rdi
	call	qtx_send
	pop	rdi
	mov	edx,[g_qtx_n]
	cmp	edx,QTX_N
	jae	.none
@@:
	imul	rax,rdx,QTX_SZ
	lea	rax,[g_qtx_buf+rax]
	ret
.none:
	xor	eax,eax
	ret

; the datagram in the batch's next slot is ready: edi = socket slot, ecx =
; its length, rsi = the address, r8d = its length
qtx_commit:
	mov	edx,[g_qtx_n]
	mov	rax,rdx
	shl	rax,6
	lea	r9,[g_qtx_mm+rax]
	mov	r10,rdx
	shl	r10,5
	lea	r10,[g_qtx_sa+r10]
	mov	[r9],r10			; msg_name: a copy
	mov	[r9+8],r8d
	push	rdi
	push	rcx
	mov	rdi,r10
	mov	ecx,28
	rep	movsb
	pop	rcx
	pop	rdi
	mov	r10,rdx
	shl	r10,4
	lea	r10,[g_qtx_iov+r10]
	mov	[r9+16],r10
	mov	qword [r9+24],1
	mov	qword [r9+32],0			; no control
	mov	qword [r9+40],0
	mov	dword [r9+48],0
	imul	rax,rdx,QTX_SZ
	lea	rax,[g_qtx_buf+rax]
	mov	[r10],rax
	mov	[r10+8],rcx
	mov	eax,[g_qs_fd+rdi*4]
	mov	[g_qtx_fds+rdx*4],eax
	inc	dword [g_qtx_n]
	ret

; the batch goes, a sendmmsg per run of datagrams on one socket
qtx_send:
	push	rbx
	push	r12
	xor	ebx,ebx
.run:
	cmp	ebx,[g_qtx_n]
	jae	.done
	mov	r12d,ebx			; the run: same socket
	mov	eax,[g_qtx_fds+rbx*4]
@@:
	inc	r12d
	cmp	r12d,[g_qtx_n]
	jae	@f
	cmp	[g_qtx_fds+r12*4],eax
	je	@b
@@:
	mov	edi,eax
	mov	rsi,rbx
	shl	rsi,6
	lea	rsi,[g_qtx_mm+rsi]
	mov	edx,r12d
	sub	edx,ebx
	xor	r10d,r10d
	mov	eax,SYS_sendmmsg
	syscall				; (a full socket drops the rest: QUIC recovers)
	mov	ebx,r12d
	jmp	.run
.done:
	mov	dword [g_qtx_n],0
	pop	r12
	pop	rbx
	ret

; The worker's loop, after the deliveries: what the connections have to
; send, then the batch
qs_flush:
	cmp	dword [g_qs_n],0
	je	.out
	push	rbx
	push	r12
	xor	r12d,r12d
.next:
	cmp	r12d,[g_qdirty_n]
	jae	.sent
	mov	rax,[g_qdirty+r12*8]
	inc	r12d
	mov	ebx,eax
	shr	rax,32
	push	rax
	call	session_ptr
	pop	rcx
	cmp	[rax+S_GEN],ecx
	jne	.next
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	test	dword [rax+S_FLAGS],SF_QC
	jz	.next
	push	r15
	qc_regs
	mov	dword [r15+QC_DIRTY],0
	pop	r15
	call	qc_send
	jmp	.next
.sent:
	mov	dword [g_qdirty_n],0
	cmp	dword [g_qtx_n],0
	je	@f
	call	qtx_send
@@:
	pop	r12
	pop	rbx
.out:
	ret

; ---------------------------------------------------------------- time

; Every 10 ms while there are connections: probe timeouts, closings
qs_tick:
	cmp	dword [g_qc_count],0
	je	.out
	push	rbx
	push	r12
	push	r15
	call	qs_clock
	mov	r12d,[g_qc_head]
.next:
	test	r12d,r12d
	jz	.done
	lea	ebx,[r12-1]
	mov	r15d,ebx
	shl	r15,HB_SHIFT
	add	r15,[g_hbuf_base]
	mov	r12d,[r15+QC_LINK]		; (before it may go)
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	jne	.pto
	test	dword [r15+QC_FLAGS],QF_CLOSE
	jnz	.next				; its CONNECTION_CLOSE has not gone yet
	mov	rax,[g_qnow]
	cmp	rax,[r15+QC_CLOSE_AT]
	jb	.next
	call	qc_free
	jmp	.next
.pto:
	mov	rax,[r15+QC_PTO_AT]
	test	rax,rax
	jz	.next
	cmp	rax,[g_qnow]
	ja	.next
	call	qc_on_pto
	jmp	.next
.done:
	pop	r15
	pop	r12
	pop	rbx
	call	qs_flush
.out:
	ret

; ebx, r15 = connection: its probe timer went off. What was sent and not
; acknowledged goes again: crypto data from the lowest offset lost, the
; streams' (http3.inc); a PING where there is nothing else to send
qc_on_pto:
	push	r12
	inc	dword [r15+QC_PTOCNT]
	mov	qword [r15+QC_PTO_AT],0
	xor	r12d,r12d
.level:
	cmp	r12d,3
	jae	.done
	mov	eax,r12d
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	ecx,SP_N
	mov	r9d,-1				; the lowest crypto offset lost
	xor	r10d,r10d			; anything ack-eliciting out
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	jne	.slot_next
	mov	r10d,1
	and	dword [r8+SP_FL],not SPF_SENT	; lost: it goes again in a new packet
	cmp	dword [r8+SP_CLEN],0
	je	@f
	mov	eax,[r8+SP_COFF]
	cmp	eax,r9d
	jae	@f
	mov	r9d,eax
@@:
	test	dword [r8+SP_FL],SPF_HDONE
	jz	@f
	or	dword [r15+QC_FLAGS],QF_HDONE
@@:
	cmp	r12d,QL_APP
	jne	.slot_next
	push	r8
	push	rcx
	push	r9
	push	r10
	mov	rdi,r8
	call	qc_app_lost			; http3.inc: its stream data goes again
	pop	r10
	pop	r9
	pop	rcx
	pop	r8
.slot_next:
	add	r8,SP_SIZE
	dec	ecx
	jnz	.slot
	cmp	r9d,-1
	je	@f
	cmp	r9d,[r15+QC_CS_SENT+r12*4]
	jae	@f
	mov	[r15+QC_CS_SENT+r12*4],r9d
@@:
	test	r10d,r10d
	jz	@f
	mov	dword [r15+QC_PROBE+r12*4],1
@@:
	inc	r12d
	jmp	.level
.done:
	pop	r12
	jmp	qc_dirty

; ebx = connection: it goes (session_close calls qc_closing)
qc_free:
	mov	edi,ebx
	jmp	session_close

; session_close of a connection (SF_QC): its IDs out of the hash, out of
; the list, its streams closed. ebx = session; keeps rbx, r12.
qc_closing:
	push	r15
	push	r14
	push	rbx
	push	r12
	qc_regs
	cmp	dword [r15+QC_GEN],0
	je	.out
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+QC_GEN]
	jne	.out
	mov	dword [r15+QC_GEN],0		; (once)
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	call	qh_del
	lea	rdi,[r15+QC_ODCID]
	mov	esi,[r15+QC_ODCIDLEN]
	call	qh_del
	mov	eax,[r15+QC_LINK]
	mov	ecx,[r15+QC_PLINK]
	test	ecx,ecx
	jz	.head
	lea	edx,[rcx-1]
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+QC_LINK],eax
	jmp	@f
.head:
	mov	[g_qc_head],eax
@@:
	test	eax,eax
	jz	@f
	lea	edx,[rax-1]
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+QC_PLINK],ecx
@@:
	dec	dword [g_qc_count]
	call	qc_streams_close		; http3.inc
.out:
	pop	r12
	pop	rbx
	pop	r14
	pop	r15
	ret
