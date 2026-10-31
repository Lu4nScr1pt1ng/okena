; HTTP/2 (RFC 9113) towards clients, on http listeners with `http2 on`:
; prior knowledge on plain listeners, ALPN h2 on TLS ones.
;
; A connection is a session in HS_H2 whose client socket carries frames,
; read and written at the same time (its own operations on io_uring, its
; own event handling on epoll, its own TLS records when they are sealed in
; user space). Each stream is a session of its own (SF_H2S) running the
; HTTP/1.1 exchange of proxy.inc unchanged (routing, pools, retries,
; upstream TLS, rewrites, logs), its client side served by the connection
; instead of a socket:
;
;   h_recv on a stream (h2s_recv) gets the request: a head written from
;       the HEADERS (and CONTINUATION) fields, then the DATA payloads
;       (chunk-framed when the client gave no content-length);
;   h_send on a stream (h2s_send) gives the response: its head becomes a
;       HEADERS frame, its body DATA frames, within the flow-control
;       windows; the end of the exchange is an empty DATA with END_STREAM.
;
; Connection buffers (in the session's area past the HTTP and TLS ones):
; the state and stream table, frames in, frames out, the HPACK decoder and
; what a header block decodes to.

HS_H2		:= 40				; H_STATE of a connection

H2_PREFACE_LEN	:= 24
H2_MAXS		:= 128				; streams a connection tracks (100 open, plus closing)
H2_MAX_OPEN	:= 100				; SETTINGS_MAX_CONCURRENT_STREAMS
H2_INIT_WIN	:= 32768			; our SETTINGS_INITIAL_WINDOW_SIZE
H2_CONN_WIN	:= 1048576			; our connection window
H2_MAX_HLIST	:= 16384			; SETTINGS_MAX_HEADER_LIST_SIZE
H2_INCAP	:= 32768
H2_OUTCAP	:= 32768
H2_HBCAP	:= 16384			; a header block (HEADERS + CONTINUATION)
H2_STRCAP	:= 16384
H2_MAXFIELDS	:= 128
H2_RST_BUDGET	:= 200				; resets a client may cause in a second
H2_CHEAP_BUDGET	:= 2000				; frames that ask work and carry nothing, a second
H2_CONT_MAX	:= 64				; CONTINUATION frames in one header block

; frame types and flags
H2F_DATA	:= 0
H2F_HEADERS	:= 1
H2F_PRIORITY	:= 2
H2F_RST		:= 3
H2F_SETTINGS	:= 4
H2F_PUSH	:= 5
H2F_PING	:= 6
H2F_GOAWAY	:= 7
H2F_WINDOW	:= 8
H2F_CONT	:= 9
H2_END_STREAM	:= 1
H2_ACK		:= 1
H2_END_HEADERS	:= 4
H2_PADDED	:= 8
H2_PRIO		:= 0x20

; error codes
H2E_NO_ERROR	:= 0
H2E_PROTOCOL	:= 1
H2E_INTERNAL	:= 2
H2E_FLOW	:= 3
H2E_CLOSED	:= 5
H2E_FRAME_SIZE	:= 6
H2E_REFUSED	:= 7
H2E_CANCEL	:= 8
H2E_COMPRESSION	:= 9
H2E_CALM	:= 11

; the connection's buffers
HB_H2		:= 1 shl 17
C2_FLAGS	:= 0				; d: C2F_*
C2_INLEN	:= 4
C2_INOFF	:= 8
C2_OUTLEN	:= 12				; frames queued in OUT
C2_OSEND	:= 16				; plain: OUT bytes in the send in flight
C2_CLEN		:= 20				; user-space TLS: sealed bytes at HB_TXC
C2_COFF		:= 24				;   and how many went out
C2_RXC		:= 28				; user-space TLS: received records at HB_RXC
C2_SWIN		:= 32				; d (signed): what we may still send on the connection
C2_RWIN		:= 36				; what the client may still send us
C2_ROWED	:= 40				; connection credit not yet given back
C2_PINIT	:= 44				; the client's SETTINGS_INITIAL_WINDOW_SIZE
C2_PMAXF	:= 48				; its SETTINGS_MAX_FRAME_SIZE
C2_LASTSID	:= 52				; the highest stream it opened
C2_NSTR		:= 56				; streams in the table
C2_HBSID	:= 60				; a header block waiting for CONTINUATION (0 none)
C2_HBLEN	:= 64
C2_HBEND	:= 68				; its HEADERS had END_STREAM
C2_BLKH		:= 72				; streams waiting for room or window (sessions)
C2_BLKT		:= 76
C2_PREF		:= 80				; preface bytes matched
C2_RSTN		:= 84				; resets this second
C2_RSTT		:= 88				; and the tick they count in
C2_CHEAPN	:= 92				; cheap frames this second
C2_CHEAPT	:= 96				; and the tick they count in
C2_HBN		:= 100				; CONTINUATION frames in the block
C2_ST		:= 128				; the stream table: H2_MAXS of S2_*
S2_SID		:= 0
S2_SESS		:= 4
S2_GEN		:= 8
S2_SIZE		:= 16
HB_H2IN		:= HB_H2 + 4096
HB_H2OUT	:= HB_H2IN + H2_INCAP
HB_H2HP		:= HB_H2OUT + H2_OUTCAP		; the HPACK decoder
HB_H2FLD	:= HB_H2HP + 8192		; decoded fields
HB_H2STR	:= HB_H2FLD + H2_MAXFIELDS * HP_SIZE
HB_H2HB		:= HB_H2STR + H2_STRCAP
assert C2_ST + H2_MAXS * S2_SIZE <= 4096
assert HPD_BYTES <= 8192
assert HB_H2HB + H2_HBCAP <= 1 shl HB_SHIFT

C2F_RECV	:= 1				; a receive in flight
C2F_SEND	:= 2				; a send in flight
C2F_CLOSING	:= 4				; GOAWAY queued: close once it is out
C2F_PEERGONE	:= 8				; the client sent GOAWAY
C2F_EPOUT	:= 16				; epoll: the socket was full
C2F_FLUSHQ	:= 32				; in the flush list: its send goes at the iteration's end
H2_FLUSH_MAX	:= 4096
H2_RESERVE	:= 17				; OUT keeps room for a GOAWAY

; a stream session's fields (the end of its H record) and request queue
H_H2C		:= 472				; d: its connection's session
H_H2CG		:= 476				; d: that session's generation
H_H2SID		:= 480				; d: the stream id
H_H2SWIN	:= 484				; d (signed): what it may still send
H_H2F		:= 488				; d: S2F_*
H_H2PP		:= 496				; q: response bytes waiting for room or window
H_H2PL		:= 504				; d: how many
H_H2BL		:= 508				; d: next in the connection's waiting list
S2F_HEAD	:= 1				; the final response head went out
S2F_END		:= 2				; END_STREAM went out
S2F_RST		:= 4				; reset (by either side)
S2F_WAITING	:= 8				; in the waiting list
S2F_FINISH	:= 16				; END_STREAM waits for room
S2F_CREDIT	:= 32				; stream credit waits for room
S2F_SENDING	:= 64				; an h_send is pending
SF_H2C		:= 4096				; S_FLAGS: an HTTP/2 connection
SF_H2S		:= 8192				; S_FLAGS: a stream of one

HB_H2Q		:= HB_TLS			; a stream's request queue (it has no TLS of its own)
Q_LEN		:= 0
Q_OFF		:= 4
Q_DST		:= 8				; q: a receive parked here
Q_ROOM		:= 16
Q_WAIT		:= 20
Q_PEND		:= 24				; payload bytes queued, credited back once drained
Q_RWIN		:= 28				; what the client may still send on this stream
Q_ENDED		:= 32				; the client ended the stream
Q_CHUNKED	:= 36				; DATA goes out chunk-framed (no content-length)
Q_CLEN		:= 40				; q: the declared content-length, -1 = none
Q_GOT		:= 48				; q: body bytes received
Q_DATA		:= 64
Q_CAP		:= (1 shl 16) - Q_DATA

bss
	align 8
	g_h2tmp:	rb 20480		; a response head's HPACK block
	g_h2fl_n	dd ?			; connections whose send waits for the iteration's end
	g_h2fl:		rq H2_FLUSH_MAX		; (session, generation) each
end bss

rodata
	h2_preface	db 'PRI * HTTP/2.0',13,10,13,10,'SM',13,10,13,10
	; our SETTINGS: MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH 0,
	; MAX_HEADER_LIST_SIZE; then a WINDOW_UPDATE for the connection
	h2_settings	db 0,0,24, H2F_SETTINGS, 0, 0,0,0,0
			db 0,3, 0,0,0,H2_MAX_OPEN
			db 0,4, 0,0,H2_INIT_WIN shr 8,0
			db 0,2, 0,0,0,0
			db 0,6, 0,0,H2_MAX_HLIST shr 8,0
			db 0,0,4, H2F_WINDOW, 0, 0,0,0,0
			db (H2_CONN_WIN - 65535) shr 24, ((H2_CONN_WIN - 65535) shr 16) and 255
			db ((H2_CONN_WIN - 65535) shr 8) and 255, (H2_CONN_WIN - 65535) and 255
	h2_settings.len = $ - h2_settings
end rodata

; edi = session: rax = its H record, rdx = its buffers, rcx = its C2 area
h2_ptrs:
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	rdx,[rax+H_BUF]
	lea	rcx,[rdx+HB_H2]
	ret

; Registers through the connection code: ebx = the connection's session,
; r15 = its H record, r14 = its buffers, r13 = its C2 area.
macro c2_regs
	h_rec
	mov	r14,[r15+H_BUF]
	lea	r13,[r14+HB_H2]
end macro

; ------------------------------------------------------------ the start

; ebx = an http session that turns into an HTTP/2 connection; edi = how
; much of the preface it consumed already (18: "PRI * HTTP/2.0\r\n\r\n"
; read as a request head on a plain listener; 0 after ALPN h2); bytes
; read past that are at HB_IN from H_INOFF to H_INLEN.
h2_start:
	push	rdi
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_H2C
	mov	edi,ebx
	call	ph_disarm
	c2_regs
	mov	dword [r15+H_STATE],HS_H2
	mov	rdi,r13				; the state and the stream table
	xor	eax,eax
	mov	ecx,4096 / 8
	rep	stosq
	pop	rax
	mov	[r13+C2_PREF],eax
	mov	dword [r13+C2_SWIN],65535
	mov	dword [r13+C2_PINIT],65535
	mov	dword [r13+C2_PMAXF],16384
	mov	dword [r13+C2_RWIN],H2_CONN_WIN
	lea	rdi,[r14+HB_H2HP]
	mov	esi,4096
	call	hpack_init
	c2_regs
	mov	ecx,[r15+H_INLEN]		; what was read already
	mov	eax,[r15+H_INOFF]
	sub	ecx,eax
	jbe	@f
	lea	rsi,[r14+HB_IN+rax]
	lea	rdi,[r14+HB_H2IN]
	mov	[r13+C2_INLEN],ecx
	rep	movsb
@@:
	lea	rsi,[h2_settings]		; our side of the preface
	mov	ecx,h2_settings.len
	call	h2_out_raw
	call	h2_process
	jmp	h2_pump

; ---------------------------------------------------------------- output

; rsi = bytes, ecx = length: appended to OUT (room checked by the caller).
; c2 registers.
h2_out_raw:
	mov	eax,[r13+C2_OUTLEN]
	lea	rdi,[r14+HB_H2OUT+rax]
	add	[r13+C2_OUTLEN],ecx
	rep	movsb
	ret

; eax = room in OUT. c2 registers.
h2_room:
	mov	eax,H2_OUTCAP
	sub	eax,[r13+C2_OUTLEN]
	ret

; esi = length, dl = type, cl = flags, r8d = stream: a frame header at the
; end of OUT, rdi = where its payload goes (OUTLEN counts header and
; payload). c2 registers.
h2_frame:
	mov	eax,[r13+C2_OUTLEN]
	lea	rdi,[r14+HB_H2OUT+rax]
	lea	eax,[rax+rsi+9]
	mov	[r13+C2_OUTLEN],eax
	mov	eax,esi
	bswap	eax
	shr	eax,8				; 24-bit length, big endian
	mov	[rdi],ax
	shr	eax,16
	mov	[rdi+2],al
	mov	[rdi+3],dl
	mov	[rdi+4],cl
	mov	eax,r8d
	bswap	eax
	mov	[rdi+5],eax
	add	rdi,9
	ret

; esi = stream, edx = error: RST_STREAM, when there is room
h2_out_rst:
	call	h2_room
	cmp	eax,13 + H2_RESERVE
	jb	.out
	push	rdx
	mov	r8d,esi
	mov	esi,4
	mov	dl,H2F_RST
	xor	ecx,ecx
	call	h2_frame
	pop	rax
	bswap	eax
	mov	[rdi],eax
.out:
	ret

; esi = stream (0: the connection), edx = increment: WINDOW_UPDATE. CF
; when there is no room.
h2_out_window:
	call	h2_room
	cmp	eax,13 + H2_RESERVE
	jb	.full
	push	rdx
	mov	r8d,esi
	mov	esi,4
	mov	dl,H2F_WINDOW
	xor	ecx,ecx
	call	h2_frame
	pop	rax
	bswap	eax
	mov	[rdi],eax
	clc
	ret
.full:
	stc
	ret

; edx = error: GOAWAY with the last stream we took, then close once it
; is out. Streams are closed now.
h2_goaway:
	test	dword [r13+C2_FLAGS],C2F_CLOSING
	jnz	.out
	or	dword [r13+C2_FLAGS],C2F_CLOSING
	push	rdx
	call	h2_room
	pop	rdx
	cmp	eax,17
	jb	.closed
	push	rdx
	mov	esi,8
	mov	dl,H2F_GOAWAY
	xor	ecx,ecx
	xor	r8d,r8d
	call	h2_frame
	mov	eax,[r13+C2_LASTSID]
	bswap	eax
	mov	[rdi],eax
	pop	rax
	bswap	eax
	mov	[rdi+4],eax
.closed:
	call	h2_streams_close
.out:
	ret

; ------------------------------------------------------------- the pump

; Start what can start: the send of what OUT holds, the next receive;
; close the connection when it is over. ebx = the connection.
h2_pump:
	c2_regs
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	call	h2_want_send
	c2_regs
	test	dword [r13+C2_FLAGS],C2F_CLOSING
	jnz	.closing
	test	dword [r13+C2_FLAGS],C2F_PEERGONE
	jz	.recv
	cmp	dword [r13+C2_NSTR],0
	jne	.recv
	xor	edx,edx				; the client left and nothing is open
	call	h2_goaway
	jmp	h2_pump
.recv:
	jmp	h2_recv
.closing:
	test	dword [r13+C2_FLAGS],C2F_SEND
	jnz	.out
	cmp	dword [r13+C2_OUTLEN],0
	jne	.out
	cmp	dword [r13+C2_CLEN],0
	jne	.out
	mov	edi,ebx				; the GOAWAY is out
	jmp	session_close
.out:
	ret

; c2 registers: the send of what OUT holds goes at the end of this loop
; iteration (h2_flush), so frames from every stream answered in it go in
; one send; at once when the list is full.
h2_want_send:
	test	dword [r13+C2_FLAGS],C2F_SEND or C2F_FLUSHQ
	jnz	.out
	cmp	dword [r13+C2_OUTLEN],0
	jne	@f
	cmp	dword [r13+C2_CLEN],0
	je	.out
@@:
	mov	eax,[g_h2fl_n]
	cmp	eax,H2_FLUSH_MAX
	jae	h2_send
	inc	dword [g_h2fl_n]
	or	dword [r13+C2_FLAGS],C2F_FLUSHQ
	mov	[g_h2fl+rax*8],ebx
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	mov	eax,[g_h2fl_n]
	mov	[g_h2fl+rax*8-4],ecx
.out:
	ret

; The worker's loop, after the deliveries: every connection that asked
; sends what it has.
h2_flush:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	xor	r12d,r12d
.next:
	cmp	r12d,[g_h2fl_n]
	jae	.done
	mov	ebx,[g_h2fl+r12*8]
	mov	ecx,[g_h2fl+r12*8+4]
	inc	r12d
	call	session_ptr
	cmp	[rax+S_GEN],ecx
	jne	.next				; gone (or another session now)
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	test	dword [rax+S_FLAGS],SF_H2C
	jz	.next
	c2_regs
	and	dword [r13+C2_FLAGS],not C2F_FLUSHQ
	call	h2_send
	jmp	.next
.done:
	mov	dword [g_h2fl_n],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; the send of what OUT holds, unless one is in flight. c2 registers.
h2_send:
	test	dword [r13+C2_FLAGS],C2F_SEND
	jnz	.out
	cmp	dword [r15+H_UTLS],0
	jne	.sealed
	mov	esi,[r13+C2_OUTLEN]
	test	esi,esi
	jz	.out
	mov	[r13+C2_OSEND],esi
	lea	rdi,[r14+HB_H2OUT]
	jmp	h2_sock_send
.sealed:
	cmp	dword [r13+C2_CLEN],0
	jne	.cipher				; sealed bytes still to go
	cmp	dword [r13+C2_OUTLEN],0
	je	.out
	; seal up to two records of OUT into HB_TXC
	push	r12
	lea	r12,[r14+HB_TXC]
	mov	ecx,UTLS_TX_RECS
.rec:
	push	rcx
	mov	edx,[r13+C2_OUTLEN]
	cmp	edx,TLS_RECORD_MAX
	jbe	@f
	mov	edx,TLS_RECORD_MAX
@@:
	push	rdx
	lea	rdi,[r12+5]
	lea	rsi,[r14+HB_H2OUT]
	mov	ecx,edx
	rep	movsb
	mov	rdx,[rsp]
	lea	rdi,[r14+HB_TS]
	mov	rsi,r12
	mov	ecx,23
	call	tls_seal
	add	r12,rax
	pop	rdx				; OUT loses what was sealed
	mov	ecx,[r13+C2_OUTLEN]
	sub	ecx,edx
	mov	[r13+C2_OUTLEN],ecx
	lea	rdi,[r14+HB_H2OUT]
	lea	rsi,[rdi+rdx]
	rep	movsb
	pop	rcx
	cmp	dword [r13+C2_OUTLEN],0
	je	.sealed_all
	dec	ecx
	jnz	.rec
.sealed_all:
	lea	rax,[r14+HB_TXC]
	sub	r12,rax
	mov	[r13+C2_CLEN],r12d
	mov	dword [r13+C2_COFF],0
	pop	r12
.cipher:
	mov	eax,[r13+C2_COFF]
	lea	rdi,[r14+HB_TXC+rax]
	mov	esi,[r13+C2_CLEN]
	sub	esi,eax
	jmp	h2_sock_send
.out:
	ret

; rdi = bytes, esi = length: to the client socket (c2 registers)
h2_sock_send:
	or	dword [r13+C2_FLAGS],C2F_SEND
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	push	rdi
	push	rsi
	mov	edi,OP_H2_SEND
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],esi
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	xor	ecx,ecx
	jmp	h_sqe_fd
.epoll:
	push	rdi
	push	rsi
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	pop	rdx
	pop	rsi
	mov	eax,SYS_write			; (the epoll worker's seccomp allows write)
	syscall
	cmp	rax,-EAGAIN
	je	.full
	jmp	h2_sent
.full:
	or	dword [r13+C2_FLAGS],C2F_EPOUT	; again when it is writable
	ret

; a send of the connection finished: rax = bytes or -errno (c2 registers,
; C2F_SEND still set)
h2_sent:
	and	dword [r13+C2_FLAGS],not (C2F_SEND or C2F_EPOUT)
	test	rax,rax
	js	.gone
	cmp	dword [r15+H_UTLS],0
	jne	.cipher
	mov	ecx,[r13+C2_OUTLEN]		; plain: what went out leaves OUT
	sub	ecx,eax
	mov	[r13+C2_OUTLEN],ecx
	lea	rdi,[r14+HB_H2OUT]
	lea	rsi,[rdi+rax]
	rep	movsb
	jmp	.more
.cipher:
	add	[r13+C2_COFF],eax
	mov	ecx,[r13+C2_COFF]
	cmp	ecx,[r13+C2_CLEN]
	jb	.more
	mov	dword [r13+C2_CLEN],0
.more:
	call	h2_unblock			; room again: the streams waiting
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.ep
	jmp	h2_pump
.ep:
	c2_regs					; epoll: keep writing until it would block
	jmp	h2_send
.gone:
	jmp	h2_drop

; the next receive, unless one is in flight (c2 registers)
h2_recv:
	test	dword [r13+C2_FLAGS],C2F_RECV
	jnz	.out
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.out				; epoll reads on events
	cmp	dword [r15+H_UTLS],0
	jne	.sealed
	mov	eax,[r13+C2_INLEN]
	lea	rdi,[r14+HB_H2IN+rax]
	mov	esi,H2_INCAP
	sub	esi,eax
	jmp	.post
.sealed:
	mov	eax,[r13+C2_RXC]
	lea	rdi,[r14+HB_RXC+rax]
	mov	esi,UTLS_RX_CAP
	sub	esi,eax
.post:
	test	esi,esi
	jz	.out				; full: processing makes room first
	or	dword [r13+C2_FLAGS],C2F_RECV
	push	rdi
	push	rsi
	mov	edi,OP_H2_RECV
	mov	esi,ebx
	call	sess_sqe
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],esi
	mov	dword [rax+SQE_OP_FLAGS],0
	xor	ecx,ecx
	jmp	h_sqe_fd
.out:
	ret

; rax = bytes received (into the place h2_recv chose) or <= 0: the
; connection's input grows; the frames are processed. c2 registers.
h2_received:
	; C2F_RECV stays set while the frames are processed: a stream woken
	; meanwhile may pump the connection, which must not post a receive
	; into IN while IN is being read and compacted
	test	rax,rax
	jle	h2_drop				; the client is gone
	push	rax
	mov	edi,ebx
	call	idle_touch
	pop	rax
	c2_regs
	cmp	dword [r15+H_UTLS],0
	jne	.records
	add	[r13+C2_INLEN],eax
	jmp	.process
.records:
	add	[r13+C2_RXC],eax
.open:
	; a record is opened only when its plaintext fits in IN
	mov	edx,[r13+C2_RXC]
	cmp	edx,5
	jb	.process
	movzx	ecx,word [r14+HB_RXC+3]
	rol	cx,8
	mov	eax,H2_INCAP
	sub	eax,[r13+C2_INLEN]
	cmp	ecx,eax
	ja	.process			; IN must drain first
	lea	rdi,[r14+HB_TS]
	lea	rsi,[r14+HB_RXC]
	call	tls_open
	cmp	eax,TH_MORE
	je	.process
	cmp	eax,TH_FAIL
	je	h2_drop
	push	rdx				; the record's length
	cmp	r8d,23
	jne	.not_data
	mov	eax,[r13+C2_INLEN]
	lea	rdi,[r14+HB_H2IN+rax]
	add	[r13+C2_INLEN],ecx
	rep	movsb
	jmp	.drop_rec
.not_data:
	cmp	r8d,21				; an alert: the client closes
	jne	.drop_rec			; (post-handshake messages: not taken)
	pop	rdx
	jmp	h2_drop
.drop_rec:
	pop	rdx
	mov	ecx,[r13+C2_RXC]
	sub	ecx,edx
	mov	[r13+C2_RXC],ecx
	lea	rdi,[r14+HB_RXC]
	lea	rsi,[rdi+rdx]
	rep	movsb
	jmp	.open
.process:
	call	h2_process
	c2_regs
	cmp	dword [r15+H_UTLS],0
	je	@f
	cmp	dword [r13+C2_RXC],0		; records that waited for room in IN
	je	@f
	mov	eax,[r13+C2_INLEN]
	cmp	eax,H2_INCAP / 2
	jae	@f
	xor	eax,eax
	jmp	.records
@@:
	and	dword [r13+C2_FLAGS],not C2F_RECV
	jmp	h2_pump

; the connection ends at once (the socket failed or the client left):
; its streams close, then it does.
h2_drop:
	c2_regs
	or	dword [r13+C2_FLAGS],C2F_CLOSING
	call	h2_streams_close
	mov	edi,ebx
	jmp	session_close

; ------------------------------------------------------- io_uring, epoll

; completions: ebx = session, r12d = generation, r14 = res
on_h2_recv:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	mov	rax,r14
	c2_regs
	jmp	h2_received
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

on_h2_send:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	mov	rax,r14
	c2_regs
	jmp	h2_sent
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; epoll: an event on a connection's socket, edi = events
h2_ep_event:
	push	rdi
	c2_regs
	pop	rdi
	test	edi,EPOLLOUT or EPOLLERR or EPOLLHUP
	jz	.read
	test	dword [r13+C2_FLAGS],C2F_EPOUT
	jz	.read
	push	rdi
	and	dword [r13+C2_FLAGS],not (C2F_EPOUT or C2F_SEND)
	call	h2_send
	pop	rdi
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	c2_regs
.read:
	test	edi,EPOLLIN or EPOLLRDHUP or EPOLLHUP or EPOLLERR
	jz	.out
.again:
	; read until the socket is empty (edge-triggered)
	cmp	dword [r15+H_UTLS],0
	jne	.sealed
	mov	eax,[r13+C2_INLEN]
	lea	rsi,[r14+HB_H2IN+rax]
	mov	edx,H2_INCAP
	sub	edx,eax
	jmp	.read_now
.sealed:
	mov	eax,[r13+C2_RXC]
	lea	rsi,[r14+HB_RXC+rax]
	mov	edx,UTLS_RX_CAP
	sub	edx,eax
.read_now:
	test	edx,edx
	jz	.out				; full: the streams drain it first
	push	rsi
	push	rdx
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	pop	rdx
	pop	rsi
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.drained
	cmp	rax,-EINTR
	je	.again
	call	h2_received
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	c2_regs
	jmp	.again
.drained:
	jmp	h2_pump
.out:
	ret

; ------------------------------------------------------------- frames

; Every whole frame in IN, in order. c2 registers (kept).
h2_process:
	push	r12
.next:
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.done
	test	dword [r13+C2_FLAGS],C2F_CLOSING
	jnz	.done
	mov	ecx,[r13+C2_INLEN]
	mov	eax,[r13+C2_INOFF]
	sub	ecx,eax				; bytes on hand
	lea	r12,[r14+HB_H2IN+rax]
	mov	edx,[r13+C2_PREF]
	cmp	edx,H2_PREFACE_LEN
	jae	.frame
	; the client's preface, a byte at a time as it comes
	test	ecx,ecx
	jz	.compact
	mov	al,[r12]
	lea	rsi,[h2_preface]
	cmp	al,[rsi+rdx]
	jne	.bad_preface
	inc	dword [r13+C2_PREF]
	inc	dword [r13+C2_INOFF]
	jmp	.next
.bad_preface:
	mov	edx,H2E_PROTOCOL
	call	h2_goaway
	jmp	.done
.frame:
	cmp	ecx,9
	jb	.compact
	movzx	eax,word [r12]			; 24-bit length
	xchg	al,ah
	shl	eax,8
	movzx	edx,byte [r12+2]
	or	eax,edx
	cmp	eax,16384			; our SETTINGS_MAX_FRAME_SIZE
	ja	.too_big
	lea	edx,[rax+9]
	cmp	ecx,edx
	jb	.compact			; not all here yet
	add	[r13+C2_INOFF],edx		; consumed whatever happens
	mov	esi,eax				; esi = length
	mov	eax,[r12+5]
	bswap	eax
	and	eax,0x7FFFFFFF			; eax = stream
	movzx	edx,byte [r12+3]		; edx = type
	movzx	ecx,byte [r12+4]		; ecx = flags
	add	r12,9				; r12 = payload
	call	h2_frame_in
	jmp	.next
.too_big:
	mov	edx,H2E_FRAME_SIZE
	call	h2_goaway
	jmp	.done
.compact:
	mov	eax,[r13+C2_INOFF]		; what is left goes to the front
	test	eax,eax
	jz	.done
	mov	ecx,[r13+C2_INLEN]
	sub	ecx,eax
	mov	[r13+C2_INLEN],ecx
	mov	dword [r13+C2_INOFF],0
	lea	rdi,[r14+HB_H2IN]
	lea	rsi,[rdi+rax]
	rep	movsb
.done:
	pop	r12
	ret

; One frame: r12 = payload, esi = length, eax = stream, edx = type, ecx =
; flags. c2 registers (r12 may change).
h2_frame_in:
	; frames that ask work and carry nothing count against a budget:
	; PRIORITY, SETTINGS, PING, WINDOW_UPDATE, empty DATA without END_STREAM
	cmp	edx,H2F_PRIORITY
	je	.cheap
	cmp	edx,H2F_SETTINGS
	je	.cheap
	cmp	edx,H2F_PING
	je	.cheap
	cmp	edx,H2F_WINDOW
	je	.cheap
	cmp	edx,H2F_DATA
	jne	.counted
	test	esi,esi
	jnz	.counted
	test	ecx,H2_END_STREAM
	jnz	.counted
.cheap:
	push	rax
	mov	eax,[g_tick]
	cmp	eax,[r13+C2_CHEAPT]
	je	@f
	mov	[r13+C2_CHEAPT],eax
	mov	dword [r13+C2_CHEAPN],0
@@:
	pop	rax
	inc	dword [r13+C2_CHEAPN]
	cmp	dword [r13+C2_CHEAPN],H2_CHEAP_BUDGET
	ja	.calm
.counted:
	cmp	dword [r13+C2_HBSID],0		; a header block must go on uninterrupted
	je	@f
	cmp	edx,H2F_CONT
	jne	.protocol
	cmp	eax,[r13+C2_HBSID]
	jne	.protocol
@@:
	cmp	edx,H2F_DATA
	je	h2_in_data
	cmp	edx,H2F_HEADERS
	je	h2_in_headers
	cmp	edx,H2F_CONT
	je	h2_in_cont
	cmp	edx,H2F_PRIORITY
	je	.priority
	cmp	edx,H2F_RST
	je	h2_in_rst
	cmp	edx,H2F_SETTINGS
	je	h2_in_settings
	cmp	edx,H2F_PING
	je	h2_in_ping
	cmp	edx,H2F_GOAWAY
	je	.goaway
	cmp	edx,H2F_WINDOW
	je	h2_in_window
	cmp	edx,H2F_PUSH
	je	.protocol			; a client never pushes
	ret					; unknown types are ignored
.priority:
	test	eax,eax
	jz	.protocol
	cmp	esi,5
	je	.priority_ok
	mov	esi,eax				; a stream error (RFC 9113 6.3)
	mov	edx,H2E_FRAME_SIZE
	push	rsi
	call	h2_find
	pop	rsi
	jmp	h2_stream_reset
.priority_ok:
	mov	edx,[r12]			; a stream cannot depend on itself
	bswap	edx
	and	edx,0x7FFFFFFF
	cmp	edx,eax
	jne	@f
	mov	esi,eax
	mov	edx,H2E_PROTOCOL
	push	rsi
	call	h2_find
	pop	rsi
	jmp	h2_stream_reset
@@:
	ret
.calm:
	mov	edx,H2E_CALM
	jmp	h2_goaway
.goaway:
	test	eax,eax
	jnz	.protocol
	cmp	esi,8
	jb	.frame_size
	or	dword [r13+C2_FLAGS],C2F_PEERGONE
	ret
.protocol:
	mov	edx,H2E_PROTOCOL
	jmp	h2_goaway
.frame_size:
	mov	edx,H2E_FRAME_SIZE
	jmp	h2_goaway

; strips the padding of a PADDED frame: r12 = payload, esi = length ->
; r12/esi the content. CF when the padding does not fit (PROTOCOL_ERROR).
h2_unpad:
	test	ecx,H2_PADDED
	jz	.ok
	test	esi,esi
	jz	.bad
	movzx	edi,byte [r12]
	inc	r12
	dec	esi
	cmp	edi,esi
	ja	.bad
	sub	esi,edi
.ok:
	clc
	ret
.bad:
	stc
	ret

; eax = stream: edi = its session or NIL; r8 = its table entry. A stream
; sits in slot (id / 2) mod H2_MAXS when that was free (nearly always:
; ids are sequential, at most 100 are open), else anywhere.
h2_find:
	mov	r8d,eax
	shr	r8d,1
	and	r8d,H2_MAXS - 1
	shl	r8d,4				; * S2_SIZE
	lea	r8,[r13+C2_ST+r8]
	cmp	[r8+S2_SID],eax
	jne	.scan
	mov	edi,[r8+S2_SESS]
	ret
.scan:
	lea	r8,[r13+C2_ST]
	mov	ecx,H2_MAXS
.next:
	cmp	[r8+S2_SID],eax
	jne	.skip
	mov	edi,[r8+S2_SESS]
	ret
.skip:
	add	r8,S2_SIZE
	dec	ecx
	jnz	.next
	mov	edi,NIL
	ret

h2_in_settings:
	test	eax,eax
	jnz	h2_frame_in.protocol
	test	ecx,H2_ACK
	jz	.values
	test	esi,esi
	jnz	h2_frame_in.frame_size
	ret
.values:
	mov	eax,esi
	xor	edx,edx
	mov	edi,6
	div	edi
	test	edx,edx
	jnz	h2_frame_in.frame_size
.setting:
	test	esi,esi
	jz	.ack
	movzx	eax,word [r12]
	xchg	al,ah
	mov	edx,[r12+2]
	bswap	edx
	add	r12,6
	sub	esi,6
	cmp	eax,2				; ENABLE_PUSH
	jne	@f
	cmp	edx,1
	ja	h2_frame_in.protocol
	jmp	.setting
@@:
	cmp	eax,4				; INITIAL_WINDOW_SIZE
	jne	@f
	cmp	edx,0x7FFFFFFF
	ja	.flow
	mov	ecx,edx				; every stream's window moves by the difference
	sub	ecx,[r13+C2_PINIT]
	mov	[r13+C2_PINIT],edx
	call	h2_windows_shift
	jc	.flow
	jmp	.setting
@@:
	cmp	eax,5				; MAX_FRAME_SIZE
	jne	.setting
	cmp	edx,16384
	jb	h2_frame_in.protocol
	cmp	edx,(1 shl 24) - 1
	ja	h2_frame_in.protocol
	mov	[r13+C2_PMAXF],edx
	jmp	.setting
.ack:
	call	h2_room
	cmp	eax,9 + H2_RESERVE
	jb	.calm
	xor	esi,esi
	mov	dl,H2F_SETTINGS
	mov	cl,H2_ACK
	xor	r8d,r8d
	call	h2_frame
	jmp	h2_unblock
.flow:
	mov	edx,H2E_FLOW
	jmp	h2_goaway
.calm:
	mov	edx,H2E_CALM			; it does not read what we send
	jmp	h2_goaway

; ecx = difference of the initial window: every stream's send window
; moves by it. CF when one would pass 2^31 - 1.
h2_windows_shift:
	push	r12
	lea	r12,[r13+C2_ST]
	mov	r9d,H2_MAXS
.next:
	cmp	dword [r12+S2_SID],0
	je	.skip
	mov	edi,[r12+S2_SESS]
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	movsxd	rdx,dword [rax+H_H2SWIN]
	movsxd	r8,ecx
	add	rdx,r8
	cmp	rdx,0x7FFFFFFF
	jg	.over
	mov	[rax+H_H2SWIN],edx
.skip:
	add	r12,S2_SIZE
	dec	r9d
	jnz	.next
	pop	r12
	clc
	ret
.over:
	pop	r12
	stc
	ret

h2_in_ping:
	test	eax,eax
	jnz	h2_frame_in.protocol
	cmp	esi,8
	jne	h2_frame_in.frame_size
	test	ecx,H2_ACK
	jnz	.out
	call	h2_room
	cmp	eax,17 + H2_RESERVE
	jb	h2_in_settings.calm		; pings it does not read the answers to
	mov	esi,8
	mov	dl,H2F_PING
	mov	cl,H2_ACK
	xor	r8d,r8d
	call	h2_frame
	mov	rax,[r12]
	mov	[rdi],rax
.out:
	ret

h2_in_window:
	cmp	esi,4
	jne	h2_frame_in.frame_size
	mov	edx,[r12]
	bswap	edx
	and	edx,0x7FFFFFFF
	test	eax,eax
	jnz	.stream
	test	edx,edx
	jz	h2_frame_in.protocol
	movsxd	rax,dword [r13+C2_SWIN]
	add	rax,rdx
	cmp	rax,0x7FFFFFFF
	jg	h2_in_settings.flow
	mov	[r13+C2_SWIN],eax
	jmp	h2_unblock
.stream:
	cmp	eax,[r13+C2_LASTSID]
	ja	h2_frame_in.protocol		; an idle stream
	push	rdx
	push	rax
	call	h2_find
	pop	rsi				; the stream id
	pop	rdx
	cmp	edi,NIL
	je	.out				; closed already: ignored
	test	edx,edx
	jz	.reset
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	movsxd	rcx,dword [rax+H_H2SWIN]
	add	rcx,rdx
	cmp	rcx,0x7FFFFFFF
	jg	.flow
	mov	[rax+H_H2SWIN],ecx
	jmp	h2_unblock
.reset:
	mov	edx,H2E_PROTOCOL
	jmp	h2_stream_reset
.flow:
	mov	edx,H2E_FLOW
	jmp	h2_stream_reset
.out:
	ret

h2_in_rst:
	test	eax,eax
	jz	h2_frame_in.protocol
	cmp	esi,4
	jne	h2_frame_in.frame_size
	cmp	eax,[r13+C2_LASTSID]
	ja	h2_frame_in.protocol		; an idle stream
	call	h2_rst_count
	jc	.calm
	push	rax
	call	h2_find
	pop	rsi
	cmp	edi,NIL
	je	.out
	mov	eax,edi				; the client cancelled it: nothing back
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	or	dword [rax+H_H2F],S2F_RST or S2F_END
	call	h2_stream_abort
.out:
	ret
.calm:
	mov	edx,H2E_CALM			; rapid reset
	jmp	h2_goaway

; counts a reset the client caused; CF past the budget for this second
h2_rst_count:
	mov	ecx,[g_tick]
	cmp	ecx,[r13+C2_RSTT]
	je	@f
	mov	[r13+C2_RSTT],ecx
	mov	dword [r13+C2_RSTN],0
@@:
	inc	dword [r13+C2_RSTN]
	cmp	dword [r13+C2_RSTN],H2_RST_BUDGET
	ja	.over
	clc
	ret
.over:
	stc
	ret

h2_in_data:
	test	eax,eax
	jz	h2_frame_in.protocol
	; the whole frame, padding included, counts against the windows
	mov	edx,[r13+C2_RWIN]
	sub	edx,esi
	js	h2_in_settings.flow
	mov	[r13+C2_RWIN],edx
	add	[r13+C2_ROWED],esi
	mov	r9d,esi				; the frame's length
	push	rax
	push	r9
	call	h2_unpad
	pop	r9
	pop	rax
	jc	h2_frame_in.protocol
	push	r9
	push	rcx
	push	rsi
	push	rax
	call	h2_find
	pop	rax
	pop	rsi
	pop	rcx
	pop	rdx				; the frame's length
	cmp	edi,NIL
	je	.closed
	call	h2_stream_data
	jmp	h2_conn_credit
.closed:
	cmp	eax,[r13+C2_LASTSID]
	ja	h2_frame_in.protocol		; an idle stream
	mov	esi,eax
	mov	edx,H2E_CLOSED
	call	h2_out_rst
	jmp	h2_conn_credit

; connection credit given back in batches
h2_conn_credit:
	cmp	dword [r13+C2_ROWED],H2_CONN_WIN / 4
	jb	.out
	xor	esi,esi
	mov	edx,[r13+C2_ROWED]
	call	h2_out_window
	jc	.out
	mov	eax,[r13+C2_ROWED]
	add	[r13+C2_RWIN],eax
	mov	dword [r13+C2_ROWED],0
.out:
	ret

; DATA for a stream: edi = its session, eax = stream id, r12 = content,
; esi = its length, edx = the frame's length (padding included), ecx =
; flags. Appended to its request queue (chunk-framed when it has no
; content-length); a receive parked there is served.
h2_stream_data:
	push	rbx
	push	rbp
	push	r12
	push	r14
	push	r15
	mov	ebp,eax				; stream id
	mov	ebx,edi
	h_rec
	mov	r14,[r15+H_BUF]
	add	r14,HB_H2Q			; r14 = the queue
	test	dword [r15+H_H2F],S2F_RST
	jnz	.done				; reset: dropped
	cmp	dword [r14+Q_ENDED],0
	jne	.closed				; DATA after END_STREAM
	sub	[r14+Q_RWIN],edx
	js	.flow
	sub	edx,esi				; padding: credited back at once
	add	[r14+Q_PEND],edx
	add	[r14+Q_GOT],rsi
	mov	r8,[r14+Q_CLEN]
	cmp	r8,-1
	je	@f
	cmp	[r14+Q_GOT],r8
	ja	.malformed			; more than its content-length
@@:
	; room: content, chunk framing, the last chunk
	push	rcx
	call	h2q_compact
	pop	rcx
	mov	eax,[r14+Q_LEN]
	lea	eax,[rax+rsi+32]
	cmp	eax,Q_CAP
	ja	.flow				; beyond what its window allows
	add	[r14+Q_PEND],esi
	test	esi,esi
	jz	.end
	cmp	dword [r14+Q_CHUNKED],0
	je	.raw
	push	rcx
	push	rsi
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	mov	eax,esi
	call	fmt_hex32
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r14+Q_DATA]
	sub	rdi,rax
	mov	[r14+Q_LEN],edi
	pop	rsi
	pop	rcx
.raw:
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	add	[r14+Q_LEN],esi
	push	rcx
	mov	rcx,rsi
	mov	rsi,r12
	rep	movsb
	pop	rcx
	cmp	dword [r14+Q_CHUNKED],0
	je	.end
	mov	word [rdi],0x0A0D
	add	dword [r14+Q_LEN],2
.end:
	test	ecx,H2_END_STREAM
	jz	.serve
	mov	dword [r14+Q_ENDED],1
	mov	r8,[r14+Q_CLEN]
	cmp	r8,-1
	je	@f
	cmp	[r14+Q_GOT],r8
	jne	.malformed			; less than its content-length
@@:
	cmp	dword [r14+Q_CHUNKED],0
	je	.serve
	mov	eax,[r14+Q_LEN]			; the last chunk: "0\r\n\r\n"
	mov	dword [r14+Q_DATA+rax],0x0D0A0D30
	mov	byte [r14+Q_DATA+rax+4],10
	add	dword [r14+Q_LEN],5
.serve:
	call	h2q_serve
.done:
	pop	r15
	pop	r14
	pop	r12
	pop	rbp
	pop	rbx
	ret
.closed:
	mov	edx,H2E_CLOSED
	jmp	.reset
.flow:
	mov	edx,H2E_FLOW
	jmp	.reset
.malformed:
	mov	edx,H2E_PROTOCOL
.reset:
	mov	esi,ebp
	pop	r15
	pop	r14
	pop	r12
	pop	rbp
	pop	rbx
	jmp	h2_stream_reset

; ebx = stream, r14 = its queue: what was read leaves the front
h2q_compact:
	mov	eax,[r14+Q_OFF]
	test	eax,eax
	jz	.out
	mov	ecx,[r14+Q_LEN]
	sub	ecx,eax
	mov	[r14+Q_LEN],ecx
	mov	dword [r14+Q_OFF],0
	lea	rdi,[r14+Q_DATA]
	lea	rsi,[rdi+rax]
	rep	movsb
.out:
	ret

; ebx = stream, r15 = its record, r14 = its queue: a receive parked there
; gets what the queue holds
h2q_serve:
	cmp	dword [r14+Q_WAIT],0
	je	.out
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	.give
	cmp	dword [r14+Q_ENDED],0
	je	.out
.give:
	mov	dword [r14+Q_WAIT],0
	mov	rdi,[r14+Q_DST]
	mov	esi,[r14+Q_ROOM]
	jmp	h2s_take
.out:
	ret

; edi = stream session, esi = stream id, edx = error: RST_STREAM it and
; end its exchange
h2_stream_reset:
	push	rdi
	call	h2_out_rst
	pop	rdi
	cmp	edi,NIL
	je	.out
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	or	dword [rax+H_H2F],S2F_RST or S2F_END
	jmp	h2_stream_abort
.out:
	ret

; edi = stream session: its exchange stops (the connection code goes on)
h2_stream_abort:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	session_close
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------- header blocks

h2_in_headers:
	test	eax,eax
	jz	h2_frame_in.protocol
	test	eax,1
	jz	h2_frame_in.protocol		; client streams are odd
	push	rax
	call	h2_unpad
	pop	rax
	jc	h2_frame_in.protocol
	test	ecx,H2_PRIO
	jz	@f
	cmp	esi,5
	jb	h2_frame_in.frame_size
	mov	edx,[r12]			; a stream cannot depend on itself
	bswap	edx
	and	edx,0x7FFFFFFF
	cmp	edx,eax
	je	.self
	add	r12,5
	sub	esi,5
@@:
	mov	dword [r13+C2_HBLEN],0
	mov	dword [r13+C2_HBN],0
	mov	edx,ecx
	and	edx,H2_END_STREAM
	mov	[r13+C2_HBEND],edx
	call	h2_hb_add
	jc	.calm
	test	ecx,H2_END_HEADERS
	jnz	h2_block_done
	mov	[r13+C2_HBSID],eax
	ret
.self:
	mov	esi,eax
	mov	edx,H2E_PROTOCOL
	mov	edi,NIL
	jmp	h2_stream_reset
.calm:
	mov	edx,H2E_CALM
	jmp	h2_goaway

h2_in_cont:
	cmp	dword [r13+C2_HBSID],0
	je	h2_frame_in.protocol		; no header block to continue
	inc	dword [r13+C2_HBN]
	cmp	dword [r13+C2_HBN],H2_CONT_MAX
	ja	h2_in_headers.calm		; a CONTINUATION flood
	call	h2_hb_add
	jc	h2_in_headers.calm
	test	ecx,H2_END_HEADERS
	jz	.out
	mov	dword [r13+C2_HBSID],0
	jmp	h2_block_done
.out:
	ret

; r12/esi = a fragment: appended to the header block. CF when the block
; would be larger than we take. Keeps eax, ecx.
h2_hb_add:
	mov	edx,[r13+C2_HBLEN]
	lea	edi,[rdx+rsi]
	cmp	edi,H2_HBCAP
	ja	.big
	mov	[r13+C2_HBLEN],edi
	push	rcx
	lea	rdi,[r14+HB_H2HB+rdx]
	mov	ecx,esi
	mov	rsi,r12
	rep	movsb
	pop	rcx
	clc
	ret
.big:
	stc
	ret

; eax = stream: its header block is complete. Decoded (always, for the
; table's sake); a new stream, or trailers of an open one.
h2_block_done:
	push	r12
	mov	r12d,eax			; the stream id
	sub	rsp,HPO_SIZE
	lea	rax,[r14+HB_H2FLD]		; where it decodes to
	mov	[rsp+HPO_FIELDS],rax
	mov	dword [rsp+HPO_FMAX],H2_MAXFIELDS
	lea	rax,[r14+HB_H2STR]
	mov	[rsp+HPO_BUF],rax
	mov	dword [rsp+HPO_BCAP],H2_STRCAP
	lea	rdi,[r14+HB_H2HP]
	lea	rsi,[r14+HB_H2HB]
	mov	edx,[r13+C2_HBLEN]
	mov	rcx,rsp
	call	hpack_decode
	mov	ecx,[rsp+HPO_COUNT]
	add	rsp,HPO_SIZE
	cmp	eax,HPE_COMPRESSION
	je	.compression
	test	eax,eax
	jnz	.calm				; larger than we take (the table is
						; mid-block: the connection cannot go on)
	push	rcx
	mov	eax,r12d
	call	h2_find
	pop	rcx
	cmp	edi,NIL
	jne	.trailers
	cmp	r12d,[r13+C2_LASTSID]
	jbe	.closed_stream
	mov	[r13+C2_LASTSID],r12d
	test	dword [r13+C2_FLAGS],C2F_PEERGONE
	jnz	.refuse
	cmp	dword [r13+C2_NSTR],H2_MAX_OPEN
	jae	.refuse
	mov	edi,ecx				; how many fields
	mov	esi,r12d
	call	h2_stream_new
	jmp	.out
.trailers:
	; trailers end the request (their fields are not passed on), and carry
	; no pseudo-field
	cmp	dword [r13+C2_HBEND],0
	je	.malformed
	push	rdi
	xor	r8d,r8d
.trailer_field:
	cmp	r8d,ecx
	jae	.trailers_ok
	imul	eax,r8d,HP_SIZE
	mov	rax,[r14+HB_H2FLD+rax+HP_NAME]
	inc	r8d
	cmp	byte [rax],':'
	jne	.trailer_field
	pop	rdi
	jmp	.malformed
.trailers_ok:
	pop	rdi
	mov	eax,r12d
	xor	esi,esi
	xor	edx,edx
	mov	ecx,H2_END_STREAM
	call	h2_stream_data			; edi = the stream's session
	jmp	.out
.malformed:
	mov	esi,r12d
	mov	edx,H2E_PROTOCOL
	call	h2_stream_reset
	jmp	.out
.closed_stream:
	mov	edx,H2E_PROTOCOL		; not above the last stream it opened
	call	h2_goaway
	jmp	.out
.refuse:
	mov	esi,r12d
	mov	edx,H2E_REFUSED
	call	h2_out_rst
	jmp	.out
.compression:
	mov	edx,H2E_COMPRESSION
	call	h2_goaway
	jmp	.out
.calm:
	mov	edx,H2E_CALM
	call	h2_goaway
.out:
	pop	r12
	ret

; ------------------------------------------------------------ streams

; A new stream: edi = its decoded fields (HB_H2FLD), esi = its id. The
; request is checked (RFC 9113 8.3), written as an HTTP/1.1 head into a
; new session's queue, and that session starts its exchange. A malformed
; request is reset; no session left is REFUSED_STREAM. c2 registers.
H2N_FIELDS	:= 0
H2N_SID		:= 4
H2N_METHOD	:= 8				; q, then its length at +16 (for the pseudo fields)
H2N_PATH	:= 24
H2N_AUTH	:= 40
H2N_SCHEME	:= 56
H2N_SESS	:= 72
H2N_HAVEHOST	:= 76
H2N_CLEN	:= 80				; q
H2N_SIZE	:= 96
h2_stream_new:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,H2N_SIZE
	mov	[rsp+H2N_FIELDS],edi
	mov	[rsp+H2N_SID],esi
	xor	eax,eax
	mov	[rsp+H2N_METHOD],rax
	mov	[rsp+H2N_PATH],rax
	mov	[rsp+H2N_AUTH],rax
	mov	[rsp+H2N_SCHEME],rax
	mov	[rsp+H2N_HAVEHOST],eax
	mov	qword [rsp+H2N_CLEN],-1
	; the fields: pseudo ones first, each once, names lower case, no
	; connection-specific ones, values without CR, LF or NUL
	xor	ebp,ebp				; index
	xor	r12d,r12d			; 1 once a regular field was seen
.check:
	cmp	ebp,[rsp+H2N_FIELDS]
	jae	.checked
	imul	eax,ebp,HP_SIZE
	lea	r8,[r14+HB_H2FLD+rax]
	inc	ebp
	mov	rsi,[r8+HP_VALUE]		; the value
	mov	ecx,[r8+HP_VLEN]
@@:
	test	ecx,ecx
	jz	@f
	dec	ecx
	movzx	eax,byte [rsi+rcx]
	cmp	al,13
	je	.malformed
	cmp	al,10
	je	.malformed
	test	al,al
	jz	.malformed
	jmp	@b
@@:
	mov	rsi,[r8+HP_NAME]
	mov	ecx,[r8+HP_NLEN]
	test	ecx,ecx
	jz	.malformed
	cmp	byte [rsi],':'
	je	.pseudo
	mov	r12d,1
	xor	edx,edx				; the name: lower-case token characters
@@:
	movzx	eax,byte [rsi+rdx]
	cmp	al,'A'
	jb	.namechar
	cmp	al,'Z'
	jbe	.malformed
.namechar:
	cmp	al,' '
	jbe	.malformed
	cmp	al,':'
	je	.malformed
	cmp	al,127
	jae	.malformed
	inc	edx
	cmp	edx,ecx
	jb	@b
	; connection-specific fields are malformed in HTTP/2
	push	r8
	mov	rdi,rsi
	mov	esi,ecx
	lea	rdx,[.n_conn]
	call	h2_name_in
	pop	r8
	jnc	.malformed
	mov	rdi,[r8+HP_NAME]
	mov	esi,[r8+HP_NLEN]
	cmp	esi,2
	jne	@f
	cmp	word [rdi],'te'
	jne	@f
	cmp	dword [r8+HP_VLEN],8		; te: only "trailers"
	jne	.malformed
	mov	rax,[r8+HP_VALUE]
	mov	rax,[rax]
	mov	rdx,'trailers'
	cmp	rax,rdx
	jne	.malformed
@@:
	cmp	esi,4
	jne	@f
	cmp	dword [rdi],'host'
	jne	@f
	mov	dword [rsp+H2N_HAVEHOST],1
@@:
	cmp	esi,14
	jne	.check
	mov	rax,'content-'
	cmp	[rdi],rax
	jne	.check
	cmp	dword [rdi+8],'leng'
	jne	.check
	cmp	word [rdi+12],'th'
	jne	.check
	cmp	qword [rsp+H2N_CLEN],-1
	jne	.malformed			; twice
	mov	rdi,[r8+HP_VALUE]
	mov	esi,[r8+HP_VLEN]
	call	parse_decimal
	jc	.malformed
	mov	[rsp+H2N_CLEN],rax
	jmp	.check
.pseudo:
	test	r12d,r12d
	jnz	.malformed			; after a regular field
	xor	edi,edi
	cmp	ecx,7
	jne	@f
	cmp	dword [rsi],':met'
	jne	.not_method
	cmp	word [rsi+4],'ho'
	jne	.not_method
	cmp	byte [rsi+6],'d'
	jne	.not_method
	mov	edi,H2N_METHOD
	jmp	.pseudo_set
.not_method:
	cmp	dword [rsi],':sch'
	jne	.malformed
	cmp	word [rsi+4],'em'
	jne	.malformed
	cmp	byte [rsi+6],'e'
	jne	.malformed
	mov	edi,H2N_SCHEME
	jmp	.pseudo_set
@@:
	cmp	ecx,5
	jne	@f
	cmp	dword [rsi],':pat'
	jne	.malformed
	cmp	byte [rsi+4],'h'
	jne	.malformed
	mov	edi,H2N_PATH
	jmp	.pseudo_set
@@:
	cmp	ecx,10
	jne	.malformed			; :status or unknown
	mov	rax,':authori'
	cmp	[rsi],rax
	jne	.malformed
	cmp	word [rsi+8],'ty'
	jne	.malformed
	mov	edi,H2N_AUTH
.pseudo_set:
	cmp	qword [rsp+rdi],0
	jne	.malformed			; twice
	mov	rax,[r8+HP_VALUE]
	mov	[rsp+rdi],rax
	mov	eax,[r8+HP_VLEN]
	mov	[rsp+rdi+8],rax
	jmp	.check
.checked:
	cmp	qword [rsp+H2N_METHOD],0
	je	.malformed
	cmp	qword [rsp+H2N_SCHEME],0
	je	.malformed
	cmp	qword [rsp+H2N_PATH],0
	je	.malformed
	cmp	qword [rsp+H2N_PATH+8],0
	je	.malformed			; an empty :path
	mov	rax,[rsp+H2N_METHOD]		; CONNECT (and its extended form) not yet
	cmp	qword [rsp+H2N_METHOD+8],7
	jne	@f
	cmp	dword [rax],'CONN'
	jne	@f
	cmp	word [rax+4],'EC'
	jne	@f
	cmp	byte [rax+6],'T'
	je	.malformed
@@:
	; a session for it
	call	session_alloc
	cmp	eax,NIL
	je	.refused
	mov	[rsp+H2N_SESS],eax
	call	session_ptr			; the connection's
	mov	r12,rax
	mov	ecx,[r12+S_LST]
	inc	dword [g_ls_active+rcx*4]
	inc	dword [g_active]
	mov	edi,[rsp+H2N_SESS]
	push	rbx
	mov	ebx,edi
	call	session_ptr
	pop	rbx
	mov	dword [rax+S_STATE],ST_OPEN
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_H2S
	mov	dword [rax+S_CLIENT],-1
	mov	ecx,[r12+S_LST]
	mov	[rax+S_LST],ecx
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	mov	ecx,[r12+S_POOL]
	mov	[rax+S_POOL],ecx
	mov	r9d,[r12+S_GEN]			; the connection's generation
	push	r9
	push	rbx
	mov	ebx,[rsp+16+H2N_SESS]
	mov	edi,ebx
	call	idle_append
	call	peer_ptr			; the client's address, as the connection's
	mov	rdi,rax
	mov	ebx,[rsp]
	call	peer_ptr
	mov	rsi,rax
	mov	ecx,P_SIZE
	rep	movsb
	pop	rbx				; the connection
	pop	r9
	; the stream's record
	mov	r10,r15				; the connection's record
	mov	edi,[rsp+H2N_SESS]
	call	h2_ptrs				; rax = record, rdx = buffers
	mov	r15,rax
	mov	eax,[rsp+H2N_SESS]
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	[r15+H_FLAGS],eax
	mov	[r15+H_UTLS],eax
	mov	[r15+H_EPOP],eax		; (H_READY stays: the slot may still be queued)
	mov	rax,[r10+H_SNICERT]
	mov	[r15+H_SNICERT],rax
	mov	[r15+H_H2C],ebx
	mov	[r15+H_H2CG],r9d
	mov	eax,[rsp+H2N_SID]
	mov	[r15+H_H2SID],eax
	mov	eax,[r13+C2_PINIT]
	mov	[r15+H_H2SWIN],eax
	mov	dword [r15+H_H2F],0
	mov	dword [r15+H_H2PL],0
	mov	dword [r15+H_H2BL],0
	; its queue: the request head
	mov	rbp,[r15+H_BUF]
	add	rbp,HB_H2Q
	xor	eax,eax
	mov	[rbp+Q_LEN],eax
	mov	[rbp+Q_OFF],eax
	mov	[rbp+Q_WAIT],eax
	mov	[rbp+Q_PEND],eax
	mov	dword [rbp+Q_RWIN],H2_INIT_WIN
	mov	eax,[r13+C2_HBEND]
	mov	[rbp+Q_ENDED],eax
	mov	dword [rbp+Q_CHUNKED],0
	mov	rax,[rsp+H2N_CLEN]
	mov	[rbp+Q_CLEN],rax
	mov	qword [rbp+Q_GOT],0
	lea	rdi,[rbp+Q_DATA]
	lea	r11,[rbp+Q_DATA+H_IN_CAP-8]	; a head must fit IN
	mov	rsi,[rsp+H2N_METHOD]
	mov	rcx,[rsp+H2N_METHOD+8]
	call	.put
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[rsp+H2N_PATH]
	mov	rcx,[rsp+H2N_PATH+8]
	call	.put
	lea	rsi,[.h11]
	mov	ecx,.h11.len
	call	.put
	cmp	qword [rsp+H2N_AUTH],0		; :authority is the Host
	je	.fields
	lea	rsi,[.host]
	mov	ecx,.host.len
	call	.put
	mov	rsi,[rsp+H2N_AUTH]
	mov	rcx,[rsp+H2N_AUTH+8]
	call	.put
	mov	word [rdi],0x0A0D
	add	rdi,2
.fields:
	xor	r12d,r12d			; cookies seen
	xor	r8d,r8d
.field:
	cmp	r8d,[rsp+H2N_FIELDS]
	jae	.cookies
	imul	eax,r8d,HP_SIZE
	lea	r9,[r14+HB_H2FLD+rax]
	inc	r8d
	mov	rsi,[r9+HP_NAME]
	mov	ecx,[r9+HP_NLEN]
	cmp	byte [rsi],':'
	je	.field
	cmp	ecx,4				; host, when :authority says it
	jne	@f
	cmp	dword [rsi],'host'
	jne	@f
	cmp	qword [rsp+H2N_AUTH],0
	jne	.field
@@:
	cmp	ecx,6				; expect: nothing to wait for here
	jne	@f
	cmp	dword [rsi],'expe'
	jne	@f
	cmp	word [rsi+4],'ct'
	je	.field
@@:
	cmp	ecx,6				; cookies go out joined, below
	jne	@f
	cmp	dword [rsi],'cook'
	jne	@f
	cmp	word [rsi+4],'ie'
	jne	@f
	inc	r12d
	jmp	.field
@@:
	push	r8
	call	.put
	pop	r8
	mov	word [rdi],0x203A		; ": "
	add	rdi,2
	mov	rsi,[r9+HP_VALUE]
	mov	ecx,[r9+HP_VLEN]
	push	r8
	call	.put
	pop	r8
	mov	word [rdi],0x0A0D
	add	rdi,2
	jmp	.field
.cookies:
	test	r12d,r12d
	jz	.framing
	lea	rsi,[.cookie]
	mov	ecx,.cookie.len
	call	.put
	xor	r8d,r8d
	xor	r10d,r10d			; cookies written
.cookie_next:
	cmp	r8d,[rsp+H2N_FIELDS]
	jae	.cookie_end
	imul	eax,r8d,HP_SIZE
	lea	r9,[r14+HB_H2FLD+rax]
	inc	r8d
	mov	rsi,[r9+HP_NAME]
	cmp	dword [r9+HP_NLEN],6
	jne	.cookie_next
	cmp	dword [rsi],'cook'
	jne	.cookie_next
	test	r10d,r10d
	jz	@f
	mov	word [rdi],0x203B		; "; "
	add	rdi,2
@@:
	inc	r10d
	mov	rsi,[r9+HP_VALUE]
	mov	ecx,[r9+HP_VLEN]
	push	r8
	push	r10
	call	.put
	pop	r10
	pop	r8
	jmp	.cookie_next
.cookie_end:
	mov	word [rdi],0x0A0D
	add	rdi,2
.framing:
	cmp	dword [rbp+Q_ENDED],0
	jne	.end_head			; no body
	cmp	qword [rbp+Q_CLEN],-1
	jne	.end_head
	lea	rsi,[.chunked]			; a body of unknown length
	mov	ecx,.chunked.len
	call	.put
	mov	dword [rbp+Q_CHUNKED],1
.end_head:
	cmp	rdi,r11
	ja	.too_large
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[rbp+Q_DATA]
	sub	rdi,rax
	mov	[rbp+Q_LEN],edi
	; into the table (its home slot when free), and its exchange starts
	mov	r8d,[rsp+H2N_SID]
	shr	r8d,1
	and	r8d,H2_MAXS - 1
	shl	r8d,4
	lea	r8,[r13+C2_ST+r8]
	cmp	dword [r8+S2_SID],0
	je	.slot_found
	lea	r8,[r13+C2_ST]
	mov	ecx,H2_MAXS
.slot:
	cmp	dword [r8+S2_SID],0
	je	.slot_found
	add	r8,S2_SIZE
	dec	ecx
	jnz	.slot
	jmp	.drop_session			; (H2_MAXS > H2_MAX_OPEN: cannot happen)
.slot_found:
	mov	eax,[rsp+H2N_SID]
	mov	[r8+S2_SID],eax
	mov	eax,[rsp+H2N_SESS]
	mov	[r8+S2_SESS],eax
	push	rbx
	mov	ebx,eax
	call	session_ptr
	pop	rbx
	mov	ecx,[rax+S_GEN]
	mov	[r8+S2_GEN],ecx
	inc	dword [r13+C2_NSTR]
	mov	ebx,[rsp+H2N_SESS]
	call	http_next_request		; reads its head from the queue
	jmp	.out
.too_large:
	; the head would not fit IN: 431 the honest way would need the
	; exchange; refuse the stream
	jmp	.drop_session
.drop_session:
	mov	edi,[rsp+H2N_SESS]
	call	session_close
	mov	esi,[rsp+H2N_SID]
	mov	edx,H2E_REFUSED
	call	h2_out_rst
	jmp	.out
.refused:
	mov	esi,[rsp+H2N_SID]
	mov	edx,H2E_REFUSED
	call	h2_out_rst
	jmp	.out
.malformed:
	mov	esi,[rsp+H2N_SID]
	mov	edx,H2E_PROTOCOL
	call	h2_out_rst
.out:
	add	rsp,H2N_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; rsi/rcx appended at rdi, stopping at r11 (the caller checks rdi > r11)
.put:
	mov	rax,r11
	sub	rax,rdi
	jbe	.put_none
	cmp	rcx,rax
	jbe	@f
	mov	rcx,rax
	inc	rcx				; one past: the check sees it
@@:
	rep	movsb
	ret
.put_none:
	inc	rdi
	ret
.h11	db ' HTTP/1.1',13,10
.h11.len = $ - .h11
.host	db 'host: '
.host.len = $ - .host
.cookie	db 'cookie: '
.cookie.len = $ - .cookie
.chunked db 'transfer-encoding: chunked',13,10
.chunked.len = $ - .chunked
.n_conn	db 10,'connection',10,'keep-alive',16,'proxy-connection',17,'transfer-encoding',7,'upgrade',0

; rdi/esi = a name, rdx = a list of (length byte, name) ending with 0:
; CF clear when the name is in it
h2_name_in:
.next:
	movzx	ecx,byte [rdx]
	test	ecx,ecx
	jz	.no
	inc	rdx
	cmp	ecx,esi
	jne	.skip
	push	rsi
	push	rdi
	push	rdx
	mov	rsi,rdx
	mov	edx,ecx
	call	mem_eq
	pop	rdx
	pop	rdi
	pop	rsi
	test	eax,eax
	jnz	.yes
	movzx	ecx,byte [rdx-1]
.skip:
	add	rdx,rcx
	jmp	.next
.yes:
	clc
	ret
.no:
	stc
	ret

; every stream of the connection (c2 registers) is closed
h2_streams_close:
	push	r12
	mov	dword [r13+C2_BLKH],0		; nothing waits on a closing connection
	mov	dword [r13+C2_BLKT],0
	lea	r12,[r13+C2_ST]
	mov	ecx,H2_MAXS
.next:
	push	rcx
	cmp	dword [r12+S2_SID],0
	je	.skip
	mov	edi,[r12+S2_SESS]
	mov	dword [r12+S2_SID],0		; out of the table first
	dec	dword [r13+C2_NSTR]
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	or	dword [rax+H_H2F],S2F_RST or S2F_END
	and	dword [rax+H_H2F],not S2F_WAITING
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r12+S2_GEN]
	jne	.skip
	call	h2_stream_abort
.skip:
	add	r12,S2_SIZE
	pop	rcx
	dec	ecx
	jnz	.next
	pop	r12
	ret

; ebx = a connection's session closing (session_close, both engines):
; its streams close with it. Keeps rbx.
h2c_closing:
	push	rbx
	push	r13
	push	r14
	push	r15
	c2_regs
	or	dword [r13+C2_FLAGS],C2F_CLOSING
	call	h2_streams_close
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret

; ------------------------------------------------------ the stream side

; h_recv on a stream (from engine.inc): ebx = stream, rdi = buffer, esi
; = room. What its queue holds, or parked until DATA comes.
h2s_recv:
	push	r14
	h_rec
	mov	r14,[r15+H_BUF]
	add	r14,HB_H2Q
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	.take
	cmp	dword [r14+Q_ENDED],0
	jne	.take				; the end: 0
	mov	[r14+Q_DST],rdi
	mov	[r14+Q_ROOM],esi
	mov	dword [r14+Q_WAIT],1
	pop	r14
	ret
.take:
	call	h2s_take
	pop	r14
	ret

; ebx = stream, r15 = record, r14 = queue, rdi = buffer, esi = room: copy
; what fits, deliver it; the window is given back once the queue drains.
h2s_take:
	mov	ecx,[r14+Q_LEN]
	mov	eax,[r14+Q_OFF]
	sub	ecx,eax
	cmp	ecx,esi
	jbe	@f
	mov	ecx,esi
@@:
	push	rcx
	lea	rsi,[r14+Q_DATA+rax]
	add	[r14+Q_OFF],ecx
	rep	movsb
	mov	eax,[r14+Q_OFF]
	cmp	eax,[r14+Q_LEN]
	jne	.deliver
	mov	dword [r14+Q_OFF],0
	mov	dword [r14+Q_LEN],0
	cmp	dword [r14+Q_PEND],0
	je	.deliver
	or	dword [r15+H_H2F],S2F_CREDIT
	call	h2s_kick			; the credit goes out with the connection
.deliver:
	pop	rax
	mov	edx,1
	xor	ecx,ecx
	h_rec
	jmp	hep_queue

; h_send on a stream: ebx = stream, rdi = bytes, esi = length. Turned into
; frames as far as room and windows allow; the rest waits.
h2s_send:
	h_rec
	mov	[r15+H_H2PP],rdi
	mov	[r15+H_H2PL],esi
	or	dword [r15+H_H2F],S2F_SENDING
	jmp	h2s_kick

; ebx = stream: let its connection take what it has (response bytes,
; credit, END_STREAM), or put it in the connection's waiting list
h2s_kick:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	h_rec
	mov	r12d,ebx			; the stream
	mov	edi,[r15+H_H2C]
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+H_H2CG]
	jne	.orphan				; the connection is gone
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.orphan
	mov	ebx,edi
	c2_regs
	mov	edi,r12d
	call	h2_stream_out
	jnc	.pumped
	; waiting: into the list once (the list keeps session + 1, 0 = none)
	mov	edi,r12d
	call	h2_ptrs
	test	dword [rax+H_H2F],S2F_WAITING
	jnz	.pumped
	or	dword [rax+H_H2F],S2F_WAITING
	mov	dword [rax+H_H2BL],0
	lea	edx,[r12+1]
	mov	ecx,[r13+C2_BLKT]
	mov	[r13+C2_BLKT],edx
	test	ecx,ecx
	jz	.first
	lea	edi,[rcx-1]
	call	h2_ptrs
	lea	edx,[r12+1]
	mov	[rax+H_H2BL],edx
	jmp	.pumped
.first:
	mov	[r13+C2_BLKH],edx
.pumped:
	call	h2_pump
	jmp	.out
.orphan:
	; no connection to write to: whatever it sends goes nowhere
	mov	ebx,r12d
	h_rec
	test	dword [r15+H_H2F],S2F_SENDING
	jz	.out
	and	dword [r15+H_H2F],not S2F_SENDING
	mov	dword [r15+H_H2PL],0
	mov	rax,-1
	mov	edx,2
	xor	ecx,ecx
	call	hep_queue
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = stream session: out of the connection's waiting list, if in it
; (c2 registers). A freed session must not stay linked: reused for a new
; stream and added again, it would loop the list.
h2_unwait:
	push	r12
	mov	r12d,edi
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	test	dword [rax+H_H2F],S2F_WAITING
	jz	.out
	and	dword [rax+H_H2F],not S2F_WAITING
	lea	r9d,[r12+1]			; its list value
	xor	r8d,r8d				; the previous (+ 1), 0 = none
	mov	ecx,[r13+C2_BLKH]
.walk:
	test	ecx,ecx
	jz	.out
	lea	edi,[rcx-1]
	push	rcx
	call	h2_ptrs				; (rax = the node's record)
	pop	rcx
	mov	edx,[rax+H_H2BL]
	cmp	ecx,r9d
	je	.found
	mov	r8d,ecx
	mov	ecx,edx
	jmp	.walk
.found:
	test	r8d,r8d
	jnz	@f
	mov	[r13+C2_BLKH],edx
	jmp	.tail
@@:
	lea	edi,[r8-1]
	push	rdx
	call	h2_ptrs
	pop	rdx
	mov	[rax+H_H2BL],edx
.tail:
	cmp	[r13+C2_BLKT],r9d
	jne	.out
	mov	[r13+C2_BLKT],r8d
.out:
	pop	r12
	ret

; streams waiting for room or window get another try (c2 registers)
h2_unblock:
	push	r12
	mov	r12d,[r13+C2_BLKH]
	mov	dword [r13+C2_BLKH],0
	mov	dword [r13+C2_BLKT],0
.next:
	test	r12d,r12d
	jz	.done
	dec	r12d				; (the list keeps index + 1)
	mov	edi,r12d
	call	h2_ptrs
	test	dword [rax+H_H2F],S2F_WAITING
	jz	.done				; not linked any more: the walk ends
	mov	ecx,[rax+H_H2BL]		; the next, + 1
	push	rcx
	and	dword [rax+H_H2F],not S2F_WAITING
	mov	eax,r12d			; still a live stream of this connection?
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	test	dword [rax+S_FLAGS],SF_H2S
	jz	.skip
	cmp	dword [rax+S_STATE],ST_FREE
	je	.skip
	push	rbx
	mov	ebx,r12d
	call	h2s_kick
	pop	rbx
	c2_regs
.skip:
	pop	r12
	jmp	.next
.done:
	pop	r12
	ret

; edi = stream session: as much of what it has to say as fits, as frames
; in OUT (c2 registers of its connection). CF when something waits.
h2_stream_out:
	push	rbx
	push	rbp
	push	r12
	push	r15
	mov	ebp,edi
	mov	eax,edi
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	r15,rax				; the stream's record
	; credit for what its queue gave the exchange
	test	dword [r15+H_H2F],S2F_CREDIT
	jz	.response
	mov	rax,[r15+H_BUF]
	mov	edx,[rax+HB_H2Q+Q_PEND]
	mov	esi,[r15+H_H2SID]
	call	h2_out_window
	jc	.wait
	mov	rax,[r15+H_BUF]
	mov	edx,[rax+HB_H2Q+Q_PEND]
	add	[rax+HB_H2Q+Q_RWIN],edx
	mov	dword [rax+HB_H2Q+Q_PEND],0
	and	dword [r15+H_H2F],not S2F_CREDIT
.response:
	test	dword [r15+H_H2F],S2F_SENDING
	jz	.finish
	test	dword [r15+H_H2F],S2F_RST
	jnz	.sent				; reset: what it says is dropped
.chunk:
	cmp	dword [r15+H_H2PL],0
	je	.sent
	test	dword [r15+H_H2F],S2F_HEAD
	jz	.head
	; DATA: as much as the frame size, both windows and the room allow
	mov	eax,[r15+H_H2PL]
	cmp	eax,[r13+C2_PMAXF]
	jbe	@f
	mov	eax,[r13+C2_PMAXF]
@@:
	cmp	eax,[r13+C2_SWIN]
	jle	@f
	mov	eax,[r13+C2_SWIN]
@@:
	cmp	eax,[r15+H_H2SWIN]
	jle	@f
	mov	eax,[r15+H_H2SWIN]
@@:
	mov	r12d,eax
	call	h2_room
	sub	eax,9
	cmp	r12d,eax
	jle	@f
	mov	r12d,eax
@@:
	test	r12d,r12d
	jle	.wait
	mov	esi,r12d
	mov	dl,H2F_DATA
	xor	ecx,ecx
	mov	r8d,[r15+H_H2SID]
	call	h2_frame
	mov	rsi,[r15+H_H2PP]
	mov	ecx,r12d
	rep	movsb
	add	[r15+H_H2PP],r12
	sub	[r15+H_H2PL],r12d
	sub	[r13+C2_SWIN],r12d
	sub	[r15+H_H2SWIN],r12d
	jmp	.chunk
.head:
	call	h2_head_out			; HEADERS from the HTTP/1.1 head
	jc	.wait
	jmp	.chunk
.sent:
	; all of it taken: the exchange hears its send completed
	and	dword [r15+H_H2F],not S2F_SENDING
	push	rbx
	mov	ebx,ebp
	xor	eax,eax
	mov	edx,2
	xor	ecx,ecx
	call	hep_queue
	pop	rbx
.finish:
	test	dword [r15+H_H2F],S2F_FINISH
	jz	.done
	test	dword [r15+H_H2F],S2F_RST
	jnz	.finished
	cmp	dword [r15+H_RCK+CK_TLEN],0
	je	.no_trailers
	call	h2_trailers_out			; HEADERS with END_STREAM
	jc	.wait
	jmp	.finished
.no_trailers:
	call	h2_room
	cmp	eax,9
	jb	.wait
	xor	esi,esi
	mov	dl,H2F_DATA
	mov	cl,H2_END_STREAM
	mov	r8d,[r15+H_H2SID]
	call	h2_frame
.finished:
	and	dword [r15+H_H2F],not S2F_FINISH
	or	dword [r15+H_H2F],S2F_END
	call	h2_untable			; ebp = the stream
	push	rbx
	mov	edi,ebp
	call	session_close
	pop	rbx
.done:
	clc
	jmp	.out
.wait:
	stc
.out:
	pop	r15
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ebp = stream session: out of its connection's table (c2 registers)
h2_untable:
	mov	eax,ebp				; its home slot first
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	r8d,[rax+H_H2SID]
	shr	r8d,1
	and	r8d,H2_MAXS - 1
	shl	r8d,4
	lea	r8,[r13+C2_ST+r8]
	cmp	dword [r8+S2_SID],0
	je	.scan
	cmp	[r8+S2_SESS],ebp
	jne	.scan
	mov	dword [r8+S2_SID],0
	dec	dword [r13+C2_NSTR]
	ret
.scan:
	lea	r8,[r13+C2_ST]
	mov	ecx,H2_MAXS
.next:
	cmp	dword [r8+S2_SID],0
	je	.skip
	cmp	[r8+S2_SESS],ebp
	jne	.skip
	mov	dword [r8+S2_SID],0
	dec	dword [r13+C2_NSTR]
	ret
.skip:
	add	r8,S2_SIZE
	dec	ecx
	jnz	.next
	ret

; r15 = stream record whose pending bytes start with an HTTP/1.1 head
; ("HTTP/1.1 NNN reason\r\n" fields "\r\n"): a HEADERS frame from it, the
; pending bytes advanced past it. CF when OUT has no room for it.
; Connection-specific fields are dropped, names go lower case.
h2_head_out:
	push	r12
	push	rbp
	mov	rsi,[r15+H_H2PP]
	mov	ecx,[r15+H_H2PL]
	; the head's end
	xor	edx,edx
.find:
	lea	eax,[rdx+4]
	cmp	eax,ecx
	ja	.broken
	cmp	dword [rsi+rdx],0x0A0D0A0D
	je	.found
	inc	edx
	jmp	.find
.found:
	lea	ebp,[rdx+4]			; ebp = the head's length
	cmp	ebp,13
	jb	.broken
	lea	rdi,[g_h2tmp]
	lea	r12,[g_h2tmp+20480-512]		; the block's limit
	; :status
	push	rsi
	lea	rcx,[rsi+9]
	lea	rsi,[.status]
	mov	edx,7
	mov	r8d,3
	call	hpack_encode
	mov	rdi,rax
	pop	rsi
	movzx	eax,word [rsi+9]		; 1xx: an informational head
	mov	r9d,eax
	; the fields: from after the status line to the empty line
	xor	ecx,ecx
@@:
	cmp	word [rsi+rcx],0x0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	add	ecx,2
.line:
	lea	eax,[rcx+2]
	cmp	eax,ebp
	jae	.block				; the empty line
	; name: to ':'
	mov	edx,ecx
@@:
	cmp	byte [rsi+rdx],':'
	je	@f
	cmp	byte [rsi+rdx],13
	je	.broken
	inc	edx
	jmp	@b
@@:
	mov	r8d,edx				; the name's end
	inc	edx
@@:
	cmp	byte [rsi+rdx],' '
	jne	@f
	inc	edx
	jmp	@b
@@:
	mov	r10d,edx			; the value's start
@@:
	cmp	word [rsi+rdx],0x0A0D
	je	@f
	inc	edx
	jmp	@b
@@:
	; lower case the name in place (the buffer is the exchange's, sent once)
	push	rcx
	push	rdx
@@:
	cmp	ecx,r8d
	jae	@f
	movzx	eax,byte [rsi+rcx]
	lea	r11d,[rax-'A']
	cmp	r11d,25
	ja	.lc_next
	or	byte [rsi+rcx],0x20
.lc_next:
	inc	ecx
	jmp	@b
@@:
	pop	rdx
	pop	rcx
	push	rsi
	push	rdx
	push	rcx
	push	r9
	lea	rax,[rsi+rcx]			; skip connection-specific fields
	push	rdi
	mov	rdi,rax
	mov	esi,r8d
	sub	esi,ecx
	lea	rdx,[h2_stream_new.n_conn]
	call	h2_name_in
	pop	rdi
	pop	r9
	pop	rcx
	pop	rdx
	pop	rsi
	jnc	.next_line
	cmp	rdi,r12
	ja	.broken				; a head larger than one block
	push	rsi
	push	rdx
	push	r9
	lea	rax,[rsi+rcx]			; name
	lea	r11,[rsi+r10]			; value
	mov	r8d,r8d
	sub	r8d,ecx
	push	rax
	mov	eax,edx
	sub	eax,r10d
	mov	edx,r8d
	mov	r8d,eax
	pop	rsi
	mov	rcx,r11
	call	hpack_encode
	mov	rdi,rax
	pop	r9
	pop	rdx
	pop	rsi
.next_line:
	lea	ecx,[rdx+2]
	jmp	.line
.block:
	; the block in HEADERS (and CONTINUATION past the client's frame size)
	lea	rax,[g_h2tmp]
	sub	rdi,rax
	mov	r12d,edi			; its length
	mov	eax,r12d
	xor	edx,edx
	div	dword [r13+C2_PMAXF]
	inc	eax
	imul	eax,eax,9
	add	eax,r12d
	push	rax
	call	h2_room
	pop	rdx
	cmp	eax,edx
	jb	.full
	lea	r11,[g_h2tmp]
	mov	r10b,H2F_HEADERS
.frame:
	mov	esi,r12d
	cmp	esi,[r13+C2_PMAXF]
	jbe	@f
	mov	esi,[r13+C2_PMAXF]
@@:
	xor	ecx,ecx
	cmp	esi,r12d
	jne	@f
	mov	cl,H2_END_HEADERS
@@:
	push	rsi
	push	r11
	push	r10
	mov	dl,r10b
	mov	r8d,[r15+H_H2SID]
	call	h2_frame
	pop	r10
	pop	r11
	pop	rcx
	mov	rsi,r11
	add	r11,rcx
	sub	r12d,ecx
	rep	movsb
	mov	r10b,H2F_CONT
	test	r12d,r12d
	jnz	.frame
	; past the head
	add	[r15+H_H2PP],rbp
	sub	[r15+H_H2PL],ebp
	cmp	r9b,'1'				; 1xx: another head follows
	je	@f
	or	dword [r15+H_H2F],S2F_HEAD
@@:
	clc
	jmp	.out
.broken:
	; not a head we wrote (cannot happen): the stream is reset
	mov	dword [r15+H_H2PL],0
	or	dword [r15+H_H2F],S2F_RST
	mov	esi,[r15+H_H2SID]
	mov	edx,H2E_INTERNAL
	call	h2_out_rst
	clc
	jmp	.out
.full:
	stc
.out:
	pop	rbp
	pop	r12
	ret
.status	db ':status'

; r15 = stream record whose response had trailers (HB_TRAIL, CK_TLEN
; bytes of "name: value\r\n"): a HEADERS frame with END_STREAM from
; them, names lower case, connection-specific fields dropped. CF when OUT
; has no room for it.
h2_trailers_out:
	push	rbx
	push	r12
	mov	rbx,[r15+H_BUF]
	add	rbx,HB_TRAIL			; rbx = the lines
	mov	r12d,[r15+H_RCK+CK_TLEN]	; r12d = their length
	lea	rdi,[g_h2tmp]
	xor	ecx,ecx				; a line's start
.line:
	cmp	ecx,r12d
	jae	.block
	mov	edx,ecx				; the name, to ':'
@@:
	cmp	edx,r12d
	jae	.block
	cmp	byte [rbx+rdx],':'
	je	@f
	movzx	eax,byte [rbx+rdx]
	lea	r8d,[rax-'A']
	cmp	r8d,25
	ja	.lc
	or	byte [rbx+rdx],0x20
.lc:
	inc	edx
	jmp	@b
@@:
	mov	r8d,edx				; the name's end
	inc	edx
@@:
	cmp	byte [rbx+rdx],' '
	je	.sp
	cmp	byte [rbx+rdx],9
	jne	@f
.sp:
	inc	edx
	jmp	@b
@@:
	mov	r9d,edx				; the value's start
@@:
	cmp	word [rbx+rdx],0x0A0D
	je	@f
	inc	edx
	jmp	@b
@@:
	push	rdx
	push	rcx
	push	r8
	push	r9
	push	rdi
	lea	rdi,[rbx+rcx]			; connection-specific: dropped
	mov	esi,r8d
	sub	esi,ecx
	lea	rdx,[h2_stream_new.n_conn]
	call	h2_name_in
	pop	rdi
	pop	r9
	pop	r8
	pop	rcx
	pop	rdx
	jnc	.next
	push	rdx
	lea	rsi,[rbx+rcx]			; name
	mov	eax,edx
	sub	eax,r9d				; value length
	mov	edx,r8d
	sub	edx,ecx				; name length
	lea	rcx,[rbx+r9]			; value
	mov	r8d,eax
	call	hpack_encode
	mov	rdi,rax
	pop	rdx
.next:
	lea	ecx,[rdx+2]
	jmp	.line
.block:
	lea	rax,[g_h2tmp]
	sub	rdi,rax
	mov	r12d,edi
	call	h2_room
	lea	edx,[r12+9+H2_RESERVE]
	cmp	eax,edx
	jb	.full
	mov	esi,r12d
	mov	dl,H2F_HEADERS
	mov	cl,H2_END_HEADERS or H2_END_STREAM
	mov	r8d,[r15+H_H2SID]
	call	h2_frame
	lea	rsi,[g_h2tmp]
	mov	ecx,r12d
	rep	movsb
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r12
	pop	rbx
	ret

; ebx = stream: its exchange is over (proxy.inc, in place of the next
; request or of closing the client). END_STREAM, then the session goes.
h2s_finish:
	h_rec
	or	dword [r15+H_H2F],S2F_FINISH
	jmp	h2s_kick

; ebx = stream session closing (session_close, both engines): RST_STREAM
; if it ended without END_STREAM, out of its connection's table. Keeps
; rbx, r12.
h2s_closing:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	h_rec
	mov	r12d,ebx
	mov	edi,[r15+H_H2C]
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+H_H2CG]
	jne	.out				; its connection is gone
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	mov	ebx,edi
	push	r15
	c2_regs
	pop	rax				; the stream's record
	test	dword [rax+H_H2F],S2F_END
	jnz	.untable
	or	dword [rax+H_H2F],S2F_END or S2F_RST
	mov	esi,[rax+H_H2SID]
	mov	edx,H2E_INTERNAL
	call	h2_out_rst
.untable:
	push	rbp
	mov	ebp,r12d
	call	h2_untable
	pop	rbp
	mov	edi,r12d
	call	h2_unwait
	call	h2_pump
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
