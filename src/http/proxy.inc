; HTTP/1.1 reverse proxy: the exchange state machine (docs/HTTP.md).
;
; Written once for both engines. It talks to them through four
; primitives each engine implements:
;   h_recv   ebx = session, ecx = side (0 client, 1 upstream), rdi = buffer,
;            esi = room. Later: http_recv_done(ebx, ecx, rax = bytes,
;            0 at the end of the stream, negative on an error).
;   h_send   ebx, ecx, rdi = bytes, esi = how many. Later:
;            http_send_done(ebx, ecx, rax = 0, or negative on an error).
;   h_connect  ebx: connect to a server of S_POOL. Later: http_connected
;            or http_connect_failed.
;   h_upclose  ebx: close the upstream connection (nothing in flight on it).
; One operation of a session is in flight at a time, so a slow side
; stops the other (backpressure), and every buffer has one owner.
;
; This first version opens one upstream connection per request; pooling
; comes next.

; A session's state is 512 bytes in a dense array (8 to a page): what an
; idle keep-alive connection keeps. Its buffers are 64 KiB of address
; space of their own, touched only as far as an exchange uses them, and
; given back whole when the connection is idle (PH_TRIM).
H_SHIFT		:= 9		; state
HB_SHIFT	:= 18		; buffers: 64 KiB for HTTP, the TLS area, the upstream TLS area
H_STATE		:= 0
H_INLEN		:= 4		; bytes in IN
H_INOFF		:= 8		; first unconsumed byte of IN
H_OUTLEN	:= 12
H_UPLEN		:= 16
H_UPOFF		:= 20
H_BODY		:= 24		; BK_* of the request body
H_RBODY		:= 28		; BK_* of the response body
H_REMAIN	:= 32		; q: request body bytes left (BK_LENGTH)
H_RREMAIN	:= 40		; q: response body bytes left
H_FLAGS		:= 48		; HX_*
H_STATUS	:= 52
H_SPTR		:= 56		; q: what an engine still has to send
H_SLEN		:= 64		; d
H_CK		:= 72		; request chunked decoder (CK_SIZE)
H_RCK		:= 104		; response chunked decoder
; buffers, from H_BUF
HB_IN		:= 0		; client bytes: the request head, then its body
H_IN_CAP	:= 16384
HB_OUT		:= HB_IN + H_IN_CAP	; heads okena writes, chunk framing
H_OUT_CAP	:= 20480
HB_UP		:= HB_OUT + H_OUT_CAP	; upstream bytes: the response
H_UP_CAP	:= 16384
; access log: the request as it was, and its exchange's counters
H_LT0		:= 184		; q: TSC when the request head was parsed, 0 = none
H_XBYTES	:= 192		; q: bytes sent to the client in this exchange
H_LMLEN		:= 200		; d
H_LHLEN		:= 204		; d
H_LTLEN		:= 208		; d
H_CKIND		:= 212		; d: 4 or 6
H_CLIENT	:= 216		; 16 bytes: the client (the peer, or what trusted proxies say)
H_RIDLEN	:= 232		; d: request id length, 0 = none yet
H_RID		:= 236		; the request id (RID_MAX bytes)
RID_MAX		:= 128
H_BUF		:= 368		; q: this session's buffers
H_ACT		:= 376		; d: the route's action + 1 (redirect, header changes), 0 = none
H_UPT0		:= 384		; q: peak-ewma: TSC when the request was sent, 0 = none
; TLS records sealed and opened here, when the kernel cannot (src/http/tls.inc)
H_UTLS		:= 396		; d: 1 = user-space records on the client side
H_RXC		:= 400		; d: ciphertext bytes held at HB_RXC
H_PTOFF		:= 404		; d: plaintext of an opened record not yet handed over
H_PTLEN		:= 408		; d
H_PTEND		:= 412		; d: that record's end in HB_RXC
H_UDST		:= 416		; q: where the waiting receive goes
H_UROOM		:= 424		; d: its room
H_TXLEN		:= 428		; d: plaintext still to seal
H_TXP		:= 432		; q: and where it is
H_SNICERT	:= 440		; q: the certificate the client's SNI chose, 0 = no SNI
H_ULPERR	:= 448		; d: io_uring: what setting the TLS ULP returned
H_UHLEN		:= 452		; d: upstream TLS handshake message length to send
H_UPKTLS	:= 456		; d: 1 when the upstream is a kTLS TLS socket
H_URBUF		:= 460		; q: last upstream recv buffer (to retry after a drain)
H_URROOM	:= 468		; d: its room
assert H_ULPERR + 4 <= 1 shl H_SHIFT
assert H_BUF + 8 <= 1 shl H_SHIFT
HB_LTEXT_M	:= HB_UP + H_UP_CAP	; access log: method
H_LTEXT_M_CAP	:= 16
HB_LTEXT_H	:= HB_LTEXT_M + 16	; host
H_LTEXT_H_CAP	:= 255
HB_LTEXT_T	:= HB_LTEXT_H + 256	; target
H_LTEXT_T_CAP	:= 1024 - TRC_SIZE
HB_TRC		:= HB_LTEXT_T + H_LTEXT_T_CAP	; the request's trace (TRC_*, http/trace.inc)
HB_TRAIL	:= HB_TRC + TRC_SIZE		; a chunked response's trailer lines
assert HB_TRAIL + CK_TRAIL_MAX <= 1 shl 16

HS_HEAD		:= 1		; reading a request head
HS_CONTINUE	:= 2		; writing our 100 Continue
HS_CONNECT	:= 3
HS_SEND_HEAD	:= 4
HS_REQ_SEND	:= 5		; writing request body bytes upstream
HS_REQ_READ	:= 6		; reading request body bytes
HS_RESP_HEAD	:= 7		; reading a response head
HS_RESP_SEND	:= 8		; writing response head or body to the client
HS_RESP_READ	:= 9
HS_ERROR_SEND	:= 10		; writing an error, then closing
HS_LINGER	:= 45		; an error sent, its writing side shut: what still comes is read and dropped
HS_TUNNEL_UP	:= 11		; 101 sent: bytes the backend sent early go to the client
HS_TUNNEL_IN	:= 12		; then bytes the client sent early go to the backend
HS_INTERIM_SEND	:= 13		; writing a 1xx (103 Early Hints...) before the final response
HS_SELF_SEND	:= 14		; writing okena's own answer (a redirect), connection kept
HS_HEDGED	:= 43		; its copy won: what it writes goes through here
HS_FAULT	:= 42		; held by fault delay=: its head waits in IN, nothing reads
HS_H2TUN	:= 41		; WebSocket over an HTTP/2 stream (http_h2tun_*)

BK_NONE		:= 0
BK_LENGTH	:= 1
BK_CHUNKED	:= 2
BK_CLOSE	:= 3		; until the backend closes

HX_CLOSE	:= 1		; close the client connection after this response
HX_HEAD		:= 2		; a HEAD request
HX_STARTED	:= 4		; response bytes reached the client
HX_CHUNKOUT	:= 8		; the response goes out chunked (re-framed)
HX_CONTINUE	:= 16		; the client waits for 100 Continue
HX_LASTCHUNK	:= 32		; the last chunk is being written
HX_REUSED	:= 64		; the upstream connection came from the pool
HX_NOBODY	:= 128		; the request has no body (safe to send twice)
HX_NOPOOL	:= 256		; connect afresh (a reused one just failed)
HX_UPKEEP	:= 512		; the upstream connection may go back to the pool
HX_UPGRADE	:= 1024		; the client asks to switch protocols (WebSocket...)
HX_IDEMPOTENT	:= 2048		; GET, HEAD, PUT, DELETE, OPTIONS: may be sent twice
HX_RETRIED	:= 4096		; this request was sent again, to another server
HX_AVOID	:= 8192		; the next connect avoids S_SERVER
HX_TRUSTED	:= 16384		; the peer is in trusted_proxies: its X-Forwarded-* count
HX_XFPROTO	:= 32768		; and it sent X-Forwarded-Proto (forwarded as is)
HX_RIDKEPT	:= 65536		; the request id is the one a trusted proxy sent
HX_HTTP10	:= 131072	; the client speaks HTTP/1.0 (no 1xx for it)
HX_INTERIM	:= 262144	; the head being written is an interim (1xx) one
HX_SELF		:= 524288	; okena answers this request itself (a redirect)
HX_GRPC		:= 1048576	; a gRPC request: okena's own errors answer as gRPC
HX_DUPLEX	:= 2097152	; HTTP/2 both ends: the body goes on beside the response
HX_H2TUN	:= 4194304	; WebSocket over an HTTP/2 stream: bytes both ways
HX_HWON		:= 536870912	; a copy that hedges: its answer goes to the client
HX_HEDGE	:= 1073741824	; a copy that hedges: its answer may count
HX_HEDGEW	:= 0x80000000	; its hedge's time is set; its answer ends the race
HX_TEE		:= 268435456	; its body goes to a copy too: HB_MIRS
HX_MIRROR	:= 134217728	; a copy (`mirror`): its pool in HB_SPLIT, no filters
HX_SPLIT	:= 67108864	; `split`: this response gives the client its cookie
HX_CORS		:= 33554432	; its Origin was let in: HB_CORS
HX_FAULTED	:= 16777216	; fault: this request was picked, and has waited
HX_TSEND	:= 8388608	; its bytes to the backend: a send in flight, or the
				; socket full (epoll: EPOLLOUT resumes it)

SIDE_CLIENT	:= 0
SIDE_UP		:= 1

bss
	align 8
	g_http_base	dq ?		; the states
	g_hbuf_base	dq ?		; the buffers
	g_hm:		rb HM_SIZE		; the message being parsed
end bss

; Worker: the session states and buffers (address space only; pages
; come with use). eax = 0 or -errno.
http_worker_init:
	mov	ecx,H_SHIFT
	call	.reserve
	cmp	rax,-4096
	ja	.done
	mov	[g_http_base],rax
	mov	ecx,HB_SHIFT
	call	.reserve
	cmp	rax,-4096
	ja	.done
	mov	[g_hbuf_base],rax
	call	retry_budget_tick		; budgets start at their floor, not empty
	mov	dword [g_hready_head],NIL	; deliveries (epoll, user-space TLS)
	mov	dword [g_hready_tail],NIL
	mov	dword [g_hlater_head],NIL
	mov	dword [g_hlater_tail],NIL
	xor	eax,eax
.done:
	ret
; ecx = shift of one session's share. rax = the region or -errno.
.reserve:
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,cl
	push	rsi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	pop	rsi
	cmp	rax,-4096
	ja	@f
	push	rax
	mov	rdi,rax
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	pop	rax
@@:
	ret

; Append literal text at rdi (rdi = after it).
macro memit_x text&
	local s
	cstring s, text,0
	lea	rsi,[s]
	call	fmt_cstr
end macro

; ebx = session. r15 = its record. Keeps everything else.
macro h_rec
	mov	r15d,ebx
	shl	r15,H_SHIFT
	add	r15,[g_http_base]
end macro

; A new client connection: wait for its first request.
http_start:
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN	; no upstream yet: reading the request
	h_rec
	mov	eax,ebx				; this slot's buffers
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	mov	dword [rax+HB_CW],0		; (cache.inc: a stale copy kept, none)
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	[r15+H_FLAGS],eax
	mov	[r15+H_UTLS],eax
	mov	[r15+H_SNICERT],rax
	mov	edi,ebx
	mov	esi,PH_HEAD
	call	ph_arm
	call	http_tls_cred
	h_rec
	test	rax,rax
	jnz	http_tls_start			; HTTPS: the handshake first
	jmp	http_next_request

; ----------------------------------------------------------- requests

; Take the next request from IN, reading more when the head is not all
; there. ebx = session.
http_next_request:
	h_rec
	mov	dword [r15+H_STATE],HS_HEAD
	and	dword [r15+H_FLAGS],HX_CLOSE
	mov	dword [r15+H_RIDLEN],0
	mov	dword [r15+H_ACT],0
	; the unconsumed bytes (a pipelined request) move to the front
	mov	ecx,[r15+H_INLEN]
	mov	eax,[r15+H_INOFF]
	sub	ecx,eax
	jz	.empty
	test	eax,eax
	jz	.parse
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	[r15+H_INLEN],ecx
	rep	movsb
	mov	dword [r15+H_INOFF],0
	mov	edi,ebx				; a pipelined request: its clock starts now
	mov	esi,PH_HEAD
	call	ph_arm
	h_rec
	jmp	.parse
.empty:
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	call	session_ptr
	cmp	dword [rax+S_PH_KIND],0
	jne	.read				; a new connection: its header clock runs
	mov	edi,ebx
	mov	esi,PH_TRIM
	call	ph_arm
	h_rec
	jmp	.read
.parse:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,[r15+H_INLEN]
	; empty lines before a request line are dropped (RFC 9112 2.2: a client
	; may send a CRLF after a body)
	xor	ecx,ecx
@@:
	lea	eax,[rcx+2]
	cmp	eax,esi
	ja	@f
	cmp	word [rdi+rcx],0x0A0D
	jne	@f
	mov	ecx,eax
	jmp	@b
@@:
	test	ecx,ecx
	jz	.lines_kept
	sub	esi,ecx
	mov	[r15+H_INLEN],esi
	push	rsi
	lea	rsi,[rdi+rcx]
	mov	ecx,[rsp]
	rep	movsb				; (forwards: the source is ahead)
	pop	rsi
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	test	esi,esi
	jz	.read
.lines_kept:
	call	http_head_end
	cmp	eax,-1
	je	.bad
	test	eax,eax
	jnz	http_request
	call	http_line_one		; its first line whole: HTTP/0.9, or too long?
	cmp	eax,1
	je	.bad
	cmp	dword [r15+H_INLEN],H_IN_CAP
	jae	.too_large
.read:
	mov	ecx,SIDE_CLIENT
	mov	edi,[r15+H_INLEN]
	lea	rdi,[rdi+HB_IN]
	add	rdi,[r15+H_BUF]
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	jmp	h_recv
.bad:
	mov	edi,400
	jmp	http_error
.too_large:
	mov	edi,431
	cmp	eax,2
	jne	http_error
	mov	edi,414				; the request line alone fills it
	jmp	http_error

; ebx, r15: a head not yet whole. eax = 1 when its first line has ended with no
; version after the target (HTTP/0.9, "GET /": nothing more will come to make a
; head of it), 2 when it has not ended at all, 0 otherwise.
http_line_one:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,[r15+H_INLEN]
	xor	ecx,ecx
	xor	edx,edx				; spaces
.next:
	cmp	ecx,esi
	jae	.open
	movzx	eax,byte [rdi+rcx]
	inc	ecx
	cmp	al,' '
	jne	@f
	inc	edx
@@:
	cmp	al,10
	jne	.next
	xor	eax,eax
	cmp	edx,2
	jae	@f
	mov	eax,1
@@:
	ret
.open:
	mov	eax,2
	ret

; fault delay=: requests held, a table a worker, looked through when one is
; due (few, and only on routes that ask for this). Their heads wait where they
; were read, so they are parsed again; no read is posted meanwhile: a client
; that goes is seen after.
FD_MAX		:= 1024
FD_AT		:= 0				; q: µs
FD_SESS		:= 8				; d
FD_GEN		:= 12				; d
FD_SIZE		:= 16
bss
	g_fd_n		dd ?
	align 8
	g_fd_armed	dq ?			; µs the io_uring timer wakes us, 0 none
	g_fd_next	dq ?			; µs the earliest is due, 0 none
	g_fd_ts		rq 2
	g_fd:		rb FD_MAX * FD_SIZE
end bss

; ebx = session, r15 = its record, rax = µs: it waits
fault_hold:
	push	rax
	call	qs_clock
	pop	rax
	add	rax,[g_qnow]
	mov	ecx,[g_fd_n]
	inc	dword [g_fd_n]
	shl	rcx,4
	mov	[g_fd+rcx+FD_AT],rax
	mov	[g_fd+rcx+FD_SESS],ebx
	mov	rdx,[g_fd_next]
	test	rdx,rdx
	jz	.first
	cmp	rax,rdx
	jae	.kept
.first:
	mov	[g_fd_next],rax
.kept:
	push	rcx
	call	session_ptr
	pop	rcx
	mov	eax,[rax+S_GEN]
	mov	[g_fd+rcx+FD_GEN],eax
	or	dword [r15+H_FLAGS],HX_FAULTED
	mov	dword [r15+H_STATE],HS_FAULT
	ret

; every turn of the loop: those whose time has come go on
fault_flush:
	cmp	dword [g_fd_n],0
	je	.none
	call	qs_clock
	mov	rax,[g_fd_next]
	cmp	rax,[g_qnow]
	ja	.timer
	push	rbx
	push	r12
	push	r13
	xor	r12d,r12d			; i
	xor	r13d,r13d			; the earliest left
	mov	qword [g_fd_next],0		; (what is made due meanwhile says so here)
.next:
	cmp	r12d,[g_fd_n]
	jae	.looked
	mov	rcx,r12
	shl	rcx,4
	mov	rax,[g_fd+rcx+FD_AT]
	cmp	rax,[g_qnow]
	jbe	.due
	inc	r12d
	test	r13,r13
	jz	.earliest
	cmp	rax,r13
	jae	.next
.earliest:
	mov	r13,rax
	jmp	.next
.due:
	mov	ebx,[g_fd+rcx+FD_SESS]
	mov	r8d,[g_fd+rcx+FD_GEN]
	mov	r9,rax				; its time
	dec	dword [g_fd_n]			; the last takes its place
	mov	edx,[g_fd_n]
	shl	rdx,4
	mov	rax,[g_fd+rdx+FD_AT]
	mov	[g_fd+rcx+FD_AT],rax
	mov	rax,[g_fd+rdx+FD_SESS]
	mov	[g_fd+rcx+FD_SESS],rax
	cmp	ebx,QPOLL_SESS
	jne	@f
	call	queue_poll			; the queue's clock: no session
	jmp	.next
@@:
	mov	r10d,ebx
	and	ebx,not (FD_HEDGE or FD_FWD or FD_CACHE or FD_HOLD or FD_SLICE)
	push	r8
	push	r9
	push	r10
	call	session_ptr
	pop	r10
	pop	r9
	pop	r8
	cmp	[rax+S_GEN],r8d
	jne	.next				; it went meanwhile
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	h_rec
	test	r10d,FD_HEDGE
	jz	.not_hedge
	call	hedge_fire
	jmp	.next
.not_hedge:
	test	r10d,FD_FWD
	jz	.not_fwd
	call	fwd_timeout
	jmp	.next
.not_fwd:
	test	r10d,FD_CACHE
	jz	.not_cache
	call	cache_poll
	jmp	.next
.not_cache:
	test	r10d,FD_SLICE
	jz	.not_slice
	call	slice_poll
	jmp	.next
.not_slice:
	test	r10d,FD_HOLD
	jz	.held
	call	hold_again
	jmp	.next
.held:
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.next
	mov	eax,[r15+H_INOFF]
	call	http_request
	jmp	.next
.looked:
	; the earliest of those left, and of what was made due or added meanwhile
	; (an entry made due behind i is not looked at again in this turn)
	mov	rax,[g_fd_next]
	test	rax,rax
	jz	@f
	test	r13,r13
	jz	.keep
	cmp	rax,r13
	jb	.keep
@@:
	mov	[g_fd_next],r13
.keep:
	pop	r13
	pop	r12
	pop	rbx
	cmp	dword [g_fd_n],0
	je	.none
.timer:
	; io_uring: a timer for the next (epoll's wait takes it: ep_wait_timeout)
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.none
	mov	rax,[g_fd_next]
	mov	rcx,[g_fd_armed]		; (one set for later is no use: another)
	test	rcx,rcx
	jz	.arm
	cmp	rcx,rax
	jbe	.none
.arm:
	mov	[g_fd_armed],rax
	sub	rax,[g_qnow]
	cmp	rax,100
	jge	@f
	mov	eax,100
@@:
	imul	rax,rax,1000			; ns
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	mov	[g_fd_ts],rax
	mov	[g_fd_ts+8],rdx
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[g_fd_ts]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],0
	mov	rcx,OP_FDELAY shl 56
	mov	[rax+SQE_USER_DATA],rcx
.none:
	ret

; io_uring: fault_flush's timer; the turn of the loop does the rest
on_fdelay:
	mov	qword [g_fd_armed],0
	ret

; ebx = session, eax = length of the head at the start of IN.
http_request:
	cmp	eax,18				; "PRI * HTTP/2.0\r\n\r\n": HTTP/2 by prior
	jne	.h1				; knowledge, where the listener takes it
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	test	dword [g_listeners+rcx+LS_FLAGS],LSF_H2
	jz	.h1_len
	cmp	dword [g_listeners+rcx+LS_TLS],0
	jne	.h1_len				; over TLS only ALPN says h2
	h_rec
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_IN]
	lea	rdi,[h2_preface]
	mov	edx,18
	call	mem_eq
	test	eax,eax
	jz	.h1_len
	h_rec
	mov	dword [r15+H_INOFF],18
	mov	edi,18
	jmp	h2_start
.h1_len:
	mov	eax,18
.h1:
	push	rax
	mov	edi,ebx
	call	ph_disarm			; the head is all here
	h_rec
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,[rsp]
	lea	rdx,[g_hm]
	call	http_parse_request
	pop	rcx
	test	eax,eax
	jnz	.parse_error
	mov	[r15+H_INOFF],ecx		; the body (or the next request) follows
	; what this exchange has to do
	lea	r14,[g_hm]
	mov	rdi,[r14+HM_METHOD]
	mov	esi,[r14+HM_MLEN]
	call	method_bit
	test	eax,RM_GET or RM_HEAD or RM_PUT or RM_DELETE or RM_OPTIONS
	jz	@f
	or	dword [r15+H_FLAGS],HX_IDEMPOTENT
@@:
	test	dword [r15+H_FLAGS],HX_FAULTED	; (its clock started before it waited)
	jnz	@f
	call	alog_request
@@:
	h_rec
	lea	r14,[g_hm]
	mov	eax,[r14+HM_FLAGS]
	test	eax,HMF_CLOSE
	jz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [g_overload],2		; pressed: slots come back
	jb	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	mov	rax,[g_api_ov]			; `okena drain`: clients go elsewhere
	cmp	dword [rax+AP_DRAIN],0
	je	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [g_draining],0		; a reload, an upgrade or a stop replaced
	je	@f				; this worker: its clients go to the new one
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [r14+HM_VERSION],10
	jne	@f
	or	dword [r15+H_FLAGS],HX_CLOSE or HX_HTTP10	; HTTP/1.0 clients: one exchange
@@:
	cmp	dword [r14+HM_MLEN],4
	jne	@f
	mov	rdx,[r14+HM_METHOD]
	cmp	dword [rdx],'HEAD'
	jne	@f
	or	dword [r15+H_FLAGS],HX_HEAD
@@:
	call	http_grpc_mark			; content-type: application/grpc...
	h_rec
	lea	r14,[g_hm]
	mov	eax,[r14+HM_FLAGS]
	test	eax,HMF_UPGRADE
	jz	@f
	or	dword [r15+H_FLAGS],HX_UPGRADE
@@:
	; TRACE would echo the request (cookies, auth) back: refused
	cmp	dword [r14+HM_MLEN],5
	jne	@f
	mov	rsi,[r14+HM_METHOD]
	cmp	dword [rsi],'TRAC'
	jne	@f
	cmp	byte [rsi+4],'E'
	jne	@f
	mov	edi,405
	jmp	http_error
@@:
	; body
	mov	dword [r15+H_BODY],BK_NONE
	test	eax,HMF_CHUNKED
	jz	.length
	mov	dword [r15+H_BODY],BK_CHUNKED
	lea	rdi,[r15+H_CK]
	xor	eax,eax
	mov	ecx,CK_SIZE
	rep	stosb
	jmp	.route
.length:
	mov	rax,[r14+HM_LENGTH]
	cmp	rax,-1
	je	.route
	test	rax,rax
	jz	.route
	mov	dword [r15+H_BODY],BK_LENGTH
	mov	[r15+H_REMAIN],rax
.route:
	cmp	dword [r15+H_BODY],BK_NONE
	jne	@f
	or	dword [r15+H_FLAGS],HX_NOBODY
	jmp	.framed
@@:
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	.framed
	mov	edi,400				; an upgrade carrying a body: ambiguous
	jmp	http_error
.framed:
	test	dword [r14+HM_FLAGS],HMF_CONTINUE
	jz	@f
	cmp	dword [r15+H_BODY],BK_NONE
	je	@f
	or	dword [r15+H_FLAGS],HX_CONTINUE
@@:
	call	http_sni_host_check
	jc	.misdirected
	test	dword [r15+H_FLAGS],HX_MIRROR	; `auth forward` asks: not a route's
	jz	.routing
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_FWD
	jz	.routing
	mov	dword [r15+H_ACT],0
	mov	rax,[r15+H_BUF]
	mov	r13d,[rax+HB_MIRS]
	jmp	.pool_chosen
.routing:
	call	acme_challenge			; /.well-known/acme-challenge/: okena's own
	test	rax,rax
	jnz	acme_answer
	call	acme_redirect			; then a name from the CA: to https (acmeauto.inc)
	call	http_route			; eax = route entry, -1 none, -2 unsafe path
	cmp	eax,-1
	je	.no_route
	cmp	eax,-2
	je	.parse_error_400
	imul	rcx,rax,RT_SIZE
	lea	rcx,[g_routes+rcx]
	cmp	dword [rcx+RT_MATCH],0
	je	@f
	call	match_pick
	h_rec
@@:
	mov	edx,[rcx+RT_ACT]
	mov	[r15+H_ACT],edx
	test	dword [r15+H_FLAGS],HX_MIRROR
	jz	.not_copy
	mov	rax,[r15+H_BUF]
	mov	r13d,[rax+HB_MIRS]
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_CREF
	jz	.pool_chosen
	call	cache_refetch
	jmp	.pool_chosen
.not_copy:
	push	rax				; (RFC 8586: round in circles)
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	call	cdnloop_check
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
	jc	.loop
	call	maint_check			; `okena maintenance on`: 503, unless let through
	jc	.maintenance
	test	edx,edx
	jnz	.has_action
	cmp	dword [g_overload],3		; no action: normal
	jb	.no_action
	mov	r9,rcx
	xor	edx,edx
	call	overload_refuses
	mov	rcx,r9
	jc	.shed
.no_action:
	jmp	.chosen_none
.maintenance:
	mov	edi,503
	jmp	http_error
.loop:
	mov	edi,508
	jmp	http_error
.shed:
	mov	qword [g_lim_retry],1
	mov	dword [g_lim_status],503
	jmp	limit_refuse
.has_action:
	dec	edx
	imul	rdx,rdx,RA_SIZE
	mov	eax,[g_acts+rdx+RA_ACL]		; who may ask at all
	test	eax,eax
	jz	.no_acl
	call	acl_check
	jnc	.no_acl
	mov	edi,403
	jmp	http_error
.no_acl:
	cmp	dword [g_acts+rdx+RA_CORS],0	; cors: a preflight costs nobody anything
	je	.no_cors
	push	rax
	push	rcx
	push	rdx
	mov	edi,[g_acts+rdx+RA_CORS]
	dec	edi
	call	cors_request
	mov	edi,eax
	pop	rdx
	pop	rcx
	pop	rax
	test	edi,edi
	jnz	cors_preflight
	h_rec
.no_cors:
	mov	eax,[g_acts+rdx+RA_SIGNED]	; signed_urls: a link the origin signed
	test	eax,eax
	jz	.no_signed
	call	signed_check
	jnc	.no_signed
	mov	edi,403
	jmp	http_error
.no_signed:
	cmp	dword [g_acts+rdx+RA_AUTH],0	; auth: who it is
	je	.no_auth
	push	rax
	push	rcx
	push	rdx
	mov	edi,[g_acts+rdx+RA_AUTH]
	dec	edi
	call	auth_check
	pop	rdx
	pop	rcx
	pop	rax
	jc	auth_refuse
	h_rec
.no_auth:
	cmp	dword [g_overload],3		; (a route with no action: below)
	jb	.not_shed
	mov	r8,rdx
	mov	r9,rcx
	mov	edx,[r15+H_ACT]
	call	overload_refuses
	mov	rdx,r8
	mov	rcx,r9
	jc	.shed
.not_shed:
	cmp	dword [g_acts+rdx+RA_LCOUNT],0	; rate limits: the cheapest refusal first
	je	.limited
	test	dword [r15+H_FLAGS],HX_FAULTED	; (counted before it waited)
	jnz	.limited
	push	rax
	push	rcx
	push	rdx
	mov	edi,[g_acts+rdx+RA_LFIRST]
	mov	esi,[g_acts+rdx+RA_LCOUNT]
	call	limit_request
	pop	rdx
	pop	rcx
	pop	rax
	jc	limit_over
	h_rec
.limited:
	cmp	dword [g_acts+rdx+RA_RMAP],0
	je	@f
	call	rm_check
	jc	http_redirect
@@:
	cmp	dword [g_acts+rdx+RA_CODE],0
	jne	http_redirect
	cmp	dword [g_acts+rdx+RA_FPCT],0	; fault: this share of the requests
	je	@f
	mov	r8,rdx
	mov	r9,rcx
	test	dword [r15+H_FLAGS],HX_FAULTED
	jnz	.fault_answer			; (it is back from waiting)
	rdtsc
	imul	eax,eax,0x9E3779B1
	mov	ecx,100
	mul	ecx				; edx: 0 .. 99
	mov	rcx,r9
	cmp	edx,[g_acts+r8+RA_FPCT]
	jae	@f
	mov	rax,[g_acts+r8+RA_FDELAY]
	test	rax,rax
	jz	.fault_answer
	cmp	dword [g_fd_n],FD_MAX
	jb	fault_hold			; (all held already: it goes on at once)
.fault_answer:
	mov	rcx,r9
	mov	edi,[g_acts+r8+RA_FCODE]
	test	edi,edi
	jnz	http_error
.chosen_none:
@@:
	mov	r13d,[rcx+RT_POOL]
	mov	[g_c_pool],r13d
	push	rcx
	call	zip_request
	call	hints_request
	pop	rcx
	push	rcx
	call	idem_check
	pop	rcx
	test	eax,eax
	jz	@f
	ret
@@:
	push	rcx
	call	cache_check
	pop	rcx
	test	eax,eax
	jz	@f
	ret
@@:
	push	rcx
	call	files_check
	pop	rcx
	test	eax,eax
	jz	@f
	ret
@@:
	mov	eax,[r15+H_ACT]			; split: another pool, perhaps
	test	eax,eax
	jz	.its_pool
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	edi,[g_acts+rax+RA_SPLIT]
	test	edi,edi
	jz	.its_pool
	call	split_pick
	mov	r13d,eax
.its_pool:
	mov	eax,[r15+H_ACT]			; mirror: a copy to another pool
	test	eax,eax
	jz	.pool_chosen
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_MPCT],0
	je	.pool_chosen
	lea	rdi,[g_acts+rax]
	call	mirror_spawn
	h_rec
.pool_chosen:
	test	dword [r15+H_FLAGS],HX_MIRROR	; hedge: a time for the second try
	jnz	.not_hedged
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.not_hedged
	dec	eax
	imul	rax,rax,RA_SIZE
	lea	rdi,[g_acts+rax]
	mov	rcx,[rdi+RA_HAFTER]
	or	ecx,[rdi+RA_HPCT]
	jz	.not_hedged
	call	hedge_arm
	h_rec
.not_hedged:
	add	dword [g_retry_tokens+r13*4],RETRY_PER_REQ	; the pool's budget grows with its traffic
	cmp	dword [g_retry_tokens+r13*4],RETRY_CAP
	jbe	@f
	mov	dword [g_retry_tokens+r13*4],RETRY_CAP
@@:
	mov	eax,r13d			; FastCGI: HB_FCGI (fastcgi.inc)
	call	fcgi_mark
	call	session_ptr
	mov	[rax+S_POOL],r13d
	mov	dword [rax+S_TRIES],0
	test	dword [r15+H_FLAGS],HX_HEDGE	; (a hedge: S_SERVER, the one to avoid)
	jnz	@f
	mov	dword [rax+S_SERVER],NIL
@@:
	h_rec
	call	http_write_request_head
	jc	.head_too_large
	call	fcgi_active
	test	eax,eax
	jz	@f
	call	fcgi_head			; its records, in place of the head
	jc	.head_too_large
@@:
	test	dword [r15+H_FLAGS],HX_CONTINUE
	jz	.connect
	; the client waits for 100 Continue before sending its body: say it
	; now (the Expect field is not forwarded)
	mov	dword [r15+H_STATE],HS_CONTINUE
	cstring str_100, 'HTTP/1.1 100 Continue',13,10,13,10
	mov	ecx,SIDE_CLIENT
	lea	rdi,[str_100]
	mov	esi,str_100.len
	jmp	h_send
.connect:
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect
.parse_error:
	mov	edi,eax
	cmp	eax,400
	jne	http_error
	cmp	dword [g_hm+HM_MLEN],7		; CONNECT: no tunnels here (forward proxy is
	jne	http_error			; a route's), not a malformed request
	mov	rax,[g_hm+HM_METHOD]
	cmp	dword [rax],'CONN'
	jne	http_error
	cmp	dword [rax+3],'NECT'
	jne	http_error
	mov	edi,405
	jmp	http_error
.no_route:
	mov	edi,404
	jmp	http_error
.misdirected:
	mov	edi,421				; this connection's certificate is another host's
	jmp	http_error
.parse_error_400:
	mov	edi,400
	jmp	http_error
.head_too_large:
	mov	edi,431
	jmp	http_error

; The route for g_hm on the session's listener: an exact path beats a
; prefix, a longer prefix beats a shorter one, methods must match.
; ebx = session. eax = pool or -1.
http_route:
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	lea	rax,[g_listeners+rax]
; rax = the listener (okena route has no session)
http_route_on:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rax
	; the path: the target up to '?', after "http://host" in absolute form
	lea	r13,[g_hm]
	mov	rsi,[r13+HM_TARGET]
	mov	edx,[r13+HM_PLEN]
	cmp	byte [rsi],'/'
	je	.path
	cmp	byte [rsi],'*'
	je	.path
	add	rsi,7				; "http://"
	sub	edx,7
@@:
	test	edx,edx
	jz	.root
	cmp	byte [rsi],'/'
	je	.path
	inc	rsi
	dec	edx
	jmp	@b
.root:
	cstring str_slash, '/'
	lea	rsi,[str_slash]
	mov	edx,1
.path:
	mov	dword [g_npath_len],0		; (a "*" target has no path to keep)
	cmp	byte [rsi],'/'
	jne	@f				; "*" (OPTIONS *): nothing to normalize
	mov	rdi,rsi
	mov	esi,edx
	call	path_normalize			; routes match the normalized path
	mov	[g_npath_len],edx
	jnc	@f
	mov	eax,-2
	jmp	.done
@@:
	mov	r14,rsi				; path
	mov	r15d,edx
	call	http_route_set			; ecx/r9d = the routes of the host
	mov	rdi,[r13+HM_METHOD]
	mov	esi,[r13+HM_MLEN]
	call	method_bit
	mov	r13d,eax			; method bit
	; one pass over the path: the hash state after each '/' is the hash
	; of that prefix; the exact path is the full one
	mov	edi,[g_rset_first]
	call	rhash_seed
	xor	ecx,ecx
	xor	r10d,r10d			; prefixes seen
.walk:
	cmp	ecx,r15d
	jae	.walked
	movzx	edx,byte [r14+rcx]
	xor	eax,edx
	imul	eax,eax,16777619
	inc	ecx
	cmp	dl,'/'
	jne	.walk
	cmp	r10d,PFX_MAX
	jae	.walk				; (deeper prefixes than any route can name)
	mov	[g_pfx_hash+r10*4],eax
	mov	[g_pfx_len+r10*4],ecx
	inc	r10d
	jmp	.walk
.walked:
	xor	ecx,ecx				; the exact path first: nothing beats it
	mov	edx,r15d
	push	r10
	call	route_lookup
	pop	r10
	cmp	eax,-1
	jne	.done
	cmp	dword [g_plan_rxroutes],0	; then regexes, in the order written
	je	.pfx
	push	r10
	call	route_regex
	pop	r10
	cmp	eax,-1
	jne	.done
.pfx:
	dec	r10d				; then prefixes, the longest first
	js	.none
	mov	eax,[g_pfx_hash+r10*4]
	mov	edx,[g_pfx_len+r10*4]
	mov	ecx,1
	push	r10
	call	route_lookup
	pop	r10
	cmp	eax,-1
	je	.pfx
	jmp	.done
.none:
	mov	eax,-1
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; In http_route_on: the first route of the set whose regex (~) matches the
; normalized path and whose methods the request's are; r13d = the method bit.
; eax = it, or -1. Its captures in g_rx_cap.
route_regex:
	push	rbx
	push	r12
	mov	ebx,[g_rset_first]
	mov	r12d,ebx
	add	r12d,[g_rset_count]
.route:
	cmp	ebx,r12d
	jae	.none
	imul	rcx,rbx,RT_SIZE
	lea	rcx,[g_routes+rcx]
	movzx	eax,byte [rcx+RT_PREFIX]
	cmp	eax,2
	jne	.next
	mov	eax,[rcx+RT_METHODS]
	test	eax,eax
	jz	@f
	test	eax,r13d
	jz	.next
@@:
	mov	eax,[rcx+RT_PREFIX]		; (2 | the regex << 8)
	shr	eax,8
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	call	rx_match
	test	eax,eax
	jnz	.found
.next:
	inc	ebx
	jmp	.route
.found:
	mov	eax,ebx
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r12
	pop	rbx
	ret

; rdi/esi = path (starts with '/'). rsi/edx = the form routes are
; matched on, in g_npath; CF when the path cannot be normalized safely.
;   %XX of an unreserved character (A-Z a-z 0-9 - . _ ~) is decoded,
;   other %XX kept with upper-case hex; %XX of '/', '\' or a control
;   byte is refused (the backend could split or join segments on it);
;   a raw '\' is refused; "//" is one '/'; a "." or ".." segment
;   (decoded ones included) is refused, so /public/../admin can never
;   match /public/* while the backend serves /admin;
;   a segment's parameters (";..." up to the next '/') are not part of it,
;   as servlet containers drop them: /admin;x/y is /admin/y, "..;" is "..";
;   overlong UTF-8 (%C0%AE is a '.' to a careless decoder) is refused.
; The target forwarded is still the original one.
path_normalize:
	lea	r8,[g_npath]
	xor	ecx,ecx				; input index
	xor	r9d,r9d				; output length
.byte:
	cmp	ecx,esi
	jae	.segments
	movzx	eax,byte [rdi+rcx]
	inc	ecx
	cmp	al,'\'
	je	.bad
	cmp	al,'/'
	je	.slash
	cmp	al,';'
	je	.params
	cmp	al,'%'
	jne	.put
	; %XX
	lea	edx,[rcx+2]
	cmp	edx,esi
	ja	.bad
	movzx	eax,byte [rdi+rcx]
	call	.hex
	jc	.bad
	mov	r10d,eax
	movzx	eax,byte [rdi+rcx+1]
	call	.hex
	jc	.bad
	shl	r10d,4
	or	eax,r10d
	add	ecx,2
	cmp	al,0xC0
	jb	.not_overlong
	cmp	al,0xC1
	jbe	.bad				; a 2-byte form of an ASCII byte
	cmp	al,0xE0
	je	.lead3
	cmp	al,0xF0
	jne	.not_overlong
	mov	r11d,0x90			; F0 then under 90: a 3-byte one in 4
	jmp	.lead
.lead3:
	mov	r11d,0xA0			; E0 then under A0: a 2-byte one in 3
.lead:
	push	rax
	call	.next_hex
	jc	@f
	cmp	eax,r11d
	jb	.bad_pop
@@:
	pop	rax
.not_overlong:
	cmp	al,'/'
	je	.bad
	cmp	al,'\'
	je	.bad
	cmp	al,0x20
	jb	.bad
	cmp	al,0x7F
	je	.bad
	call	.unreserved
	jnc	.put				; decoded
	mov	byte [r8+r9],'%'		; kept encoded, canonical case
	mov	edx,eax
	shr	edx,4
	mov	dl,[hex_upper+rdx]
	mov	[r8+r9+1],dl
	and	eax,15
	mov	al,[hex_upper+rax]
	mov	[r8+r9+2],al
	add	r9d,3
	jmp	.byte
.params:
	; ";..." to the next '/': not part of the segment
	cmp	ecx,esi
	jae	.segments
	cmp	byte [rdi+rcx],'/'
	je	.byte
	inc	ecx
	jmp	.params
.bad_pop:
	pop	rax
	jmp	.bad
; the %XX at ecx, if there is one: eax = its value, CF when none
.next_hex:
	lea	edx,[rcx+3]
	cmp	edx,esi
	ja	.none
	cmp	byte [rdi+rcx],'%'
	jne	.none
	movzx	eax,byte [rdi+rcx+1]
	call	.hex
	jc	.none
	mov	edx,eax
	shl	edx,4
	movzx	eax,byte [rdi+rcx+2]
	call	.hex
	jc	.none
	or	eax,edx
	clc
	ret
.none:
	stc
	ret
.slash:
	test	r9d,r9d
	jz	.put
	cmp	byte [r8+r9-1],'/'
	je	.byte				; "//" -> "/"
.put:
	mov	[r8+r9],al
	inc	r9d
	jmp	.byte
.segments:
	; refuse "." and ".." segments
	xor	ecx,ecx
.seg:
	cmp	ecx,r9d
	jae	.ok
	cmp	byte [r8+rcx],'/'
	jne	.seg_next
	lea	edx,[rcx+1]			; segment start
	cmp	edx,r9d
	jae	.ok
	cmp	byte [r8+rdx],'.'
	jne	.seg_next
	inc	edx
	cmp	edx,r9d
	jae	.bad				; "/." at the end
	cmp	byte [r8+rdx],'/'
	je	.bad				; "/./"
	cmp	byte [r8+rdx],'.'
	jne	.seg_next
	inc	edx
	cmp	edx,r9d
	jae	.bad				; "/.." at the end
	cmp	byte [r8+rdx],'/'
	je	.bad				; "/../"
.seg_next:
	inc	ecx
	jmp	.seg
.ok:
	mov	rsi,r8
	mov	edx,r9d
	clc
	ret
.bad:
	stc
	ret
; al = hex digit -> eax = value, CF when not one
.hex:
	cmp	al,'0'
	jb	.nothex
	cmp	al,'9'
	jbe	.digit
	or	al,0x20
	cmp	al,'a'
	jb	.nothex
	cmp	al,'f'
	ja	.nothex
	sub	al,'a'-10
	clc
	ret
.digit:
	sub	al,'0'
	clc
	ret
.nothex:
	stc
	ret
; al: CF clear when unreserved
.unreserved:
	cmp	al,'-'
	je	.yes
	cmp	al,'.'
	je	.yes
	cmp	al,'_'
	je	.yes
	cmp	al,'~'
	je	.yes
	cmp	al,'0'
	jb	.no
	cmp	al,'9'
	jbe	.yes
	cmp	al,'A'
	jb	.no
	cmp	al,'Z'
	jbe	.yes
	cmp	al,'a'
	jb	.no
	cmp	al,'z'
	jbe	.yes
.no:
	stc
	ret
.yes:
	clc
	ret

rodata
	hex_upper	db '0123456789ABCDEF'
end rodata

; eax = hash state of the path's first edx bytes, ecx = 1 prefix / 0
; exact, r14 = path, r13d = the request's method bit, g_rset_* = the
; route set. eax = the pool of the route it names, or -1.
route_lookup:
	push	rdx
	call	rhash_final
	pop	rdx
	mov	r11d,eax
.probe:
	and	eax,RHASH_SIZE - 1
	mov	r10,[g_rhash+rax*8]
	test	r10,r10
	jz	.miss
	cmp	r10d,r11d
	jne	.next
	shr	r10,32
	dec	r10d				; route entry
	mov	r9d,r10d
	sub	r9d,[g_rset_first]
	cmp	r9d,[g_rset_count]
	jae	.next				; another set's
	imul	r8,r10,RT_SIZE
	lea	r8,[g_routes+r8]
	cmp	[r8+RT_PREFIX],ecx
	jne	.next
	cmp	[r8+RT_PLEN],edx
	jne	.next
	mov	r9d,[r8+RT_METHODS]
	test	r9d,r9d
	jz	@f
	test	r9d,r13d
	jz	.next				; another method's: the chain goes on
@@:
	push	rax
	push	rcx
	push	rdx
	push	r8
	push	r11
	mov	rdi,[r8+RT_PATH]
	mov	rsi,r14
	call	mem_eq
	pop	r11
	pop	r8
	pop	rdx
	pop	rcx
	test	eax,eax
	pop	rax
	jz	.next
	mov	eax,r10d			; the route entry
	ret
.next:
	inc	eax
	jmp	.probe
.miss:
	mov	eax,-1
	ret

PFX_MAX		:= 256
bss
	g_pfx_hash	rd PFX_MAX
	g_pfx_len	rd PFX_MAX
	g_npath_len	dd ?
	g_npath		rb H_IN_CAP
	g_rset_first	dd ?
	g_rset_count	dd ?
end bss

; The route set for g_hm's Host on listener r12: an exact host name,
; else the longest wildcard suffix, else the listener's own routes.
; Sets g_rset_first/count. Keeps r12-r15.
http_route_set:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	eax,[r12+LS_RFIRST]
	mov	[g_rset_first],eax
	mov	eax,[r12+LS_RCOUNT]
	mov	[g_rset_count],eax
	cmp	dword [r12+LS_HCOUNT],0
	je	.done
	lea	rax,[g_hm]
	mov	ecx,[rax+HM_HOST]
	cmp	ecx,-1
	je	.done
	imul	rcx,rcx,HF_SIZE
	lea	rcx,[rax+HM_HDRS+rcx]
	mov	r13,[rcx+HF_VALUE]
	mov	r14d,[rcx+HF_VLEN]
	; without its port ("[::1]:80" keeps its brackets)
	mov	ecx,r14d
@@:
	test	ecx,ecx
	jz	.portless
	dec	ecx
	cmp	byte [r13+rcx],']'
	je	.portless
	cmp	byte [r13+rcx],':'
	jne	@b
	mov	r14d,ecx
.portless:
	; a trailing dot names the same host
	test	r14d,r14d
	jz	.done
	cmp	byte [r13+r14-1],'.'
	jne	@f
	dec	r14d
@@:
	; the exact name: one lookup
	mov	rsi,r13
	mov	edx,r14d
	xor	ecx,ecx
	call	host_find
	test	rcx,rcx
	jnz	.use
	; ".example.com" matches "a.example.com" and "b.a.example.com", not
	; "example.com": one lookup per label, the longest suffix first
	xor	ebx,ebx
.dot:
	inc	ebx				; a label before the dot
	cmp	ebx,r14d
	jae	.wild_done
	cmp	byte [r13+rbx],'.'
	jne	.dot
	lea	rsi,[r13+rbx]
	mov	edx,r14d
	sub	edx,ebx
	mov	ecx,1
	call	host_find
	test	rcx,rcx
	jz	.dot
.use:
	mov	eax,[rcx+HO_RFIRST]
	mov	[g_rset_first],eax
	mov	eax,[rcx+HO_RCOUNT]
	mov	[g_rset_count],eax
.wild_done:
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12 = listener, rsi/edx = name, ecx = 1 for a wildcard suffix. rcx =
; its host entry, or 0. Keeps rbx, r12-r15.
host_find:
	push	rsi
	push	rdx
	push	rcx
	mov	edi,[r12+LS_HFIRST]
	call	host_hash
	mov	r11d,eax			; hash
	pop	rcx
	pop	rdx
	pop	rsi
.probe:
	and	eax,HHASH_SIZE - 1
	mov	r10,[g_hhash+rax*8]
	test	r10,r10
	jz	.none
	cmp	r10d,r11d
	jne	.next
	mov	r9,r10
	shr	r9,32
	dec	r9d				; host entry
	mov	r8d,r9d
	sub	r8d,[r12+LS_HFIRST]
	cmp	r8d,[r12+LS_HCOUNT]
	jae	.next				; another listener's
	imul	r9,r9,HO_SIZE
	lea	r9,[g_hosts+r9]
	cmp	[r9+HO_WILD],ecx
	jne	.next
	cmp	[r9+HO_NLEN],edx
	jne	.next
	push	rax
	push	rcx
	push	rdx
	push	rsi
	push	r9
	push	r11
	mov	rdi,[r9+HO_NAME]
	call	mem_eq_nocase
	pop	r11
	pop	r9
	pop	rsi
	pop	rdx
	pop	rcx
	test	eax,eax
	pop	rax
	jz	.next
	mov	rcx,r9
	ret
.next:
	inc	eax
	jmp	.probe
.none:
	xor	ecx,ecx
	ret

; OUT = the request head okena sends upstream. ebx = session, r15 =
; record, g_hm = the parsed request. CF when it does not fit.
http_write_request_head:
	push	rbx
	push	r12
	push	r13
	push	r14
	call	gweb_pool			; (gRPC-Web to an HTTP/2 pool: gRPC)
	lea	r12,[g_hm]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	r13,[r15+H_BUF]	; room kept for what okena adds
	lea	r13,[r13+HB_OUT+H_OUT_CAP-256]
	mov	rsi,[r12+HM_METHOD]
	mov	ecx,[r12+HM_MLEN]
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	; origin form towards the backend
	mov	rsi,[r12+HM_TARGET]
	mov	ecx,[r12+HM_TLEN]
	cmp	byte [rsi],'/'
	je	.target
	cmp	byte [rsi],'*'
	je	.target
	add	rsi,7
	sub	ecx,7
@@:
	test	ecx,ecx
	jz	.slash
	cmp	byte [rsi],'/'
	je	.target
	inc	rsi
	dec	ecx
	jmp	@b
.slash:
	mov	byte [rdi],'/'
	inc	rdi
	jmp	.version
.target:
	call	http_rewrite_target		; the route's rewrite, if it applies
	jnc	.version
	rep	movsb
.version:
	mov	rax,' HTTP/1.'
	mov	[rdi],rax
	mov	dword [rdi+8],0x0A0D31		; "1\r\n"
	add	rdi,11
	push	rdi
	call	http_client_resolve
	pop	rdi
	; fields, except hop-by-hop ones and those okena writes itself
	xor	ebx,ebx
.field:
	cmp	ebx,[r12+HM_NHDR]
	jae	.own
	imul	r14,rbx,HF_SIZE
	lea	r14,[r12+HM_HDRS+r14]
	test	dword [r14+HF_FLAGS],HFF_HOP
	jz	.end_to_end
	; hop-by-hop, but an upgrade carries its Upgrade field to the backend
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	.skip
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_upgrade]
	call	hf_is
	pop	rdi
	jnz	.skip
	jmp	.copy
.end_to_end:
	call	trace_drops			; (the client's traceparent: ours goes)
	je	.skip
	push	rdi				; (what `auth` keeps from the backend)
	mov	rdi,r14
	call	auth_hides
	pop	rdi
	je	.skip
	push	rdi				; (a slice's copy: the client's Range)
	call	slice_drops
	pop	rdi
	je	.skip
	; the route's header changes: a field it sets or drops is not copied
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	@f
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	esi,[g_acts+rax+RA_QFIRST]
	mov	edx,[g_acts+rax+RA_QCOUNT]
	test	edx,edx
	jz	@f
	push	rdi
	mov	rdi,r14
	call	hdrop_skip
	pop	rdi
	jc	.skip
@@:
	; from a trusted proxy, its X-Forwarded-Proto and -Host stand (its
	; X-Forwarded-For is merged below)
	test	dword [r15+H_FLAGS],HX_TRUSTED
	jz	.untrusted
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_x_forwarded_proto]
	call	hf_is
	pop	rdi
	jnz	@f
	or	dword [r15+H_FLAGS],HX_XFPROTO
	jmp	.copy
@@:
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_x_forwarded_host]
	call	hf_is
	pop	rdi
	jz	.copy
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_x_request_id]
	call	hf_is
	pop	rdi
	jnz	.untrusted
	test	dword [r15+H_FLAGS],HX_RIDKEPT
	jnz	.skip				; one id: the first valid one
	mov	rsi,[r14+HF_VALUE]
	mov	edx,[r14+HF_VLEN]
	call	rid_valid
	jc	.skip				; not an id we can carry: ours instead
	or	dword [r15+H_FLAGS],HX_RIDKEPT
	push	rdi
	lea	rdi,[r15+H_RID]
	mov	[r15+H_RIDLEN],edx
	mov	ecx,edx
	rep	movsb
	pop	rdi
	jmp	.copy
.untrusted:
	push	rdi
	irp name, hn_x_forwarded_for, hn_x_forwarded_proto, hn_x_forwarded_host, hn_forwarded, hn_expect, hn_x_request_id
		mov	rdi,r14
		lea	rsi,[name]
		call	hf_is
		jz	.skip_pop
	end irp
	pop	rdi
.copy:
	xor	edx,edx				; gRPC-Web: its content-type as gRPC's
	call	gweb_field
	jc	.skip
	mov	eax,[r14+HF_NLEN]
	add	eax,[r14+HF_VLEN]
	add	eax,4
	lea	rcx,[rdi+rax]
	cmp	rcx,r13
	ja	.full
	mov	rsi,[r14+HF_NAME]
	mov	ecx,[r14+HF_NLEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,[r14+HF_VALUE]
	mov	ecx,[r14+HF_VLEN]
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	jmp	.skip
.skip_pop:
	pop	rdi
.skip:
	inc	ebx
	jmp	.field
.own:
	cmp	dword [r12+HM_HOST],-1
	jne	.has_host
	; HTTP/1.0 without Host goes on as HTTP/1.1, which needs one: the address
	; the client reached (as nginx sends the upstream's own name)
	memit_x 'Host: '
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	rsi,[g_listeners+rax+LS_TEXT]
	mov	ecx,[g_listeners+rax+LS_TLEN]
	cmp	ecx,5
	jb	.host_name
	cmp	dword [rsi],'unix'
	je	.host_local
.host_name:
	test	ecx,ecx
	jz	.host_local
	cmp	byte [rsi],':'			; ":8080": every address
	jne	.host_copy
	memit_x 'localhost'
.host_copy:
	rep	movsb
	jmp	.host_done
.host_local:
	memit_x 'localhost'
.host_done:
	memit_x 13,10
.has_host:
	call	auth_emit
	call	slice_range_emit
	call	cdnloop_emit
	call	trace_emit
	test	dword [r15+H_FLAGS],HX_RIDKEPT
	jnz	@f
	push	rdi
	call	rid_new
	pop	rdi
	memit_x 'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
@@:
	mov	eax,[r15+H_ACT]			; the route's set and add
	test	eax,eax
	jz	@f
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	esi,[g_acts+rax+RA_QFIRST]
	mov	edx,[g_acts+rax+RA_QCOUNT]
	call	hdrop_emit
	jc	.full
@@:
	; X-Forwarded-For: what trusted proxies said, then the peer; from
	; anyone else, only the peer, never what the client claims
	memit_x 'X-Forwarded-For: '
	test	dword [r15+H_FLAGS],HX_TRUSTED
	jz	.xff_peer
	xor	ebx,ebx
.xff:
	cmp	ebx,[r12+HM_NHDR]
	jae	.xff_peer
	imul	r14,rbx,HF_SIZE
	lea	r14,[r12+HM_HDRS+r14]
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_x_forwarded_for]
	call	hf_is
	pop	rdi
	jnz	.xff_next
	mov	ecx,[r14+HF_VLEN]
	test	ecx,ecx
	jz	.xff_next
	lea	rax,[rdi+rcx+2]
	cmp	rax,r13
	ja	.full
	mov	rsi,[r14+HF_VALUE]
	rep	movsb
	mov	word [rdi],', '
	add	rdi,2
.xff_next:
	inc	ebx
	jmp	.xff
.xff_peer:
	mov	rbx,[rsp+24]			; the session (pushed rbx)
	call	peer_ptr
	push	rdi
	lea	rdi,[g_ip_a]
	lea	rsi,[rax+P_PEER]
	call	peer_normalize
	pop	rdi
	lea	rsi,[g_ip_a]
	mov	edx,eax
	call	fmt_ip
	memit_x 13,10
	h_rec
	test	dword [r15+H_FLAGS],HX_XFPROTO
	jnz	@f
	memit_x 'X-Forwarded-Proto: http'
	call	http_tls_cred
	test	rax,rax
	jz	.xfp_end
	mov	byte [rdi],'s'
	inc	rdi
.xfp_end:
	memit_x 13,10
@@:
	mov	rax,[r15+H_BUF]			; gRPC-Web text: its length changes (decoded)
	cmp	byte [rax+HB_GWEB],4
	je	.conn
	mov	eax,[r15+H_BODY]
	cmp	eax,BK_LENGTH
	jne	@f
	memit_x 'Content-Length: '
	mov	rax,[r15+H_REMAIN]
	call	fmt_u64
	memit_x 13,10
	jmp	.conn
@@:
	cmp	eax,BK_CHUNKED
	jne	.conn
	memit_x 'Transfer-Encoding: chunked',13,10
.conn:
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	@f
	memit_x 'Connection: upgrade',13,10
@@:
	memit_x 13,10				; HTTP/1.1 keep-alive towards the backend
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	[r15+H_OUTLEN],edi
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring hn_x_forwarded_for, 'x-forwarded-for',0
cstring hn_accept_ranges, 'accept-ranges',0
cstring hn_etag, 'etag',0
cstring hn_x_forwarded_proto, 'x-forwarded-proto',0
cstring hn_x_forwarded_host, 'x-forwarded-host',0
cstring hn_forwarded, 'forwarded',0
cstring hn_x_request_id, 'x-request-id',0

; Request ids: a random 64-bit base per worker plus a counter, as 16 hex
; digits. No system call, unique in practice across workers and
; restarts.
bss
	g_rid_next	dq ?
end bss

; r15 = record: a fresh id in H_RID. Keeps rbx and r12-r15.
rid_new:
	mov	rax,[g_rid_next]
	inc	qword [g_rid_next]
	lea	rdi,[r15+H_RID+15]
	mov	ecx,16
@@:
	mov	edx,eax
	and	edx,15
	mov	dl,[hex_digits+rdx]
	mov	[rdi],dl
	dec	rdi
	shr	rax,4
	dec	ecx
	jnz	@b
	mov	dword [r15+H_RIDLEN],16
	ret

; rsi/edx = a client's id: CF unless 1 .. RID_MAX bytes of
; A-Z a-z 0-9 - _ . : (nothing a log or a header could be split on).
rid_valid:
	test	edx,edx
	jz	.bad
	cmp	edx,RID_MAX
	ja	.bad
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.ok
	movzx	eax,byte [rsi+rcx]
	inc	ecx
	cmp	al,':'
	je	.next
	call	path_normalize.unreserved	; - . _ ~ and alphanumerics
	jnc	.next
.bad:
	stc
	ret
.ok:
	clc
	ret


; ------------------------------------------------------------- engine

; The upstream is connected: send the request head.
http_connected:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2U
	jnz	h2u_ready			; an upstream HTTP/2 connection is up
	h_rec
	mov	dword [r15+H_STATE],HS_SEND_HEAD
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	h_send

; A pooled connection failed before any response byte: the backend
; closed it as okena reused it. A request without a body is sent again
; on a new connection; anything else is a 502. Does not return when it
; retries.
http_retry_fresh:
	h_rec
	test	dword [r15+H_FLAGS],HX_REUSED
	jz	.no
	test	dword [r15+H_FLAGS],HX_NOBODY
	jz	.no
	add	rsp,8				; we do not return
	and	dword [r15+H_FLAGS],not HX_REUSED
	or	dword [r15+H_FLAGS],HX_NOPOOL
	call	h_upclose
	h_rec
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect
.no:
	ret

; No server could be reached.
http_connect_failed:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2U
	jnz	h2u_failed			; an upstream HTTP/2 connection: its requests fail over
	call	hold_wait
	jnc	@f
	ret
@@:
	h_rec
	call	idem_release			; nothing reached a backend
	mov	edi,502
	cmp	dword [g_pick_full],0
	je	@f
	mov	edi,503				; there are servers, all full
@@:
	jmp	http_error

; ebx = session, ecx = side, rax = bytes read (0 = end, < 0 = error).
http_recv_done:
	h_rec
	test	ecx,ecx
	jz	@f
	push	rax
	call	fcgi_active
	test	eax,eax
	pop	rax
	jnz	fcgi_rx_done			; FastCGI records arrived
	jmp	http_recv_plain
@@:
	cmp	dword [r15+H_UTLS],0
	jne	utls_rx_done			; ciphertext arrived
; the same, with plaintext (or no TLS)
http_recv_plain:
	h_rec
	mov	edx,[r15+H_STATE]
	cmp	edx,HS_HEDGED
	je	.dropped			; (its old backend, late)
	cmp	edx,HS_HEAD
	je	.head
	cmp	edx,HS_REQ_READ
	je	.body
	cmp	edx,HS_RESP_HEAD
	je	.resp_head
	cmp	edx,HS_RESP_READ
	je	.resp_body
	cmp	edx,HS_TLS_HELLO
	je	http_tls_hello_in
	cmp	edx,HS_TLS_FIN
	je	http_tls_fin_peeked
	cmp	edx,HS_TLS_TAKE
	je	http_tls_fin_in
	cmp	edx,HS_PT_HELLO
	je	http_pt_in
	jmp	.past_pt
.dropped:
	ret
.past_pt:
	cmp	edx,HS_UTLS_FLIGHT
	je	http_uptls_flight_in
	cmp	edx,HS_UTLS12_RX
	je	http_uptls12_rx
	cmp	edx,HS_TLS12_FIN
	je	http_tls12_fin
	cmp	edx,HS_H2TUN
	je	http_h2tun_recv
	cmp	edx,HS_LINGER
	je	.linger
	ret
.linger:
	test	rax,rax
	jg	http_linger_read
	mov	edi,ebx				; the client is done too
	jmp	session_close
.head:
	test	rax,rax
	jle	.client_gone			; the client is done
	add	[r15+H_INLEN],eax
	push	rax
	mov	edi,ebx
	call	idle_touch
	call	session_ptr
	cmp	dword [rax+S_PH_KIND],PH_HEAD
	je	@f
	mov	edi,ebx				; the first bytes of a request
	mov	esi,PH_HEAD
	call	ph_arm
@@:
	h_rec
	pop	rax
	jmp	http_next_request.parse
.body:
	test	rax,rax
	jle	.client_gone			; went away in the middle of its body
	add	[r15+H_INLEN],eax
	test	dword [r15+H_FLAGS],HX_TEE
	jz	.body_kept
	mov	ecx,eax
	mov	esi,[r15+H_INLEN]
	sub	esi,eax
	add	rsi,[r15+H_BUF]
	add	rsi,HB_IN
	call	mirror_tee
.body_kept:
	mov	edi,ebx
	call	idle_touch
	jmp	http_req_pump
.resp_head:
	test	rax,rax
	jg	@f
	cmp	dword [r15+H_UPLEN],0
	jne	.bad_gateway
	call	http_retry_fresh		; returns only when it may not retry
	call	http_gateway_failed		; or elsewhere, within the budget
	jmp	.bad_gateway
@@:
	add	[r15+H_UPLEN],eax
	mov	edi,ebx
	call	idle_touch
	jmp	http_resp_head
.resp_body:
	test	rax,rax
	jz	.upstream_end
	js	.abort
	add	[r15+H_UPLEN],eax
	mov	edi,ebx
	call	idle_touch
	jmp	http_resp_pump
.upstream_end:
	; the end of a body delimited by close is fine; any other is not
	cmp	dword [r15+H_RBODY],BK_CLOSE
	jne	.abort
	mov	dword [r15+H_RBODY],BK_NONE
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jnz	http_last_chunk
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jz	http_exchange_done
	jmp	http_last_chunk
.client_gone:
.abort:
	mov	edi,ebx
	jmp	session_close
.bad_gateway:
	mov	edi,502
	jmp	http_error

; ebx = session, ecx = side, rax = 0 or negative (the send failed).
http_send_done:
	h_rec
	test	ecx,ecx
	jnz	http_send_plain
	cmp	dword [r15+H_UTLS],0
	jne	utls_tx_done			; records went out
http_send_plain:
	h_rec
	test	rax,rax
	js	.failed
	mov	edx,[r15+H_STATE]
	cmp	edx,HS_HEDGED
	je	.hedged
	cmp	edx,HS_CONTINUE
	je	.continued
	cmp	edx,HS_SEND_HEAD
	je	http_req_pump
	cmp	edx,HS_REQ_SEND
	je	http_req_pump
	cmp	edx,HS_RESP_SEND
	je	.resp
	cmp	edx,HS_ERROR_SEND
	je	.error_sent
	cmp	edx,HS_TUNNEL_UP
	je	http_tunnel_in
	cmp	edx,HS_TUNNEL_IN
	je	http_tunnel_start
	cmp	edx,HS_INTERIM_SEND
	je	.interim_sent
	cmp	edx,HS_SELF_SEND
	je	.self_sent
	cmp	edx,HS_TLS_FLIGHT
	je	http_tls_flight_sent
	cmp	edx,HS_TLS_RETRY
	je	http_tls_retry_sent
	cmp	edx,HS_TLS_ALERT
	je	.close
	cmp	edx,HS_TLS_NST
	je	http_tls_fin_keys		; client_ca's ticket out: the keys now
	cmp	edx,HS_FC_END
	je	http_start_response		; (FastCGI: the body's end is out)
	cmp	edx,HS_UTLS_HELLO
	je	http_uptls_hello_sent
	cmp	edx,HS_UTLS_FIN
	je	http_uptls_fin_sent
	cmp	edx,HS_UTLS12_FIN
	je	http_uptls12_fin_sent
	cmp	edx,HS_TLS12_FLIGHT
	je	http_tls12_flight_sent
	cmp	edx,HS_TLS12_FIN2
	je	http_tls12_fin2_sent
	cmp	edx,HS_H2TUN
	je	http_h2tun_read			; (its sends to the client: the next read)
	ret
.hedged:
	test	ecx,ecx
	jz	hedge_sent			; (its old backend: nothing to it now)
	ret
.self_sent:
	test	dword [r15+H_FLAGS],HX_CLOSE
	jnz	.error_sent			; logged, then closed
	jmp	http_exchange_done
.interim_sent:
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	jmp	http_resp_head			; the next head may be in UP already
.continued:
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect
.resp:
	test	dword [r15+H_FLAGS],HX_LASTCHUNK
	jnz	http_exchange_done
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jnz	http_tunnel_up
	jmp	http_resp_pump
.failed:
	cmp	ecx,SIDE_UP
	jne	.close
	cmp	dword [r15+H_STATE],HS_SEND_HEAD
	jne	@f
	call	http_retry_fresh		; returns only when it may not retry
@@:
	mov	edi,502				; the backend went away under the request
	jmp	http_error
.error_sent:
	mov	esi,1
	call	alog_exchange
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H3S
	jnz	h3s_finish
	test	dword [rax+S_FLAGS],SF_H2S
	jnz	h2s_finish			; the error is the stream's whole answer
	jmp	http_close_notify
.close:
	mov	edi,ebx
	jmp	session_close

; ------------------------------------------------------- request body

; Move the request body upstream, a piece at a time. ebx = session.
http_req_pump:
	h_rec
	cmp	dword [r15+H_STATE],HS_SEND_HEAD
	jne	.pump
	cmp	dword [r15+H_BODY],BK_NONE
	je	.pump
	call	session_ptr			; the head went: HTTP/2 both ends?
	mov	eax,[rax+S_FLAGS]
	and	eax,SF_H2S or SF_UPH2
	cmp	eax,SF_H2S or SF_UPH2
	jne	.pump
	or	dword [r15+H_FLAGS],HX_DUPLEX	; then the response is read at once
	call	http_duplex_pump
	jmp	http_start_response
.pump:
	h_rec
	mov	eax,[r15+H_BODY]
	cmp	eax,BK_LENGTH
	je	.length
	cmp	eax,BK_CHUNKED
	je	.chunked
	jmp	http_start_response
.length:
	cmp	qword [r15+H_REMAIN],0
	je	.done
	mov	ecx,[r15+H_INLEN]
	sub	ecx,[r15+H_INOFF]
	jz	.read
	mov	rax,[r15+H_REMAIN]
	cmp	rax,rcx
	jae	@f
	mov	ecx,eax
@@:
	sub	[r15+H_REMAIN],rcx
	mov	eax,[r15+H_INOFF]
	add	[r15+H_INOFF],ecx
	mov	dword [r15+H_STATE],HS_REQ_SEND
	mov	esi,ecx
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rax]
	mov	ecx,SIDE_UP
	jmp	h_send
.done:
	mov	dword [r15+H_BODY],BK_NONE
	jmp	http_start_response
.read:
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	mov	dword [r15+H_STATE],HS_REQ_READ
	mov	edi,ebx				; more of the body: its clock starts again
	mov	esi,PH_BODY
	call	ph_arm
	h_rec
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,H_IN_CAP
	jmp	h_recv
.chunked:
	lea	rdi,[r15+H_CK]
	mov	eax,[r15+H_INOFF]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	edx,[r15+H_INLEN]
	sub	edx,eax
	call	chunk_step
	add	[r15+H_INOFF],ecx
	cmp	eax,CK_DATAOUT
	je	.chunk_data
	cmp	eax,CK_END
	je	.chunk_end
	cmp	eax,CK_MORE
	je	.read
	mov	edi,400				; a broken chunked body
	jmp	http_error
.chunk_data:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	@f
	mov	dword [r15+H_STATE],HS_REQ_SEND	; a stream: DATA carries it as it is
	mov	ecx,SIDE_UP
	mov	rdi,r8
	mov	esi,r9d
	jmp	h_send
@@:
	call	http_frame_chunk		; r8/r9d: OUT = framed chunk
	mov	dword [r15+H_STATE],HS_REQ_SEND
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	h_send
.chunk_end:
	mov	dword [r15+H_BODY],BK_NONE
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jnz	http_start_response		; a stream: END_STREAM instead
	mov	dword [r15+H_STATE],HS_REQ_SEND
	cstring str_last_chunk, '0',13,10,13,10
	mov	ecx,SIDE_UP
	lea	rdi,[str_last_chunk]
	mov	esi,str_last_chunk.len
	jmp	h_send

; HTTP/2 at both ends (a stream from the client, a stream to the backend):
; the request body goes on beside the response, as gRPC's bidirectional
; streams need (the backend answers messages before the request ends).
; The exchange reads the response; this moves the body from the client
; stream's queue to the upstream stream, decoded as http_req_pump decodes
; it, whenever either can take more: DATA from the client (h2q_serve), the
; upstream window opening (h2u_kick). Its end is END_STREAM upstream.
; ebx = session; keeps every register but rax, rcx, rdx, rsi, rdi, r8-r11.
http_duplex_pump:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.out
	h_rec
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jz	.out
	u2_at	r12, ebx
	test	dword [r12+U2_F],U2F_DPUMP
	jnz	.out
	or	dword [r12+U2_F],U2F_DPUMP
.next:
	h_rec
	test	dword [r12+U2_F],U2F_SENDING
	jnz	.wait				; until the window lets the rest go
	test	dword [r12+U2_F],U2F_RST
	jnz	.stop
	mov	eax,[r15+H_BODY]
	cmp	eax,BK_LENGTH
	je	.length
	cmp	eax,BK_CHUNKED
	jne	.stop
	lea	rdi,[r15+H_CK]
	mov	eax,[r15+H_INOFF]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	edx,[r15+H_INLEN]
	sub	edx,eax
	call	chunk_step
	h_rec
	add	[r15+H_INOFF],ecx
	cmp	eax,CK_DATAOUT
	je	.data
	cmp	eax,CK_MORE
	je	.refill
	jmp	.ended				; the end (the framing is okena's own)
.length:
	cmp	qword [r15+H_REMAIN],0
	je	.ended
	mov	ecx,[r15+H_INLEN]
	sub	ecx,[r15+H_INOFF]
	jz	.refill
	mov	rax,[r15+H_REMAIN]
	cmp	rax,rcx
	jae	@f
	mov	ecx,eax
@@:
	sub	[r15+H_REMAIN],rcx
	mov	eax,[r15+H_INOFF]
	add	[r15+H_INOFF],ecx
	mov	r8,[r15+H_BUF]
	lea	r8,[r8+HB_IN+rax]
	mov	r9d,ecx
.data:
	mov	rax,[r15+H_BUF]			; gRPC-Web text: decoded first
	cmp	byte [rax+HB_GWEB],4
	jne	@f
	call	gweb_decode
	jnc	@f
	call	gweb_fail			; not base64: the exchange fails
	jmp	.stop
@@:
	mov	[r12+U2_PP],r8
	mov	[r12+U2_PL],r9d
	or	dword [r12+U2_F],U2F_SENDING
	call	h2u_kick
	test	dword [r12+U2_F],U2F_SENDING
	jnz	.wait
	cmp	dword [r12+U2_PL],0
	jne	.stop				; nowhere to go (its connection went)
	jmp	.next
.refill:
	; IN is all taken (and sent): the stream's queue next
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	mov	r14,[r15+H_BUF]
	add	r14,HB_H2Q
	mov	ecx,[r14+Q_LEN]
	cmp	ecx,[r14+Q_OFF]
	je	.wait				; more when the client sends it
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,H_IN_CAP
	call	h2s_copy
	h_rec
	add	[r15+H_INLEN],eax
	jmp	.next
.ended:
	mov	dword [r15+H_BODY],BK_NONE
	or	dword [r12+U2_F],U2F_FINISH
	call	h2u_kick
.stop:
	h_rec
	and	dword [r15+H_FLAGS],not HX_DUPLEX
.wait:
	and	dword [r12+U2_F],not U2F_DPUMP
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; r8 = data, r9d = length, r15 = record: OUT = "<hex>\r\n<data>\r\n".
http_frame_chunk:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	eax,r9d
	call	fmt_hex32
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	[r15+H_OUTLEN],edi
	ret

; rdi = output, eax = value: lowercase hex, no leading zeros.
fmt_hex32:
	mov	ecx,28
	xor	edx,edx
.digit:
	mov	r10d,eax
	shr	r10d,cl
	and	r10d,15
	test	edx,edx
	jnz	.emit
	test	r10d,r10d
	jnz	.emit
	test	ecx,ecx
	jnz	.skip
.emit:
	mov	edx,1
	cmp	r10d,10
	jb	@f
	add	r10d,'a' - '0' - 10
@@:
	add	r10d,'0'
	mov	[rdi],r10b
	inc	rdi
.skip:
	sub	ecx,4
	jns	.digit
	ret

; ----------------------------------------------------------- response

http_start_response:
	h_rec
	call	fcgi_active
	test	eax,eax
	jz	@f
	call	fcgi_body_end			; (FastCGI: an empty FCGI_STDIN, once)
@@:
	call	session_ptr			; a stream upstream: the request ends
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	@f
	h_rec
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jnz	@f				; (unless its body goes on beside)
	call	h2u_req_end
@@:
	h_rec
	mov	qword [r15+H_UPT0],0
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	cmp	dword [g_pools+rax+PL_BALANCE],BAL_PEAK_EWMA
	jne	@f
	rdtsc					; the backend's latency starts now
	shl	rdx,32
	or	rax,rdx
	mov	[r15+H_UPT0],rax
@@:
	mov	dword [r15+H_UPLEN],0
	mov	dword [r15+H_UPOFF],0
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	h_rec
	call	hints_inject
	test	eax,eax
	jnz	http_resp_head
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	mov	esi,H_UP_CAP
	jmp	h_recv

; A response head may be complete in UP. ebx = session.
http_resp_head:
	h_rec
	mov	eax,[r15+H_UPOFF]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rax]
	mov	esi,[r15+H_UPLEN]
	sub	esi,eax
	call	http_head_end
	cmp	eax,-1
	je	.bad
	test	eax,eax
	jnz	.parse
	cmp	dword [r15+H_UPLEN],H_UP_CAP
	jae	.bad				; a response head that large: refused
	mov	ecx,SIDE_UP
	mov	edi,[r15+H_UPLEN]
	lea	rdi,[rdi+HB_UP]
	add	rdi,[r15+H_BUF]
	mov	esi,H_UP_CAP
	sub	esi,[r15+H_UPLEN]
	jmp	h_recv
.parse:
	push	rax
	mov	ecx,[r15+H_UPOFF]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rcx]
	mov	esi,eax
	lea	rdx,[g_hm]
	call	http_parse_response
	pop	rcx
	test	eax,eax
	jnz	.bad
	add	[r15+H_UPOFF],ecx
	lea	r14,[g_hm]
	mov	eax,[r14+HM_STATUS]
	cmp	eax,200
	jae	.final
	; 1xx: 100 Continue was ours already; 101 is an upgrade; others (103
	; Early Hints...) go to the client before the final response, unless
	; it speaks HTTP/1.0
	cmp	eax,101
	je	.switching
	cmp	eax,100
	je	http_resp_head
	test	dword [r15+H_FLAGS],HX_HTTP10
	jnz	http_resp_head
	or	dword [r15+H_FLAGS],HX_INTERIM
	call	http_write_response_head
	pushf
	and	dword [r15+H_FLAGS],not HX_INTERIM
	popf
	jc	http_resp_head			; too large to pass on: dropped
	mov	dword [r15+H_STATE],HS_INTERIM_SEND
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	h_send
.switching:
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	.bad				; switching protocols nobody asked for
	push	rax
	mov	edi,ebx
	call	ph_disarm
	pop	rax
	h_rec
	lea	r14,[g_hm]
	mov	edi,eax
	xor	esi,esi
	call	http_count
	mov	[r15+H_STATUS],eax
	mov	dword [r15+H_RBODY],BK_NONE
	and	dword [r15+H_FLAGS],not HX_CHUNKOUT
	jmp	.write
.final:
	push	rax
	mov	edi,ebx
	call	ph_disarm
	call	hedge_answer
	mov	eax,[rsp]
	call	fwd_answer
	call	http_latency_sample
	pop	rax
	mov	edi,eax
	call	http_backend_status		; may send the request elsewhere
	h_rec
	push	rax				; a failure, with a stale copy kept for it?
	call	cache_sie_ok
	pop	rax
	jnc	cache_sie_serve
	lea	r14,[g_hm]
	mov	edi,eax
	xor	esi,esi
	call	http_count
	and	dword [r15+H_FLAGS],not HX_UPGRADE	; the backend did not switch
	mov	[r15+H_STATUS],eax
	; an error of the backend's, with a page of one's own for it (`errors
	; ... backend`): its status stays, its body goes
	cmp	eax,400
	jb	@f
	test	dword [r15+H_FLAGS],HX_GRPC
	jnz	@f
	mov	ecx,1
	call	errpage_find
	test	rsi,rsi
	jnz	http_error_backend
@@:
	cmp	dword [r14+HM_VERSION],11
	jne	@f
	test	dword [r14+HM_FLAGS],HMF_CLOSE
	jnz	@f
	or	dword [r15+H_FLAGS],HX_UPKEEP
@@:
	; the response body
	mov	dword [r15+H_RCK+CK_TLEN],0	; (no trailers unless it is chunked)
	mov	dword [r15+H_RBODY],BK_NONE
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.write
	cmp	eax,204
	je	.write
	cmp	eax,304
	je	.write
	test	dword [r14+HM_FLAGS],HMF_CHUNKED
	jz	@f
	mov	dword [r15+H_RBODY],BK_CHUNKED
	call	h_chunkout
	lea	rdi,[r15+H_RCK]
	xor	eax,eax
	mov	ecx,CK_SIZE
	rep	stosb
	mov	rax,[r15+H_BUF]			; its trailers are kept, to pass on
	add	rax,HB_TRAIL
	mov	[r15+H_RCK+CK_TBUF],rax
	jmp	.write
@@:
	mov	rax,[r14+HM_LENGTH]
	cmp	rax,-1
	je	.close_delimited
	mov	[r15+H_RREMAIN],rax
	mov	dword [r15+H_RBODY],BK_LENGTH
	jmp	.write
.close_delimited:
	and	dword [r15+H_FLAGS],not HX_UPKEEP	; the end is the close
	mov	dword [r15+H_RBODY],BK_CLOSE
	call	h_chunkout			; framed for the client
.write:
	call	cache_head
	call	idem_head
	call	zip_head
	call	gweb_text_head
	call	http_write_response_head
	mov	dword [g_zh],0
	jc	.bad
	or	dword [r15+H_FLAGS],HX_STARTED
	cmp	dword [r15+H_RBODY],BK_LENGTH
	jne	.send_head
	mov	rax,[r15+H_BUF]			; (gRPC-Web text: the pump encodes it)
	cmp	byte [rax+HB_GWEB],4
	je	.send_head
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jnz	.send_head			; (http_resp_pump takes it from UP)
	mov	ecx,[r15+H_UPLEN]
	sub	ecx,[r15+H_UPOFF]
	jz	.send_head
	mov	rax,[r15+H_RREMAIN]
	cmp	rax,rcx
	jae	@f
	mov	ecx,eax
@@:
	mov	eax,H_OUT_CAP
	sub	eax,[r15+H_OUTLEN]
	cmp	ecx,eax
	jbe	@f
	mov	ecx,eax
@@:
	test	ecx,ecx
	jz	.send_head
	mov	rdi,[r15+H_BUF]
	mov	eax,[r15+H_OUTLEN]		; a dword: a qword add would pull H_UPLEN in
	lea	rdi,[rdi+rax+HB_OUT]
	mov	eax,[r15+H_UPOFF]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+rax+HB_UP]
	call	cache_tee
	add	[r15+H_UPOFF],ecx
	sub	[r15+H_RREMAIN],rcx
	add	[r15+H_OUTLEN],ecx
	rep	movsb
.send_head:
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	h_send
.bad:
	mov	edi,502
	jmp	http_error

; OUT = the response head okena sends the client. CF when it does not fit.
http_write_response_head:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	r12,[g_hm]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	r13,[r15+H_BUF]
	lea	r13,[r13+HB_OUT+H_OUT_CAP-256]
	memit_x 'HTTP/1.1 '
	mov	eax,[r12+HM_STATUS]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[r12+HM_TARGET]		; the reason phrase
	mov	ecx,[r12+HM_TLEN]
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	xor	ebx,ebx
.field:
	cmp	ebx,[r12+HM_NHDR]
	jae	.own
	imul	r14,rbx,HF_SIZE
	lea	r14,[r12+HM_HDRS+r14]
	test	dword [r14+HF_FLAGS],HFF_HOP
	jz	.e2e
	test	dword [r15+H_FLAGS],HX_UPGRADE	; a 101 keeps its Upgrade field
	jz	.skip
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_upgrade]
	call	hf_is
	pop	rdi
	jnz	.skip
.e2e:
	cmp	dword [g_zh],0
	je	.not_zipped
	; compressed: its length is unknown, ranges are of something else
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_content_length]
	call	hf_is
	pop	rdi
	jz	.skip
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_accept_ranges]
	call	hf_is
	pop	rdi
	jz	.skip
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_etag]
	call	hf_is
	pop	rdi
	jz	.skip				; (of the bytes it had: these are others)
.not_zipped:
	; the route's response header changes (final heads only)
	test	dword [r15+H_FLAGS],HX_INTERIM
	jnz	.copy
	cors_of_h				; cors here: the backend's say nothing
	jz	.no_cors_fields
	cmp	dword [r14+HF_NLEN],15
	jb	.no_cors_fields
	push	rdi
	mov	rdi,[r14+HF_NAME]
	cstring str_acf, 'access-control-'
	lea	rsi,[str_acf]
	mov	edx,15
	call	mem_eq_nocase
	pop	rdi
	test	eax,eax
	jnz	.skip
.no_cors_fields:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.copy
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	esi,[g_acts+rax+RA_PFIRST]
	mov	edx,[g_acts+rax+RA_PCOUNT]
	test	edx,edx
	jz	.copy
	push	rdi
	mov	rdi,r14
	call	hdrop_skip
	pop	rdi
	jc	.skip
.copy:
	mov	edx,1				; gRPC-Web's content-type (grpcweb.inc)
	call	gweb_field
	jc	.skip
	mov	eax,[r14+HF_NLEN]
	add	eax,[r14+HF_VLEN]
	add	eax,4
	lea	rcx,[rdi+rax]
	cmp	rcx,r13
	ja	.full
	mov	rsi,[r14+HF_NAME]
	mov	ecx,[r14+HF_NLEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,[r14+HF_VALUE]
	mov	ecx,[r14+HF_VLEN]
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
.skip:
	inc	ebx
	jmp	.field
.own:
	cmp	dword [g_zh],0
	je	.own_plain
	cmp	dword [g_zh],2
	je	.own_br
	memit_x 'Content-Encoding: gzip',13,10,'Vary: Accept-Encoding',13,10
	jmp	.own_plain
.own_br:
	memit_x 'Content-Encoding: br',13,10,'Vary: Accept-Encoding',13,10
.own_plain:
	test	dword [r15+H_FLAGS],HX_INTERIM
	jz	@f
	memit_x 13,10				; an interim head: no framing of its own
	jmp	.done
@@:
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	@f
	mov	eax,[rsp+24]			; a WebSocket that only upgrades is kept too
	call	sticky_emit_for
	memit_x 'Connection: upgrade',13,10,13,10
	jmp	.done
@@:
	mov	eax,[r15+H_ACT]			; the route's response set and add
	test	eax,eax
	jz	@f
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	esi,[g_acts+rax+RA_PFIRST]
	mov	edx,[g_acts+rax+RA_PCOUNT]
	call	hdrop_emit
	jc	.full
@@:
	test	dword [r15+H_FLAGS],HX_INTERIM
	jnz	@f
	call	cors_emit
	call	split_emit
	call	cache_status_emit
	mov	eax,[rsp+24]			; the session
	call	sticky_emit_for
@@:
	; `http3 on`: HTTP/3 on the same port (RFC 7838), but on HTTP/3 itself
	mov	eax,[rsp+24]			; the session
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	test	dword [rax+S_FLAGS],SF_H3S
	jnz	@f
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	test	dword [g_listeners+rcx+LS_FLAGS],LSF_H3
	jz	@f
	push	rcx
	memit_x 'Alt-Svc: h3=":'
	pop	rcx
	mov	eax,[g_listeners+rcx+LS_PORT]
	call	fmt_u64
	memit_x '"; ma=86400',13,10
@@:
	mov	eax,[r15+H_RBODY]
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jz	@f
	memit_x 'Transfer-Encoding: chunked',13,10
	jmp	.conn
@@:
	mov	rcx,[r15+H_BUF]			; gRPC-Web text: its DATA say how long
	cmp	byte [rcx+HB_GWEB],4
	je	.conn
	cmp	eax,BK_LENGTH
	je	.length
	; no body: a HEAD response keeps the length it announces
	test	dword [r15+H_FLAGS],HX_HEAD
	jz	.conn
	mov	rax,[r12+HM_LENGTH]
	cmp	rax,-1
	je	.conn
	memit_x 'Content-Length: '
	mov	rax,[r12+HM_LENGTH]
	call	fmt_u64
	memit_x 13,10
	jmp	.conn
.length:
	memit_x 'Content-Length: '
	mov	rax,[r15+H_RREMAIN]
	call	fmt_u64
	memit_x 13,10
.conn:
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	mov	word [rdi],0x0A0D
	add	rdi,2
.done:
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	[r15+H_OUTLEN],edi
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Move the response body to the client. ebx = session.
http_resp_pump:
	h_rec
	mov	eax,[r15+H_RBODY]
	cmp	eax,BK_LENGTH
	je	.length
	cmp	eax,BK_CHUNKED
	je	.chunked
	cmp	eax,BK_CLOSE
	je	.close
	jmp	http_exchange_done
.length:
	cmp	qword [r15+H_RREMAIN],0
	je	.length_done
	mov	ecx,[r15+H_UPLEN]
	sub	ecx,[r15+H_UPOFF]
	jnz	@f
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],4
	je	.read				; (gRPC-Web text: through the encoder)
	call	zc_ok				; from a file or the disk cache: without copies?
	jnc	zc_send
	jmp	.read
@@:
	mov	rax,[r15+H_RREMAIN]
	cmp	rax,rcx
	jae	@f
	mov	ecx,eax
@@:
	sub	[r15+H_RREMAIN],rcx
	mov	eax,[r15+H_UPOFF]
	add	[r15+H_UPOFF],ecx
	mov	rdi,[r15+H_BUF]
	lea	rsi,[rdi+HB_UP+rax]
	call	cache_tee
	mov	rdi,rsi
	mov	esi,ecx
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],4
	jne	@f
	mov	r8,rdi
	mov	r9d,esi
	jmp	.gweb_text
@@:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jz	.send
	mov	r8,rdi
	mov	r9d,esi
	jmp	.squeeze
.send:
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.length_done:
	mov	dword [r15+H_RBODY],BK_NONE
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],4
	je	http_last_chunk			; (gRPC-Web text: its padding, its end)
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jnz	http_last_chunk
	jmp	http_exchange_done
.read:
	mov	dword [r15+H_UPLEN],0
	mov	dword [r15+H_UPOFF],0
	mov	dword [r15+H_STATE],HS_RESP_READ
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	mov	esi,H_UP_CAP
	jmp	h_recv
.chunked:
	lea	rdi,[r15+H_RCK]
	mov	eax,[r15+H_UPOFF]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_UP+rax]
	mov	edx,[r15+H_UPLEN]
	sub	edx,eax
	call	chunk_step
	add	[r15+H_UPOFF],ecx
	cmp	eax,CK_DATAOUT
	je	.framed
	cmp	eax,CK_END
	je	.chunk_end
	cmp	eax,CK_MORE
	je	.read
	mov	edi,ebx				; a broken body from the backend
	jmp	session_close
.chunk_end:
	mov	dword [r15+H_RBODY],BK_NONE
	call	cache_commit
	h_rec
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_IDEMF
	jz	@f
	call	idem_commit
	h_rec
@@:
	jmp	http_last_chunk
.close:
	; until the backend closes, each piece framed as a chunk
	mov	ecx,[r15+H_UPLEN]
	sub	ecx,[r15+H_UPOFF]
	jz	.read
	mov	eax,[r15+H_UPOFF]
	mov	r8,[r15+H_BUF]
	lea	r8,[r8+HB_UP+rax]
	mov	r9d,ecx
	add	[r15+H_UPOFF],ecx
.framed:
	push	rcx
	mov	rsi,r8
	mov	ecx,r9d
	call	cache_tee
	pop	rcx
	mov	rax,[r15+H_BUF]			; gRPC-Web text: in base64
	cmp	byte [rax+HB_GWEB],4
	jne	@f
.gweb_text:
	call	gweb_text_feed
	jnc	.send
	jmp	http_resp_pump
@@:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jz	.plain
.squeeze:
	call	zip_feed
	test	esi,esi
	jnz	.send
	jmp	http_resp_pump
.plain:
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jz	@f
	mov	rdi,r8				; a stream: the bytes as they are, in DATA
	mov	esi,r9d
	jmp	.send
@@:
	call	http_frame_chunk
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	.send

; ebx = session, r15 = record: the response goes out chunk-framed, except
; to an HTTP/2 stream (DATA frames carry the length). Keeps everything but
; rax.
h_chunkout:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CHUNKOUT
@@:
	ret

; The final chunk to the client, then the exchange is over.
http_last_chunk:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_ZIP
	jz	.not_zip
	; the rest of it, the last chunk with it: what comes after the send is the end
	h_rec
	call	zip_finish
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.not_zip:
	h_rec
	mov	rax,[r15+H_BUF]			; gRPC-Web: its trailers as its last message
	cmp	byte [rax+HB_GWEB],4
	je	gweb_text_end			; (text: base64, and padded)
	cmp	byte [rax+HB_GWEB],2
	jne	@f
	cmp	dword [r15+H_RCK+CK_TLEN],0
	jne	gweb_trailers
@@:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jnz	http_exchange_done		; a stream ends with END_STREAM (and its trailers)
	h_rec
	or	dword [r15+H_FLAGS],HX_LASTCHUNK
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	mov	edx,[r15+H_RCK+CK_TLEN]
	test	edx,edx
	jnz	.trailers
	lea	rdi,[str_last_chunk]
	mov	esi,str_last_chunk.len
	jmp	h_send
.trailers:
	; "0\r\n", the backend's trailer lines, "\r\n"
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	dword [rdi],0x000A0D30
	add	rdi,3
	mov	rsi,[r15+H_BUF]
	add	rsi,HB_TRAIL
	mov	ecx,edx
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	mov	esi,edi
	sub	esi,eax
	mov	rdi,rax
	mov	ecx,SIDE_CLIENT
	jmp	h_send

; ebx = session, r15 = state, its final response head just parsed: the
; time since the request was sent is its server's latency sample.
http_latency_sample:
	mov	rcx,[r15+H_UPT0]
	test	rcx,rcx
	jz	.out
	mov	qword [r15+H_UPT0],0
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,rcx
	xor	edx,edx
	div	qword [g_tsc_per_us]
	mov	rsi,rax
	call	session_ptr
	mov	edi,[rax+S_SERVER]
	cmp	edi,NIL
	je	.out
	call	sv_ewma_observe
.out:
	ret

; ------------------------------------------------- retries and outliers

; Outlier ejection (per worker, like the connect failures): a server that
; answers OUTLIER_5XX 5xx in a row (or times out) is ejected for
; EJECT_TICKS; any other answer resets its count.
;
; Retries: a request that is idempotent and has no body goes once more
; to another server when the backend answers 502, 503 or 504 or closes
; before any response byte. A budget keeps retries from multiplying a
; failure: per worker, at most a fifth of the requests plus 10 per second
; (tokens in tenths of a retry).
OUTLIER_5XX	:= 5
RETRY_COST	:= 10
RETRY_PER_REQ	:= 2
RETRY_FLOOR	:= 100
RETRY_CAP	:= 1000

bss
	g_sv_5xx	rd MAX_SERVERS
	g_retry_tokens	rd MAX_POOLS		; per pool, tenths of a retry
end bss

; Tick: the budget's floor.
retry_budget_tick:
	xor	ecx,ecx
.pool:
	cmp	ecx,[g_plan_pools]
	jae	.done
	cmp	dword [g_retry_tokens+rcx*4],RETRY_FLOOR
	jae	@f
	mov	dword [g_retry_tokens+rcx*4],RETRY_FLOOR
@@:
	inc	ecx
	jmp	.pool
.done:
	ret

; edi = server: one more failing answer. Keeps rax, rbx.
server_5xx:
	cmp	edi,NIL
	je	.done
	inc	dword [g_sv_5xx+rdi*4]
	cmp	dword [g_sv_5xx+rdi*4],OUTLIER_5XX
	jb	.done
	mov	dword [g_sv_5xx+rdi*4],0
	mov	ecx,[g_sv_down+rdi*4]
	cmp	ecx,[g_tick]
	ja	.done				; already ejected
	call	eject_share_full		; never more than half a pool
	jc	.done
	mov	ecx,[g_tick]
	add	ecx,EJECT_TICKS
	mov	[g_sv_down+rdi*4],ecx
	push	rax
	push	rdi
	call	log_begin
	out_lit 'backend '
	mov	rdi,[rsp]
	call	log_server
	out_lit ' ejected for 10 s after 5 failing answers in a row'
	call	log_end
	pop	rdi
	pop	rax
.done:
	ret

; ebx = session (its S_POOL), edi = server about to be ejected. CF when
; half of the pool's servers are out already: a bad signal (a broken
; health endpoint, a shared dependency failing) must not empty a pool.
; Runs on the rare ejection only. Keeps rax, rdi.
eject_share_full:
	push	rax
	push	rdi
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	r8,[g_pools+rax]
	mov	ecx,[r8+PL_FIRST]
	mov	r9d,ecx
	add	r9d,[r8+PL_COUNT]
	xor	edx,edx				; ejected now
	mov	r10d,[g_tick]
@@:
	cmp	ecx,r9d
	jae	@f
	cmp	[g_sv_down+rcx*4],r10d
	jbe	.next
	inc	edx
.next:
	inc	ecx
	jmp	@b
@@:
	inc	edx				; with this one
	add	edx,edx
	cmp	edx,[r8+PL_COUNT]
	pop	rdi
	pop	rax
	ja	.full
	clc
	ret
.full:
	stc
	ret

; ebx = session, edi = status of the backend's final answer. Keeps rax.
; Does not return when the request goes to another server.
http_backend_status:
	push	rax
	call	session_ptr
	mov	ecx,[rax+S_SERVER]
	cmp	edi,500
	jae	.failing
	cmp	ecx,NIL
	je	.done
	mov	dword [g_sv_5xx+rcx*4],0
.done:
	pop	rax
	ret
.failing:
	push	rdi
	mov	edi,ecx
	call	server_5xx
	pop	rdi
	cmp	edi,502
	jb	.done
	cmp	edi,504
	ja	.done
	call	http_may_retry
	jnc	.done
	add	rsp,16				; rax, and we do not return
	jmp	http_retry_other

; ebx = session: the backend closed before answering. Returns when the
; request may not go elsewhere.
http_gateway_failed:
	call	session_ptr
	mov	edi,[rax+S_SERVER]
	call	server_5xx
	call	http_may_retry
	jnc	.no
	add	rsp,8
	jmp	http_retry_other
.no:
	ret

; ebx = session. CF when its request may be sent once more (and the
; budget is charged).
http_may_retry:
	h_rec
	mov	eax,[r15+H_FLAGS]
	and	eax,HX_NOBODY or HX_IDEMPOTENT or HX_RETRIED or HX_STARTED or HX_UPGRADE
	cmp	eax,HX_NOBODY or HX_IDEMPOTENT
	jne	.no
	call	session_ptr
	mov	eax,[rax+S_POOL]
	cmp	dword [g_retry_tokens+rax*4],RETRY_COST
	jb	.no
	sub	dword [g_retry_tokens+rax*4],RETRY_COST
	stc
	ret
.no:
	clc
	ret

; ebx = session: send the request (its head is still in OUT) to another
; server, on a new or pooled connection.
http_retry_other:
	h_rec
	or	dword [r15+H_FLAGS],HX_RETRIED or HX_AVOID
	and	dword [r15+H_FLAGS],not (HX_REUSED or HX_UPKEEP)
	call	session_ptr
	mov	eax,[rax+S_LST]
	inc	qword [g_st_l_retries+rax*8]
	call	h_upclose
	h_rec
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect

; ---------------------------------------------------- trusted proxies

; ebx = session, r15 = record, g_hm = the request. H_CLIENT/H_CKIND =
; the client: the peer, unless the peer is a trusted proxy; then the
; rightmost address of X-Forwarded-For that is not trusted (the hop a
; trusted proxy saw), or the leftmost when all are. An entry that is not
; an address stops the walk at the last trusted hop. Sets HX_TRUSTED.
http_client_resolve:
	push	rbx
	push	r12
	push	r13
	push	r14
	call	peer_ptr
	lea	rdi,[r15+H_CLIENT]
	lea	rsi,[rax+P_PEER]
	call	peer_normalize
	mov	[r15+H_CKIND],eax
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	lea	r14,[g_listeners+rax]
	cmp	dword [r14+LS_TCOUNT],0
	je	.done
	lea	rsi,[r15+H_CLIENT]
	mov	edx,[r15+H_CKIND]
	call	trust_match
	jnc	.done
	or	dword [r15+H_FLAGS],HX_TRUSTED
	lea	r12,[g_hm]
	mov	ebx,[r12+HM_NHDR]
.header:
	dec	ebx
	js	.done
	imul	rdi,rbx,HF_SIZE
	lea	rdi,[r12+HM_HDRS+rdi]
	lea	rsi,[hn_x_forwarded_for]
	call	hf_is
	jnz	.header
	imul	rax,rbx,HF_SIZE
	lea	rax,[r12+HM_HDRS+rax]
	mov	r13,[rax+HF_VALUE]
	mov	ecx,[rax+HF_VLEN]		; entries end here, right to left
.entry:
	test	ecx,ecx
	jz	.header
	mov	edx,ecx				; end
@@:
	dec	ecx
	js	.first
	cmp	byte [r13+rcx],','
	jne	@b
	jmp	.found
.first:
	mov	rcx,-1				; the entry starts at 0 (64-bit: rcx indexes)
.found:
	; entry = [ecx+1, edx)
	push	rcx
	lea	rdi,[r13+rcx+1]
	mov	esi,edx
	sub	esi,ecx
	dec	esi
	sub	rsp,16
	mov	rdx,rsp
	call	parse_xff_ip			; eax = 4 or 6, CF when not an address
	jc	.not_address
	mov	[r15+H_CKIND],eax
	mov	rcx,[rsp]
	mov	[r15+H_CLIENT],rcx
	mov	rcx,[rsp+8]
	mov	[r15+H_CLIENT+8],rcx
	add	rsp,16
	lea	rsi,[r15+H_CLIENT]
	mov	edx,eax
	call	trust_match
	pop	rcx
	jnc	.done				; not trusted: this is the client
	cmp	ecx,-1
	je	.header
	jmp	.entry
.not_address:
	add	rsp,24
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r14 = listener, rsi = 16 address bytes, edx = 4 or 6. CF when the
; address is in one of the listener's trusted_proxies ranges. Keeps
; rbx and r12-r15.
trust_match:
	mov	r8d,[r14+LS_TFIRST]
	mov	r9d,r8d
	add	r9d,[r14+LS_TCOUNT]
.range:
	cmp	r8d,r9d
	jae	.no
	imul	r10,r8,TR_SIZE
	lea	r10,[g_trust+r10]
	inc	r8d
	cmp	[r10+TR_KIND],edx
	jne	.range
	mov	ecx,[r10+TR_BITS]
	xor	r11d,r11d			; byte index
.byte:
	cmp	ecx,8
	jb	.partial
	mov	al,[rsi+r11]
	cmp	al,[r10+TR_IP+r11]
	jne	.range
	inc	r11d
	sub	ecx,8
	jmp	.byte
.partial:
	test	ecx,ecx
	jz	.yes
	movzx	eax,byte [rsi+r11]
	xor	al,[r10+TR_IP+r11]
	neg	ecx
	add	ecx,8
	shr	eax,cl				; only the top (prefix) bits may differ: none
	test	eax,eax
	jnz	.range
.yes:
	stc
	ret
.no:
	clc
	ret

; rdi/esi = an X-Forwarded-For entry ("1.2.3.4", " 2001:db8::1",
; "1.2.3.4:5678", "[2001:db8::1]:443"), rdx = 16-byte output. eax = 4
; or 6, CF when it is not an address.
parse_xff_ip:
	push	rbx
	push	r12
	mov	r12,rdx
	xor	eax,eax
	mov	[r12],rax
	mov	[r12+8],rax
	; trim
@@:
	test	esi,esi
	jz	.bad
	cmp	byte [rdi],' '
	je	.lead
	cmp	byte [rdi],9
	jne	@f
.lead:
	inc	rdi
	dec	esi
	jmp	@b
@@:
	cmp	byte [rdi+rsi-1],' '
	je	.trail
	cmp	byte [rdi+rsi-1],9
	jne	@f
.trail:
	dec	esi
	jmp	@b
@@:
	cmp	byte [rdi],'['
	jne	.colons
	inc	rdi				; [v6] or [v6]:port
	dec	esi
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	.bad
	cmp	byte [rdi+rcx],']'
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	esi,ecx
	jmp	.v6
.colons:
	xor	ecx,ecx
	xor	ebx,ebx				; ':' count
	xor	edx,edx				; position of the last one
@@:
	cmp	ecx,esi
	jae	@f
	cmp	byte [rdi+rcx],':'
	jne	.nc
	inc	ebx
	mov	edx,ecx
.nc:
	inc	ecx
	jmp	@b
@@:
	test	ebx,ebx
	jz	.v4
	cmp	ebx,1
	jne	.v6
	mov	esi,edx				; a.b.c.d:port
.v4:
	call	parse_ipv4_text
	jc	.bad
	mov	[r12],eax
	mov	eax,4
	jmp	.ok
.v6:
	mov	rdx,r12
	call	parse_ipv6_text
	jc	.bad
	; ::ffff:a.b.c.d is an IPv4 client
	cmp	qword [r12],0
	jne	.six
	cmp	dword [r12+8],0xFFFF0000
	jne	.six
	mov	eax,[r12+12]
	mov	[r12],eax
	xor	eax,eax
	mov	[r12+4],eax
	mov	[r12+8],rax
	mov	eax,4
	jmp	.ok
.six:
	mov	eax,6
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ metrics

; edi = status, esi = 0 when the backend's, 5 when okena's own. ebx =
; session. Keeps everything but rcx, rdx.
http_count:
	push	rax
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_MIR	; (a copy answers nobody)
	pop	rax
	jz	.counted
	ret
.counted:
	push	rax
	mov	eax,edi
	xor	edx,edx
	mov	ecx,100
	div	ecx
	dec	eax				; 1xx -> 0 ... 5xx -> 4
	cmp	eax,4
	jbe	@f
	mov	eax,4
@@:
	add	eax,esi
	push	rdx
	mov	ecx,ebx
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	mov	edx,[rcx+S_FLAGS]
	mov	ecx,[rcx+S_LST]
	push	rcx
	imul	ecx,ecx,10
	add	eax,ecx
	inc	qword [g_st_l_http+rax*8]
	pop	rcx				; the listener
	; its protocol: an HTTP/2 stream, an HTTP/3 one, or HTTP/1
	lea	eax,[rcx*2+rcx]
	test	edx,SF_H2S
	jz	@f
	inc	eax
@@:
	test	edx,SF_H3S
	jz	@f
	add	eax,2
@@:
	inc	qword [g_st_l_proto+rax*8]
	test	edx,SF_CACHED
	jz	@f
	inc	qword [g_st_l_cache+rcx*8]
@@:
	; statuses that say something of their own
	cmp	edi,101
	jne	@f
	inc	qword [g_st_l_ws+rcx*8]
@@:
	lea	eax,[rcx*4]
	cmp	edi,401
	je	.code
	inc	eax
	cmp	edi,403
	je	.code
	inc	eax
	cmp	edi,404
	je	.code
	inc	eax
	cmp	edi,429
	jne	.codes_done
.code:
	inc	qword [g_st_l_codes+rax*8]
.codes_done:
	pop	rdx
	pop	rax
	ret

; --------------------------------------------------------- route actions

; rdi = field (HF_*), esi/edx = first and count of header changes. CF
; when the field is not to be copied: a drop names it (or a prefix of
; it), or a set replaces it. Keeps rbx, r12-r15.
hdrop_skip:
	test	edx,edx
	jz	.keep
	imul	r8,rsi,HD_SIZE
	lea	r8,[g_hdrops+r8]
	mov	r9d,edx
.op:
	cmp	dword [r8+HD_KIND],HOP_ADD
	je	.next				; add keeps what the message had
	mov	ecx,[r8+HD_NLEN]
	mov	eax,[rdi+HF_NLEN]
	cmp	dword [r8+HD_PREFIX],0
	jne	.prefix
	cmp	eax,ecx
	jne	.next
	jmp	.compare
.prefix:
	cmp	eax,ecx
	jb	.next
.compare:
	push	rdi
	push	r8
	push	r9
	mov	edx,ecx
	mov	rsi,[rdi+HF_NAME]
	mov	rdi,[r8+HD_NAME]
	call	mem_eq_nocase
	pop	r9
	pop	r8
	pop	rdi
	test	eax,eax
	jnz	.drop
.next:
	add	r8,HD_SIZE
	dec	r9d
	jnz	.op
.keep:
	clc
	ret
.drop:
	stc
	ret

; rdi = output, esi/edx = first and count of header changes, r13 = the
; limit. Writes the set and add ones; CF when they do not fit. Keeps
; rbx, r12-r15.
hdrop_emit:
	test	edx,edx
	jz	.done
	imul	r8,rsi,HD_SIZE
	lea	r8,[g_hdrops+r8]
	mov	r9d,edx
.op:
	cmp	dword [r8+HD_KIND],HOP_DROP
	je	.next
	imul	eax,[r8+HD_VARS],40		; a variable is at most 39 bytes
	add	eax,[r8+HD_NLEN]
	add	eax,[r8+HD_VLEN]
	lea	rax,[rdi+rax+4]
	cmp	rax,r13
	ja	.full
	mov	rsi,[r8+HD_NAME]
	mov	ecx,[r8+HD_NLEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,[r8+HD_VAL]
	mov	ecx,[r8+HD_VLEN]
	cmp	dword [r8+HD_VARS],0
	jne	.vars
	rep	movsb
	jmp	.eol
.vars:
	call	hvar_expand
.eol:
	mov	word [rdi],0x0A0D
	add	rdi,2
.next:
	add	r8,HD_SIZE
	dec	r9d
	jnz	.op
.done:
	clc
	ret
.full:
	stc
	ret

; rdi = output, rsi/ecx = a header value with ${...} in it (checked at
; load), r15 = state: the value with each variable written. rdi = after
; it. Keeps rbx, r8, r9, r12-r15.
hvar_expand:
	push	r8
	push	r9
.byte:
	test	ecx,ecx
	jz	.done
	cmp	ecx,2
	jb	.copy
	cmp	word [rsi],'${'
	jne	.copy
	; which one: by its first letters (the names were checked)
	cmp	byte [rsi+2],'c'
	je	.client
	cmp	byte [rsi+2],'r'
	je	.rid
	push	rsi
	push	rcx
	mov	r8d,1000000000			; time.s
	cmp	byte [rsi+7],'u'
	jne	@f
	mov	r8d,1000			; time.us
@@:
	push	r8
	call	wall_ns				; (may read the clock: rcx, r11 go)
	pop	r8
	xor	edx,edx
	div	r8
	call	fmt_u64
	pop	rcx
	pop	rsi
	jmp	.skip_var
.client:
	push	rsi
	push	rcx
	lea	rsi,[r15+H_CLIENT]
	mov	edx,[r15+H_CKIND]
	test	edx,edx
	jz	@f
	call	fmt_ip
@@:
	pop	rcx
	pop	rsi
	jmp	.skip_var
.rid:
	push	rsi
	push	rcx
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	pop	rcx
	pop	rsi
.skip_var:
	; past the "}"
@@:
	mov	al,[rsi]
	inc	rsi
	dec	ecx
	cmp	al,'}'
	jne	@b
	jmp	.byte
.copy:
	movsb
	dec	ecx
	jmp	.byte
.done:
	pop	r9
	pop	r8
	ret

; rdi = output, rsi/ecx = the request's target (origin form). When the
; route rewrites and the path starts with its prefix: TO is written with
; {*} = the rest of the (normalized) path, then the request's query; CF
; clear. Otherwise CF set and nothing is written. Keeps rsi, rcx when it
; does not apply; r12-r15, rbx always.
http_rewrite_target:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,RA_SIZE
	lea	r8,[g_acts+rax]
	mov	r9,[r8+RA_WFROM]
	test	r9,r9
	jz	.no
	cmp	dword [r8+RA_WRX],0
	jne	.regex
	mov	edx,[r8+RA_WFLEN]
	cmp	[g_npath_len],edx
	jb	.no
	push	rsi
	push	rcx
	push	rdi
	lea	rdi,[g_npath]
	mov	rsi,r9
	mov	ecx,edx
	repe	cmpsb
	pop	rdi
	pop	rcx
	pop	rsi
	jne	.no
	; the query: from the first '?' of the original target
	mov	r10,rsi
	mov	r11d,ecx
@@:
	test	r11d,r11d
	jz	@f
	cmp	byte [r10],'?'
	je	@f
	inc	r10
	dec	r11d
	jmp	@b
@@:
	; TO, with {*} = the normalized path after the prefix
	mov	rsi,[r8+RA_WTO]
	mov	ecx,[r8+RA_WTLEN]
.to:
	test	ecx,ecx
	jz	.query
	mov	al,[rsi]
	cmp	al,'{'
	jne	.byte
	cmp	ecx,3
	jb	.byte
	cmp	word [rsi+1],'*}'
	jne	.byte
	push	rsi
	push	rcx
	mov	ecx,[g_npath_len]
	sub	ecx,edx
	lea	rsi,[g_npath+rdx]
	rep	movsb
	pop	rcx
	pop	rsi
	add	rsi,3
	sub	ecx,3
	jmp	.to
.byte:
	mov	[rdi],al
	inc	rdi
	inc	rsi
	dec	ecx
	jmp	.to
.query:
	mov	rsi,r10
	mov	ecx,r11d
	rep	movsb
	clc
	ret
.no:
	stc
	ret
.regex:
	; ~REGEX -> TO: TO, with $1-$9 the groups of its match (of the normalized
	; path), then the request's query; no match, no rewrite
	push	rsi
	push	rcx
	push	rdi
	push	r8
	mov	eax,[r8+RA_WRX]
	dec	eax
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	call	rx_match
	pop	r8
	pop	rdi
	pop	rcx
	pop	rsi
	test	eax,eax
	jz	.no
	mov	r10,rsi				; the query: from the first '?'
	mov	r11d,ecx
@@:
	test	r11d,r11d
	jz	@f
	cmp	byte [r10],'?'
	je	@f
	inc	r10
	dec	r11d
	jmp	@b
@@:
	lea	r9,[rdi+8192]			; (a bound on what the groups make it)
	mov	rsi,[r8+RA_WTO]
	mov	ecx,[r8+RA_WTLEN]
.rx_to:
	test	ecx,ecx
	jz	.query
	mov	al,[rsi]
	cmp	al,'$'
	jne	.rx_byte
	cmp	ecx,2
	jb	.rx_byte
	movzx	edx,byte [rsi+2-1]
	sub	edx,'1'
	cmp	edx,8
	ja	.rx_byte
	push	rsi
	push	rcx
	inc	edx				; the group
	mov	eax,[g_rx_cap+rdx*8]		; its start, its end
	mov	ecx,[g_rx_cap+rdx*8+4]
	cmp	eax,-1
	je	.rx_none
	sub	ecx,eax
	jbe	.rx_none
	lea	rsi,[g_npath+rax]
	lea	rax,[rdi+rcx]
	cmp	rax,r9
	ja	.rx_long
	rep	movsb
.rx_none:
	pop	rcx
	pop	rsi
	add	rsi,2
	sub	ecx,2
	jmp	.rx_to
.rx_byte:
	cmp	rdi,r9
	jae	.no
	mov	[rdi],al
	inc	rdi
	inc	rsi
	dec	ecx
	jmp	.rx_to
.rx_long:
	pop	rcx
	pop	rsi
	stc
	ret

; A route that redirects: okena answers it, the connection goes on (or
; closes when the request has a body okena would have to read away).
; ebx = session, r15 = state, rcx = the matched route entry, rdx = its
; action's offset in g_acts, g_hm = the request.
http_redirect:
	push	r12
	push	r13
	lea	r12,[g_acts+rdx]
	mov	r13,rcx
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; its body is not read: close after
@@:
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	eax,[r12+RA_CODE]
	mov	[r15+H_STATUS],eax
	mov	edi,eax
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 '
	mov	eax,[r12+RA_CODE]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,[r12+RA_CODE]
	call	http_reason
	call	fmt_cstr
	memit_x 13,10
	cmp	dword [r12+RA_TLEN],0
	je	.headers_crlf			; `respond`: no target
	memit_x 'Location: '
	; the target, {*} = the rest of the path after the route's prefix, {host}
	; the request's host name
	mov	rsi,[r12+RA_TGT]
	mov	ecx,[r12+RA_TLEN]
	xor	r8d,r8d				; '?' in the target
.tgt:
	test	ecx,ecx
	jz	.query
	mov	al,[rsi]
	cmp	al,'?'
	jne	@f
	inc	r8d
@@:
	cmp	al,'{'
	jne	.tgt_byte
	cmp	ecx,6
	jb	@f
	cmp	dword [rsi+1],'host'
	jne	.not_host
	cmp	byte [rsi+5],'}'
	jne	.not_host
	call	.host
	add	rsi,6
	sub	ecx,6
	jmp	.tgt
.not_host:
	cmp	dword [rsi+1],'path'		; {path}: the whole (normalized) path
	jne	@f
	cmp	byte [rsi+5],'}'
	jne	@f
	push	rsi
	push	rcx
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	rep	movsb
	pop	rcx
	pop	rsi
	add	rsi,6
	sub	ecx,6
	jmp	.tgt
@@:
	cmp	ecx,3
	jb	.tgt_byte
	cmp	word [rsi+1],'*}'
	jne	.tgt_byte
	push	rsi
	push	rcx
	cmp	dword [r13+RT_PREFIX],1
	jne	.rest_done			; an exact route has no rest (nor a regex's)
	mov	ecx,[g_npath_len]
	sub	ecx,[r13+RT_PLEN]
	jbe	.rest_done
	mov	eax,[r13+RT_PLEN]
	lea	rsi,[g_npath+rax]
	rep	movsb
.rest_done:
	pop	rcx
	pop	rsi
	add	rsi,3
	sub	ecx,3
	jmp	.tgt
.tgt_byte:
	mov	[rdi],al
	inc	rdi
	inc	rsi
	dec	ecx
	jmp	.tgt
.query:
	; the request's query goes along, unless the target has its own
	test	r8d,r8d
	jnz	.headers
	lea	rax,[g_hm]
	mov	rsi,[rax+HM_TARGET]
	mov	ecx,[rax+HM_TLEN]
.find_q:
	test	ecx,ecx
	jz	.headers
	cmp	byte [rsi],'?'
	je	.copy_q
	inc	rsi
	dec	ecx
	jmp	.find_q
.copy_q:
	rep	movsb
.headers:
	memit_x 13,10
.headers_crlf:
	call	cors_emit
	memit_x 'Content-Length: 0',13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi				; rdi = OUT, esi = its length
	pop	r13
	pop	r12
	jmp	h_send
; rdi = out: the Host's name, without its port; only what a name or an
; address is made of ([v6] kept whole)
.host:
	push	rsi
	push	rcx
	mov	eax,[g_hm+HM_HOST]
	cmp	eax,-1
	je	.host_done
	imul	rax,rax,HF_SIZE
	lea	rax,[g_hm+HM_HDRS+rax]
	mov	rsi,[rax+HF_VALUE]
	mov	ecx,[rax+HF_VLEN]
	xor	edx,edx				; in brackets
.host_char:
	test	ecx,ecx
	jz	.host_done
	movzx	eax,byte [rsi]
	cmp	al,'['
	jne	@f
	mov	edx,1
	jmp	.host_put
@@:
	cmp	al,']'
	jne	@f
	xor	edx,edx
	jmp	.host_put
@@:
	cmp	al,':'
	jne	@f
	test	edx,edx
	jz	.host_done			; its port
	jmp	.host_put
@@:
	cmp	al,'-'
	je	.host_put
	cmp	al,'.'
	je	.host_put
	mov	r9d,eax
	sub	r9d,'0'
	cmp	r9d,9
	jbe	.host_put
	mov	r9d,eax
	or	r9d,0x20
	sub	r9d,'a'
	cmp	r9d,25
	ja	.host_done			; not of a name: it ends there
.host_put:
	mov	[rdi],al
	inc	rdi
	inc	rsi
	dec	ecx
	jmp	.host_char
.host_done:
	pop	rcx
	pop	rsi
	ret

; ------------------------------------------------------ phase timeouts

; Two clocks besides the idle one, per listener, each a FIFO list (all
; its sessions share one limit, so the oldest is always at the head and
; a tick looks only at what expires):
;   PH_HEAD      a request head must arrive whole within `header`
;                (slowloris); 408, or a silent close when nothing came;
;   PH_RESPONSE  the backend must start its response within `response`
;                once the request is sent; 504.
; While a session waits on its backend it is not idle (idle_expire).

PH_HEAD		:= 1
PH_RESPONSE	:= 2
PH_TRIM		:= 3		; idle keep-alive: give the record's buffers back
PH_BODY		:= 4		; the request body must keep coming: `body_idle`
PH_KINDS	:= 4
TRIM_SECS	:= 2

bss
	g_ph_head	rd MAX_LISTENERS * PH_KINDS
	g_ph_tail	rd MAX_LISTENERS * PH_KINDS
end bss

; edi = session, esi = PH_*: start that clock now.
ph_arm:
	push	rsi
	push	rdi
	call	ph_disarm
	pop	rdi
	pop	rsi
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	[rax+S_PH_KIND],esi
	mov	ecx,[g_tick]
	mov	[rax+S_PH_AT],ecx
	mov	ecx,[rax+S_LST]
	lea	ecx,[rcx*4+rsi-1]
	mov	edx,[g_ph_tail+rcx*4]
	mov	[rax+S_PH_PREV],edx
	mov	dword [rax+S_PH_NEXT],NIL
	mov	[g_ph_tail+rcx*4],edi
	cmp	edx,NIL
	je	.first
	shl	rdx,S_SHIFT
	add	rdx,[g_sess_base]
	mov	[rdx+S_PH_NEXT],edi
	ret
.first:
	mov	[g_ph_head+rcx*4],edi
	ret

; edi = session: stop its clock, if one runs.
ph_disarm:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	esi,[rax+S_PH_KIND]
	test	esi,esi
	jz	.none
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[rax+S_LST]
	lea	ecx,[rcx*4+rsi-1]
	mov	edx,[rax+S_PH_PREV]
	mov	r8d,[rax+S_PH_NEXT]
	cmp	edx,NIL
	je	.head
	mov	r9d,edx
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_PH_NEXT],r8d
	jmp	.next
.head:
	mov	[g_ph_head+rcx*4],r8d
.next:
	cmp	r8d,NIL
	je	.tail
	mov	r9d,r8d
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_PH_PREV],edx
	ret
.tail:
	mov	[g_ph_tail+rcx*4],edx
.none:
	ret

; Tick: answer the sessions whose clock ran out.
ph_expire:
	push	rbx
	push	r12
	push	r13
	push	r14
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.done
	imul	rax,r12,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	je	@f
	cmp	dword [g_listeners+rax+LS_TLS],0
	je	.next				; a tcp listener: only its handshakes
@@:
	mov	r14d,PH_HEAD
.kind:
	imul	rax,r12,LS_SIZE
	mov	r13d,[g_listeners+rax+LS_T_HEADER]
	cmp	r14d,PH_HEAD
	je	.oldest
	mov	r13d,[g_listeners+rax+LS_T_RESPONSE]
	cmp	r14d,PH_RESPONSE
	je	.oldest
	mov	r13d,[g_listeners+rax+LS_T_BODY]
	cmp	r14d,PH_BODY
	je	.oldest
	mov	r13d,TRIM_SECS
.oldest:
	lea	ecx,[r12*4+r14-1]
	mov	ebx,[g_ph_head+rcx*4]
	cmp	ebx,NIL
	je	.next_kind
	call	session_ptr
	mov	ecx,[g_tick]
	sub	ecx,[rax+S_PH_AT]
	cmp	ecx,r13d
	jbe	.next_kind			; never early
	mov	edi,ebx
	call	ph_disarm
	push	r12
	push	r13
	push	r14
	push	rbx
	mov	esi,r14d
	call	http_phase_expired
	pop	rbx
	pop	r14
	pop	r13
	pop	r12
	jmp	.oldest
.next_kind:
	inc	r14d
	cmp	r14d,PH_KINDS
	jbe	.kind
.next:
	inc	r12d
	jmp	.listener
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = session, esi = the PH_* that ran out.
http_phase_expired:
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	h_rec
	cmp	esi,PH_TRIM
	je	.trim
	cmp	esi,PH_BODY
	je	.body
	cmp	esi,PH_HEAD
	jne	.response
	mov	eax,[r15+H_STATE]
	cmp	eax,HS_TLS_QUEUED
	je	.silent				; waited for the handshake budget
	cmp	eax,HS_TLS_ODWAIT
	je	.silent				; (an on-demand certificate never came)
	cmp	eax,HS_TLS_HELLO
	jb	@f
	cmp	eax,HS_TLS_LAST
	jbe	.silent				; the handshake never finished
@@:
	cmp	eax,HS_LINGER
	je	.silent				; its error long sent
	cmp	eax,HS_HEAD
	jne	.out
	cmp	dword [r15+H_INLEN],0
	je	.silent				; connected, never asked anything
	mov	edi,408
	jmp	http_error
.silent:
	mov	edi,ebx
	jmp	session_close
.body:
	; the client stopped sending its body (a stall, or slow upload abuse)
	cmp	dword [r15+H_STATE],HS_REQ_READ
	jne	.out
	mov	edi,408
	jmp	http_error
.trim:
	; idle between requests: everything but the first page (the record's
	; fields, and where the next request's first bytes land) goes back to
	; the kernel; a read in flight there just faults a fresh page in
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H2C or SF_H3S or SF_QC
	jnz	.out				; HTTP/2 and 3 keep their queues and tables
	cmp	dword [r15+H_STATE],HS_HEAD
	jne	.out
	cmp	dword [r15+H_INLEN],0
	jne	.out
	mov	rdi,[r15+H_BUF]
	mov	esi,1 shl HB_SHIFT
	cmp	dword [r15+H_UTLS],0
	je	@f
	mov	esi,HB_TLS			; user-space records: the keys stay
@@:
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	cmp	dword [r15+H_UTLS],0
	je	@f
	cmp	dword [r15+H_RXC],0		; ciphertext of the next request waits
	jne	@f
	mov	rdi,[r15+H_BUF]			; the record buffers past the keys' page
	add	rdi,HB_TLS + 4096
	mov	esi,(1 shl HB_SHIFT) - HB_TLS - 4096
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
@@:
	inc	qword [g_st_http_trimmed]
	ret
.response:
	cmp	dword [r15+H_STATE],HS_RESP_HEAD
	jne	.out
	call	session_ptr
	mov	edi,[rax+S_SERVER]
	call	server_5xx			; a silent backend counts as failing
	mov	edi,504
	jmp	http_error
.out:
	ret

; ------------------------------------------------------------- tunnel

; 101 sent. Bytes that arrived after the heads go first: the backend's
; to the client, then the client's to the backend; then the session is a
; plain L4 tunnel (the same relay as tcp listeners).
http_tunnel_up:
	h_rec
	mov	dword [r15+H_STATE],HS_TUNNEL_UP
	mov	esi,[r15+H_UPLEN]
	mov	eax,[r15+H_UPOFF]
	sub	esi,eax
	jz	http_tunnel_in
	mov	[r15+H_UPOFF],esi		; (all taken)
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rax]
	mov	ecx,SIDE_CLIENT
	jmp	h_send

http_tunnel_in:
	h_rec
	mov	dword [r15+H_STATE],HS_TUNNEL_IN
	mov	esi,[r15+H_INLEN]
	mov	eax,[r15+H_INOFF]
	sub	esi,eax
	jz	http_tunnel_start
	mov	[r15+H_INOFF],esi
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rax]
	mov	ecx,SIDE_UP
	jmp	h_send

http_tunnel_start:
	xor	esi,esi
	call	alog_exchange			; the 101 exchange; then bytes, unlogged
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S
	jnz	http_h2tun_start		; a stream: no socket of its own to relay
	or	dword [rax+S_FLAGS],SF_TUNNEL
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	jmp	start_relay
.epoll:
	push	rbx
	mov	edi,ebx
	mov	esi,EK_CLIENT
	call	ep_pump
	pop	rbx
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	mov	edi,ebx
	mov	esi,EK_UPSTREAM
	jmp	ep_pump
.out:
	ret

; WebSocket over an HTTP/2 stream (RFC 8441), after the 101 (the stream's
; 200): the backend's bytes go to the stream by the exchange's own loop
; (h_recv on the upstream side, h_send of them on the stream), the
; client's DATA to the backend beside it (http_h2tun_pump, with sends of
; its own). It ends when the backend closes: END_STREAM. ebx = session.
http_h2tun_start:
	h_rec
	mov	dword [r15+H_STATE],HS_H2TUN
	or	dword [r15+H_FLAGS],HX_H2TUN
	and	dword [r15+H_FLAGS],not HX_TSEND
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	call	http_h2tun_pump			; what the client sent already
http_h2tun_read:
	h_rec
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	mov	esi,H_UP_CAP
	jmp	h_recv

; rax = the backend's bytes (side 1), or its end
http_h2tun_recv:
	test	rax,rax
	jle	.end
	push	rax
	mov	edi,ebx
	call	idle_touch
	pop	rsi
	h_rec
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.end:
	h_rec
	and	dword [r15+H_FLAGS],not HX_H2TUN
	jmp	http_exchange_done		; END_STREAM, the upstream closed

; The client's bytes to the backend: what IN holds, then the stream's
; queue, a send at a time (io_uring: OP_H2T_SEND; epoll: written at once,
; EPOLLOUT when the socket is full). The client's END_STREAM sends
; nothing: the backend ends the tunnel. ebx = session; keeps every
; register but rax, rcx, rdx, rsi, rdi, r8-r11.
http_h2tun_pump:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	h_rec
	test	dword [r15+H_FLAGS],HX_H2TUN
	jz	.out
	test	dword [r15+H_FLAGS],HX_TSEND
	jnz	.out				; its end calls again
.next:
	mov	ecx,[r15+H_INLEN]
	sub	ecx,[r15+H_INOFF]
	jnz	.send
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	mov	r14,[r15+H_BUF]
	add	r14,HB_H2Q
	mov	ecx,[r14+Q_LEN]
	cmp	ecx,[r14+Q_OFF]
	je	.out				; nothing more yet
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,H_IN_CAP
	call	h2s_copy			; (the window goes back as it drains)
	h_rec
	add	[r15+H_INLEN],eax
	jmp	.next
.send:
	mov	edi,ebx
	push	rcx
	call	idle_touch
	pop	rcx
	h_rec
	mov	eax,[r15+H_INOFF]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_IN+rax]
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.write
	or	dword [r15+H_FLAGS],HX_TSEND
	push	rsi
	push	rcx
	mov	edi,OP_H2T_SEND
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	pop	rcx
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	[rax+SQE_ADDR],rsi
	mov	[rax+SQE_LEN],ecx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	mov	ecx,SIDE_UP
	call	h_sqe_fd
	jmp	.out
.write:
	push	rsi
	push	rcx
	call	session_ptr
	mov	edi,[rax+S_UPFD]
	pop	rdx
	pop	rsi
	mov	eax,SYS_write
	syscall
	cmp	rax,-EINTR
	je	.send
	cmp	rax,-EAGAIN
	je	.full
	test	rax,rax
	js	.stop				; (the backend's side ends it)
	h_rec
	add	[r15+H_INOFF],eax
	jmp	.next
.full:
	h_rec
	or	dword [r15+H_FLAGS],HX_TSEND	; until EPOLLOUT (hep_event)
	jmp	.out
.stop:
	h_rec
	or	dword [r15+H_FLAGS],HX_TSEND	; nothing more goes
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; io_uring: a send of the pump finished (ebx, r12d = generation, r14 = res)
on_h2t_send:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	test	r14,r14
	js	.out				; the backend's side ends it (HX_TSEND stays)
	add	[r15+H_INOFF],r14d
	and	dword [r15+H_FLAGS],not HX_TSEND
	jmp	http_h2tun_pump
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; One exchange is over: drop the upstream connection, then the next
; request on the client connection, or close it.
http_exchange_done:
	h_rec
	; a file or the cache answered: okena's own (cache_finish forgets which)
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_FILE or SF_CACHED
	jz	@f
	or	dword [r15+H_FLAGS],HX_SELF
@@:
	call	cache_finish
	h_rec
	and	dword [r15+H_FLAGS],not (HX_DUPLEX or HX_H2TUN)
	test	dword [r15+H_FLAGS],HX_MIRROR	; (a copy is nobody's request: not logged)
	jnz	.logged
	xor	esi,esi
	test	dword [r15+H_FLAGS],HX_SELF
	setnz	sil				; okena's own answer, or the backend's
	call	alog_exchange
.logged:
	h_rec
	and	dword [r15+H_FLAGS],not HX_LASTCHUNK
	test	dword [r15+H_FLAGS],HX_UPKEEP
	jz	.drop
	call	h_park				; back to the pool, or closed when full
	jmp	.next
.drop:
	call	h_upclose
.next:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_HEDGE
	jnz	hedge_done
	test	dword [rax+S_FLAGS],SF_MIR
	jnz	.close				; a copy: nothing comes after it
	test	dword [rax+S_FLAGS],SF_H3S
	jnz	h3s_finish			; an HTTP/3 stream: FIN, then it goes
	test	dword [rax+S_FLAGS],SF_H2S
	jnz	h2s_finish			; an HTTP/2 stream: END_STREAM, then it goes
	h_rec
	test	dword [r15+H_FLAGS],HX_CLOSE
	jnz	http_close_notify		; (a TLS client is told: tls.inc)
	jmp	http_next_request
.close:
	mov	edi,ebx
	jmp	session_close

; r15 = record, g_hm = the request: HX_GRPC when its content-type is
; application/grpc (or application/grpc+proto, ...). Keeps rbx, r12-r15.
cstring hn_content_type, 'content-type',0
http_grpc_mark:
	push	rbx
	push	r12
	mov	rax,[r15+H_BUF]			; (grpcweb.inc: none, until said)
	mov	byte [rax+HB_GWEB],0
	lea	r12,[g_hm]
	xor	ebx,ebx
.field:
	cmp	ebx,[r12+HM_NHDR]
	jae	.out
	imul	rdi,rbx,HF_SIZE
	lea	rdi,[r12+HM_HDRS+rdi]
	inc	ebx
	push	rdi
	lea	rsi,[hn_content_type]
	call	hf_is
	pop	rdi
	jnz	.field
	cmp	dword [rdi+HF_VLEN],16
	jb	.out
	push	rdi
	mov	rdi,[rdi+HF_VALUE]
	lea	rsi,[.grpc]
	mov	edx,16
	call	mem_eq_nocase
	pop	rdi
	test	eax,eax
	jz	.out
	or	dword [r15+H_FLAGS],HX_GRPC
	call	gweb_mark			; and gRPC-Web? (grpcweb.inc)
.out:
	pop	r12
	pop	rbx
	ret
.grpc	db 'application/grpc'

; ------------------------------------------------------------- errors

; edi = status: answer it and close. Once the response has started there
; is nothing honest to send: just close.
http_error:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2U
	jnz	h2u_failed			; (its TLS handshake failed: nobody to answer)
	h_rec
	and	dword [r15+H_FLAGS],not HX_DUPLEX
	test	dword [r15+H_FLAGS],HX_STARTED
	jnz	.close
	mov	eax,edi				; a stale copy kept for this?
	push	rdi
	call	cache_sie_ok
	pop	rdi
	jnc	cache_sie_serve
	push	rdi
	call	h_upclose
	pop	rax
	h_rec
	or	dword [r15+H_FLAGS],HX_CLOSE or HX_STARTED
	mov	dword [r15+H_STATE],HS_ERROR_SEND
	mov	[r15+H_STATUS],eax
	mov	edi,eax
	mov	esi,5
	call	http_count
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	push	rax
	call	rid_new
	pop	rax
@@:
	test	dword [r15+H_FLAGS],HX_GRPC
	jnz	http_error_grpc
	xor	ecx,ecx				; a page of one's own for it?
	call	errpage_find
	test	rsi,rsi
	jnz	http_error_page
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	push	rax
	memit_x 'HTTP/1.1 '
	mov	rax,[rsp]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,[rsp]
	call	http_reason			; rsi = text
	push	rsi
	call	fmt_cstr
	memit_x 13,10,'Content-Type: text/plain',13,10,'Connection: close',13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	call	cors_emit
	memit_x 'Content-Length: '
	mov	rsi,[rsp]
	xor	eax,eax
@@:
	cmp	byte [rsi+rax],0
	je	@f
	inc	eax
	jmp	@b
@@:
	add	eax,[r15+H_RIDLEN]
	add	eax,14				; newline, "request id: ", newline
	call	fmt_u64
	memit_x 13,10,13,10
	pop	rsi
	call	fmt_cstr
	memit_x 10,'request id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	add	rsp,8
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	esi,edi
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	jmp	h_send
.close:
	mov	edi,ebx
	jmp	session_close

; A backend's error answered with a page: eax = its status, rsi = the page.
; The upstream connection goes (its body is not read), the client's closes
; after the page as with okena's own errors.
http_error_backend:
	push	rsi
	push	rax
	call	h_upclose
	h_rec
	or	dword [r15+H_FLAGS],HX_CLOSE or HX_STARTED
	mov	dword [r15+H_STATE],HS_ERROR_SEND
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	pop	rax
	pop	rsi
	jmp	http_error_page

; http_error for a gRPC request, eax = the HTTP status: a "Trailers-Only"
; answer (gRPC over HTTP/2: status 200, no body, grpc-status in the head),
; the code from the HTTP status as gRPC maps it (502 and 503 UNAVAILABLE,
; 504 and 408 DEADLINE_EXCEEDED, ...). The log and the counters keep the
; HTTP status.
http_error_grpc:
	mov	qword [g_ep_force],0		; (no page for gRPC: maintenance's is let go)
	mov	dword [g_ep_retry],0
	push	rax
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 200 OK',13,10,'content-type: application/grpc'
	mov	rax,[r15+H_BUF]			; gRPC-Web: what its client asked in
	movzx	eax,byte [rax+HB_GWEB]
	test	eax,eax
	jz	.ct_end
	push	rax
	memit_x '-web'
	pop	rax
	cmp	eax,4
	jb	.ct_end
	memit_x '-text'
.ct_end:
	memit_x 13,10,'grpc-status: '
	mov	eax,[rsp]
	lea	rsi,[.map]
@@:
	mov	ecx,[rsi]
	test	ecx,ecx
	jz	@f
	cmp	ecx,eax
	je	@f
	add	rsi,8
	jmp	@b
@@:
	mov	eax,[rsi+4]
	call	fmt_u64
	memit_x 13,10,'grpc-message: '
	mov	eax,[rsp]
	call	http_reason			; rsi = text
	call	fmt_cstr
	memit_x 13,10,'x-request-id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10,'content-length: 0',13,10,'connection: close',13,10,13,10
	add	rsp,8
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	esi,edi
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	jmp	h_send
.map	dd 400,13, 401,16, 403,7, 404,12, 408,4, 421,14, 429,14, 431,13
	dd 501,12, 502,14, 503,14, 504,4, 505,12, 0,2

; eax = status. rsi = reason phrase.
macro reasons pairs&
	rodata
		align 8
		http_reasons:
		iterate <code,text>, pairs
			dq code, http_reason_text.%
		end iterate
		dq 0, 0
		iterate <code,text>, pairs
			http_reason_text.%:
			db text,0
		end iterate
	end rodata
end macro
reasons 409,'Conflict', 422,'Unprocessable Content', 301,'Moved Permanently', 302,'Found', 303,'See Other', 307,'Temporary Redirect', \
	308,'Permanent Redirect', 400,'Bad Request', 429,'Too Many Requests', 403,'Forbidden', 401,'Unauthorized', 404,'Not Found', 405,'Method Not Allowed', 408,'Request Timeout', \
	421,'Misdirected Request', \
	410,'Gone', 411,'Length Required', 413,'Content Too Large', 414,'URI Too Long', 415,'Unsupported Media Type', \
	431,'Request Header Fields Too Large', 500,'Internal Server Error', 501,'Not Implemented', 502,'Bad Gateway', \
	503,'Service Unavailable', 504,'Gateway Timeout', 505,'HTTP Version Not Supported', 508,'Loop Detected'

http_reason:
	lea	rcx,[http_reasons]
.next:
	mov	rdx,[rcx]
	test	rdx,rdx
	jz	.other
	cmp	rdx,rax
	je	.found
	add	rcx,16
	jmp	.next
.found:
	mov	rsi,[rcx+8]
	ret
.other:
	cstring str_reason_other, 'Error',0
	lea	rsi,[str_reason_other]
	ret

; An error answered on a connection in the clear (HTTP/1.1): close only once the
; client has stopped sending. Closed with bytes of its unread (a body, a head too
; large, what it pipelined), the socket sends a reset, and a client still sending
; may lose the answer with it. So the writing side is shut (the client reads the
; end of the answer), what comes is read and dropped until the client closes or
; the header timeout passes. ebx = session.
http_linger:
	h_rec
	mov	dword [r15+H_STATE],HS_LINGER
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	.ring
	xor	ecx,ecx
	call	hep_fd
	mov	edi,eax
	mov	esi,SHUT_WR
	mov	eax,SYS_shutdown
	syscall
	jmp	.armed
.ring:
	; the session's own operation: io_uring runs a SHUTDOWN on a thread of io-wq,
	; later, and finds a direct descriptor's file only then. Uncounted, the session
	; could close first and its slot go to a new connection, which the shutdown
	; would then cut. Counted, the slot is closed only after it (or its cancel).
	mov	edi,OP_S_SHUT
	mov	esi,ebx
	call	sess_sqe			; (rdx = the session)
	mov	byte [rax+SQE_OPCODE],IORING_OP_SHUTDOWN
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe rdx
	mov	dword [rax+SQE_LEN],SHUT_WR
.armed:
	mov	edi,ebx
	mov	esi,PH_HEAD
	call	ph_arm
; what the client sends next, into nothing
http_linger_read:
	h_rec
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	esi,H_IN_CAP
	jmp	h_recv
