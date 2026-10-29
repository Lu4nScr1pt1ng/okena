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

H_SHIFT		= 16		; 64 KiB per session, reserved, touched when used
H_STATE		= 0
H_INLEN		= 4		; bytes in IN
H_INOFF		= 8		; first unconsumed byte of IN
H_OUTLEN	= 12
H_UPLEN		= 16
H_UPOFF		= 20
H_BODY		= 24		; BK_* of the request body
H_RBODY		= 28		; BK_* of the response body
H_REMAIN	= 32		; q: request body bytes left (BK_LENGTH)
H_RREMAIN	= 40		; q: response body bytes left
H_FLAGS		= 48		; HX_*
H_STATUS	= 52
H_SPTR		= 56		; q: what an engine still has to send
H_SLEN		= 64		; d
H_CK		= 72		; request chunked decoder (CK_SIZE)
H_RCK		= 104		; response chunked decoder
H_IN		= 1024		; client bytes: the request head, then its body
H_IN_CAP	= 16384
H_OUT		= H_IN + H_IN_CAP	; heads okena writes, chunk framing
H_OUT_CAP	= 20480
H_UP		= H_OUT + H_OUT_CAP	; upstream bytes: the response
H_UP_CAP	= 16384
; access log: the request as it was, and its exchange's counters
H_LT0		= 184		; q: TSC when the request head was parsed, 0 = none
H_XBYTES	= 192		; q: bytes sent to the client in this exchange
H_LMLEN		= 200		; d
H_LHLEN		= 204		; d
H_LTLEN		= 208		; d
H_LTEXT_M	= H_UP + H_UP_CAP	; method
H_LTEXT_M_CAP	= 16
H_LTEXT_H	= H_LTEXT_M + 16	; host
H_LTEXT_H_CAP	= 255
H_LTEXT_T	= H_LTEXT_H + 256	; target
H_LTEXT_T_CAP	= 1024
assert H_LTEXT_T + H_LTEXT_T_CAP <= 1 shl H_SHIFT

HS_HEAD		= 1		; reading a request head
HS_CONTINUE	= 2		; writing our 100 Continue
HS_CONNECT	= 3
HS_SEND_HEAD	= 4
HS_REQ_SEND	= 5		; writing request body bytes upstream
HS_REQ_READ	= 6		; reading request body bytes
HS_RESP_HEAD	= 7		; reading a response head
HS_RESP_SEND	= 8		; writing response head or body to the client
HS_RESP_READ	= 9
HS_ERROR_SEND	= 10		; writing an error, then closing
HS_TUNNEL_UP	= 11		; 101 sent: bytes the backend sent early go to the client
HS_TUNNEL_IN	= 12		; then bytes the client sent early go to the backend

BK_NONE		= 0
BK_LENGTH	= 1
BK_CHUNKED	= 2
BK_CLOSE	= 3		; until the backend closes

HX_CLOSE	= 1		; close the client connection after this response
HX_HEAD		= 2		; a HEAD request
HX_STARTED	= 4		; response bytes reached the client
HX_CHUNKOUT	= 8		; the response goes out chunked (re-framed)
HX_CONTINUE	= 16		; the client waits for 100 Continue
HX_LASTCHUNK	= 32		; the last chunk is being written
HX_REUSED	= 64		; the upstream connection came from the pool
HX_NOBODY	= 128		; the request has no body (safe to send twice)
HX_NOPOOL	= 256		; connect afresh (a reused one just failed)
HX_UPKEEP	= 512		; the upstream connection may go back to the pool
HX_UPGRADE	= 1024		; the client asks to switch protocols (WebSocket...)
HX_IDEMPOTENT	= 2048		; GET, HEAD, PUT, DELETE, OPTIONS: may be sent twice
HX_RETRIED	= 4096		; this request was sent again, to another server
HX_AVOID	= 8192		; the next connect avoids S_SERVER

SIDE_CLIENT	= 0
SIDE_UP		= 1

bss
	align 8
	g_http_base	dq ?
	g_hm:		rb HM_SIZE		; the message being parsed
end bss

; Worker: the session records. eax = 0 or -errno.
http_worker_init:
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,H_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_http_base],rax
	mov	rdi,rax
	mov	esi,[g_sessions]
	shl	rsi,H_SHIFT
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	xor	eax,eax
.done:
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
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	[r15+H_FLAGS],eax
	mov	edi,ebx
	mov	esi,PH_HEAD
	call	ph_arm
	jmp	http_next_request

; ----------------------------------------------------------- requests

; Take the next request from IN, reading more when the head is not all
; there. ebx = session.
http_next_request:
	h_rec
	mov	dword [r15+H_STATE],HS_HEAD
	and	dword [r15+H_FLAGS],HX_CLOSE
	; the unconsumed bytes (a pipelined request) move to the front
	mov	ecx,[r15+H_INLEN]
	mov	eax,[r15+H_INOFF]
	sub	ecx,eax
	jz	.empty
	test	eax,eax
	jz	.parse
	lea	rsi,[r15+H_IN+rax]
	lea	rdi,[r15+H_IN]
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
	jmp	.read
.parse:
	lea	rdi,[r15+H_IN]
	mov	esi,[r15+H_INLEN]
	call	http_head_end
	cmp	eax,-1
	je	.bad
	test	eax,eax
	jnz	http_request
	cmp	dword [r15+H_INLEN],H_IN_CAP
	jae	.too_large
.read:
	mov	ecx,SIDE_CLIENT
	mov	edi,[r15+H_INLEN]
	lea	rdi,[r15+H_IN+rdi]
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	jmp	h_recv
.bad:
	mov	edi,400
	jmp	http_error
.too_large:
	mov	edi,431
	jmp	http_error

; ebx = session, eax = length of the head at the start of IN.
http_request:
	push	rax
	mov	edi,ebx
	call	ph_disarm			; the head is all here
	h_rec
	lea	rdi,[r15+H_IN]
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
	call	alog_request
	h_rec
	lea	r14,[g_hm]
	mov	eax,[r14+HM_FLAGS]
	test	eax,HMF_CLOSE
	jz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [r14+HM_VERSION],10
	jne	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; HTTP/1.0 clients: one exchange
@@:
	cmp	dword [r14+HM_MLEN],4
	jne	@f
	mov	rdx,[r14+HM_METHOD]
	cmp	dword [rdx],'HEAD'
	jne	@f
	or	dword [r15+H_FLAGS],HX_HEAD
@@:
	test	eax,HMF_UPGRADE
	jz	@f
	or	dword [r15+H_FLAGS],HX_UPGRADE
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
@@:
	test	dword [r14+HM_FLAGS],HMF_CONTINUE
	jz	@f
	cmp	dword [r15+H_BODY],BK_NONE
	je	@f
	or	dword [r15+H_FLAGS],HX_CONTINUE
@@:
	add	dword [g_retry_tokens],RETRY_PER_REQ
	cmp	dword [g_retry_tokens],RETRY_CAP
	jbe	@f
	mov	dword [g_retry_tokens],RETRY_CAP
@@:
	call	http_route			; eax = pool or -1
	cmp	eax,-1
	je	.no_route
	mov	r13d,eax
	call	session_ptr
	mov	[rax+S_POOL],r13d
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	h_rec
	call	http_write_request_head
	jc	.head_too_large
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
	jmp	http_error
.no_route:
	mov	edi,404
	jmp	http_error
.head_too_large:
	mov	edi,431
	jmp	http_error

; The route for g_hm on the session's listener: an exact path beats a
; prefix, a longer prefix beats a shorter one, methods must match.
; ebx = session. eax = pool or -1.
http_route:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	lea	r12,[g_listeners+rax]
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
	mov	r14,rsi				; path
	mov	r15d,edx
	call	http_route_set			; ecx/r9d = the routes of the host
	mov	rdi,[r13+HM_METHOD]
	mov	esi,[r13+HM_MLEN]
	call	method_bit
	mov	r13d,eax			; method bit
	mov	eax,-1				; best pool
	mov	r8d,-1				; best score
	mov	ecx,[g_rset_first]
	mov	r9d,ecx
	add	r9d,[g_rset_count]
.next:
	cmp	ecx,r9d
	jae	.done
	imul	rbx,rcx,RT_SIZE
	lea	rbx,[g_routes+rbx]
	mov	edx,[rbx+RT_METHODS]
	test	edx,edx
	jz	@f
	test	edx,r13d
	jz	.skip
@@:
	mov	edx,[rbx+RT_PLEN]
	cmp	dword [rbx+RT_PREFIX],0
	jne	.prefix
	cmp	edx,r15d
	jne	.skip
	push	rcx
	push	rax
	push	r8
	push	r9
	mov	rdi,[rbx+RT_PATH]
	mov	rsi,r14
	call	mem_eq
	pop	r9
	pop	r8
	mov	r10d,eax
	pop	rax
	pop	rcx
	test	r10d,r10d
	jz	.skip
	mov	eax,[rbx+RT_POOL]		; exact: nothing beats it
	jmp	.done
.prefix:
	cmp	edx,r15d
	ja	.skip
	cmp	edx,r8d
	jle	.skip				; not better than what we have
	push	rcx
	push	rax
	push	r8
	push	r9
	push	rdx
	mov	rdi,[rbx+RT_PATH]
	mov	rsi,r14
	call	mem_eq
	pop	rdx
	pop	r9
	pop	r8
	mov	r10d,eax
	pop	rax
	pop	rcx
	test	r10d,r10d
	jz	.skip
	mov	r8d,edx
	mov	eax,[rbx+RT_POOL]
.skip:
	inc	ecx
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

bss
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
	mov	r15d,-1				; best wildcard (length)
	mov	ebx,[r12+LS_HFIRST]
	mov	r8d,ebx
	add	r8d,[r12+LS_HCOUNT]
.host:
	cmp	ebx,r8d
	jae	.wild_done
	imul	rcx,rbx,HO_SIZE
	lea	rcx,[g_hosts+rcx]
	mov	edx,[rcx+HO_NLEN]
	cmp	dword [rcx+HO_WILD],0
	jne	.wild
	cmp	edx,r14d
	jne	.next
	push	rcx
	push	r8
	mov	rdi,[rcx+HO_NAME]
	mov	rsi,r13
	call	mem_eq_nocase
	pop	r8
	pop	rcx
	test	eax,eax
	jz	.next
	jmp	.use				; exact: done
.wild:
	; ".example.com" matches "a.example.com", not "example.com"
	cmp	edx,r14d
	jae	.next
	cmp	edx,r15d
	jle	.next
	push	rcx
	push	r8
	push	rdx
	mov	rdi,[rcx+HO_NAME]
	mov	esi,r14d
	sub	esi,edx
	lea	rsi,[r13+rsi]
	call	mem_eq_nocase
	pop	rdx
	pop	r8
	pop	rcx
	test	eax,eax
	jz	.next
	mov	r15d,edx
	mov	eax,[rcx+HO_RFIRST]
	mov	[g_rset_first],eax
	mov	eax,[rcx+HO_RCOUNT]
	mov	[g_rset_count],eax
.next:
	inc	ebx
	jmp	.host
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

; OUT = the request head okena sends upstream. ebx = session, r15 =
; record, g_hm = the parsed request. CF when it does not fit.
http_write_request_head:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	r12,[g_hm]
	lea	rdi,[r15+H_OUT]
	lea	r13,[r15+H_OUT+H_OUT_CAP-256]	; room kept for what okena adds
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
	rep	movsb
.version:
	mov	rax,' HTTP/1.'
	mov	[rdi],rax
	mov	dword [rdi+8],0x0A0D31		; "1\r\n"
	add	rdi,11
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
	push	rdi
	irp name, hn_x_forwarded_for, hn_x_forwarded_proto, hn_x_forwarded_host, hn_forwarded, hn_expect
		mov	rdi,r14
		lea	rsi,[name]
		call	hf_is
		jz	.skip_pop
	end irp
	pop	rdi
.copy:
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
	; the client as okena saw it; never what the client claims
	mov	rbx,[rsp+24]			; the session (pushed rbx)
	memit_x 'X-Forwarded-For: '
	call	peer_ptr
	push	rdi
	lea	rdi,[g_ip_a]
	lea	rsi,[rax+P_PEER]
	call	peer_normalize
	pop	rdi
	lea	rsi,[g_ip_a]
	mov	edx,eax
	call	fmt_ip
	memit_x 13,10,'X-Forwarded-Proto: http',13,10
	h_rec
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
	lea	rax,[r15+H_OUT]
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
cstring hn_x_forwarded_proto, 'x-forwarded-proto',0
cstring hn_x_forwarded_host, 'x-forwarded-host',0
cstring hn_forwarded, 'forwarded',0


; ------------------------------------------------------------- engine

; The upstream is connected: send the request head.
http_connected:
	h_rec
	mov	dword [r15+H_STATE],HS_SEND_HEAD
	mov	ecx,SIDE_UP
	lea	rdi,[r15+H_OUT]
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
	mov	edi,502
	jmp	http_error

; ebx = session, ecx = side, rax = bytes read (0 = end, < 0 = error).
http_recv_done:
	h_rec
	mov	edx,[r15+H_STATE]
	cmp	edx,HS_HEAD
	je	.head
	cmp	edx,HS_REQ_READ
	je	.body
	cmp	edx,HS_RESP_HEAD
	je	.resp_head
	cmp	edx,HS_RESP_READ
	je	.resp_body
	ret
.head:
	test	rax,rax
	jle	.client_gone			; the client is done
	add	[r15+H_INLEN],eax
	push	rax
	mov	edi,ebx
	call	idle_touch
	call	session_ptr
	cmp	dword [rax+S_PH_KIND],0
	jne	@f
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
	test	rax,rax
	js	.failed
	mov	edx,[r15+H_STATE]
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
	ret
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
.close:
	mov	edi,ebx
	jmp	session_close

; ------------------------------------------------------- request body

; Move the request body upstream, a piece at a time. ebx = session.
http_req_pump:
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
	lea	rdi,[r15+H_IN+rax]
	mov	ecx,SIDE_UP
	jmp	h_send
.done:
	mov	dword [r15+H_BODY],BK_NONE
	jmp	http_start_response
.read:
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_INOFF],0
	mov	dword [r15+H_STATE],HS_REQ_READ
	mov	ecx,SIDE_CLIENT
	lea	rdi,[r15+H_IN]
	mov	esi,H_IN_CAP
	jmp	h_recv
.chunked:
	lea	rdi,[r15+H_CK]
	mov	eax,[r15+H_INOFF]
	lea	rsi,[r15+H_IN+rax]
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
	call	http_frame_chunk		; r8/r9d: OUT = framed chunk
	mov	dword [r15+H_STATE],HS_REQ_SEND
	mov	ecx,SIDE_UP
	lea	rdi,[r15+H_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	h_send
.chunk_end:
	mov	dword [r15+H_BODY],BK_NONE
	mov	dword [r15+H_STATE],HS_REQ_SEND
	cstring str_last_chunk, '0',13,10,13,10
	mov	ecx,SIDE_UP
	lea	rdi,[str_last_chunk]
	mov	esi,str_last_chunk.len
	jmp	h_send

; r8 = data, r9d = length, r15 = record: OUT = "<hex>\r\n<data>\r\n".
http_frame_chunk:
	lea	rdi,[r15+H_OUT]
	mov	eax,r9d
	call	fmt_hex32
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r15+H_OUT]
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
	mov	dword [r15+H_UPLEN],0
	mov	dword [r15+H_UPOFF],0
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	h_rec
	mov	ecx,SIDE_UP
	lea	rdi,[r15+H_UP]
	mov	esi,H_UP_CAP
	jmp	h_recv

; A response head may be complete in UP. ebx = session.
http_resp_head:
	h_rec
	mov	eax,[r15+H_UPOFF]
	lea	rdi,[r15+H_UP+rax]
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
	lea	rdi,[r15+H_UP+rdi]
	mov	esi,H_UP_CAP
	sub	esi,[r15+H_UPLEN]
	jmp	h_recv
.parse:
	push	rax
	mov	ecx,[r15+H_UPOFF]
	lea	rdi,[r15+H_UP+rcx]
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
	; 1xx: 100 Continue was ours already; others are dropped (for now)
	cmp	eax,101
	jne	http_resp_head
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
	pop	rax
	mov	edi,eax
	call	http_backend_status		; may send the request elsewhere
	h_rec
	lea	r14,[g_hm]
	mov	edi,eax
	xor	esi,esi
	call	http_count
	and	dword [r15+H_FLAGS],not HX_UPGRADE	; the backend did not switch
	mov	[r15+H_STATUS],eax
	cmp	dword [r14+HM_VERSION],11
	jne	@f
	test	dword [r14+HM_FLAGS],HMF_CLOSE
	jnz	@f
	or	dword [r15+H_FLAGS],HX_UPKEEP
@@:
	; the response body
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
	or	dword [r15+H_FLAGS],HX_CHUNKOUT
	lea	rdi,[r15+H_RCK]
	xor	eax,eax
	mov	ecx,CK_SIZE
	rep	stosb
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
	or	dword [r15+H_FLAGS],HX_CHUNKOUT	; framed for the client
.write:
	call	http_write_response_head
	jc	.bad
	or	dword [r15+H_FLAGS],HX_STARTED
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	lea	rdi,[r15+H_OUT]
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
	lea	rdi,[r15+H_OUT]
	lea	r13,[r15+H_OUT+H_OUT_CAP-256]
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
	jz	.copy
	test	dword [r15+H_FLAGS],HX_UPGRADE	; a 101 keeps its Upgrade field
	jz	.skip
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_upgrade]
	call	hf_is
	pop	rdi
	jnz	.skip
.copy:
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
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	@f
	memit_x 'Connection: upgrade',13,10,13,10
	jmp	.done
@@:
	mov	eax,[r15+H_RBODY]
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jz	@f
	memit_x 'Transfer-Encoding: chunked',13,10
	jmp	.conn
@@:
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
	lea	rax,[r15+H_OUT]
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
	jz	.read
	mov	rax,[r15+H_RREMAIN]
	cmp	rax,rcx
	jae	@f
	mov	ecx,eax
@@:
	sub	[r15+H_RREMAIN],rcx
	mov	eax,[r15+H_UPOFF]
	add	[r15+H_UPOFF],ecx
	mov	esi,ecx
	lea	rdi,[r15+H_UP+rax]
.send:
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.length_done:
	mov	dword [r15+H_RBODY],BK_NONE
	jmp	http_exchange_done
.read:
	mov	dword [r15+H_UPLEN],0
	mov	dword [r15+H_UPOFF],0
	mov	dword [r15+H_STATE],HS_RESP_READ
	mov	ecx,SIDE_UP
	lea	rdi,[r15+H_UP]
	mov	esi,H_UP_CAP
	jmp	h_recv
.chunked:
	lea	rdi,[r15+H_RCK]
	mov	eax,[r15+H_UPOFF]
	lea	rsi,[r15+H_UP+rax]
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
	jmp	http_last_chunk
.close:
	; until the backend closes, each piece framed as a chunk
	mov	ecx,[r15+H_UPLEN]
	sub	ecx,[r15+H_UPOFF]
	jz	.read
	mov	eax,[r15+H_UPOFF]
	lea	r8,[r15+H_UP+rax]
	mov	r9d,ecx
	add	[r15+H_UPOFF],ecx
.framed:
	call	http_frame_chunk
	lea	rdi,[r15+H_OUT]
	mov	esi,[r15+H_OUTLEN]
	jmp	.send

; The final chunk to the client, then the exchange is over.
http_last_chunk:
	h_rec
	or	dword [r15+H_FLAGS],HX_LASTCHUNK
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	lea	rdi,[str_last_chunk]
	mov	esi,str_last_chunk.len
	jmp	h_send

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
OUTLIER_5XX	= 5
RETRY_COST	= 10
RETRY_PER_REQ	= 2
RETRY_FLOOR	= 100
RETRY_CAP	= 1000

bss
	g_sv_5xx	rd MAX_SERVERS
	g_retry_tokens	dd ?
end bss

; Tick: the budget's floor.
retry_budget_tick:
	cmp	dword [g_retry_tokens],RETRY_FLOOR
	jae	@f
	mov	dword [g_retry_tokens],RETRY_FLOOR
@@:
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
	cmp	dword [g_retry_tokens],RETRY_COST
	jb	.no
	sub	dword [g_retry_tokens],RETRY_COST
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

; ------------------------------------------------------------ metrics

; edi = status, esi = 0 when the backend's, 5 when okena's own. ebx =
; session. Keeps everything but rcx, rdx.
http_count:
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
	mov	ecx,ebx
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	mov	ecx,[rcx+S_LST]
	imul	ecx,ecx,10
	add	eax,ecx
	inc	qword [g_st_l_http+rax*8]
	pop	rax
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

PH_HEAD		= 1
PH_RESPONSE	= 2

bss
	g_ph_head	rd MAX_LISTENERS * 2
	g_ph_tail	rd MAX_LISTENERS * 2
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
	lea	ecx,[rcx*2+rsi-1]
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
	lea	ecx,[rcx*2+rsi-1]
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
	jne	.next
	mov	r14d,PH_HEAD
.kind:
	imul	rax,r12,LS_SIZE
	mov	r13d,[g_listeners+rax+LS_T_HEADER]
	cmp	r14d,PH_HEAD
	je	.oldest
	mov	r13d,[g_listeners+rax+LS_T_RESPONSE]
.oldest:
	lea	ecx,[r12*2+r14-1]
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
	cmp	r14d,PH_RESPONSE
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
	cmp	esi,PH_HEAD
	jne	.response
	cmp	dword [r15+H_STATE],HS_HEAD
	jne	.out
	cmp	dword [r15+H_INLEN],0
	je	.silent				; connected, never asked anything
	mov	edi,408
	jmp	http_error
.silent:
	mov	edi,ebx
	jmp	session_close
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
	lea	rdi,[r15+H_UP+rax]
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
	lea	rdi,[r15+H_IN+rax]
	mov	ecx,SIDE_UP
	jmp	h_send

http_tunnel_start:
	xor	esi,esi
	call	alog_exchange			; the 101 exchange; then bytes, unlogged
	call	session_ptr
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

; One exchange is over: drop the upstream connection, then the next
; request on the client connection, or close it.
http_exchange_done:
	xor	esi,esi
	call	alog_exchange
	h_rec
	and	dword [r15+H_FLAGS],not HX_LASTCHUNK
	test	dword [r15+H_FLAGS],HX_UPKEEP
	jz	.drop
	call	h_park				; back to the pool, or closed when full
	jmp	.next
.drop:
	call	h_upclose
.next:
	h_rec
	test	dword [r15+H_FLAGS],HX_CLOSE
	jnz	.close
	jmp	http_next_request
.close:
	mov	edi,ebx
	jmp	session_close

; ------------------------------------------------------------- errors

; edi = status: answer it and close. Once the response has started there
; is nothing honest to send: just close.
http_error:
	h_rec
	test	dword [r15+H_FLAGS],HX_STARTED
	jnz	.close
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
	lea	rdi,[r15+H_OUT]
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
	memit_x 13,10,'Content-Type: text/plain',13,10,'Connection: close',13,10,'Content-Length: '
	mov	rsi,[rsp]
	xor	eax,eax
@@:
	cmp	byte [rsi+rax],0
	je	@f
	inc	eax
	jmp	@b
@@:
	inc	eax				; and a newline
	call	fmt_u64
	memit_x 13,10,13,10
	pop	rsi
	call	fmt_cstr
	mov	byte [rdi],10
	inc	rdi
	add	rsp,8
	lea	rax,[r15+H_OUT]
	sub	rdi,rax
	mov	esi,edi
	mov	ecx,SIDE_CLIENT
	lea	rdi,[r15+H_OUT]
	jmp	h_send
.close:
	mov	edi,ebx
	jmp	session_close

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
reasons 400,'Bad Request', 404,'Not Found', 408,'Request Timeout', \
	431,'Request Header Fields Too Large', 501,'Not Implemented', 502,'Bad Gateway', \
	503,'Service Unavailable', 504,'Gateway Timeout', 505,'HTTP Version Not Supported'

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
