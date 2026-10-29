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
HB_SHIFT	:= 16		; buffers
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
assert H_BUF + 8 <= 1 shl H_SHIFT
HB_LTEXT_M	:= HB_UP + H_UP_CAP	; access log: method
H_LTEXT_M_CAP	:= 16
HB_LTEXT_H	:= HB_LTEXT_M + 16	; host
H_LTEXT_H_CAP	:= 255
HB_LTEXT_T	:= HB_LTEXT_H + 256	; target
H_LTEXT_T_CAP	:= 1024
assert HB_LTEXT_T + H_LTEXT_T_CAP <= 1 shl HB_SHIFT

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
HS_TUNNEL_UP	:= 11		; 101 sent: bytes the backend sent early go to the client
HS_TUNNEL_IN	:= 12		; then bytes the client sent early go to the backend
HS_INTERIM_SEND	:= 13		; writing a 1xx (103 Early Hints...) before the final response
HS_SELF_SEND	:= 14		; writing okena's own answer (a redirect), connection kept

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
	jmp	http_error

; ebx = session, eax = length of the head at the start of IN.
http_request:
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
	or	dword [r15+H_FLAGS],HX_CLOSE or HX_HTTP10	; HTTP/1.0 clients: one exchange
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
	call	http_route			; eax = route entry, -1 none, -2 unsafe path
	cmp	eax,-1
	je	.no_route
	cmp	eax,-2
	je	.parse_error_400
	imul	rcx,rax,RT_SIZE
	lea	rcx,[g_routes+rcx]
	mov	edx,[rcx+RT_ACT]
	mov	[r15+H_ACT],edx
	test	edx,edx
	jz	@f
	dec	edx
	imul	rdx,rdx,RA_SIZE
	cmp	dword [g_acts+rdx+RA_CODE],0
	jne	http_redirect
@@:
	mov	r13d,[rcx+RT_POOL]
	add	dword [g_retry_tokens+r13*4],RETRY_PER_REQ	; the pool's budget grows with its traffic
	cmp	dword [g_retry_tokens+r13*4],RETRY_CAP
	jbe	@f
	mov	dword [g_retry_tokens+r13*4],RETRY_CAP
@@:
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

; rdi/esi = path (starts with '/'). rsi/edx = the form routes are
; matched on, in g_npath; CF when the path cannot be normalized safely.
;   %XX of an unreserved character (A-Z a-z 0-9 - . _ ~) is decoded,
;   other %XX kept with upper-case hex; %XX of '/', '\' or a control
;   byte is refused (the backend could split or join segments on it);
;   a raw '\' is refused; "//" is one '/'; a "." or ".." segment
;   (decoded ones included) is refused, so /public/../admin can never
;   match /public/* while the backend serves /admin.
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
	memit_x 'X-Forwarded-Proto: http',13,10
@@:
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
	cmp	edx,HS_INTERIM_SEND
	je	.interim_sent
	cmp	edx,HS_SELF_SEND
	je	.self_sent
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
	call	http_frame_chunk		; r8/r9d: OUT = framed chunk
	mov	dword [r15+H_STATE],HS_REQ_SEND
	mov	ecx,SIDE_UP
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
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
	call	http_latency_sample
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
	; the route's response header changes (final heads only)
	test	dword [r15+H_FLAGS],HX_INTERIM
	jnz	.copy
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
	test	dword [r15+H_FLAGS],HX_INTERIM
	jz	@f
	memit_x 13,10				; an interim head: no framing of its own
	jmp	.done
@@:
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jz	@f
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
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rax]
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
	call	http_frame_chunk
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
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
	mov	eax,[r8+HD_NLEN]
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
	rep	movsb
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
	memit_x 13,10,'Location: '
	; the target, {*} = the rest of the path after the route's prefix
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
	cmp	ecx,3
	jb	.tgt_byte
	cmp	word [rsi+1],'*}'
	jne	.tgt_byte
	push	rsi
	push	rcx
	cmp	dword [r13+RT_PREFIX],0
	je	.rest_done			; an exact route has no rest
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
	memit_x 13,10,'Content-Length: 0',13,10,'X-Request-Id: '
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
	jne	.next
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
	cmp	dword [r15+H_STATE],HS_HEAD
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
	cmp	dword [r15+H_STATE],HS_HEAD
	jne	.out
	cmp	dword [r15+H_INLEN],0
	jne	.out
	mov	rdi,[r15+H_BUF]
	mov	esi,1 shl HB_SHIFT
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
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
	h_rec
	xor	esi,esi
	test	dword [r15+H_FLAGS],HX_SELF
	setnz	sil				; okena's own answer, or the backend's
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
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	push	rax
	call	rid_new
	pop	rax
@@:
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
	memit_x 13,10,'Content-Length: '
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
reasons 301,'Moved Permanently', 302,'Found', 303,'See Other', 307,'Temporary Redirect', \
	308,'Permanent Redirect', 400,'Bad Request', 404,'Not Found', 405,'Method Not Allowed', 408,'Request Timeout', \
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
