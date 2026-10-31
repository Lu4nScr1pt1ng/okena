; okena bench: an open-loop load generator for HTTP, HTTPS and TCP.
;
;   okena bench URL [rate=N] [conns=N] [duration=10s] [warmup=1s]
;                   [workers=N] [method=GET] [header='Name: value']...
;                   [body=TEXT] [size=N] [sni=NAME] [format=text|kv]
;
; URL is http://ADDR[:PORT]/PATH, https://ADDR[:PORT]/PATH (TLS 1.3, its
; records sealed and opened in user space) or tcp://ADDR:PORT (echo: `size` bytes out, as many back). ADDR is
; an IP address ([::1] for IPv6) or localhost. rate takes k and M (200k).
;
; Every connection has a schedule: with rate=N in all, one request every
; conns/N seconds, the connections staggered across the interval. A late
; answer delays the next send but not the schedule, and latency counts from
; the time the schedule asked for the request (as wrk2 does), so a stall is
; charged to every request it held back: coordinated omission corrected.
; "service" is the latency from the actual send. Without rate= the run is
; closed loop (a connection sends again as soon as it has its answer) and
; the two are the same. Requests the schedule asked for but that never went
; out before the end are reported as "behind": the rate was not reached.
;
; Workers are processes, each with its own connections, epoll set and
; histograms in shared memory; the parent adds them up. Time is the TSC,
; calibrated against CLOCK_MONOTONIC. Connections (and TLS handshakes) are
; made before the clock starts; answers to requests scheduled during the
; warmup are not counted.

BH_NB		:= 2240				; histogram buckets: exact below 128 ns, then 64 per octave
BH_MAXV		:= (1 shl 40) - 1		; ~18 minutes, in ns

; per-connection state
BC_FD		:= 0				; d
BC_STATE	:= 4				; d: BCS_*
BC_NEXT		:= 8				; q: when the schedule wants the current/next request (TSC)
BC_SENT		:= 16				; q: when it actually went out
BC_REM		:= 24				; q: body (or echo) bytes still expected
BC_SOFF		:= 32				; d: request bytes written
BC_RLEN		:= 36				; d: bytes in the buffer
BC_ROFF		:= 40				; d: bytes of the buffer consumed
BC_PHASE	:= 44				; d: BP_*
BC_STATUS	:= 48				; d
BC_GIDX		:= 52				; d: index among all connections
BC_FLAGS	:= 56				; d: BF_*
BC_SLOT		:= 60				; d: which of its schedule's requests is next
BC_HS		:= 64				; d: BH_* (0 = plain bytes)
BC_HTRY		:= 68				; d: the server flight's records tried so far
BC_CLEN		:= 72				; d: ciphertext bytes in BC_CBUF
BC_BUF		:= 128				; plaintext of the answer
BC_CAP		:= 16384
BC_CBUF		:= BC_BUF + BC_CAP		; new=on, https: records as received
BC_CCAP		:= 32768
BC_TC		:= BC_CBUF + BC_CCAP		; new=on, https: the handshake
BC_SNAP		:= BC_TC + TC_FULL		; the transcript through the ClientHello
BC_SIZE		:= (BC_SNAP + SHA256_CTX_SIZE + 63) and not 63

BH_CONNECTING	:= 1				; waiting for the connect
BH_FLIGHT	:= 2				; ClientHello sent, reading the server's flight
BH_RECORDS	:= 3				; established: records opened here

BCS_WAIT	:= 0				; idle, its next request in the heap
BCS_FLIGHT	:= 1				; a request out, its answer pending
BCS_DEAD	:= 2				; could not reconnect
BCS_DONE	:= 3				; its schedule ended

BP_HEAD		:= 0
BP_BODY		:= 1				; Content-Length body
BP_CSIZE	:= 2				; chunk-size line
BP_CDATA	:= 3				; chunk data and its CRLF
BP_TRAILER	:= 4
BP_ECHO		:= 5
BP_CLOSE	:= 6				; body until the server closes

BF_CLOSE	:= 1				; the server said Connection: close
BF_OUT		:= 2				; EPOLLOUT armed (a request only partly written)

; shared memory: a header, then one block per worker
BS_READY	:= 0				; d: workers connected
BS_FAIL		:= 4				; d: workers that could not
BS_T0		:= 8				; q: the TSC the run starts at, 0 until then
BS_W		:= 64
BW_COUNT	:= 0				; q: answers recorded
BW_2XX		:= 8
BW_OTHER	:= 16
BW_ERR		:= 24				; connection or protocol errors
BW_BEHIND	:= 32
BW_TIMEOUT	:= 40				; requests still unanswered at the end
BW_MAXC		:= 48				; q: the largest corrected latency (ns)
BW_MAXS		:= 56
BW_BYTES	:= 64				; bytes received
BW_RECON	:= 72				; reconnections after Connection: close
BW_HC		:= 128				; histogram, latency from the schedule
BW_HS		:= BW_HC + BH_NB * 8		; histogram, latency from the send
BW_HL		:= BW_HS + BH_NB * 8		; histogram, how late the generator sent
BW_LAGN		:= 80				; q: sends in BW_HL
BW_MAXL		:= 88
BW_SIZE		:= (BW_HL + BH_NB * 8 + 4095) and not 4095

BENCH_WORKERS_MAX := 64
BENCH_CONNS_MAX	:= 20000
BENCH_REQ_CAP	:= 16384
BENCH_HDRS_MAX	:= 32
BENCH_EVENTS	:= 256
BENCH_HIN_CAP	:= 65536
BENCH_SPIN_NS	:= 50000			; closer to a send than this, poll instead of sleeping

SYS_epoll_pwait2 = 441
PR_SET_TIMERSLACK := 29

bss
	align 8
	g_b_mode	dd ?			; 0 http, 1 https, 2 tcp
	g_b_conns	dd ?
	g_b_workers	dd ?
	g_b_fmt		dd ?			; 0 text, 1 key=value
	g_b_nobody	dd ?			; HEAD: answers carry no body
	g_b_salen	dd ?
	g_b_family	dd ?
	g_b_snilen	dd ?
	g_b_reqlen	dd ?
	g_b_nhdr	dd ?
	g_b_wid		dd ?
	g_b_c0		dd ?			; this worker's first connection
	g_b_nc		dd ?			; and how many it has
	g_b_ep		dd ?
	g_b_inflight	dd ?
	g_b_heapn	dd ?
	g_b_alive	dd ?
	g_b_new		dd ?			; a new connection (and handshake) per request
	g_b_rate	dq ?			; requests/s in all, 0 = closed loop
	g_b_dur		dq ?			; us
	g_b_warm	dq ?			; us
	g_b_size	dq ?			; tcp: bytes per message
	g_b_url		dq ?
	g_b_sni		dq ?
	g_b_path	dq ?
	g_b_pathlen	dq ?
	g_b_auth	dq ?			; host[:port] as written, for Host
	g_b_authlen	dq ?
	g_b_method	dq ?
	g_b_methodlen	dq ?
	g_b_body	dq ?
	g_b_bodylen	dq ?
	g_b_hdr		rq BENCH_HDRS_MAX
	g_b_hz		dq ?			; TSC ticks a second
	g_b_mult	dq ?			; ns = ticks * mult >> 32
	g_b_shared	dq ?
	g_b_wres	dq ?			; this worker's result block
	g_b_conn	dq ?			; connection array
	g_b_heap	dq ?			; min-heap of connection indices by BC_NEXT
	g_b_iv		dq ?			; ticks between two requests of a connection
	g_b_t0		dq ?
	g_b_trec	dq ?			; recording starts (after warmup)
	g_b_tend	dq ?			; the schedule ends
	g_b_tquit	dq ?			; answers stop being waited for
	g_b_sa:		rb 32			; the target's sockaddr
	g_b_ad:		rb AD_SIZE
	g_b_authtmp:	rb 300
	g_b_ts:		rq 2
	g_b_events:	rb BENCH_EVENTS * EPOLL_EVENT
	align 16
	g_b_tc:		rb TC_FULL
	g_b_snap:	rb SHA256_CTX_SIZE
	g_b_hout:	rb 4096			; ClientHello, then the client Finished
	g_b_hsend:	rb BENCH_REQ_CAP + 4096	; new=on: the Finished and the sealed request
	g_b_hdec:	rb BENCH_HIN_CAP	; the decrypted server flight (as large as what it comes from)
	g_b_hin:	rb BENCH_HIN_CAP	; the server's flight as received
	g_b_req:	rb BENCH_REQ_CAP
	g_b_hist:	rq 3 * BH_NB		; the parent's sum
	g_b_sum:	rq 16
	g_b_pctn	dq ?			; the count the percentiles are of
end bss

cstring str_bench_ua, 'User-Agent: okena-bench',13,10
cstring str_bench_localhost, 'localhost',0

; ------------------------------------------------------------- arguments

macro bench_key name*, target*
	local next
	lea	rdx,[name]
	mov	rdi,r12
	mov	esi,r13d
	call	mem_eq_cstr
	test	eax,eax
	jz	next
	jmp	target
next:
end macro

cstring str_bk_rate, 'rate',0
cstring str_bk_conns, 'conns',0
cstring str_bk_duration, 'duration',0
cstring str_bk_warmup, 'warmup',0
cstring str_bk_workers, 'workers',0
cstring str_bk_method, 'method',0
cstring str_bk_header, 'header',0
cstring str_bk_body, 'body',0
cstring str_bk_size, 'size',0
cstring str_bk_sni, 'sni',0
cstring str_bk_format, 'format',0
cstring str_bk_new, 'new',0
cstring str_bk_on, 'on',0
cstring str_bk_off, 'off',0
cstring str_bk_text, 'text',0
cstring str_bk_kv, 'kv',0
cstring str_bk_head, 'HEAD',0

cli_bench:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [g_out_fd],2
	mov	dword [g_b_conns],64
	mov	dword [g_b_workers],1
	mov	qword [g_b_dur],10000000
	mov	qword [g_b_warm],1000000
	mov	qword [g_b_size],64
	lea	rax,[.get]
	mov	[g_b_method],rax
	mov	qword [g_b_methodlen],3
	mov	ebx,2				; argv index
.arg:
	cmp	rbx,[g_argc]
	jae	.args_done
	mov	rax,[g_argv]
	mov	r14,[rax+rbx*8]			; the argument
	inc	ebx
	xor	ecx,ecx				; find '=' and the length
	mov	r15d,-1
.scan:
	mov	al,[r14+rcx]
	test	al,al
	jz	.scanned
	cmp	al,'='
	jne	@f
	cmp	r15d,-1
	jne	@f
	mov	r15d,ecx
@@:
	inc	ecx
	jmp	.scan
.scanned:
	cmp	r15d,-1
	jne	.keyval
	cmp	qword [g_b_url],0		; a URL, the only positional argument
	jne	.usage
	mov	[g_b_url],r14
	jmp	.arg
.keyval:
	mov	r12,r14				; key
	mov	r13d,r15d
	lea	r14,[r14+r15+1]			; value
	sub	ecx,r15d
	dec	ecx
	mov	r15d,ecx			; its length
	bench_key str_bk_rate, .rate
	bench_key str_bk_conns, .conns
	bench_key str_bk_duration, .duration
	bench_key str_bk_warmup, .warmup
	bench_key str_bk_workers, .workers
	bench_key str_bk_method, .method
	bench_key str_bk_header, .header
	bench_key str_bk_body, .body
	bench_key str_bk_size, .size
	bench_key str_bk_sni, .sni
	bench_key str_bk_format, .format
	bench_key str_bk_new, .new
	jmp	.badkey
.new:
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[str_bk_on]
	call	mem_eq_cstr
	mov	[g_b_new],eax
	test	eax,eax
	jnz	.arg
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[str_bk_off]
	call	mem_eq_cstr
	test	eax,eax
	jz	.badval
	jmp	.arg
.rate:
	mov	rdi,r14
	mov	esi,r15d
	call	bench_parse_count
	jc	.badval
	mov	[g_b_rate],rax
	jmp	.arg
.conns:
	mov	rdi,r14
	mov	esi,r15d
	call	bench_parse_count
	jc	.badval
	test	rax,rax
	jz	.badval
	cmp	rax,BENCH_CONNS_MAX
	ja	.badval
	mov	[g_b_conns],eax
	jmp	.arg
.duration:
	mov	rdi,r14
	mov	esi,r15d
	call	parse_duration
	jc	.badval
	test	rax,rax
	jz	.badval
	mov	[g_b_dur],rax
	jmp	.arg
.warmup:
	mov	rdi,r14
	mov	esi,r15d
	call	parse_duration
	jc	.badval
	mov	[g_b_warm],rax
	jmp	.arg
.workers:
	mov	rdi,r14
	mov	esi,r15d
	call	parse_decimal
	jc	.badval
	test	rax,rax
	jz	.badval
	cmp	rax,BENCH_WORKERS_MAX
	ja	.badval
	mov	[g_b_workers],eax
	jmp	.arg
.method:
	test	r15d,r15d
	jz	.badval
	mov	[g_b_method],r14
	mov	[g_b_methodlen],r15
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[str_bk_head]
	call	mem_eq_cstr
	mov	[g_b_nobody],eax
	jmp	.arg
.header:
	mov	eax,[g_b_nhdr]
	cmp	eax,BENCH_HDRS_MAX
	jae	.badval
	mov	[g_b_hdr+rax*8],r14		; NUL-terminated in argv
	inc	dword [g_b_nhdr]
	jmp	.arg
.body:
	mov	[g_b_body],r14
	mov	[g_b_bodylen],r15
	jmp	.arg
.size:
	mov	rdi,r14				; bytes, with or without a unit
	mov	esi,r15d
	call	parse_decimal
	jnc	@f
	mov	rdi,r14
	mov	esi,r15d
	call	parse_size
	jc	.badval
@@:
	test	rax,rax
	jz	.badval
	cmp	rax,BENCH_REQ_CAP
	ja	.badval
	mov	[g_b_size],rax
	jmp	.arg
.sni:
	mov	[g_b_sni],r14
	mov	[g_b_snilen],r15d
	jmp	.arg
.format:
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[str_bk_kv]
	call	mem_eq_cstr
	mov	[g_b_fmt],eax
	test	eax,eax
	jnz	.arg
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[str_bk_text]
	call	mem_eq_cstr
	test	eax,eax
	jz	.badval
	jmp	.arg
.args_done:
	cmp	qword [g_b_url],0
	je	.usage
	mov	eax,[g_b_workers]
	cmp	eax,[g_b_conns]
	ja	.toomany
	call	bench_parse_url
	jc	.badurl
	call	bench_build_request
	jc	.toolong
	call	bench_calibrate
	call	bench_run			; eax = exit status
	mov	edi,eax
	jmp	exit_process
.usage:
	call	log_begin
	out_lit 'usage: okena bench URL [rate=N] [conns=N] [duration=10s] [warmup=1s] [workers=N] [new=on] [method=GET] [header=...] [body=TEXT] [size=N] [sni=NAME] [format=text|kv]'
	jmp	.fail
.badkey:
	call	log_begin
	out_lit 'bench: unknown option `'
	mov	rsi,r12
	mov	edx,r13d
	call	out_str
	out_lit '`'
	jmp	.fail
.badval:
	call	log_begin
	out_lit 'bench: bad value for `'
	mov	rsi,r12
	mov	edx,r13d
	call	out_str
	out_lit '`'
	jmp	.fail
.toomany:
	call	log_begin
	out_lit 'bench: more workers than connections'
	jmp	.fail
.badurl:
	call	log_begin
	out_lit 'bench: the URL must be http://, https:// or tcp:// and an IP address or localhost with a port'
	jmp	.fail
.toolong:
	call	log_begin
	out_lit 'bench: the request does not fit in 16 KiB'
.fail:
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process
.get	db 'GET'

; rdi/esi = "1000", "200k", "1.5M". rax = count, CF on error.
bench_parse_count:
	push	rbx
	call	parse_number_prefix
	jc	.out
	mov	r9d,1
	test	r8d,r8d
	jz	.scale
	cmp	r8d,1
	jne	.bad
	mov	r9d,1000
	cmp	byte [rcx],'k'
	je	.scale
	mov	r9d,1000000
	cmp	byte [rcx],'M'
	jne	.bad
.scale:
	mov	rbx,rdx				; thousandths
	imul	rax,r9
	imul	rdx,rbx,1
	imul	rdx,r9
	mov	r10,rax
	mov	rax,rdx
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	test	rdx,rdx
	jnz	.bad				; not a whole number
	add	rax,r10
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	rbx
	ret

; g_b_url -> mode, sockaddr, Host, path, SNI. CF on error.
bench_parse_url:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,[g_b_url]
	cmp	dword [rbx],'http'
	jne	.tcp
	cmp	dword [rbx+4],'s://'
	je	.https
	cmp	word [rbx+4],':/'
	jne	.bad
	cmp	byte [rbx+6],'/'
	jne	.bad
	mov	dword [g_b_mode],0
	add	rbx,7
	mov	r14d,80
	jmp	.auth
.https:
	mov	dword [g_b_mode],1
	add	rbx,8
	mov	r14d,443
	jmp	.auth
.tcp:
	cmp	dword [rbx],'tcp:'
	jne	.bad
	cmp	word [rbx+4],'//'
	jne	.bad
	mov	dword [g_b_mode],2
	add	rbx,6
	xor	r14d,r14d			; no default port
.auth:
	mov	[g_b_auth],rbx
	xor	ecx,ecx
@@:
	mov	al,[rbx+rcx]
	test	al,al
	jz	@f
	cmp	al,'/'
	je	@f
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	mov	[g_b_authlen],rcx
	lea	rax,[rbx+rcx]			; the path, "/" when there is none
	mov	[g_b_path],rax
	xor	edx,edx
@@:
	cmp	byte [rax+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	mov	[g_b_pathlen],rdx
	test	edx,edx
	jnz	@f
	lea	rax,[.slash]
	mov	[g_b_path],rax
	mov	qword [g_b_pathlen],1
@@:
	mov	r12d,ecx			; authority length
	mov	rdi,rbx
	mov	esi,r12d
	lea	rdx,[g_b_ad]
	mov	ecx,1
	call	parse_address
	jnc	.parsed
	; no port: add the scheme's
	test	r14d,r14d
	jz	.bad
	cmp	r12d,280
	ja	.bad
	lea	rdi,[g_b_authtmp]
	mov	rsi,rbx
	mov	ecx,r12d
	rep	movsb
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,r14d
	lea	r13,[rdi+5]			; the port, right-aligned in 5 digits
	mov	ecx,10
	mov	r8,r13
@@:
	xor	edx,edx
	div	ecx
	add	dl,'0'
	dec	r8
	mov	[r8],dl
	test	eax,eax
	jnz	@b
	mov	rsi,r8				; move the digits up to the ':'
	mov	rcx,r13
	sub	rcx,r8
	mov	rdx,rcx
	rep	movsb
	lea	rax,[g_b_authtmp]
	sub	rdi,rax				; total length
	mov	esi,edi
	mov	rdi,rax
	lea	rdx,[g_b_ad]
	mov	ecx,1
	call	parse_address
	jc	.bad
.parsed:
	mov	eax,[g_b_ad+AD_KIND]
	cmp	eax,ADDR_V4
	je	.v4
	cmp	eax,ADDR_V6
	je	.v6
	cmp	eax,ADDR_NAME
	jne	.bad
	mov	rdi,[g_b_ad+AD_NAME]		; only localhost: bench resolves nothing
	mov	esi,[g_b_ad+AD_NLEN]
	lea	rdx,[str_bench_localhost]
	call	mem_eq_cstr
	test	eax,eax
	jz	.bad
	cmp	qword [g_b_sni],0
	jne	@f
	lea	rax,[str_bench_localhost]
	mov	[g_b_sni],rax
	mov	dword [g_b_snilen],str_bench_localhost.len - 1
@@:
	mov	dword [g_b_ad+AD_IP],0x0100007F
.v4:
	mov	word [g_b_sa],AF_INET
	mov	eax,[g_b_ad+AD_PORT]
	xchg	al,ah
	mov	[g_b_sa+2],ax
	mov	eax,[g_b_ad+AD_IP]
	mov	[g_b_sa+4],eax
	mov	dword [g_b_salen],16
	mov	dword [g_b_family],AF_INET
	jmp	.ok
.v6:
	mov	word [g_b_sa],AF_INET6
	mov	eax,[g_b_ad+AD_PORT]
	xchg	al,ah
	mov	[g_b_sa+2],ax
	mov	dword [g_b_sa+4],0		; flowinfo
	movdqu	xmm0,[g_b_ad+AD_IP]
	movdqu	[g_b_sa+8],xmm0
	mov	dword [g_b_sa+24],0		; scope
	mov	dword [g_b_salen],28
	mov	dword [g_b_family],AF_INET6
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.slash	db '/'

; append rsi/rdx to g_b_req at rdi (advancing it); CF when it would not fit
macro breq_put
	local ok
	lea	rax,[rdi+rdx]
	lea	rcx,[g_b_req+BENCH_REQ_CAP]
	cmp	rax,rcx
	jbe	ok
	stc
	ret
ok:
	mov	rcx,rdx
	rep	movsb
end macro

macro breq_lit text&
	local s
	cstring s, text
	lea	rsi,[s]
	mov	edx,s.len
	breq_put
end macro

; The request every connection sends (tcp: size bytes). CF when too long.
bench_build_request:
	lea	rdi,[g_b_req]
	cmp	dword [g_b_mode],2
	jne	.http
	mov	rcx,[g_b_size]
	mov	al,'x'
	rep	stosb
	mov	rax,[g_b_size]
	mov	[g_b_reqlen],eax
	clc
	ret
.http:
	mov	rsi,[g_b_method]
	mov	rdx,[g_b_methodlen]
	breq_put
	breq_lit ' '
	mov	rsi,[g_b_path]
	mov	rdx,[g_b_pathlen]
	breq_put
	breq_lit ' HTTP/1.1',13,10,'Host: '
	mov	rsi,[g_b_auth]
	mov	rdx,[g_b_authlen]
	breq_put
	breq_lit 13,10
	lea	rsi,[str_bench_ua]
	mov	edx,str_bench_ua.len
	breq_put
	xor	r8d,r8d
.hdr:
	cmp	r8d,[g_b_nhdr]
	jae	.hdrs_done
	mov	rsi,[g_b_hdr+r8*8]
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	breq_put
	breq_lit 13,10
	inc	r8d
	jmp	.hdr
.hdrs_done:
	cmp	dword [g_b_new],0
	je	@f
	breq_lit 'Connection: close',13,10
@@:
	cmp	qword [g_b_body],0
	je	.end
	breq_lit 'Content-Length: '
	mov	rax,[g_b_bodylen]		; the length in decimal
	sub	rsp,24
	lea	r9,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	rcx
	add	dl,'0'
	dec	r9
	mov	[r9],dl
	test	rax,rax
	jnz	@b
	mov	rsi,r9
	lea	rdx,[rsp+24]
	sub	rdx,r9
	lea	rax,[rdi+rdx]
	lea	rcx,[g_b_req+BENCH_REQ_CAP]
	cmp	rax,rcx
	ja	.long
	mov	rcx,rdx
	rep	movsb
	add	rsp,24
	breq_lit 13,10
.end:
	breq_lit 13,10
	mov	rsi,[g_b_body]
	test	rsi,rsi
	jz	.done
	mov	rdx,[g_b_bodylen]
	breq_put
.done:
	lea	rax,[g_b_req]
	sub	rdi,rax
	mov	[g_b_reqlen],edi
	clc
	ret
.long:
	add	rsp,24
	stc
	ret

; ------------------------------------------------------------------ time

macro bench_now
	rdtsc
	shl	rdx,32
	or	rax,rdx
end macro

; g_b_hz and g_b_mult from the TSC against CLOCK_MONOTONIC over 50 ms.
bench_calibrate:
	push	rbx
	push	r12
	push	r13
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	bench_now
	mov	rbx,rax				; tsc0
	imul	r12,[rsp],1000000000
	add	r12,[rsp+8]			; ns0
.spin:
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	bench_now
	mov	r13,rax
	imul	rcx,[rsp],1000000000
	add	rcx,[rsp+8]
	sub	rcx,r12
	cmp	rcx,50000000
	jb	.spin
	sub	r13,rbx				; ticks over rcx ns
	mov	rax,r13
	mov	r8,rcx
	mov	ecx,1000000000
	mul	rcx
	div	r8
	mov	[g_b_hz],rax
	mov	rcx,rax				; mult = 1e9 << 32 / hz
	mov	rax,1000000000 shl 32
	xor	edx,edx
	div	rcx
	mov	[g_b_mult],rax
	add	rsp,24
	pop	r13
	pop	r12
	pop	rbx
	ret

; rax = ticks -> rax = ns. Clobbers rdx.
bench_ns:
	mul	qword [g_b_mult]
	shrd	rax,rdx,32
	ret

; rax = us -> rax = ticks. Clobbers rcx, rdx.
bench_us_ticks:
	mul	qword [g_b_hz]
	mov	ecx,1000000
	div	rcx
	ret

; ------------------------------------------------------------- histogram

; rax = ns -> eax = bucket. Clobbers rcx.
bh_index:
	cmp	rax,128
	jb	.small
	mov	rcx,BH_MAXV
	cmp	rax,rcx
	cmova	rax,rcx
	bsr	rcx,rax				; the octave, 7 and up
	sub	ecx,6
	shr	rax,cl				; 64..127
	sub	eax,64
	dec	ecx
	shl	ecx,6
	lea	eax,[rax+rcx+128]
.small:
	ret

; eax = bucket -> rax = the largest ns it holds. Clobbers rcx, rdx.
bh_value:
	cmp	eax,128
	jb	.small
	sub	eax,128
	mov	ecx,eax
	shr	ecx,6
	and	eax,63
	add	eax,64
	inc	ecx
	shl	rax,cl
	mov	edx,1
	shl	rdx,cl
	lea	rax,[rax+rdx-1]
	ret
.small:
	mov	eax,eax
	ret

; ------------------------------------------------------------------ heap

; dst = BC_NEXT of the connection whose index is in idx (a 32-bit register)
macro bkey dst*, idx*
	mov	eax,idx
	imul	rax,rax,BC_SIZE
	add	rax,[g_b_conn]
	mov	dst,[rax+BC_NEXT]
end macro

; edi = connection index
bheap_push:
	push	rbx
	push	r12
	push	r13
	mov	r12d,edi
	mov	rbx,[g_b_heap]
	mov	ecx,[g_b_heapn]
	inc	dword [g_b_heapn]
	bkey	r13, r12d
.up:
	test	ecx,ecx
	jz	.place
	lea	edx,[rcx-1]
	shr	edx,1
	mov	r8d,[rbx+rdx*4]
	bkey	r9, r8d
	cmp	r9,r13
	jbe	.place
	mov	[rbx+rcx*4],r8d
	mov	ecx,edx
	jmp	.up
.place:
	mov	[rbx+rcx*4],r12d
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = the connection index with the smallest BC_NEXT, removed
bheap_pop:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,[g_b_heap]
	mov	r14d,[rbx]
	dec	dword [g_b_heapn]
	mov	ecx,[g_b_heapn]
	test	ecx,ecx
	jz	.done
	mov	r12d,[rbx+rcx*4]		; the last, sifted down from the root
	bkey	r13, r12d
	xor	ecx,ecx
.down:
	lea	edx,[rcx*2+1]
	cmp	edx,[g_b_heapn]
	jae	.place
	mov	r8d,edx
	mov	r10d,[rbx+rdx*4]
	bkey	r9, r10d
	lea	r10d,[rdx+1]
	cmp	r10d,[g_b_heapn]
	jae	.cmp
	mov	r11d,[rbx+r10*4]
	bkey	r11, r11d
	cmp	r11,r9
	jae	.cmp
	mov	r8d,r10d
	mov	r9,r11
.cmp:
	cmp	r9,r13
	jae	.place
	mov	eax,[rbx+r8*4]
	mov	[rbx+rcx*4],eax
	mov	ecx,r8d
	jmp	.down
.place:
	mov	[rbx+rcx*4],r12d
.done:
	mov	eax,r14d
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ connections

; rdi = buffer, esi = length: written whole to the connection in rbx.
; eax = 1, or 0 on error.
bench_write_all:
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
.loop:
	test	r13d,r13d
	jz	.ok
	mov	edi,[rbx+BC_FD]
	mov	rsi,r12
	mov	edx,r13d
	mov	r10d,MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	cmp	rax,-EINTR
	je	.loop
	test	rax,rax
	jle	.err
	add	r12,rax
	sub	r13d,eax
	jmp	.loop
.ok:
	mov	eax,1
	jmp	.out
.err:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	ret

; rbx = connection: a new socket, connected (and through TLS), in the
; epoll set. eax = 1, or 0 on failure. Blocking: used before the clock
; starts, and to replace a connection the server closed.
bench_open:
	push	r12
	mov	edi,[g_b_family]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.fail
	mov	[rbx+BC_FD],eax
	sub	rsp,16
	mov	dword [rsp],1
	mov	edi,[rbx+BC_FD]
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,16
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_b_sa]
	mov	edx,[g_b_salen]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jnz	.close
	mov	dword [rbx+BC_HS],0
	mov	dword [rbx+BC_CLEN],0
	cmp	dword [g_b_mode],1
	jne	@f
	call	bench_tls
	test	eax,eax
	jz	.close
@@:
	xor	eax,eax
	mov	[rbx+BC_RLEN],eax
	mov	[rbx+BC_ROFF],eax
	mov	[rbx+BC_FLAGS],eax
	sub	rsp,16
	mov	dword [rsp],EPOLLIN
	mov	eax,[rbx+BC_GIDX]
	sub	eax,[g_b_c0]
	mov	[rsp+4],rax			; data: the local connection index
	mov	edi,[g_b_ep]
	mov	esi,EPOLL_CTL_ADD
	mov	edx,[rbx+BC_FD]
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	test	eax,eax
	jnz	.close
	mov	eax,1
	pop	r12
	ret
.close:
	mov	edi,[rbx+BC_FD]
	mov	eax,SYS_close
	syscall
.fail:
	xor	eax,eax
	pop	r12
	ret

; rbx = connection, just connected: a TLS 1.3 handshake, then the keys to
; the connection's records go through user space. Records the server sent
; after its Finished (session tickets, in okena's own flight) are opened
; here.
; eax = 1, or 0.
bench_tls:
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hout]
	mov	rdx,[g_b_sni]
	mov	ecx,[g_b_snilen]
	call	tlsc_client_hello
	test	eax,eax
	jz	.fail
	lea	rdi,[g_b_hout]
	mov	esi,eax
	call	bench_write_all
	test	eax,eax
	jz	.fail
	lea	rsi,[g_b_tc+TC_SHA]		; the transcript through the ClientHello
	lea	rdi,[g_b_snap]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	xor	r12d,r12d			; bytes received
	xor	r13d,r13d			; the records tried so far end here
.read:
	call	.recv
	test	eax,eax
	jz	.fail
.rec:
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.read
	movzx	eax,word [g_b_hin+r13+3]
	xchg	al,ah
	lea	eax,[r13+rax+5]
	cmp	eax,r12d
	ja	.read
	mov	r13d,eax
	lea	rsi,[g_b_hin]			; a 1.2 server is not supported here
	mov	edx,r13d
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.fail
	lea	rsi,[g_b_snap]			; try the flight as far as this record
	lea	rdi,[g_b_tc+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hin]
	mov	edx,r13d
	lea	rcx,[g_b_hdec]
	call	tlsc_server_flight
	test	eax,eax
	jz	.rec
	mov	r14d,eax
	lea	rsi,[g_b_hdec]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.rec
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hdec]
	mov	edx,r14d
	call	tlsc_verify
	test	eax,eax
	jz	.fail
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hout]
	call	tlsc_finish
	lea	rdi,[g_b_hout]
	mov	esi,eax
	call	bench_write_all
	test	eax,eax
	jz	.fail
.extra:
	cmp	r13d,r12d			; whole records after the Finished
	je	.keys
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.more
	movzx	eax,word [g_b_hin+r13+3]
	xchg	al,ah
	lea	r15d,[r13+rax+5]
	cmp	r15d,r12d
	ja	.more
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hin+r13]
	call	tlsc_open
	test	eax,eax
	jz	.fail
	mov	r13d,r15d
	jmp	.extra
.more:
	call	.recv
	test	eax,eax
	jz	.fail
	jmp	.extra
.keys:
	; the keys stay here: the connection's records are sealed and opened
	; in user space, as with new=on (cheaper than the kernel's, and no
	; tls module needed)
	lea	rsi,[g_b_tc]
	lea	rdi,[rbx+BC_TC]
	mov	ecx,TC_FULL
	rep	movsb
	mov	dword [rbx+BC_HS],BH_RECORDS
	mov	eax,1
	jmp	.out
.fail:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
; more of the server's bytes after r12d; eax = 0 when it closed or is full
.recv:
	mov	edx,BENCH_HIN_CAP
	sub	edx,r12d
	jz	.recv_fail
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_b_hin+r12]
	xor	eax,eax				; SYS_read
	syscall
	cmp	rax,-EINTR
	je	.recv
	test	rax,rax
	jle	.recv_fail
	add	r12d,eax
	mov	eax,1
	ret
.recv_fail:
	xor	eax,eax
	ret

; rbx = connection whose server closed it or broke the protocol: replace
; it. A connection that cannot be replaced is dead. Keeps the schedule.
bench_reconnect:
	mov	edi,[rbx+BC_FD]
	mov	eax,SYS_close
	syscall
	call	bench_open
	test	eax,eax
	jnz	.ok
	mov	dword [rbx+BC_STATE],BCS_DEAD
	dec	dword [g_b_alive]
	ret
.ok:
	mov	dword [rbx+BC_STATE],BCS_WAIT
	ret

; ------------------------------------------------------------ data path

; rbx = connection, rax = now: the next request goes out.
bench_send:
	mov	[rbx+BC_SENT],rax
	mov	dword [rbx+BC_STATE],BCS_FLIGHT
	inc	dword [g_b_inflight]
	xor	eax,eax
	mov	[rbx+BC_SOFF],eax
	mov	[rbx+BC_STATUS],eax
	mov	dword [rbx+BC_PHASE],BP_HEAD
	cmp	dword [g_b_mode],2
	jne	@f
	mov	dword [rbx+BC_PHASE],BP_ECHO
	mov	rax,[g_b_size]
	mov	[rbx+BC_REM],rax
@@:
	cmp	dword [g_b_new],0
	jne	bench_new_open
; the rest of the request, as far as the socket takes it
bench_send_more:
	cmp	dword [rbx+BC_HS],BH_RECORDS
	je	.sealed
.again:
	mov	edx,[g_b_reqlen]
	mov	eax,[rbx+BC_SOFF]
	sub	edx,eax
	jz	.sent
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_b_req+rax]
	mov	r10d,MSG_DONTWAIT or MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	cmp	rax,-EINTR
	je	.again
	cmp	rax,-EAGAIN
	je	.blocked
	test	rax,rax
	js	bench_fail
	add	[rbx+BC_SOFF],eax
	jmp	.again
.blocked:
	test	dword [rbx+BC_FLAGS],BF_OUT
	jnz	.ret
	or	dword [rbx+BC_FLAGS],BF_OUT
	mov	edi,EPOLLIN or EPOLLOUT
	jmp	bench_epoll_mod
.sent:
	test	dword [rbx+BC_FLAGS],BF_OUT
	jz	.ret
	and	dword [rbx+BC_FLAGS],not BF_OUT
	mov	edi,EPOLLIN
	jmp	bench_epoll_mod
.ret:
	ret
.sealed:
	; one record, sealed and written whole (a request fits the socket)
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[g_b_hsend]
	lea	rdx,[g_b_req]
	mov	ecx,[g_b_reqlen]
	call	tlsc_seal
	lea	rsi,[g_b_hsend]
	mov	edx,eax
	call	bench_new_sendall
	jc	bench_fail
	mov	eax,[g_b_reqlen]
	mov	[rbx+BC_SOFF],eax
	ret

; edi = events for the connection in rbx
bench_epoll_mod:
	sub	rsp,16
	mov	[rsp],edi
	mov	eax,[rbx+BC_GIDX]
	sub	eax,[g_b_c0]
	mov	[rsp+4],rax
	mov	edi,[g_b_ep]
	mov	esi,EPOLL_CTL_MOD
	mov	edx,[rbx+BC_FD]
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	ret

; rbx = connection: an error. Its request is lost; it is replaced and its
; schedule goes on.
bench_fail:
	mov	rax,[g_b_wres]
	inc	qword [rax+BW_ERR]
	cmp	dword [g_b_new],0
	jne	bench_new_fail
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	bench_reconnect_wait		; idle: it may be in the heap already
	dec	dword [g_b_inflight]
	call	bench_reconnect
	cmp	dword [rbx+BC_STATE],BCS_DEAD
	je	.ret
	bench_now
	jmp	bench_schedule
.ret:
	ret

; rbx = connection, readable
bench_readable:
	cmp	dword [rbx+BC_HS],BH_FLIGHT
	jae	bench_tls_readable
	mov	ecx,[rbx+BC_ROFF]		; move what is left to the front
	test	ecx,ecx
	jz	.read
	mov	edx,[rbx+BC_RLEN]
	sub	edx,ecx
	mov	[rbx+BC_RLEN],edx
	mov	dword [rbx+BC_ROFF],0
	lea	rsi,[rbx+BC_BUF+rcx]
	lea	rdi,[rbx+BC_BUF]
	mov	ecx,edx
	rep	movsb
.read:
	mov	edx,BC_CAP
	sub	edx,[rbx+BC_RLEN]
	jz	bench_fail			; a head that does not fit
	mov	edi,[rbx+BC_FD]
	mov	eax,[rbx+BC_RLEN]
	lea	rsi,[rbx+BC_BUF+rax]
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.ret
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	bench_fail
	jz	.eof
	add	[rbx+BC_RLEN],eax
	mov	rcx,[g_b_wres]
	add	[rcx+BW_BYTES],rax
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	bench_fail			; bytes nobody asked for
	call	bench_parse
	test	eax,eax
	js	bench_fail
	jz	.ret
	mov	eax,[rbx+BC_ROFF]
	cmp	eax,[rbx+BC_RLEN]
	jne	bench_fail			; more than the one answer
	jmp	bench_complete
.eof:
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	.closed_idle
	cmp	dword [rbx+BC_PHASE],BP_CLOSE
	jne	bench_fail
	or	dword [rbx+BC_FLAGS],BF_CLOSE
	jmp	bench_complete
.closed_idle:
	; the server closed a keep-alive connection between requests
	cmp	dword [g_b_new],0
	jne	bench_fail
	mov	rax,[g_b_wres]
	inc	qword [rax+BW_RECON]
	jmp	bench_reconnect_wait
.ret:
	ret

; ------------------------------------------------- new=on: a connection each

; rbx = connection whose server closed it while records were read here
bench_eof:
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	bench_fail
	cmp	dword [rbx+BC_PHASE],BP_CLOSE
	jne	bench_fail
	or	dword [rbx+BC_FLAGS],BF_CLOSE
	jmp	bench_complete

; rbx = connection whose request is due: a new socket, connecting. The
; request (after a TLS handshake for https) goes out when it is connected.
bench_new_open:
	mov	edi,[g_b_family]
	mov	esi,SOCK_STREAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	bench_fail
	mov	[rbx+BC_FD],eax
	sub	rsp,16
	mov	dword [rsp],1
	mov	edi,[rbx+BC_FD]
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	dword [rsp],1			; SO_LINGER 0: the close resets, so
	mov	dword [rsp+4],0			; no TIME_WAIT eats the local ports
	mov	edi,[rbx+BC_FD]
	mov	esi,1				; SOL_SOCKET
	mov	edx,13				; SO_LINGER
	mov	r10,rsp
	mov	r8d,8
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,16
	xor	eax,eax
	mov	[rbx+BC_RLEN],eax
	mov	[rbx+BC_ROFF],eax
	mov	[rbx+BC_CLEN],eax
	mov	[rbx+BC_FLAGS],eax
	mov	dword [rbx+BC_HS],BH_CONNECTING
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_b_sa]
	mov	edx,[g_b_salen]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jz	@f
	cmp	eax,-EINPROGRESS
	jne	bench_fail
@@:
	sub	rsp,16
	mov	dword [rsp],EPOLLOUT
	mov	eax,[rbx+BC_GIDX]
	sub	eax,[g_b_c0]
	mov	[rsp+4],rax
	mov	edi,[g_b_ep]
	mov	esi,EPOLL_CTL_ADD
	mov	edx,[rbx+BC_FD]
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	test	eax,eax
	jnz	bench_fail
	ret

; rbx: the connect finished (or failed)
bench_new_connected:
	sub	rsp,16
	mov	dword [rsp],0
	mov	dword [rsp+4],4
	mov	edi,[rbx+BC_FD]
	mov	esi,1				; SOL_SOCKET
	mov	edx,4				; SO_ERROR
	mov	r10,rsp
	lea	r8,[rsp+4]
	mov	eax,SYS_getsockopt
	syscall
	mov	ecx,[rsp]
	add	rsp,16
	test	eax,eax
	jnz	bench_fail
	test	ecx,ecx
	jnz	bench_fail
	cmp	dword [g_b_mode],1
	je	.tls
	mov	dword [rbx+BC_HS],0
	mov	edi,EPOLLIN
	call	bench_epoll_mod
	jmp	bench_send_more
.tls:
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[g_b_hout]
	mov	rdx,[g_b_sni]
	mov	ecx,[g_b_snilen]
	call	tlsc_client_hello
	test	eax,eax
	jz	bench_fail
	push	rax
	lea	rsi,[rbx+BC_TC+TC_SHA]		; the transcript through the ClientHello
	lea	rdi,[rbx+BC_SNAP]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	pop	rdx
	lea	rsi,[g_b_hout]
	call	bench_new_sendall
	jc	bench_fail
	mov	dword [rbx+BC_HS],BH_FLIGHT
	mov	dword [rbx+BC_HTRY],0
	mov	edi,EPOLLIN
	jmp	bench_epoll_mod

; rsi = bytes, edx = length: all of it into the fresh connection in rbx at
; once (it fits the socket's buffer), else CF
bench_new_sendall:
	push	rdx
	mov	edi,[rbx+BC_FD]
	mov	r10d,MSG_DONTWAIT or MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	pop	rdx
	cmp	rax,rdx
	jne	.short
	clc
	ret
.short:
	stc
	ret

; rbx = connection, its exchange over: closed (with a reset)
bench_new_close:
	mov	edi,[rbx+BC_FD]
	test	edi,edi
	js	@f
	mov	eax,SYS_close
	syscall
@@:
	mov	dword [rbx+BC_FD],-1
	mov	dword [rbx+BC_HS],0
	ret

; rbx = connection: an error (counted already). Closed; the schedule goes on.
bench_new_fail:
	call	bench_new_close
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	.idle
	dec	dword [g_b_inflight]
	mov	dword [rbx+BC_STATE],BCS_WAIT
	bench_now
	jmp	bench_schedule
.idle:
	ret

; rbx = connection in its TLS handshake or on user-space records: readable
bench_tls_readable:
	push	r12
	push	r13
	push	r14
.read:
	mov	edx,BC_CCAP
	sub	edx,[rbx+BC_CLEN]
	jz	.fail
	mov	edi,[rbx+BC_FD]
	mov	eax,[rbx+BC_CLEN]
	lea	rsi,[rbx+BC_CBUF+rax]
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.out
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	.fail
	jz	.eof
	add	[rbx+BC_CLEN],eax
	mov	rcx,[g_b_wres]
	add	[rcx+BW_BYTES],rax
	cmp	dword [rbx+BC_HS],BH_FLIGHT
	je	.flight
.records:
	; every whole record: its plaintext to the answer's buffer, parsed
	xor	r12d,r12d
.record:
	lea	eax,[r12+5]
	cmp	eax,[rbx+BC_CLEN]
	ja	.compact
	movzx	eax,word [rbx+BC_CBUF+r12+3]
	xchg	al,ah
	lea	r13d,[r12+rax+5]
	cmp	r13d,[rbx+BC_CLEN]
	ja	.compact
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[rbx+BC_CBUF+r12]
	call	tlsc_open
	mov	r12d,r13d
	test	eax,eax
	jz	.fail
	cmp	r8d,21				; an alert: the end
	je	.eof
	cmp	r8d,23
	jne	.record				; a session ticket: not kept
	mov	r14,rsi				; plaintext
	mov	r13d,ecx
	mov	ecx,[rbx+BC_ROFF]		; what is parsed leaves the buffer
	test	ecx,ecx
	jz	@f
	mov	edx,[rbx+BC_RLEN]
	sub	edx,ecx
	mov	[rbx+BC_RLEN],edx
	mov	dword [rbx+BC_ROFF],0
	lea	rsi,[rbx+BC_BUF+rcx]
	lea	rdi,[rbx+BC_BUF]
	mov	ecx,edx
	rep	movsb
@@:
	mov	eax,[rbx+BC_RLEN]
	add	eax,r13d
	cmp	eax,BC_CAP
	ja	.fail
	mov	ecx,[rbx+BC_RLEN]
	lea	rdi,[rbx+BC_BUF+rcx]
	mov	rsi,r14
	mov	ecx,r13d
	rep	movsb
	mov	[rbx+BC_RLEN],eax
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	.fail
	call	bench_parse
	test	eax,eax
	js	.fail
	jz	.record
	mov	eax,[rbx+BC_ROFF]
	cmp	eax,[rbx+BC_RLEN]
	jne	.fail
	mov	ecx,[rbx+BC_CLEN]		; the records opened leave the buffer
	sub	ecx,r12d			; (a keep-alive connection reads on)
	mov	[rbx+BC_CLEN],ecx
	lea	rsi,[rbx+BC_CBUF+r12]
	lea	rdi,[rbx+BC_CBUF]
	rep	movsb
	pop	r14
	pop	r13
	pop	r12
	jmp	bench_complete
.compact:
	mov	ecx,[rbx+BC_CLEN]		; a partial record to the front
	sub	ecx,r12d
	mov	[rbx+BC_CLEN],ecx
	lea	rsi,[rbx+BC_CBUF+r12]
	lea	rdi,[rbx+BC_CBUF]
	rep	movsb
	jmp	.read
.flight:
	mov	r12d,[rbx+BC_HTRY]
.frec:
	lea	eax,[r12+5]
	cmp	eax,[rbx+BC_CLEN]
	ja	.fmore
	movzx	eax,word [rbx+BC_CBUF+r12+3]
	xchg	al,ah
	lea	r12d,[r12+rax+5]
	cmp	r12d,[rbx+BC_CLEN]
	ja	.fmore_back
	lea	rsi,[rbx+BC_CBUF]
	mov	edx,r12d
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.fail
	lea	rsi,[rbx+BC_SNAP]
	lea	rdi,[rbx+BC_TC+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[rbx+BC_CBUF]
	mov	edx,r12d
	lea	rcx,[g_b_hdec]
	call	tlsc_server_flight
	test	eax,eax
	jz	.frec
	mov	r13d,eax
	lea	rsi,[g_b_hdec]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.frec
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[g_b_hdec]
	mov	edx,r13d
	call	tlsc_verify
	test	eax,eax
	jz	.fail
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[g_b_hsend]
	call	tlsc_finish
	mov	r13d,eax			; the Finished, then the request sealed
	lea	rdi,[rbx+BC_TC]
	lea	rsi,[g_b_hsend+r13]
	lea	rdx,[g_b_req]
	mov	ecx,[g_b_reqlen]
	call	tlsc_seal
	add	r13d,eax
	lea	rsi,[g_b_hsend]
	mov	edx,r13d
	call	bench_new_sendall
	jc	.fail
	mov	eax,[g_b_reqlen]
	mov	[rbx+BC_SOFF],eax
	mov	dword [rbx+BC_HS],BH_RECORDS
	mov	ecx,[rbx+BC_CLEN]		; what came after the Finished stays
	sub	ecx,r12d
	mov	[rbx+BC_CLEN],ecx
	lea	rsi,[rbx+BC_CBUF+r12]
	lea	rdi,[rbx+BC_CBUF]
	rep	movsb
	jmp	.records
.fmore_back:
	; that record is not whole: from the last whole one next time
	mov	r12d,[rbx+BC_HTRY]
.fmore_scan:
	; the last whole-record boundary at or after HTRY
	lea	eax,[r12+5]
	cmp	eax,[rbx+BC_CLEN]
	ja	.fmore
	movzx	eax,word [rbx+BC_CBUF+r12+3]
	xchg	al,ah
	lea	eax,[r12+rax+5]
	cmp	eax,[rbx+BC_CLEN]
	ja	.fmore
	mov	r12d,eax
	jmp	.fmore_scan
.fmore:
	mov	[rbx+BC_HTRY],r12d
	jmp	.read
.eof:
	pop	r14
	pop	r13
	pop	r12
	jmp	bench_eof
.fail:
	pop	r14
	pop	r13
	pop	r12
	jmp	bench_fail
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; rbx: the connection closed between requests; replace it, same schedule
bench_reconnect_wait:
	cmp	dword [rbx+BC_STATE],BCS_DONE
	je	.done
	call	bench_reconnect
	cmp	dword [rbx+BC_STATE],BCS_DEAD
	je	.ret
	call	bench_in_heap			; its next request may be queued already
	test	eax,eax
	jnz	.ret
	bench_now
	jmp	bench_schedule_at
.done:
	; its schedule is over: close it rather than keep a dead socket readable
	mov	edi,[rbx+BC_FD]
	mov	eax,SYS_close
	syscall
	mov	dword [rbx+BC_STATE],BCS_DEAD
.ret:
	ret

; eax = 1 when the connection in rbx is in the heap
bench_in_heap:
	mov	ecx,[g_b_heapn]
	mov	edx,[rbx+BC_GIDX]
	sub	edx,[g_b_c0]
	mov	r8,[g_b_heap]
@@:
	test	ecx,ecx
	jz	.no
	dec	ecx
	cmp	[r8+rcx*4],edx
	jne	@b
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; rbx = connection whose answer is whole
bench_complete:
	bench_now
	push	r12
	mov	r12,rax
	dec	dword [g_b_inflight]
	mov	dword [rbx+BC_STATE],BCS_WAIT
	mov	rcx,[rbx+BC_NEXT]
	cmp	rcx,[g_b_trec]
	jb	.counted			; scheduled during the warmup
	mov	r8,[g_b_wres]
	inc	qword [r8+BW_COUNT]
	mov	eax,[rbx+BC_STATUS]
	sub	eax,200
	cmp	eax,100
	jb	.ok
	cmp	dword [g_b_mode],2
	je	.ok
	inc	qword [r8+BW_OTHER]
	jmp	@f
.ok:
	inc	qword [r8+BW_2XX]
@@:
	mov	rax,r12				; from the schedule
	sub	rax,rcx
	call	bench_ns
	mov	r8,[g_b_wres]
	cmp	rax,[r8+BW_MAXC]
	jbe	@f
	mov	[r8+BW_MAXC],rax
@@:
	call	bh_index
	inc	qword [r8+BW_HC+rax*8]
	mov	rax,r12				; from the send
	sub	rax,[rbx+BC_SENT]
	call	bench_ns
	mov	r8,[g_b_wres]
	cmp	rax,[r8+BW_MAXS]
	jbe	@f
	mov	[r8+BW_MAXS],rax
@@:
	call	bh_index
	inc	qword [r8+BW_HS+rax*8]
.counted:
	mov	dword [rbx+BC_RLEN],0
	mov	dword [rbx+BC_ROFF],0
	cmp	dword [g_b_new],0
	je	@f
	call	bench_new_close
	jmp	.next
@@:
	test	dword [rbx+BC_FLAGS],BF_CLOSE
	jz	.next
	mov	rax,[g_b_wres]
	inc	qword [rax+BW_RECON]
	call	bench_reconnect
	cmp	dword [rbx+BC_STATE],BCS_DEAD
	je	.out
.next:
	mov	rax,r12
	pop	r12
	jmp	bench_schedule
.out:
	pop	r12
	ret

; rbx = connection: rax = the time of its schedule's request BC_SLOT,
; t0 + (gidx + slot * conns) / rate seconds, exact (no interval summed up)
bench_slot_time:
	mov	eax,[rbx+BC_SLOT]
	mov	ecx,[g_b_conns]
	imul	rax,rcx
	mov	ecx,[rbx+BC_GIDX]
	add	rax,rcx
	mul	qword [g_b_hz]
	div	qword [g_b_rate]
	add	rax,[g_b_t0]
	ret

; rbx = connection that just finished a request (or lost one), rax = now:
; its next request, now when the schedule is behind, else in the heap.
bench_schedule:
	cmp	qword [g_b_rate],0
	jne	.open
	mov	[rbx+BC_NEXT],rax		; closed loop: at once
	jmp	bench_schedule_at
.open:
	inc	dword [rbx+BC_SLOT]
	push	rax
	call	bench_slot_time
	mov	[rbx+BC_NEXT],rax
	pop	rax
; rax = now
bench_schedule_at:
	mov	rcx,[rbx+BC_NEXT]
	cmp	rcx,[g_b_tend]
	jae	.done
	cmp	rcx,rax
	jbe	bench_send			; due already
	mov	edi,[rbx+BC_GIDX]
	sub	edi,[g_b_c0]
	jmp	bheap_push
.done:
	mov	dword [rbx+BC_STATE],BCS_DONE
	ret

; rbx = connection: parse what the buffer holds. eax = 1 when the answer
; is whole, 0 when more is needed, -1 on a protocol error.
bench_parse:
	push	r12
	push	r13
.again:
	mov	r12d,[rbx+BC_ROFF]
	mov	r13d,[rbx+BC_RLEN]
	mov	eax,[rbx+BC_PHASE]
	cmp	eax,BP_HEAD
	je	.head
	cmp	eax,BP_BODY
	je	.body
	cmp	eax,BP_ECHO
	je	.body
	cmp	eax,BP_CSIZE
	je	.csize
	cmp	eax,BP_CDATA
	je	.body
	cmp	eax,BP_TRAILER
	je	.trailer
	mov	[rbx+BC_ROFF],r13d		; BP_CLOSE: everything, until EOF
	jmp	.more
.head:
	mov	ecx,r12d			; the end of the head
.find:
	lea	eax,[rcx+4]
	cmp	eax,r13d
	ja	.more
	cmp	dword [rbx+BC_BUF+rcx],0x0A0D0A0D
	je	.found
	inc	ecx
	jmp	.find
.found:
	lea	r8d,[rcx+4]			; the head ends here
	lea	eax,[r12+12]
	cmp	eax,r8d
	ja	.bad
	cmp	dword [rbx+BC_BUF+r12],'HTTP'
	jne	.bad
	cmp	dword [rbx+BC_BUF+r12+4],'/1.1'
	je	@f
	cmp	dword [rbx+BC_BUF+r12+4],'/1.0'
	jne	.bad
	or	dword [rbx+BC_FLAGS],BF_CLOSE	; 1.0: assume it closes
@@:
	xor	eax,eax				; the status
	lea	ecx,[r12+9]
.status:
	movzx	edx,byte [rbx+BC_BUF+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	lea	edx,[r12+12]
	cmp	ecx,edx
	jb	.status
	mov	[rbx+BC_STATUS],eax
	; the fields: Content-Length, Transfer-Encoding, Connection
	mov	qword [rbx+BC_REM],-1		; no length yet
	xor	r9d,r9d				; 1 = chunked
	lea	ecx,[r12+12]
.line:
	; to the next line
	cmp	ecx,r8d
	jae	.fields_done
	cmp	byte [rbx+BC_BUF+rcx],10
	je	.at_line
	inc	ecx
	jmp	.line
.at_line:
	inc	ecx				; first byte of a field line
	lea	eax,[rcx+2]
	cmp	eax,r8d
	jae	.fields_done			; the empty line
	lea	rdi,[rbx+BC_BUF+rcx]
	mov	esi,r8d
	sub	esi,ecx
	cmp	esi,15
	jb	.line
	push	rcx
	push	r8
	push	r9
	lea	rsi,[.f_cl]
	mov	edx,15
	call	mem_eq_nocase
	pop	r9
	pop	r8
	pop	rcx
	test	eax,eax
	jnz	.cl
	lea	rdi,[rbx+BC_BUF+rcx]
	push	rcx
	push	r8
	push	r9
	lea	rsi,[.f_conn]
	mov	edx,11
	call	mem_eq_nocase
	pop	r9
	pop	r8
	pop	rcx
	test	eax,eax
	jnz	.conn
	mov	esi,r8d
	sub	esi,ecx
	cmp	esi,18
	jb	.line
	lea	rdi,[rbx+BC_BUF+rcx]
	push	rcx
	push	r8
	push	r9
	lea	rsi,[.f_te]
	mov	edx,18
	call	mem_eq_nocase
	pop	r9
	pop	r8
	pop	rcx
	test	eax,eax
	jz	.line
	mov	r9d,1				; any Transfer-Encoding a server sends us is chunked
	jmp	.line
.cl:
	add	ecx,15
	xor	eax,eax
@@:
	cmp	byte [rbx+BC_BUF+rcx],' '
	jne	@f
	inc	ecx
	jmp	@b
@@:
	movzx	edx,byte [rbx+BC_BUF+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	@f
	imul	rax,rax,10
	add	rax,rdx
	inc	ecx
	jmp	@b
@@:
	mov	[rbx+BC_REM],rax
	jmp	.line
.conn:
	; "close" anywhere in the value
	add	ecx,11
@@:
	lea	eax,[rcx+5]
	cmp	eax,r8d
	ja	.line
	cmp	byte [rbx+BC_BUF+rcx],10
	je	.line
	lea	rdi,[rbx+BC_BUF+rcx]
	push	rcx
	push	r8
	push	r9
	lea	rsi,[.v_close]
	mov	edx,5
	call	mem_eq_nocase
	pop	r9
	pop	r8
	pop	rcx
	inc	ecx
	test	eax,eax
	jz	@b
	or	dword [rbx+BC_FLAGS],BF_CLOSE
	jmp	.line
.fields_done:
	mov	[rbx+BC_ROFF],r8d
	mov	eax,[rbx+BC_STATUS]
	cmp	eax,101
	je	.done				; an upgrade: nothing more here
	sub	eax,100
	cmp	eax,100
	jb	.again				; 1xx: the real answer follows
	cmp	dword [g_b_nobody],0
	jne	.done
	mov	eax,[rbx+BC_STATUS]
	cmp	eax,204
	je	.done
	cmp	eax,304
	je	.done
	test	r9d,r9d
	jnz	.chunked
	cmp	qword [rbx+BC_REM],-1
	je	.untilclose
	mov	dword [rbx+BC_PHASE],BP_BODY
	cmp	qword [rbx+BC_REM],0
	je	.done
	jmp	.again
.chunked:
	mov	dword [rbx+BC_PHASE],BP_CSIZE
	jmp	.again
.untilclose:
	mov	dword [rbx+BC_PHASE],BP_CLOSE
	or	dword [rbx+BC_FLAGS],BF_CLOSE
	jmp	.again
.body:
	mov	eax,r13d			; available
	sub	eax,r12d
	jz	.more
	mov	rcx,[rbx+BC_REM]
	cmp	rax,rcx
	cmova	rax,rcx
	add	[rbx+BC_ROFF],eax
	sub	[rbx+BC_REM],rax
	jnz	.more
	cmp	dword [rbx+BC_PHASE],BP_CDATA
	jne	.done
	mov	dword [rbx+BC_PHASE],BP_CSIZE
	jmp	.again
.csize:
	mov	ecx,r12d			; a whole line: hex size [; ext] CRLF
@@:
	lea	eax,[rcx+2]
	cmp	eax,r13d
	ja	.more_line
	cmp	word [rbx+BC_BUF+rcx],0x0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	r8d,[rcx+2]			; after the line
	mov	ecx,r12d
	xor	eax,eax
	xor	r9d,r9d				; digits
.hex:
	movzx	edx,byte [rbx+BC_BUF+rcx]
	mov	r10d,edx
	sub	r10d,'0'
	cmp	r10d,9
	jbe	.digit
	or	edx,0x20
	sub	edx,'a'
	cmp	edx,5
	ja	.hexend
	lea	r10d,[rdx+10]
.digit:
	cmp	r9d,15
	jae	.bad
	shl	rax,4
	add	rax,r10
	inc	r9d
	inc	ecx
	jmp	.hex
.hexend:
	test	r9d,r9d
	jz	.bad
	mov	[rbx+BC_ROFF],r8d
	test	rax,rax
	jz	.last
	add	rax,2				; the data's CRLF
	mov	[rbx+BC_REM],rax
	mov	dword [rbx+BC_PHASE],BP_CDATA
	jmp	.again
.last:
	mov	dword [rbx+BC_PHASE],BP_TRAILER
	jmp	.again
.trailer:
	mov	ecx,r12d
@@:
	lea	eax,[rcx+2]
	cmp	eax,r13d
	ja	.more_line
	cmp	word [rbx+BC_BUF+rcx],0x0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	r8d,[rcx+2]
	mov	[rbx+BC_ROFF],r8d
	cmp	ecx,r12d
	je	.done				; the empty line
	jmp	.again
.more_line:
	mov	eax,r13d
	sub	eax,r12d
	cmp	eax,4096
	ja	.bad
.more:
	xor	eax,eax
	jmp	.out
.done:
	mov	eax,1
	jmp	.out
.bad:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	ret
.f_cl	db 'content-length:'
.f_conn	db 'connection:'
.f_te	db 'transfer-encoding:'
.v_close db 'close'

; ---------------------------------------------------------------- worker

; edi = worker index. Never returns.
bench_worker:
	mov	[g_b_wid],edi
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	edi,PR_SET_TIMERSLACK
	mov	esi,1
	mov	eax,SYS_prctl
	syscall
	; this worker's share of the connections
	mov	eax,[g_b_conns]
	xor	edx,edx
	div	dword [g_b_workers]		; eax = each, edx = the rest
	mov	ecx,[g_b_wid]
	mov	r8d,eax
	imul	r8d,ecx
	mov	r9d,ecx
	cmp	r9d,edx
	cmova	r9d,edx
	add	r8d,r9d				; first = w*each + min(w, rest)
	mov	[g_b_c0],r8d
	cmp	ecx,edx
	adc	eax,0				; one more for the first `rest` workers
	mov	[g_b_nc],eax
	mov	[g_b_alive],eax
	mov	eax,[g_b_wid]
	imul	rax,rax,BW_SIZE
	add	rax,[g_b_shared]
	add	rax,BS_W
	mov	[g_b_wres],rax
	; connections and the heap
	mov	esi,[g_b_nc]
	imul	rsi,rsi,BC_SIZE + 4
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fail
	mov	[g_b_conn],rax
	mov	ecx,[g_b_nc]
	imul	rcx,rcx,BC_SIZE
	add	rax,rcx
	mov	[g_b_heap],rax
	mov	edi,EPOLL_CLOEXEC
	mov	eax,SYS_epoll_create1
	syscall
	test	eax,eax
	js	.fail
	mov	[g_b_ep],eax
	xor	r12d,r12d
.open:
	cmp	r12d,[g_b_nc]
	jae	.opened
	mov	eax,r12d
	imul	rax,rax,BC_SIZE
	mov	rbx,[g_b_conn]
	add	rbx,rax
	mov	eax,[g_b_c0]
	add	eax,r12d
	mov	[rbx+BC_GIDX],eax
	mov	dword [rbx+BC_FD],-1
	cmp	dword [g_b_new],0		; new=on: each request connects
	jne	@f
	call	bench_open
	test	eax,eax
	jz	.fail
@@:
	inc	r12d
	jmp	.open
.opened:
	mov	rax,[g_b_shared]
	lock inc dword [rax+BS_READY]
.wait:
	mov	rax,[g_b_shared]
	mov	rcx,[rax+BS_T0]
	test	rcx,rcx
	jnz	.go
	sub	rsp,16
	mov	qword [rsp],0
	mov	qword [rsp+8],100000
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	jmp	.wait
.go:
	mov	[g_b_t0],rcx
	mov	rax,[g_b_warm]
	call	bench_us_ticks
	add	rax,[g_b_t0]
	mov	[g_b_trec],rax
	mov	rax,[g_b_dur]
	call	bench_us_ticks
	add	rax,[g_b_trec]
	mov	[g_b_tend],rax
	mov	rax,2000000			; answers are waited for 2 s past the end
	call	bench_us_ticks
	add	rax,[g_b_tend]
	mov	[g_b_tquit],rax
	; every connection a request each conns/rate seconds, staggered
	mov	qword [g_b_iv],0
	mov	rcx,[g_b_rate]
	test	rcx,rcx
	jz	@f
	mov	eax,[g_b_conns]
	mul	qword [g_b_hz]
	div	rcx
	mov	[g_b_iv],rax
@@:
	xor	r12d,r12d
.first:
	cmp	r12d,[g_b_nc]
	jae	.run
	mov	eax,r12d
	imul	rax,rax,BC_SIZE
	mov	rbx,[g_b_conn]
	add	rbx,rax
	mov	dword [rbx+BC_SLOT],0
	mov	rax,[g_b_t0]
	cmp	qword [g_b_rate],0
	je	@f
	call	bench_slot_time
@@:
	mov	[rbx+BC_NEXT],rax
	mov	edi,r12d
	call	bheap_push
	inc	r12d
	jmp	.first
.run:
	call	bench_loop
	call	bench_tally
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall
.fail:
	mov	rax,[g_b_shared]
	lock inc dword [rax+BS_FAIL]
	mov	edi,EXIT_FAILURE
	mov	eax,SYS_exit_group
	syscall

; the event loop, until the schedule is over and its answers are in
bench_loop:
	push	rbx
	push	r12
	push	r13
	push	r14
.top:
	bench_now
	mov	r12,rax
	cmp	r12,[g_b_tquit]
	jae	.quit
	cmp	dword [g_b_alive],0
	je	.quit
	cmp	r12,[g_b_tend]
	jb	.due
	cmp	dword [g_b_inflight],0
	jne	.due
	cmp	dword [g_b_heapn],0
	je	.quit
.due:
	; every request whose time has come
	cmp	dword [g_b_heapn],0
	je	.timeout
	mov	rcx,[g_b_heap]
	bkey	rdx, [rcx]
	cmp	rdx,r12
	ja	.timeout
	call	bheap_pop
	imul	rax,rax,BC_SIZE
	mov	rbx,[g_b_conn]
	add	rbx,rax
	cmp	dword [rbx+BC_STATE],BCS_WAIT
	jne	.due
	mov	rax,r12				; the generator's own lag: an idle
	sub	rax,[rbx+BC_NEXT]		; connection should send on time
	mov	rcx,[rbx+BC_NEXT]
	cmp	rcx,[g_b_trec]
	jb	@f
	call	bench_ns
	mov	r8,[g_b_wres]
	inc	qword [r8+BW_LAGN]
	cmp	rax,[r8+BW_MAXL]
	jbe	.lagged
	mov	[r8+BW_MAXL],rax
.lagged:
	call	bh_index
	inc	qword [r8+BW_HL+rax*8]
@@:
	mov	rax,r12
	call	bench_send
	bench_now
	mov	r12,rax
	jmp	.due
.timeout:
	; sleep until the next send (or poll when it is close)
	mov	rax,[g_b_tquit]
	cmp	dword [g_b_heapn],0
	je	@f
	mov	rcx,[g_b_heap]
	bkey	rax, [rcx]
@@:
	sub	rax,r12
	jbe	.poll
	call	bench_ns
	sub	rax,BENCH_SPIN_NS
	jbe	.poll
	cmp	rax,100000000
	jbe	@f
	mov	eax,100000000
@@:
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	mov	[g_b_ts],rax
	mov	[g_b_ts+8],rdx
	jmp	.wait
.poll:
	mov	qword [g_b_ts],0
	mov	qword [g_b_ts+8],0
.wait:
	mov	edi,[g_b_ep]
	lea	rsi,[g_b_events]
	mov	edx,BENCH_EVENTS
	lea	r10,[g_b_ts]
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_epoll_pwait2
	syscall
	test	eax,eax
	jle	.top
	mov	r13d,eax
	xor	r14d,r14d
.event:
	cmp	r14d,r13d
	jae	.top
	imul	eax,r14d,EPOLL_EVENT
	lea	rcx,[g_b_events+rax]
	mov	edx,[rcx]			; events
	mov	eax,[rcx+4]			; the connection
	inc	r14d
	imul	rax,rax,BC_SIZE
	mov	rbx,[g_b_conn]
	add	rbx,rax
	cmp	dword [rbx+BC_STATE],BCS_DEAD
	je	.event
	cmp	dword [rbx+BC_HS],BH_CONNECTING
	jne	@f
	call	bench_new_connected
	jmp	.event
@@:
	push	rdx
	test	edx,EPOLLOUT
	jz	@f
	test	dword [rbx+BC_FLAGS],BF_OUT
	jz	@f
	call	bench_send_more
@@:
	pop	rdx
	test	edx,EPOLLIN or EPOLLERR or EPOLLHUP
	jz	.event
	call	bench_readable
	jmp	.event
.quit:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; what the schedule asked for and did not get
bench_tally:
	push	rbx
	push	r12
	cmp	qword [g_b_iv],0
	je	.out				; closed loop: no schedule to fall behind
	xor	r12d,r12d
.conn:
	cmp	r12d,[g_b_nc]
	jae	.out
	mov	eax,r12d
	imul	rax,rax,BC_SIZE
	mov	rbx,[g_b_conn]
	add	rbx,rax
	inc	r12d
	mov	rax,[rbx+BC_NEXT]
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	.missed
	cmp	rax,[g_b_trec]			; its answer never came
	jb	@f
	mov	rcx,[g_b_wres]
	inc	qword [rcx+BW_TIMEOUT]
@@:
	add	rax,[g_b_iv]
.missed:
	cmp	dword [rbx+BC_STATE],BCS_DONE
	je	.conn
	; the slots from max(next, trec) to tend never went out
	cmp	rax,[g_b_trec]
	jae	@f
	mov	rax,[g_b_trec]
@@:
	mov	rcx,[g_b_tend]
	sub	rcx,rax
	jbe	.conn
	mov	rax,rcx
	add	rax,[g_b_iv]
	dec	rax
	xor	edx,edx
	div	qword [g_b_iv]
	mov	rcx,[g_b_wres]
	add	[rcx+BW_BEHIND],rax
	jmp	.conn
.out:
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- parent

; eax = exit status
bench_run:
	push	rbx
	push	r12
	push	r13
	mov	esi,[g_b_workers]
	imul	rsi,rsi,BW_SIZE
	add	rsi,BS_W
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.nomem
	mov	[g_b_shared],rax
	call	out_flush
	xor	ebx,ebx
.fork:
	cmp	ebx,[g_b_workers]
	jae	.forked
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	js	.nofork
	jnz	@f
	mov	edi,ebx
	jmp	bench_worker
@@:
	inc	ebx
	jmp	.fork
.forked:
	; every worker connected (or one failed), then the clock starts
	mov	r12d,30000			; 30 s in 1 ms steps
.ready:
	mov	rax,[g_b_shared]
	cmp	dword [rax+BS_FAIL],0
	jne	.connfail
	mov	ecx,[rax+BS_READY]
	cmp	ecx,[g_b_workers]
	je	.start
	dec	r12d
	jz	.connfail
	sub	rsp,16
	mov	qword [rsp],0
	mov	qword [rsp+8],1000000
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	jmp	.ready
.start:
	mov	eax,10000			; 10 ms from now
	call	bench_us_ticks
	mov	rbx,rax
	bench_now
	add	rax,rbx
	mov	rcx,[g_b_shared]
	mov	[rcx+BS_T0],rax
	call	bench_reap
	call	bench_report
	xor	eax,eax
	jmp	.out
.connfail:
	; the workers die with us (PR_SET_PDEATHSIG), even one blocked in a handshake
	call	log_begin
	out_lit 'bench: could not connect to '
	mov	rsi,[g_b_url]
	call	out_cstr
	cmp	dword [g_b_mode],1
	jne	@f
	out_lit ' (or the TLS 1.3 handshake failed)'
@@:
	call	log_end
	mov	eax,EXIT_FAILURE
	jmp	.out
.nofork:
.nomem:
	call	log_begin
	out_lit 'bench: could not start the workers'
	call	log_end
	mov	eax,EXIT_FAILURE
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; wait for every worker to exit
bench_reap:
	sub	rsp,136
.loop:
	mov	edi,P_ALL
	xor	esi,esi
	mov	rdx,rsp
	mov	r10d,WEXITED
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	cmp	rax,-EINTR
	je	.loop
	test	rax,rax
	jz	.loop
	add	rsp,136
	ret

; ns in rax, printed with a unit
bench_out_dur:
	cmp	rax,1000
	jb	.ns
	cmp	rax,1000000
	jb	.us
	cmp	rax,1000000000
	jb	.ms
	mov	ecx,10000000			; s, two decimals
	lea	r8,[.s]
	jmp	.frac2
.ms:
	mov	ecx,10000
	lea	r8,[.m]
	jmp	.frac2
.us:
	; one decimal
	xor	edx,edx
	mov	ecx,100
	div	rcx				; tenths of a us
	push	r8
	xor	edx,edx
	mov	ecx,10
	div	rcx
	push	rdx
	call	out_u64
	out_lit '.'
	pop	rax
	call	out_u64
	pop	r8
	out_lit 'us'
	ret
.ns:
	call	out_u64
	out_lit 'ns'
	ret
.frac2:
	xor	edx,edx
	div	rcx				; hundredths of the unit
	push	r8
	xor	edx,edx
	mov	ecx,100
	div	rcx
	push	rdx
	call	out_u64
	pop	rax
	test	rax,rax
	jz	.unit				; a whole number: no decimals
	push	rax
	out_lit '.'
	pop	rax
	cmp	rax,10
	jae	@f
	push	rax
	out_lit '0'
	pop	rax
@@:
	call	out_u64
.unit:
	pop	rsi
	mov	edx,2
	cmp	byte [rsi],'s'
	jne	@f
	mov	edx,1
@@:
	jmp	out_str
.s	db 's '
.m	db 'ms'

; rdi = histogram, rsi = total, edx = parts per million: rax = ns
bench_pct:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	rax,rsi				; target = ceil(total * ppm / 1e6)
	mov	ecx,edx
	mul	rcx
	add	rax,999999
	adc	rdx,0
	mov	ecx,1000000
	div	rcx
	test	rax,rax
	jnz	@f
	inc	rax
@@:
	mov	r12,rax
	xor	ecx,ecx
	xor	r8d,r8d
.walk:
	cmp	ecx,BH_NB
	jae	.last
	add	r8,[rbx+rcx*8]
	cmp	r8,r12
	jae	.hit
	inc	ecx
	jmp	.walk
.last:
	mov	ecx,BH_NB - 1
.hit:
	mov	eax,ecx
	call	bh_value
	pop	r12
	pop	rbx
	ret

; the workers' results, added up and printed
bench_report:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	xor	ebx,ebx
.worker:
	cmp	ebx,[g_b_workers]
	jae	.summed
	mov	eax,ebx
	imul	rax,rax,BW_SIZE
	mov	r12,[g_b_shared]
	lea	r12,[r12+BS_W+rax]
	xor	ecx,ecx
.counter:
	mov	rax,[r12+rcx*8]
	cmp	ecx,BW_MAXC / 8
	je	.max
	cmp	ecx,BW_MAXS / 8
	je	.max
	cmp	ecx,BW_MAXL / 8
	je	.max
	add	[g_b_sum+rcx*8],rax
	jmp	.cnext
.max:
	cmp	rax,[g_b_sum+rcx*8]
	jbe	.cnext
	mov	[g_b_sum+rcx*8],rax
.cnext:
	inc	ecx
	cmp	ecx,16
	jb	.counter
	xor	ecx,ecx
.bucket:
	mov	rax,[r12+BW_HC+rcx*8]
	add	[g_b_hist+rcx*8],rax
	inc	ecx
	cmp	ecx,3 * BH_NB
	jb	.bucket
	inc	ebx
	jmp	.worker
.summed:
	mov	rax,[g_b_sum+BW_COUNT]
	mov	[g_b_pctn],rax
	mov	edi,1
	call	out_select
	cmp	dword [g_b_fmt],1
	je	.kv
	out_lit 'okena bench '
	mov	rsi,[g_b_url]
	call	out_cstr
	out_lit ': '
	mov	eax,[g_b_conns]
	call	out_u64
	out_lit ' connections'
	cmp	dword [g_b_new],0
	je	@f
	out_lit ' (a new one for each request)'
@@:
	out_lit ', '
	mov	eax,[g_b_workers]
	call	out_u64
	out_lit ' worker'
	cmp	dword [g_b_workers],1
	je	@f
	out_lit 's'
@@:
	out_lit ', '
	cmp	qword [g_b_rate],0
	je	.closed
	out_lit 'rate '
	mov	rax,[g_b_rate]
	call	out_u64
	out_lit '/s'
	jmp	@f
.closed:
	out_lit 'closed loop'
@@:
	out_lit ', '
	mov	rax,[g_b_dur]
	imul	rax,rax,1000
	call	bench_out_dur
	out_lit ' after a '
	mov	rax,[g_b_warm]
	imul	rax,rax,1000
	call	bench_out_dur
	out_lit ' warmup'
	mov	edi,10
	call	out_char
	out_lit '  requests '
	mov	rax,[g_b_sum+BW_COUNT]
	call	out_u64
	out_lit ' ('
	call	bench_out_rps
	out_lit '/s)  2xx '
	mov	rax,[g_b_sum+BW_2XX]
	call	out_u64
	out_lit '  other '
	mov	rax,[g_b_sum+BW_OTHER]
	call	out_u64
	out_lit '  errors '
	mov	rax,[g_b_sum+BW_ERR]
	call	out_u64
	out_lit '  timeouts '
	mov	rax,[g_b_sum+BW_TIMEOUT]
	call	out_u64
	out_lit '  reconnects '
	mov	rax,[g_b_sum+BW_RECON]
	call	out_u64
	mov	edi,10
	call	out_char
	cmp	qword [g_b_sum+BW_COUNT],0
	je	.behind
	out_lit '  latency  '
	lea	r13,[g_b_hist]
	mov	r14,[g_b_sum+BW_MAXC]
	call	.line
	cmp	qword [g_b_rate],0
	je	.behind
	out_lit '  service  '
	lea	r13,[g_b_hist+BH_NB*8]
	mov	r14,[g_b_sum+BW_MAXS]
	call	.line
	cmp	qword [g_b_sum+BW_LAGN],0
	je	.behind
	out_lit '  sender   '
	lea	r13,[g_b_hist+2*BH_NB*8]
	mov	r14,[g_b_sum+BW_MAXL]
	mov	rax,[g_b_sum+BW_LAGN]
	mov	[g_b_pctn],rax
	call	.line
.behind:
	cmp	qword [g_b_sum+BW_BEHIND],0
	je	.done
	out_lit '  behind   '
	mov	rax,[g_b_sum+BW_BEHIND]
	call	out_u64
	out_lit ' requests of the schedule never went out: the rate was not reached, and the percentiles leave them out'
	mov	edi,10
	call	out_char
	jmp	.done
.kv:
	out_lit 'requests='
	mov	rax,[g_b_sum+BW_COUNT]
	call	out_u64
	out_lit ' rps='
	call	bench_out_rps
	out_lit ' ok='
	mov	rax,[g_b_sum+BW_2XX]
	call	out_u64
	out_lit ' other='
	mov	rax,[g_b_sum+BW_OTHER]
	call	out_u64
	out_lit ' errors='
	mov	rax,[g_b_sum+BW_ERR]
	call	out_u64
	out_lit ' timeouts='
	mov	rax,[g_b_sum+BW_TIMEOUT]
	call	out_u64
	out_lit ' behind='
	mov	rax,[g_b_sum+BW_BEHIND]
	call	out_u64
	out_lit ' reconnects='
	mov	rax,[g_b_sum+BW_RECON]
	call	out_u64
	lea	r13,[g_b_hist]
	mov	r14,[g_b_sum+BW_MAXC]
	lea	r15,[.kv_c]
	call	.kvline
	lea	r13,[g_b_hist+BH_NB*8]
	mov	r14,[g_b_sum+BW_MAXS]
	lea	r15,[.kv_s]
	call	.kvline
	mov	rax,[g_b_sum+BW_LAGN]
	test	rax,rax
	jz	@f
	mov	[g_b_pctn],rax
	lea	r13,[g_b_hist+2*BH_NB*8]
	mov	r14,[g_b_sum+BW_MAXL]
	lea	r15,[.kv_l]
	call	.kvline
@@:
	mov	edi,10
	call	out_char
.done:
	call	out_flush
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; r13 = histogram, r14 = max: "p50 X  p90 X  p99 X  p99.9 X  p99.99 X  max X"
.line:
	xor	r12d,r12d
.lp:
	lea	rsi,[.names]
	movzx	eax,byte [.namelen+r12]
	movzx	ecx,byte [.nameoff+r12]
	add	rsi,rcx
	mov	edx,eax
	call	out_str
	out_lit ' '
	cmp	r12d,5
	je	.lmax
	mov	rdi,r13
	mov	rsi,[g_b_pctn]
	mov	edx,[.ppm+r12*4]
	call	bench_pct
	cmp	rax,r14
	cmova	rax,r14
	jmp	.lval
.lmax:
	mov	rax,r14
.lval:
	call	bench_out_dur
	inc	r12d
	cmp	r12d,6
	jae	.lend
	out_lit '  '
	jmp	.lp
.lend:
	mov	edi,10
	jmp	out_char
; r13 = histogram, r14 = max, r15 = prefix (5 bytes): " p50_ns=..." etc.
.kvline:
	xor	r12d,r12d
.kp:
	out_lit ' '
	mov	rsi,r15
	mov	edx,2
	call	out_str
	lea	rsi,[.knames]
	movzx	ecx,byte [.knameoff+r12]
	add	rsi,rcx
	movzx	edx,byte [.knamelen+r12]
	call	out_str
	out_lit '_ns='
	cmp	r12d,5
	je	.kmax
	mov	rdi,r13
	mov	rsi,[g_b_pctn]
	mov	edx,[.ppm+r12*4]
	call	bench_pct
	cmp	rax,r14
	cmova	rax,r14
	jmp	.kval
.kmax:
	mov	rax,r14
.kval:
	call	out_u64
	inc	r12d
	cmp	r12d,6
	jb	.kp
	ret
.ppm	dd 500000, 900000, 990000, 999000, 999900
.names	db 'p50p90p99p99.9p99.99max'
.nameoff db 0, 3, 6, 9, 14, 20
.namelen db 3, 3, 3, 5, 6, 3
.knames	db 'p50p90p99p999p9999max'
.knameoff db 0, 3, 6, 9, 13, 18
.knamelen db 3, 3, 3, 4, 5, 3
.kv_c	db 'c_'
.kv_s	db 's_'
.kv_l	db 'l_'

; requests per second over the measured window, one decimal
bench_out_rps:
	mov	rax,[g_b_sum+BW_COUNT]
	imul	rax,rax,10000000		; tenths: count * 10 * 1e6 / us
	xor	edx,edx
	div	qword [g_b_dur]
	xor	edx,edx
	mov	ecx,10
	div	rcx
	push	rdx
	call	out_u64
	out_lit '.'
	pop	rax
	jmp	out_u64
