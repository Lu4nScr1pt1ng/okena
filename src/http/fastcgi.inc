; FastCGI to PHP-FPM and others (FastCGI 1.0): a pool's `protocol fastcgi`, and
; `php ROOT [index=index.php]` on a route, as nginx and Caddy do it.
;
;   pool fpm { server unix:/run/php-fpm.sock; protocol fastcgi }
;   http :80 { route /* { php /srv/www; to pool fpm } }
;
; The rest of okena speaks HTTP/1.1 to the backend, and so it goes on to: the
; request head okena builds (its header changes, X-Forwarded-For, the request
; id) becomes FCGI_BEGIN_REQUEST and FCGI_PARAMS, a body FCGI_STDIN records,
; and the answer's FCGI_STDOUT is read back as an HTTP/1.1 response, its CGI
; head (Status:, Location:) turned into a status line and its body into chunks,
; FCGI_END_REQUEST its last chunk. This sits under h_send and h_recv on the
; upstream side, as user-space TLS does on the client's. The connection is kept
; (FCGI_KEEP_CONN) and goes back to the pool as any other. FCGI_STDERR is said
; in the log. A request body must have a length (chunked: 411, as PHP wants
; CONTENT_LENGTH).
;
; `php ROOT` picks the script, as try_files would, beneath ROOT (opened as
; `files` opens, RESOLVE_BENEATH, Landlock): a path with a segment ending in .php
; is that script and what follows it PATH_INFO (/blog/index.php/2026/11); a
; directory its index; any other file that is there is served as `files` serves
; it, never given to PHP; anything else goes to ROOT's index (a front
; controller: Laravel, WordPress, Symfony). A script that is not there: 404.
; Only names ending in .php reach PHP.

HB_FC		:= 1 shl 17			; (the upstream TLS area: no TLS to FastCGI)
FC_PHASE	:= 0				; d: 0 the head, 1 the body, 3 done
FC_RXLEN	:= 4				; d: bytes in FC_RX
FC_RXOFF	:= 8				; d: read so far
FC_REC		:= 12				; d: content left in the record being read
FC_PAD		:= 16				; d: and its padding
FC_TYPE		:= 20				; d: its type
FC_HDRLEN		:= 24				; d: the CGI head so far, in FC_HEAD
FC_CHUNK	:= 28				; d: 1 the body goes out in chunks (0: 204, 304, HEAD)
FC_HB		:= 32				; d: body bytes that came with the head: where in FC_HEAD
FC_HBLEN	:= 36				; d: and how many
FC_SET		:= 40				; d: 1 `php` chose the script
FC_SLEN		:= 44				; d: SCRIPT_NAME's length
FC_PLEN		:= 48				; d: PATH_INFO's
FC_RLEN		:= 52				; d: the root's
FC_ROOT		:= 56				; q: the root
FC_DST		:= 64				; q: where decoded bytes go
FC_ROOM		:= 72				; d: and their room
FC_BODYEND	:= 76				; d: 1 the empty FCGI_STDIN is out
FC_T		:= 80				; q: (fcgi_head: the request's target)
FC_TL		:= 88				; d: (and its length)
FC_PORT		:= 92				; d: (the listener's port)
FC_TAG		:= 96				; q: FastCGI for this request: 'FCGI' << 32 | the session's generation + 1
HB_FCGI		:= HB_FC + FC_TAG
FC_SCRIPT	:= 128				; SCRIPT_NAME, with its leading /
FC_SCRIPTMAX	:= 1024
FC_PINFO	:= FC_SCRIPT + FC_SCRIPTMAX	; PATH_INFO
FC_PINFOMAX	:= 2048
FC_HEAD		:= 4096				; the CGI head
FC_HEADMAX	:= 8192
FC_RX		:= FC_HEAD + FC_HEADMAX		; records from the backend
FC_RXCAP	:= 16384
FC_TX		:= FC_RX + FC_RXCAP		; records to it
FC_TXCAP	:= 32768
assert HB_FC + FC_TX + FC_TXCAP <= 1 shl HB_SHIFT

HS_FC_END	:= 44				; the empty FCGI_STDIN going out, then the answer

FCGI_STDIN	:= 5
FC_MAGIC	:= 0x4643474900000000
FCGI_STDOUT	:= 6
FCGI_STDERR	:= 7
FCGI_END	:= 3

; ---------------------------------------------------------------- the request

; ebx = a session: eax = 1 when its request speaks FastCGI to its backend (HB_FCGI
; is its generation + 1: a buffer another session had says nothing). Keeps all
; but rax and r8.
fcgi_active:
	cmp	dword [g_fcgi_any],0
	je	.no				; (no FastCGI pool: not even a look, its
	mov	eax,ebx				; tag sits 128 KiB into the buffers)
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	rax,[rax+H_BUF]
	mov	r8,[rax+HB_FCGI]
	test	r8,r8
	jz	.no
	push	rcx				; ('FCGI' << 32 | the generation + 1, as
	call	session_ptr			; fcgi_mark puts it)
	mov	ecx,[rax+S_GEN]
	inc	ecx
	mov	rax,FC_MAGIC
	or	rax,rcx
	pop	rcx
	cmp	rax,r8
	jne	.no
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; Features a plan may not have at all. A session's buffers belong to its
; worker and start zeroed, so the fields of a feature the plan lacks
; (FastCGI's tag, early hints', compression's, a trace's flags) stay zero:
; nothing needs to clear or read them on each request, and they sit on
; pages of the buffers no other part of a plain request touches (a cache
; miss each, ~1% of the CPU between them).
bss
	g_fcgi_any	dd ?		; the plan has a `protocol fastcgi` pool
	g_eh_any	dd ?		; a route with `early_hints`
	g_zip_any	dd ?		; a route with `compress`
	g_trace_any	dd ?		; a listener with tracing
end bss

; Worker start: the g_*_any above.
fcgi_worker_init:
	xor	eax,eax
	xor	ecx,ecx
.pool:
	cmp	ecx,[g_plan_pools]
	jae	.pools
	imul	rdx,rcx,PL_SIZE
	or	eax,[g_pools+rdx+PL_FCGI]
	inc	ecx
	jmp	.pool
.pools:
	mov	[g_fcgi_any],eax
	xor	eax,eax				; early hints
	xor	r8d,r8d				; compression
	xor	ecx,ecx
.act:
	cmp	ecx,[g_plan_acts]
	jae	.acts
	imul	rdx,rcx,RA_SIZE
	or	eax,[g_acts+rdx+RA_EHLEN]
	or	r8d,[g_acts+rdx+RA_ZMIN]
	inc	ecx
	jmp	.act
.acts:
	mov	[g_eh_any],eax
	mov	[g_zip_any],r8d
	xor	eax,eax
	xor	ecx,ecx
.listener:
	cmp	ecx,[g_plan_listeners]
	jae	.listeners
	imul	rdx,rcx,LS_SIZE
	or	eax,[g_listeners+rdx+LS_TRACE]
	inc	ecx
	jmp	.listener
.listeners:
	mov	[g_trace_any],eax
	ret

; In http_route, a request whose pool is `protocol fastcgi`: HB_FCGI. eax = the
; pool. Exits to 411 for a chunked body.
fcgi_mark:
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_FCGI]
	test	ecx,ecx
	jz	.off
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	inc	ecx
	mov	rax,FC_MAGIC
	or	rcx,rax
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_FCGI],rcx
	cmp	dword [r15+H_BODY],BK_CHUNKED
	jne	.out
	add	rsp,8				; (not back: answered)
	mov	edi,411
	jmp	http_error
.off:
	cmp	dword [g_fcgi_any],0
	je	.out				; (never set: zero already)
	mov	rax,[r15+H_BUF]
	mov	qword [rax+HB_FCGI],0
.out:
	ret

; r12 = a `php` files entry, r13d = which: the script for g_npath, as the head
; says above. eax = 1 answered here (a static file, 404, 301), 0 on to FastCGI.
php_answer:
	mov	rax,[r15+H_BUF]
	lea	rdx,[rax+HB_FC]
	mov	rcx,[r12+FI_ROOT]
	mov	[rdx+FC_ROOT],rcx
	mov	ecx,[r12+FI_RLEN]
	mov	[rdx+FC_RLEN],ecx
	mov	dword [rdx+FC_PLEN],0
	call	fs_path
	jc	.front				; (a name not served: the front controller has it)
	; a segment ending in .php: the script, the rest PATH_INFO
	xor	ecx,ecx
	mov	edx,[g_fs_plen]
.scan:
	lea	eax,[rcx+4]
	cmp	eax,edx
	ja	.no_php
	cmp	dword [g_fs_path+rcx],'.php'
	jne	.scan_next
	cmp	eax,edx
	je	.php				; at the end
	cmp	byte [g_fs_path+rax],'/'
	je	.php
.scan_next:
	inc	ecx
	jmp	.scan
.php:
	; eax = the script's length; PATH_INFO from there
	mov	r8d,edx
	sub	r8d,eax				; PATH_INFO's length
	cmp	r8d,FC_PINFOMAX
	ja	.missing
	mov	rdx,[r15+H_BUF]
	lea	rdx,[rdx+HB_FC]
	mov	[rdx+FC_PLEN],r8d
	lea	rsi,[g_fs_path+rax]
	lea	rdi,[rdx+FC_PINFO]
	mov	ecx,r8d
	rep	movsb
	mov	[g_fs_plen],eax
	lea	rdi,[g_fs_path+rax]
	call	fs_open
	jc	.front
	call	.regular
	jc	.front
	jmp	.script
.no_php:
	lea	rdi,[g_fs_path+rdx]
	call	fs_open
	jc	.front
	mov	eax,dword [g_fs_stat+ST_MODE]
	and	eax,S_IFMT_
	cmp	eax,S_IFREG_
	je	.static
	cmp	eax,S_IFDIR_
	jne	.not_there
	call	fs_close
	; a directory: its index, under a name that ends in /
	mov	eax,[g_fs_plen]
	test	eax,eax
	jz	.dir
	cmp	byte [g_fs_path+rax-1],'/'
	je	.dir
	call	fs_slash
	mov	eax,1
	ret
.dir:
	mov	ecx,[r12+FI_ILEN]
	lea	edx,[rax+rcx]
	cmp	edx,FC_SCRIPTMAX - 2
	ja	.missing
	mov	[g_fs_plen],edx
	lea	rdi,[g_fs_path+rax]
	mov	rsi,[r12+FI_INDEX]
	rep	movsb
	call	fs_open
	jc	.front
	call	.regular
	jc	.front
	jmp	.script
.not_there:
	call	fs_close
.front:
	; the front controller: ROOT's index, PATH_INFO none
	mov	rdx,[r15+H_BUF]
	mov	dword [rdx+HB_FC+FC_PLEN],0
	mov	ecx,[r12+FI_ILEN]
	mov	[g_fs_plen],ecx
	lea	rdi,[g_fs_path]
	mov	rsi,[r12+FI_INDEX]
	rep	movsb
	call	fs_open
	jc	.missing
	call	.regular
	jc	.missing
.script:
	; SCRIPT_NAME: / and what g_fs_path has, which ends in .php (else: none)
	mov	ecx,[g_fs_plen]
	cmp	ecx,4
	jb	.missing
	cmp	dword [g_fs_path+rcx-4],'.php'
	jne	.missing
	cmp	ecx,FC_SCRIPTMAX - 2
	ja	.missing
	mov	rdx,[r15+H_BUF]
	lea	rdx,[rdx+HB_FC]
	lea	eax,[rcx+1]
	mov	[rdx+FC_SLEN],eax
	mov	byte [rdx+FC_SCRIPT],'/'
	lea	rdi,[rdx+FC_SCRIPT+1]
	lea	rsi,[g_fs_path]
	rep	movsb
	mov	dword [rdx+FC_SET],1
	xor	eax,eax
	ret
.static:
	call	fs_close
	call	files_answer			; (not PHP's: as `files`)
	mov	eax,1
	ret
.missing:
	mov	edi,404
	call	http_error
	mov	eax,1
	ret
; the open file a regular one? Closed either way. CF: not.
.regular:
	mov	eax,dword [g_fs_stat+ST_MODE]
	and	eax,S_IFMT_
	push	rax
	call	fs_close
	pop	rax
	cmp	eax,S_IFREG_
	je	@f
	stc
	ret
@@:
	clc
	ret

; After http_write_request_head, HB_FCGI: the HTTP/1.1 head in OUT becomes
; FCGI_BEGIN_REQUEST, FCGI_PARAMS (then an empty one), and, with no body, an
; empty FCGI_STDIN. CF: it does not fit.
fcgi_head:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,[r15+H_BUF]
	lea	r14,[rbp+HB_FC]			; the state
	xor	eax,eax				; a new exchange on it
	mov	[r14+FC_PHASE],eax
	mov	[r14+FC_RXLEN],eax
	mov	[r14+FC_RXOFF],eax
	mov	[r14+FC_REC],eax
	mov	[r14+FC_PAD],eax
	mov	[r14+FC_HDRLEN],eax
	mov	[r14+FC_HBLEN],eax
	mov	[r14+FC_BODYEND],eax
	call	session_ptr			; (ebx the session, still)
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_PORT]
	mov	[r14+FC_PORT],eax
	lea	r12,[rbp+HB_OUT]		; the head
	mov	r13d,[r15+H_OUTLEN]
	add	r13,r12				; its end
	lea	rdi,[r14+FC_TX]
	; FCGI_BEGIN_REQUEST: id 1, the responder, the connection kept
	mov	rax,0x0000080000010101
	stosq
	mov	rax,0x0000000000010100
	stosq
	mov	rbx,rdi				; FCGI_PARAMS' header, its length after
	add	rdi,8
	; the request line: METHOD TARGET VERSION
	mov	rsi,r12
	call	.word
	jc	.bad
	push	rsi
	push	rcx
	mov	rdx,rsi
	mov	r8d,ecx
	lea	rsi,[.n_method]
	mov	ecx,14
	call	.pair
	pop	rcx
	pop	rsi
	lea	rsi,[rsi+rcx+1]
	call	.word
	jc	.bad
	mov	[r14+FC_T],rsi			; (the target, kept below the frame)
	mov	[r14+FC_TL],ecx
	mov	rdx,rsi
	mov	r8d,ecx
	lea	rsi,[.n_uri]
	mov	ecx,11
	call	.pair
	; the path and the query
	mov	rdx,[r14+FC_T]
	mov	ecx,[r14+FC_TL]
	xor	r8d,r8d
@@:
	cmp	r8d,ecx
	jae	@f
	cmp	byte [rdx+r8],'?'
	je	@f
	inc	r8d
	jmp	@b
@@:
	push	rdx
	push	rcx
	push	r8
	lea	rsi,[.n_docuri]
	mov	ecx,12
	call	.pair
	cmp	dword [r14+FC_SET],0
	jne	@f
	mov	rdx,[rsp+16]
	mov	r8,[rsp]
	lea	rsi,[.n_script]
	mov	ecx,11
	call	.pair
@@:
	pop	r8
	pop	rcx
	pop	rdx
	lea	rdx,[rdx+r8]			; the query: after ?
	sub	ecx,r8d
	jz	@f
	inc	rdx
	dec	ecx
@@:
	mov	r8d,ecx
	lea	rsi,[.n_query]
	mov	ecx,12
	call	.pair
	; the version
	mov	rsi,[r14+FC_T]
	mov	eax,[r14+FC_TL]
	add	rsi,rax
	inc	rsi
	mov	rdx,rsi
	xor	r8d,r8d
@@:
	cmp	byte [rdx+r8],13
	je	@f
	inc	r8d
	cmp	r8d,16
	jb	@b
	jmp	.bad
@@:
	lea	rsi,[.n_proto]
	mov	ecx,15
	call	.pair
	lea	rsi,[rdx+r8+2]			; the first field
	mov	r12,rsi
	; what okena says of itself
	lea	rsi,[.n_gw]
	mov	ecx,17
	lea	rdx,[.v_gw]
	mov	r8d,7
	call	.pair
	lea	rsi,[.n_sw]
	mov	ecx,15
	lea	rdx,[.v_sw]
	mov	r8d,5
	call	.pair
	lea	rsi,[.n_redirect]
	mov	ecx,15
	lea	rdx,[.v_200]
	mov	r8d,3
	call	.pair
	; SERVER_PORT: the listener's
	push	rdi
	mov	eax,[r14+FC_PORT]
	lea	rdi,[r14+FC_HEAD]		; (a scratch: the head comes later)
	call	fmt_u64
	lea	rdx,[r14+FC_HEAD]
	mov	r8,rdi
	sub	r8,rdx
	pop	rdi
	lea	rsi,[.n_port]
	mov	ecx,11
	call	.pair
	; the script, beneath the root (`php`)
	cmp	dword [r14+FC_SET],0
	je	.fields
	lea	rsi,[.n_script]
	mov	ecx,11
	lea	rdx,[r14+FC_SCRIPT]
	mov	r8d,[r14+FC_SLEN]
	call	.pair
	lea	rsi,[.n_docroot]
	mov	ecx,13
	mov	rdx,[r14+FC_ROOT]
	mov	r8d,[r14+FC_RLEN]
	call	.pair
	; SCRIPT_FILENAME: the root, then SCRIPT_NAME (a pair of two parts)
	mov	eax,[r14+FC_RLEN]
	add	eax,[r14+FC_SLEN]
	cmp	eax,127
	ja	@f
	mov	byte [rdi],15
	mov	[rdi+1],al
	add	rdi,2
	jmp	.sf_name
@@:
	mov	byte [rdi],15
	bswap	eax
	or	eax,0x80
	mov	[rdi+1],eax
	add	rdi,5
.sf_name:
	lea	rsi,[.n_filename]
	mov	ecx,15
	rep	movsb
	mov	rsi,[r14+FC_ROOT]
	mov	ecx,[r14+FC_RLEN]
	rep	movsb
	lea	rsi,[r14+FC_SCRIPT]
	mov	ecx,[r14+FC_SLEN]
	rep	movsb
	mov	r8d,[r14+FC_PLEN]
	test	r8d,r8d
	jz	.fields
	lea	rsi,[.n_pinfo]
	mov	ecx,9
	lea	rdx,[r14+FC_PINFO]
	call	.pair
.fields:
	; the fields: Content-Type and -Length as CGI has them, Host as SERVER_NAME
	; too, X-Forwarded-For's last address as REMOTE_ADDR, HTTPS from
	; X-Forwarded-Proto; the rest HTTP_NAME, but Proxy (httpoxy), and
	; Connection and Transfer-Encoding
.field:
	cmp	r12,r13
	jae	.bad
	cmp	word [r12],0x0A0D
	je	.fields_done
	mov	rsi,r12				; the name
	xor	ecx,ecx
@@:
	lea	rax,[rsi+rcx]
	cmp	rax,r13
	jae	.bad
	cmp	byte [rsi+rcx],':'
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	rdx,[rsi+rcx+1]			; the value, past blanks
@@:
	cmp	byte [rdx],' '
	jne	@f
	inc	rdx
	jmp	@b
@@:
	xor	r8d,r8d
@@:
	lea	rax,[rdx+r8]
	cmp	rax,r13
	jae	.bad
	cmp	byte [rdx+r8],13
	je	@f
	inc	r8d
	jmp	@b
@@:
	lea	r12,[rdx+r8+2]			; the next field
	push	r12
	call	.one_field
	pop	r12
	lea	rax,[r14+FC_TX+FC_TXCAP-512]
	cmp	rdi,rax
	ja	.bad
	jmp	.field
.fields_done:
	; FCGI_PARAMS' length, padded to 8; an empty one ends them
	mov	rax,rdi
	sub	rax,rbx
	sub	eax,8
	cmp	eax,65535
	ja	.bad
	mov	ecx,eax
	neg	ecx
	and	ecx,7				; padding
	mov	dword [rbx],0x00010401		; version 1, FCGI_PARAMS, id 1
	mov	edx,eax
	xchg	dl,dh
	mov	[rbx+4],dx
	mov	[rbx+6],cl
	mov	byte [rbx+7],0
	xor	eax,eax
	rep	stosb
	mov	rax,0x0000000000010401
	stosq
	cmp	dword [r15+H_BODY],BK_NONE
	jne	@f
	mov	rax,0x0000000000010501		; no body: FCGI_STDIN ends at once
	stosq
	mov	dword [r14+FC_BODYEND],1
@@:
	; into OUT, as the head to send
	lea	rsi,[r14+FC_TX]
	mov	rcx,rdi
	sub	rcx,rsi
	cmp	ecx,H_OUT_CAP
	ja	.bad
	mov	[r15+H_OUTLEN],ecx
	lea	rdi,[rbp+HB_OUT]
	rep	movsb
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi = a request line's word: rcx = its length (to a space). CF: none.
.word:
	xor	ecx,ecx
@@:
	lea	rax,[rsi+rcx]
	cmp	rax,r13
	jae	.word_bad
	cmp	byte [rsi+rcx],' '
	je	@f
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.word_bad
	clc
	ret
.word_bad:
	stc
	ret
; rsi/ecx = a name, rdx/r8d = a value: the pair at rdi (FastCGI's lengths: a
; byte below 128, else four with the high bit). Keeps rdx, r8 (the value's
; pointer moves no further).
.pair:
	cmp	ecx,127
	ja	.pair_long
	mov	[rdi],cl
	inc	rdi
	jmp	@f
.pair_long:
	mov	eax,ecx
	bswap	eax
	or	eax,0x80
	mov	[rdi],eax
	add	rdi,4
@@:
	cmp	r8d,127
	ja	@f
	mov	[rdi],r8b
	inc	rdi
	jmp	.pair_bytes
@@:
	mov	eax,r8d
	bswap	eax
	or	eax,0x80
	mov	[rdi],eax
	add	rdi,4
.pair_bytes:
	rep	movsb
	push	rdx
	mov	rsi,rdx
	mov	ecx,r8d
	rep	movsb
	pop	rdx
	ret
; rsi/ecx = a field's name, rdx/r8d = its value: its params
.one_field:
	mov	r9,rsi
	mov	r10d,ecx
	lea	rax,[.f_ctype]
	mov	r11d,12
	call	.is
	jne	@f
	lea	rsi,[.n_ctype]
	mov	ecx,12
	jmp	.pair
@@:
	lea	rax,[.f_clen]
	mov	r11d,14
	call	.is
	jne	@f
	lea	rsi,[.n_clen]
	mov	ecx,14
	jmp	.pair
@@:
	lea	rax,[.f_proxy]
	mov	r11d,5
	call	.is
	je	.skip
	lea	rax,[.f_conn]
	mov	r11d,10
	call	.is
	je	.skip
	lea	rax,[.f_te]
	mov	r11d,17
	call	.is
	je	.skip
	lea	rax,[.f_host]
	mov	r11d,4
	call	.is
	jne	.not_host
	push	rdx				; SERVER_NAME: the host without a port
	push	r8
	xor	ecx,ecx
@@:
	cmp	ecx,r8d
	jae	@f
	cmp	byte [rdx+rcx],':'
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	r8d,ecx
	lea	rsi,[.n_sname]
	mov	ecx,11
	call	.pair
	pop	r8
	pop	rdx
	jmp	.http
.not_host:
	lea	rax,[.f_xff]
	mov	r11d,15
	call	.is
	jne	.not_xff
	mov	ecx,r8d				; REMOTE_ADDR: its last address
@@:
	test	ecx,ecx
	jz	@f
	cmp	byte [rdx+rcx-1],' '
	je	@f
	cmp	byte [rdx+rcx-1],','
	je	@f
	dec	ecx
	jmp	@b
@@:
	push	rdx
	push	r8
	add	rdx,rcx
	sub	r8d,ecx
	lea	rsi,[.n_raddr]
	mov	ecx,11
	call	.pair
	pop	r8
	pop	rdx
	jmp	.http
.not_xff:
	lea	rax,[.f_xfp]
	mov	r11d,17
	call	.is
	jne	.http
	cmp	r8d,5
	jne	.http
	cmp	dword [rdx],'http'
	jne	.http
	cmp	byte [rdx+4],'s'
	jne	.http
	push	rdx
	push	r8
	lea	rsi,[.n_https]
	mov	ecx,5
	lea	rdx,[.v_on]
	mov	r8d,2
	call	.pair
	pop	r8
	pop	rdx
.http:
	; HTTP_ and the name, upper case, - as _
	lea	eax,[r10+5]
	cmp	eax,127
	ja	.skip
	mov	[rdi],al
	inc	rdi
	cmp	r8d,127
	ja	@f
	mov	[rdi],r8b
	inc	rdi
	jmp	.http_name
@@:
	mov	eax,r8d
	bswap	eax
	or	eax,0x80
	mov	[rdi],eax
	add	rdi,4
.http_name:
	mov	dword [rdi],'HTTP'
	mov	byte [rdi+4],'_'
	add	rdi,5
	xor	ecx,ecx
@@:
	cmp	ecx,r10d
	jae	@f
	movzx	eax,byte [r9+rcx]
	cmp	al,'-'
	jne	.up
	mov	al,'_'
	jmp	.put
.up:
	cmp	al,'a'
	jb	.put
	cmp	al,'z'
	ja	.put
	sub	al,32
.put:
	stosb
	inc	ecx
	jmp	@b
@@:
	mov	rsi,rdx
	mov	ecx,r8d
	rep	movsb
.skip:
	ret
; r9/r10d = a name, rax/r11d = one in lower case: ZF when the same, ignoring case
.is:
	cmp	r10d,r11d
	jne	.is_out
	push	rcx
	push	rdx
	xor	ecx,ecx
@@:
	cmp	ecx,r10d
	jae	.is_same
	movzx	edx,byte [r9+rcx]
	or	dl,0x20
	cmp	dl,[rax+rcx]
	jne	.is_diff
	inc	ecx
	jmp	@b
.is_same:
	pop	rdx
	pop	rcx
	xor	eax,eax				; (ZF)
	ret
.is_diff:
	pop	rdx
	pop	rcx
	or	eax,1				; (not ZF; eax is not 0: a pointer)
.is_out:
	ret
.n_method	db 'REQUEST_METHOD'
.n_uri		db 'REQUEST_URI'
.n_docuri	db 'DOCUMENT_URI'
.n_script	db 'SCRIPT_NAME'
.n_query	db 'QUERY_STRING'
.n_proto	db 'SERVER_PROTOCOL'
.n_gw		db 'GATEWAY_INTERFACE'
.v_gw		db 'CGI/1.1'
.n_sw		db 'SERVER_SOFTWARE'
.v_sw		db 'okena'
.n_redirect	db 'REDIRECT_STATUS'
.v_200		db '200'
.n_port		db 'SERVER_PORT'
.n_docroot	db 'DOCUMENT_ROOT'
.n_filename	db 'SCRIPT_FILENAME'
.n_pinfo	db 'PATH_INFO'
.n_ctype	db 'CONTENT_TYPE'
.n_clen		db 'CONTENT_LENGTH'
.n_sname	db 'SERVER_NAME'
.n_raddr	db 'REMOTE_ADDR'
.n_https	db 'HTTPS'
.v_on		db 'on'
.f_ctype	db 'content-type'
.f_clen		db 'content-length'
.f_proxy	db 'proxy'
.f_conn		db 'connection'
.f_te		db 'transfer-encoding'
.f_host		db 'host'
.f_xff		db 'x-forwarded-for'
.f_xfp		db 'x-forwarded-proto'

; h_send on the upstream side, HB_FCGI: the head as it is (records already);
; body bytes in FCGI_STDIN records. rdi = bytes, esi = length.
fcgi_send:
	h_rec
	cmp	dword [r15+H_STATE],HS_SEND_HEAD
	je	h_send_raw
	cmp	dword [r15+H_STATE],HS_FC_END
	je	h_send_raw
	mov	rax,[r15+H_BUF]
	lea	r8,[rax+HB_FC+FC_TX]
	cmp	esi,FC_TXCAP - 8
	jbe	@f
	mov	esi,FC_TXCAP - 8
@@:
	mov	dword [r8],0x00010501		; version 1, FCGI_STDIN, id 1
	mov	eax,esi
	xchg	al,ah
	mov	[r8+4],ax
	mov	word [r8+6],0
	push	rsi
	mov	rsi,rdi
	lea	rdi,[r8+8]
	mov	ecx,[rsp]
	rep	movsb
	pop	rsi
	add	esi,8
	mov	rdi,r8
	mov	ecx,SIDE_UP
	jmp	h_send_raw

; In http_start_response, HB_FCGI: the empty FCGI_STDIN that ends a body, once.
; CF: sent (back in http_start_response when it is out).
fcgi_body_end:
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_FC+FC_BODYEND],0
	jne	.no
	mov	dword [rax+HB_FC+FC_BODYEND],1
	lea	rdi,[rax+HB_FC+FC_TX]
	mov	qword [rdi],0x0000000000010501
	mov	dword [r15+H_STATE],HS_FC_END
	mov	esi,8
	mov	ecx,SIDE_UP
	add	rsp,8				; (not back: the send's completion goes on)
	jmp	h_send_raw
.no:
	clc
	ret

; ------------------------------------------------------------- the answer

; h_recv on the upstream side, HB_FCGI: rdi = room for the answer, esi = how much.
fcgi_recv:
	h_rec
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_FC+FC_DST],rdi
	mov	[rax+HB_FC+FC_ROOM],esi
fcgi_step:
	h_rec
	call	fcgi_decode
	jc	.bad
	test	eax,eax
	jnz	.deliver
	mov	rdx,[r15+H_BUF]
	lea	rdx,[rdx+HB_FC]
	cmp	dword [rdx+FC_PHASE],3
	je	.deliver			; (0: the end)
	; more from the backend: what is left to the front, then a read
	mov	ecx,[rdx+FC_RXLEN]
	mov	eax,[rdx+FC_RXOFF]
	sub	ecx,eax
	mov	[rdx+FC_RXLEN],ecx
	mov	dword [rdx+FC_RXOFF],0
	lea	rsi,[rdx+FC_RX+rax]
	lea	rdi,[rdx+FC_RX]
	rep	movsb
	mov	esi,FC_RXCAP
	sub	esi,[rdx+FC_RXLEN]
	jz	.bad
	mov	edi,[rdx+FC_RXLEN]
	lea	rdi,[rdx+FC_RX+rdi]
	mov	ecx,SIDE_UP
	jmp	h_recv_raw
.bad:
	mov	rax,-1
.deliver:
	mov	edx,3				; (http_recv_plain: decoded)
	mov	ecx,SIDE_UP
	jmp	hep_queue

; records arrived (http_recv_done on the upstream side, H_FCGI): rax = bytes
fcgi_rx_done:
	test	rax,rax
	jle	.end
	mov	rdx,[r15+H_BUF]
	add	[rdx+HB_FC+FC_RXLEN],eax
	mov	edi,ebx
	call	idle_touch
	jmp	fcgi_step
.end:
	mov	edx,3				; the backend left (before its end: the
	mov	ecx,SIDE_UP			; answer is cut, and the parser says so)
	jmp	hep_queue

; FC_RX's records into HTTP/1.1 at FC_DST (FC_ROOM): eax = bytes written. CF: not
; FastCGI as it should be.
fcgi_decode:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r14,[r15+H_BUF]
	lea	r14,[r14+HB_FC]
	mov	r12,[r14+FC_DST]		; out
	mov	r13d,[r14+FC_ROOM]
	add	r13,r12				; its end
.loop:
	cmp	dword [r14+FC_PHASE],3
	je	.done
	; body bytes that came with the head first
	cmp	dword [r14+FC_HBLEN],0
	je	.records
	mov	eax,[r14+FC_HB]
	lea	rsi,[r14+FC_HEAD+rax]
	mov	ecx,[r14+FC_HBLEN]
	call	.chunk
	jc	.done
	add	[r14+FC_HB],ecx
	sub	[r14+FC_HBLEN],ecx
	jmp	.loop
.records:
	mov	eax,[r14+FC_REC]
	or	eax,[r14+FC_PAD]
	jnz	.content
	; a record's header
	mov	eax,[r14+FC_RXOFF]
	mov	ecx,[r14+FC_RXLEN]
	sub	ecx,eax
	cmp	ecx,8
	jb	.done
	lea	rsi,[r14+FC_RX+rax]
	cmp	byte [rsi],1
	jne	.bad
	movzx	ecx,byte [rsi+1]
	mov	[r14+FC_TYPE],ecx
	movzx	ecx,word [rsi+4]
	xchg	cl,ch
	mov	[r14+FC_REC],ecx
	movzx	ecx,byte [rsi+6]
	mov	[r14+FC_PAD],ecx
	add	dword [r14+FC_RXOFF],8
	cmp	dword [r14+FC_TYPE],FCGI_END
	jne	.content
	cmp	dword [r14+FC_PHASE],0
	je	.bad				; the end, and no head
.content:
	mov	eax,[r14+FC_RXOFF]
	mov	ecx,[r14+FC_RXLEN]
	sub	ecx,eax
	lea	rsi,[r14+FC_RX+rax]
	mov	edx,[r14+FC_REC]
	cmp	ecx,edx
	cmova	ecx,edx				; what of it is here
	test	edx,edx
	jz	.padding
	test	ecx,ecx
	jz	.done
	cmp	dword [r14+FC_TYPE],FCGI_STDOUT
	je	.stdout
	cmp	dword [r14+FC_TYPE],FCGI_STDERR
	jne	.consume
	call	.stderr
	jmp	.consume
.stdout:
	cmp	dword [r14+FC_PHASE],0
	jne	.body
	call	.head
	jc	.bad
	jmp	.consume
.body:
	call	.chunk
	jc	.done
.consume:
	add	[r14+FC_RXOFF],ecx
	sub	[r14+FC_REC],ecx
	cmp	dword [r14+FC_REC],0
	jne	.loop
.padding:
	mov	eax,[r14+FC_RXOFF]		; the padding, as much as is here
	mov	ecx,[r14+FC_RXLEN]
	sub	ecx,eax
	mov	edx,[r14+FC_PAD]
	cmp	ecx,edx
	cmova	ecx,edx
	add	[r14+FC_RXOFF],ecx
	sub	[r14+FC_PAD],ecx
	cmp	dword [r14+FC_PAD],0
	jne	.done
	cmp	dword [r14+FC_TYPE],FCGI_END
	jne	.loop
	; FCGI_END_REQUEST: the last chunk
	cmp	dword [r14+FC_CHUNK],0
	je	.ended
	lea	rax,[r12+5]
	cmp	rax,r13
	ja	.done
	mov	byte [r12],'0'			; 0 CRLF CRLF
	mov	dword [r12+1],0x0A0D0A0D
	add	r12,5
.ended:
	mov	dword [r14+FC_PHASE],3
.done:
	mov	rax,r12
	sub	rax,[r14+FC_DST]
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
; rsi/ecx = body bytes: one chunk of them at r12 (as many as fit; ecx then those
; taken). CF: no room for any. With no body (FC_CHUNK 0): taken, dropped.
.chunk:
	cmp	dword [r14+FC_CHUNK],0
	je	.chunk_ok
	mov	rax,r13
	sub	rax,r12
	sub	rax,12
	jle	.chunk_none
	cmp	rcx,rax
	jbe	@f
	mov	ecx,eax
@@:
	push	rcx
	mov	eax,ecx				; its size, in hex: how many digits
	xor	edx,edx
@@:
	inc	edx
	shr	eax,4
	jnz	@b
	lea	r9,[r12+rdx]			; (the digits' end)
	mov	rdi,r9				; written from the last
	mov	eax,ecx
@@:
	dec	rdi
	mov	r8d,eax
	and	r8d,15
	mov	r8b,[hex_digits+r8]
	mov	[rdi],r8b
	shr	eax,4
	dec	edx
	jnz	@b
	mov	rdi,r9
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	ecx,[rsp]
	push	rsi
	rep	movsb
	pop	rsi
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	r12,rdi
	pop	rcx
.chunk_ok:
	clc
	ret
.chunk_none:
	stc
	ret
; rsi/ecx = FCGI_STDERR bytes: the log has (the first line of) them
.stderr:
	push	rcx
	push	rsi
	call	log_begin
	out_lit 'fastcgi: '
	mov	rsi,[rsp]
	mov	edx,[rsp+8]
	xor	ecx,ecx
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rsi+rcx],10
	je	@f
	cmp	ecx,200
	jae	@f
	inc	ecx
	jmp	@b
@@:
	mov	edx,ecx
	call	out_str
	call	log_end
	pop	rsi
	pop	rcx
	ret
; rsi/ecx = FCGI_STDOUT bytes of the CGI head: into FC_HEAD; once it ends (an
; empty line), the HTTP/1.1 head at r12 and the rest kept as body. CF: a head
; too long, or no room for it.
.head:
	mov	eax,[r14+FC_HDRLEN]		; what fits (the rest, after the head, is
	mov	edx,FC_HEADMAX			; body: taken as such once it ends)
	sub	edx,eax
	jz	.head_full
	cmp	ecx,edx
	cmova	ecx,edx
	push	rcx
	lea	edx,[rax+rcx]
	lea	rdi,[r14+FC_HEAD+rax]
	rep	movsb
	mov	[r14+FC_HDRLEN],edx
	; its end: \r\n\r\n, or \n\n
	xor	ecx,ecx
.hend:
	lea	eax,[rcx+1]
	cmp	eax,edx
	jae	.head_more
	cmp	byte [r14+FC_HEAD+rcx],10
	jne	.hend_next
	cmp	byte [r14+FC_HEAD+rcx+1],10
	je	.hend_lf
	lea	eax,[rcx+2]
	cmp	eax,edx
	jae	.hend_next
	cmp	word [r14+FC_HEAD+rcx+1],0x0A0D
	jne	.hend_next
	lea	eax,[rcx+3]
	jmp	.hend_found
.hend_lf:
	lea	eax,[rcx+2]
	jmp	.hend_found
.hend_next:
	inc	ecx
	jmp	.hend
.hend_found:
	; eax = where the body starts
	mov	[r14+FC_HB],eax
	sub	edx,eax
	mov	[r14+FC_HBLEN],edx
	call	fcgi_head_out
	jc	.head_bad
	mov	dword [r14+FC_PHASE],1
.head_more:
	pop	rcx
	clc
	ret
.head_bad:
	pop	rcx
.head_full:
	stc
	ret

; In fcgi_decode: FC_HEAD's head (to FC_HB) as an HTTP/1.1 head at r12 (r13 its
; end); r12 past it, FC_CHUNK. CF: no room.
fcgi_head_out:
	push	rbx
	push	rbp
	mov	rdi,r12
	lea	rax,[rdi+256]
	cmp	rax,r13
	ja	.full
	; the status: Status:, else 302 with a Location:, else 200
	mov	ebp,200				; the code
	xor	ebx,ebx				; its reason (0: ours)
	xor	r9d,r9d				; the reason's length
	lea	rsi,[r14+FC_HEAD]
	mov	r10d,[r14+FC_HB]
	add	r10,rsi				; the head's end
	xor	r11d,r11d			; a Location:
.line:
	cmp	rsi,r10
	jae	.status
	mov	rdx,rsi				; the line, to \n
@@:
	cmp	rdx,r10
	jae	@f
	cmp	byte [rdx],10
	je	@f
	inc	rdx
	jmp	@b
@@:
	mov	rcx,rdx
	sub	rcx,rsi
	cmp	rcx,7
	jb	.next_line
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'stat'
	jne	.not_status
	mov	eax,[rsi+4]
	or	eax,0x2020
	and	eax,0xFFFFFF
	cmp	eax,'us:'
	jne	.not_status
	lea	r8,[rsi+7]
@@:
	cmp	byte [r8],' '
	jne	@f
	inc	r8
	jmp	@b
@@:
	movzx	eax,byte [r8]			; three digits
	sub	eax,'0'
	cmp	eax,9
	ja	.next_line
	imul	ebp,eax,100
	movzx	eax,byte [r8+1]
	sub	eax,'0'
	cmp	eax,9
	ja	.next_line
	imul	eax,eax,10
	add	ebp,eax
	movzx	eax,byte [r8+2]
	sub	eax,'0'
	cmp	eax,9
	ja	.next_line
	add	ebp,eax
	lea	rbx,[r8+3]			; the reason
@@:
	cmp	byte [rbx],' '
	jne	@f
	inc	rbx
	jmp	@b
@@:
	mov	r9,rdx
	sub	r9,rbx
	jle	.no_reason
	cmp	byte [rbx+r9-1],13
	jne	.next_line
	dec	r9
	jnz	.next_line
.no_reason:
	xor	ebx,ebx
	xor	r9d,r9d
	jmp	.next_line
.not_status:
	cmp	rcx,9
	jb	.next_line
	mov	rax,[rsi]
	mov	r8,0x2020202020202020
	or	rax,r8
	mov	r8,'location'
	cmp	rax,r8
	jne	.next_line
	cmp	byte [rsi+8],':'
	jne	.next_line
	mov	r11d,1
.next_line:
	lea	rsi,[rdx+1]
	jmp	.line
.status:
	cmp	ebp,200
	jne	@f
	test	ebx,ebx
	jnz	@f
	test	r11d,r11d
	jz	@f
	mov	ebp,302				; a Location: alone
@@:
	mov	dword [rdi],'HTTP'
	mov	dword [rdi+4],'/1.1'
	mov	byte [rdi+8],' '
	add	rdi,9
	mov	eax,ebp
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	test	ebx,ebx
	jz	.our_reason
	cmp	r9d,64
	jbe	@f
	mov	r9d,64
@@:
	mov	rsi,rbx
	mov	ecx,r9d
	rep	movsb
	jmp	.reason_done
.our_reason:
	mov	eax,ebp
	call	http_reason
	call	fmt_cstr
.reason_done:
	mov	word [rdi],0x0A0D
	add	rdi,2
	; the fields, but Status:, and the framing (ours)
	lea	rsi,[r14+FC_HEAD]
.field:
	cmp	rsi,r10
	jae	.fields_done
	mov	rdx,rsi
@@:
	cmp	rdx,r10
	jae	@f
	cmp	byte [rdx],10
	je	@f
	inc	rdx
	jmp	@b
@@:
	mov	rcx,rdx
	sub	rcx,rsi
	jz	.fnext
	cmp	byte [rsi+rcx-1],13
	jne	@f
	dec	rcx
	jz	.fnext
@@:
	call	.skipped
	jz	.fnext
	lea	rax,[rdi+rcx+2+64]
	cmp	rax,r13
	ja	.full
	push	rsi
	rep	movsb
	pop	rsi
	mov	word [rdi],0x0A0D
	add	rdi,2
.fnext:
	lea	rsi,[rdx+1]
	jmp	.field
.fields_done:
	; a body, in chunks: not for HEAD, 1xx, 204, 304
	mov	dword [r14+FC_CHUNK],0
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.end
	cmp	ebp,200
	jb	.end
	cmp	ebp,204
	je	.end
	cmp	ebp,304
	je	.end
	mov	dword [r14+FC_CHUNK],1
	lea	rsi,[.te]
	mov	ecx,.te_len
	rep	movsb
.end:
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	r12,rdi
	clc
	pop	rbp
	pop	rbx
	ret
.full:
	stc
	pop	rbp
	pop	rbx
	ret
; rsi/rcx = a field line: ZF when it is not passed on (Status, Content-Length,
; Transfer-Encoding, Connection)
.skipped:
	push	rcx
	push	rdx
	lea	rax,[.s_status]
	mov	edx,7
	call	.prefix
	jz	.sk_out
	lea	rax,[.s_clen]
	mov	edx,15
	call	.prefix
	jz	.sk_out
	lea	rax,[.s_te]
	mov	edx,18
	call	.prefix
	jz	.sk_out
	lea	rax,[.s_conn]
	mov	edx,11
	call	.prefix
.sk_out:
	pop	rdx
	pop	rcx
	ret
; rsi/rcx a line, rax/edx a lower-case prefix: ZF when the line starts with it
.prefix:
	cmp	ecx,edx
	jb	.pre_no
	push	rcx
	xor	ecx,ecx
@@:
	cmp	ecx,edx
	jae	.pre_yes
	movzx	r8d,byte [rsi+rcx]
	or	r8b,0x20
	cmp	r8b,[rax+rcx]
	jne	.pre_no_pop
	inc	ecx
	jmp	@b
.pre_yes:
	pop	rcx
	xor	r8d,r8d				; (ZF)
	ret
.pre_no_pop:
	pop	rcx
.pre_no:
	or	r8d,1
	ret
.te		db 'Transfer-Encoding: chunked',13,10
.te_len := $ - .te
.s_status	db 'status:'
.s_clen		db 'content-length:'
.s_te		db 'transfer-encoding:'
.s_conn		db 'connection:'

; route `php ROOT [index=index.php]`, rbx = the node, r12 = the route's action:
; a files entry (compile_files) whose index is index.php, marked FI_PHP
compile_php:
	call	compile_files
	mov	eax,[r12+RA_FILES]
	dec	eax
	imul	rax,rax,FI_SIZE
	lea	rcx,[g_files+rax]
	mov	dword [rcx+FI_PHP],1
	mov	rdi,rbx
	lea	rsi,[compile_files.k_index]
	push	rcx
	call	node_option
	pop	rcx
	test	rax,rax
	jnz	@f
	lea	rax,[.index_php]
	mov	[rcx+FI_INDEX],rax
	mov	dword [rcx+FI_ILEN],9
@@:
	ret
.index_php	db 'index.php'
