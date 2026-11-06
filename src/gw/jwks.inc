; `jwks https://idp/.well-known/jwks.json trust=CA.pem refresh=10m stale=24h`: a
; JWK set by URL.
;
; A process of its own, okena-keys, fetches each set and publishes it in a shared
; table under a sequence counter, as the control process does with addresses;
; workers copy a set on their tick when it changed, and forget every verified
; token then, so that a key taken out stops working at once. It is not the control
; process because a slow identity provider must not hold up DNS, and because this
; is where bytes from the network get parsed: confined as the control process is.
;
; What it trusts: TLS 1.3 to the name in the URL, a chain up to `trust`, in its
; validity window. There is no way to turn that off: these are the keys that say
; who a client is. `http://` is for localhost only. Redirects are not followed.
;
; What it does when things go wrong: a failed fetch, a bad body or a set with no
; key usable here changes nothing, and the last good keys hold for `stale` after
; the last good fetch; then they go, and tokens are refused. A reload keeps them
; for the URLs that stay. An unknown `kid` asks for a fetch, JF_GAP seconds apart at
; most, so that tokens cannot be used to flood the provider. Shared secrets (`oct`)
; are left out of a set by URL: whoever can read it could sign.

MAX_JWKS	:= 8
JK_PER_SET	:= 32
JF_GAP		:= 10				; seconds between fetches a token asked for
JF_RETRY	:= 30				; after a failure, unless refresh is sooner
JF_DEADLINE	:= 10				; seconds, a whole fetch
JF_IO_SEC	:= 3				; a connect, a read
JF_MAX		:= 1 shl 18			; a response, on the wire
JF_WAIT_MS	:= 3000				; at start, for the first keys
JF_WAIT_STEP	:= 50

; a source (plan)
JS_HOST		:= 0				; q
JS_PATH		:= 8				; q
JS_HLEN		:= 16				; d
JS_PLEN		:= 20				; d
JS_PORT		:= 24				; d
JS_TLS		:= 28				; d
JS_REFRESH	:= 32				; d: seconds
JS_STALE	:= 36				; d: seconds
JS_URL		:= 40				; q: for the log
JS_ULEN		:= 48				; d
JS_HASH		:= 52				; 32: which set this is, across a reload
JS_ANCHOR	:= 88				; the trust anchor's public key
JS_SIZE		:= JS_ANCHOR + PK_SIZE

; a set (shared)
KT_SEQ		:= 0				; q: odd while being written
KT_AT		:= 8				; q: wall clock of the last good fetch
KT_N		:= 16				; d
KT_WANT		:= 20				; d: a token named a key not here
KT_HASH		:= 24				; 32
KT_KEYS		:= 64
KT_SIZE		:= KT_KEYS + JK_PER_SET * JK_SIZE
KT_TOTAL	:= MAX_JWKS * KT_SIZE

JW_OK		:= 0
JW_NAME		:= 1
JW_CONNECT	:= 2
JW_TLS		:= 3
JW_CERT		:= 4
JW_READ		:= 5
JW_STATUS	:= 6
JW_BODY		:= 7

bss
	align 8
	g_jwks_tbl	dq ?			; shared
	g_keys_pid	dd ?
	g_plan_jsrc	dd ?
	g_jsrc:		rb JS_SIZE * MAX_JWKS
	; a worker's copy
	g_jl_seq	rq MAX_JWKS
	g_jl_n		rd MAX_JWKS
	g_jl_keys:	rb MAX_JWKS * JK_PER_SET * JK_SIZE
	; okena-keys
	g_jf_sp		dq ?			; the JWK parser's way out
	g_jf_end	dq ?			; monotonic second a fetch ends
	g_jf_due	rq MAX_JWKS
	g_jf_last	rq MAX_JWKS
	g_jf_status	rd MAX_JWKS
	g_jf_notify	dd ?			; 1: close_notify seen
	g_jf_rawn	dd ?
	g_jf_bodyn	dd ?
	g_jf_fd		dd ?
	g_jf_au:	rb AU_SIZE
	g_jf_hout:	rb 4096
	g_jf_req:	rb 4096
	g_jf_time:	rb 64
	g_jf_tc:	rb TC_FULL
	g_jf_snap:	rb SHA256_CTX_SIZE
	g_jf_new:	rb JK_PER_SET * JK_SIZE
	g_jf_hin:	rb JF_MAX
	g_jf_hdec:	rb JF_MAX
	g_jf_raw:	rb JF_MAX
	g_jf_body:	rb JF_MAX
end bss

rodata
	align 8
	ts_jf_step	dq 0, JF_WAIT_STEP * 1000000
	jf_name		db 'okena-keys',0
	jf_iotv		dq JF_IO_SEC, 0
end rodata

; ----------------------------------------------------- the plan

; rax = the `jwks` node (its first value is a URL), r12 = the auth. CF never:
; a bad one ends the compile.
jwks_source:
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	r15,rax				; the node
	mov	rax,[rax+N_ARGS]
	mov	r13,[rax+A_VAL]
	mov	r14d,[rax+A_VLEN]
	mov	eax,[g_plan_jsrc]
	cmp	eax,MAX_JWKS
	jae	plan_bad_jwks
	imul	rax,rax,JS_SIZE
	lea	rbx,[g_jsrc+rax]
	mov	rdi,rbx
	mov	ecx,JS_SIZE
	xor	eax,eax
	rep	stosb
	mov	[rbx+JS_URL],r13
	mov	[rbx+JS_ULEN],r14d
	; scheme
	mov	rsi,r13
	lea	rdx,[r13+r14]
	cmp	r14d,8
	jb	plan_bad_jwks
	cmp	dword [rsi+4],'s://'
	jne	.plain
	cmp	dword [rsi],'http'
	jne	plan_bad_jwks
	mov	dword [rbx+JS_TLS],1
	mov	dword [rbx+JS_PORT],443
	add	rsi,8
	jmp	.host
.plain:
	cmp	dword [rsi],'http'
	jne	plan_bad_jwks
	cmp	word [rsi+4],':/'
	jne	plan_bad_jwks
	cmp	byte [rsi+6],'/'
	jne	plan_bad_jwks
	mov	dword [rbx+JS_PORT],80
	add	rsi,7
.host:
	mov	[rbx+JS_HOST],rsi
.h:
	cmp	rsi,rdx
	jae	.h_end
	mov	al,[rsi]
	cmp	al,'/'
	je	.h_end
	cmp	al,':'
	je	.h_end
	cmp	al,' '
	jbe	plan_bad_jwks
	inc	rsi
	jmp	.h
.h_end:
	mov	rax,rsi
	sub	rax,[rbx+JS_HOST]
	jz	plan_bad_jwks
	cmp	rax,255
	ja	plan_bad_jwks
	mov	[rbx+JS_HLEN],eax
	cmp	rsi,rdx
	jae	plan_bad_jwks			; (a path is needed)
	cmp	byte [rsi],':'
	jne	.path
	inc	rsi
	xor	eax,eax
.p:
	cmp	rsi,rdx
	jae	plan_bad_jwks
	movzx	ecx,byte [rsi]
	cmp	cl,'/'
	je	.p_end
	sub	ecx,'0'
	cmp	ecx,9
	ja	plan_bad_jwks
	imul	eax,eax,10
	add	eax,ecx
	cmp	eax,65535
	ja	plan_bad_jwks
	inc	rsi
	jmp	.p
.p_end:
	test	eax,eax
	jz	plan_bad_jwks
	mov	[rbx+JS_PORT],eax
.path:
	mov	[rbx+JS_PATH],rsi
	mov	rcx,rdx
	sub	rcx,rsi
	cmp	ecx,2048
	ja	plan_bad_jwks
	mov	[rbx+JS_PLEN],ecx
.pc:
	cmp	rsi,rdx
	jae	.url_done
	cmp	byte [rsi],' '
	jbe	plan_bad_jwks
	cmp	byte [rsi],0x7f
	jae	plan_bad_jwks
	inc	rsi
	jmp	.pc
.url_done:
	; what it trusts
	mov	rdi,r15
	lea	rsi,[str_key_trust]
	call	node_option
	cmp	dword [rbx+JS_TLS],0
	jne	.tls
	test	rax,rax
	jnz	plan_bad_jwks
	mov	rdi,[rbx+JS_HOST]		; plain: this machine only
	mov	ecx,[rbx+JS_HLEN]
	cmp	ecx,9
	jne	@f
	cmp	dword [rdi],'loca'
	jne	plan_bad_jwks
	cmp	dword [rdi+4],'lhos'
	jne	plan_bad_jwks
	cmp	byte [rdi+8],'t'
	jne	plan_bad_jwks
	jmp	.times
@@:
	cmp	ecx,10
	jne	plan_bad_jwks
	cmp	dword [rdi],'127.'
	jne	plan_bad_jwks
	cmp	dword [rdi+4],'0.0.'
	jne	plan_bad_jwks
	jmp	.times
.tls:
	test	rax,rax
	jz	plan_bad_jwks
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_jwks
	mov	rsi,[rax+A_VAL]
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_jwks
	mov	rsi,rax
	mov	edx,edx
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_bad_jwks
	lea	rsi,[g_trust_der]
	mov	edx,eax
	lea	rdi,[rbx+JS_ANCHOR]
	call	cert_pubkey
	test	eax,eax
	jz	plan_bad_jwks
.times:
	mov	dword [rbx+JS_REFRESH],600
	mov	dword [rbx+JS_STALE],86400
	mov	rdi,r15
	lea	rsi,[.k_refresh]
	lea	rcx,[rbx+JS_REFRESH]
	call	.seconds
	mov	rdi,r15
	lea	rsi,[.k_stale]
	lea	rcx,[rbx+JS_STALE]
	call	.seconds
	; the same URL and anchor elsewhere: the same set
	lea	rdi,[rbx+JS_HASH]
	mov	rsi,r13
	mov	edx,r14d
	call	sha256
	lea	rdi,[g_jw_k]
	lea	rsi,[rbx+JS_ANCHOR]
	mov	edx,PK_SIZE
	call	sha256
	mov	ecx,4
	lea	rsi,[g_jw_k]
	lea	rdi,[rbx+JS_HASH]
@@:
	mov	rax,[rsi]
	xor	[rdi],rax
	add	rsi,8
	add	rdi,8
	dec	ecx
	jnz	@b
	xor	ecx,ecx
	lea	rdi,[g_jsrc]
.same:
	cmp	ecx,[g_plan_jsrc]
	jae	.new
	lea	rsi,[rdi+JS_HASH]
	lea	r8,[rbx+JS_HASH]
	mov	rax,[rsi]
	cmp	rax,[r8]
	jne	.other
	mov	rax,[rsi+8]
	cmp	rax,[r8+8]
	jne	.other
	mov	rax,[rsi+16]
	cmp	rax,[r8+16]
	jne	.other
	mov	rax,[rsi+24]
	cmp	rax,[r8+24]
	je	.found
.other:
	add	rdi,JS_SIZE
	inc	ecx
	jmp	.same
.new:
	inc	dword [g_plan_jsrc]
.found:
	inc	ecx
	mov	[r12+AU_JSRC],ecx
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
; rdi = node, rsi = option, rcx = where its seconds go
.seconds:
	push	rcx
	call	node_option
	pop	rcx
	test	rax,rax
	jz	.sec_out
	push	rcx
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	pop	rcx
	jc	plan_bad_jwks
	xor	edx,edx
	mov	r8d,1000000
	div	r8
	test	rax,rax
	jz	plan_bad_jwks
	cmp	rax,1 shl 30
	ja	plan_bad_jwks
	mov	[rcx],eax
.sec_out:
	ret
cstring .k_refresh, 'refresh',0
cstring .k_stale, 'stale',0

plan_bad_jwks:
	call	log_begin
	out_lit 'auth jwt: a jwks URL is https://HOST[:PORT]/PATH trust=FILE, or http:// on localhost; refresh= and stale= are times; at most 8 sets'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ----------------------------------------------------- the table

; Before workers are started. The sets of the URLs that stay come along, so that
; a reload while the provider is down loses no key.
jwks_table_init:
	push	rbx
	push	r12
	xor	edi,edi
	mov	esi,KT_TOTAL
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	r12,[g_jwks_tbl]		; (the old workers keep theirs)
	mov	[g_jwks_tbl],rax
	mov	r8,rax
	test	r12,r12
	jz	.out
	xor	ebx,ebx
.src:
	cmp	ebx,[g_plan_jsrc]
	jae	.out
	imul	rax,rbx,JS_SIZE
	lea	rax,[g_jsrc+rax+JS_HASH]
	xor	ecx,ecx
	mov	rdx,r12
.old:
	cmp	ecx,MAX_JWKS
	jae	.next
	cmp	dword [rdx+KT_N],0
	je	.old_next
	mov	rsi,[rax]
	cmp	rsi,[rdx+KT_HASH]
	jne	.old_next
	mov	rsi,[rax+8]
	cmp	rsi,[rdx+KT_HASH+8]
	jne	.old_next
	mov	rsi,[rax+16]
	cmp	rsi,[rdx+KT_HASH+16]
	jne	.old_next
	mov	rsi,[rax+24]
	cmp	rsi,[rdx+KT_HASH+24]
	jne	.old_next
	imul	rdi,rbx,KT_SIZE
	add	rdi,r8
	mov	rsi,rdx
	mov	ecx,KT_SIZE
	rep	movsb
	imul	rdi,rbx,KT_SIZE
	add	rdi,r8
	mov	qword [rdi+KT_SEQ],2
	mov	dword [rdi+KT_WANT],0
	jmp	.next
.old_next:
	add	rdx,KT_SIZE
	inc	ecx
	jmp	.old
.next:
	inc	ebx
	jmp	.src
.out:
	pop	r12
	pop	rbx
	ret

spawn_keys:
	cmp	dword [g_plan_jsrc],0
	je	.none
	; the table says which set each entry is
	xor	ecx,ecx
.hash:
	imul	rax,rcx,JS_SIZE
	lea	rsi,[g_jsrc+rax+JS_HASH]
	imul	rdi,rcx,KT_SIZE
	add	rdi,[g_jwks_tbl]
	add	rdi,KT_HASH
	mov	edx,ecx
	mov	ecx,32
	rep	movsb
	mov	ecx,edx
	inc	ecx
	cmp	ecx,[g_plan_jsrc]
	jb	.hash
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	keys_main
	js	.none
	mov	[g_keys_pid],eax
.none:
	ret

; Until each set is in, or JF_WAIT_MS: the first requests find their keys.
jwks_wait:
	push	rbx
	mov	ebx,JF_WAIT_MS / JF_WAIT_STEP
.again:
	xor	ecx,ecx
	mov	rax,[g_jwks_tbl]
.src:
	cmp	ecx,[g_plan_jsrc]
	jae	.out
	cmp	dword [rax+KT_N],0
	je	.wait
	add	rax,KT_SIZE
	inc	ecx
	jmp	.src
.wait:
	dec	ebx
	js	.out
	lea	rdi,[ts_jf_step]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.again
.out:
	pop	rbx
	ret

; A worker, on its tick: the sets that changed, and the ones gone stale. Keeps all
; it is called from (rsi, rdi and such are free).
jwks_tick:
	cmp	dword [g_plan_jsrc],0
	je	.none
	push	rbx
	push	r12
	push	r13
	xor	ebx,ebx
.src:
	cmp	ebx,[g_plan_jsrc]
	jae	.out
	imul	r12,rbx,KT_SIZE
	add	r12,[g_jwks_tbl]
	mov	rax,[r12+KT_SEQ]
	test	al,1
	jnz	.age
	cmp	rax,[g_jl_seq+rbx*8]
	je	.age
	mov	r13,rax
	imul	rdi,rbx,JK_PER_SET * JK_SIZE
	lea	rdi,[g_jl_keys+rdi]
	lea	rsi,[r12+KT_KEYS]
	mov	ecx,JK_PER_SET * JK_SIZE
	rep	movsb
	mov	ecx,[r12+KT_N]
	cmp	r13,[r12+KT_SEQ]
	jne	.age				; written meanwhile: next tick
	mov	[g_jl_seq+rbx*8],r13
	mov	[g_jl_n+rbx*4],ecx
	call	.forget
.age:
	; (KT_AT is a single write: it moves with each good fetch, the keys only
	; when they differ)
	cmp	dword [g_jl_n+rbx*4],0
	je	.next
	imul	rax,rbx,JS_SIZE
	mov	eax,[g_jsrc+rax+JS_STALE]
	add	rax,[r12+KT_AT]
	cmp	rax,[g_jwt_now]
	jae	.next
	mov	dword [g_jl_n+rbx*4],0
	call	.forget
.next:
	inc	ebx
	jmp	.src
.out:
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
.forget:
	lea	rdi,[g_jc]
	mov	ecx,JC_N * JC_SIZE
	xor	eax,eax
	rep	stosb
	ret

; ----------------------------------------------------- okena-keys

; Never returns.
keys_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	mov	edi,EXIT_OK
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[jf_name]
	mov	eax,SYS_prctl
	syscall
	seccomp_for filter_control		; its needs are the same: DNS, a socket
.loop:
	xor	ebx,ebx
.src:
	cmp	ebx,[g_plan_jsrc]
	jae	.sleep
	call	monotonic_seconds
	mov	r12,rax
	cmp	rax,[g_jf_due+rbx*8]
	jae	.fetch
	imul	rax,rbx,KT_SIZE
	add	rax,[g_jwks_tbl]
	cmp	dword [rax+KT_WANT],0
	je	.next
	mov	rax,[g_jf_last+rbx*8]
	add	rax,JF_GAP
	cmp	r12,rax
	jb	.next
.fetch:
	imul	rax,rbx,KT_SIZE
	add	rax,[g_jwks_tbl]
	mov	dword [rax+KT_WANT],0
	mov	[g_jf_last+rbx*8],r12
	call	keys_refresh
	call	monotonic_seconds
	add	rax,r12				; (keys_refresh: seconds to the next)
	mov	[g_jf_due+rbx*8],rax
.next:
	inc	ebx
	jmp	.src
.sleep:
	lea	rdi,[ts_control_poll]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.loop

; ebx = the source: fetch it and publish what came. r12 = seconds to the next.
keys_refresh:
	push	r13
	push	r14
	imul	r13,rbx,JS_SIZE
	lea	r13,[g_jsrc+r13]
	imul	r14,rbx,KT_SIZE
	add	r14,[g_jwks_tbl]
	call	monotonic_seconds
	add	rax,JF_DEADLINE
	mov	[g_jf_end],rax
	mov	dword [g_jf_fd],-1
	call	jf_get
	mov	r12d,eax			; JW_*
	mov	edi,[g_jf_fd]
	test	edi,edi
	js	@f
	mov	eax,SYS_close
	syscall
@@:
	cmp	r12d,JW_OK
	jne	.failed
	call	jf_parse
	jnc	@f
	mov	r12d,JW_BODY
	jmp	.failed
@@:
	call	jf_publish
	test	eax,eax
	jnz	@f
	mov	r12d,JW_BODY
	jmp	.failed
@@:
	; good: as of now, whatever it said
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	pop	rax
	add	rsp,8
	mov	[r14+KT_AT],rax
	mov	dword [g_jf_status+rbx*4],0
	mov	r12d,[r13+JS_REFRESH]
	jmp	.out
.failed:
	cmp	r12d,[g_jf_status+rbx*4]
	je	.retry
	mov	[g_jf_status+rbx*4],r12d
	call	log_begin
	out_lit 'jwks '
	mov	rsi,[r13+JS_URL]
	mov	edx,[r13+JS_ULEN]
	call	out_str
	cmp	r12d,JW_NAME
	jne	@f
	out_lit ': the name does not resolve'
@@:
	cmp	r12d,JW_CONNECT
	jne	@f
	out_lit ': cannot connect'
@@:
	cmp	r12d,JW_TLS
	jne	@f
	out_lit ': TLS 1.3 handshake failed'
@@:
	cmp	r12d,JW_CERT
	jne	@f
	out_lit ': the certificate is not trusted, or not for this name'
@@:
	cmp	r12d,JW_READ
	jne	@f
	out_lit ': the response was cut short, too long or too slow'
@@:
	cmp	r12d,JW_STATUS
	jne	@f
	out_lit ': not a 200 with a whole body'
@@:
	cmp	r12d,JW_BODY
	jne	@f
	out_lit ': not a JWK set with a key usable here'
@@:
	out_lit '; the keys already here stay'
	call	log_end
.retry:
	mov	r12d,JF_RETRY
	cmp	r12d,[r13+JS_REFRESH]
	cmova	r12d,[r13+JS_REFRESH]
.out:
	pop	r14
	pop	r13
	ret

; The body is a JWK set: into g_jwk, as at load. CF: it is not.
jf_parse:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	[g_jf_sp],rsp
	mov	dword [g_plan_jwk],0
	lea	r12,[g_jf_au]
	mov	dword [r12+AU_JN],0
	mov	rsi,[g_jf_bodyp]
	mov	rdx,[g_jf_bodye]
	call	jwks_load
	clc
jf_parse_out:
	mov	qword [g_jf_sp],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; (plan_bad_jwt here: a bad set from the network is no reason to stop)
jf_parse_bad:
	mov	rsp,[g_jf_sp]
	stc
	jmp	jf_parse_out

bss
	align 8
	g_jf_bodyp	dq ?
	g_jf_bodye	dq ?
end bss

; rbx, r13 = the source, r14 = its entry; g_jwk has what came. eax = keys kept, 0
; for none: nothing is published. The table is written only when they differ.
jf_publish:
	lea	rsi,[g_jwk]
	lea	rdi,[g_jf_new]
	mov	ecx,JK_PER_SET * JK_SIZE
	xor	eax,eax
	push	rdi
	rep	stosb
	pop	rdi
	xor	edx,edx				; kept
	mov	r8d,[g_plan_jwk]
.key:
	test	r8d,r8d
	jz	.kept
	dec	r8d
	cmp	dword [rsi+JK_KIND],JA_HS256
	je	.skip
	cmp	edx,JK_PER_SET
	jae	.none
	mov	r9,rsi
	mov	ecx,JK_SIZE
	rep	movsb
	mov	rsi,r9
	inc	edx
.skip:
	add	rsi,JK_SIZE
	jmp	.key
.kept:
	mov	eax,edx
	test	eax,eax
	jz	.out
	push	rax
	cmp	eax,[r14+KT_N]
	jne	.write
	lea	rsi,[g_jf_new]
	lea	rdi,[r14+KT_KEYS]
	mov	ecx,JK_PER_SET * JK_SIZE
	repe	cmpsb
	je	.same
.write:
	inc	qword [r14+KT_SEQ]		; odd: being written
	lea	rsi,[g_jf_new]
	lea	rdi,[r14+KT_KEYS]
	mov	ecx,JK_PER_SET * JK_SIZE
	rep	movsb
	mov	eax,[rsp]
	mov	[r14+KT_N],eax
	inc	qword [r14+KT_SEQ]
	call	log_begin
	out_lit 'jwks '
	mov	rsi,[r13+JS_URL]
	mov	edx,[r13+JS_ULEN]
	call	out_str
	out_lit ': '
	mov	eax,[rsp]
	call	out_u64
	out_lit ' keys'
	call	log_end
.same:
	pop	rax
.out:
	ret
.none:
	xor	eax,eax
	ret

; r13 = the source: the response into g_jf_body, its body at g_jf_bodyp. eax = JW_*.
jf_get:
	push	rbx
	push	r12
	; where
	mov	rdi,[r13+JS_HOST]
	mov	esi,[r13+JS_HLEN]
	push	rdi
	push	rsi
	call	parse_ipv4_text
	pop	rsi
	pop	rdi
	jc	.name
	mov	dword [g_rs_result+RR_COUNT],1
	mov	dword [g_rs_result+RR_ADDRS],eax
	mov	byte [g_rs_result+RR_FAMILY],4
	jmp	.addr
.name:
	call	rs_lookup
	cmp	eax,RS_OK
	jne	.no_name
	cmp	dword [g_rs_result+RR_COUNT],0
	je	.no_name
.addr:
	xor	ebx,ebx
.try:
	cmp	ebx,[g_rs_result+RR_COUNT]
	jae	.no_connect
	call	jf_connect
	test	eax,eax
	jz	.connected
	inc	ebx
	jmp	.try
.connected:
	cmp	dword [r13+JS_TLS],0
	je	.request
	call	jf_tls
	test	eax,eax
	jnz	.out
.request:
	; GET path HTTP/1.1, nothing of the client's in it
	lea	rdi,[g_jf_req]
	ch_lit 'GET '
	mov	rsi,[r13+JS_PATH]
	mov	ecx,[r13+JS_PLEN]
	rep	movsb
	ch_lit ' HTTP/1.1',13,10,'Host: '
	mov	rsi,[r13+JS_HOST]
	mov	ecx,[r13+JS_HLEN]
	rep	movsb
	ch_lit 13,10,'User-Agent: okena',13,10,'Accept: application/json',13,10,'Connection: close',13,10,13,10
	mov	rcx,rdi
	lea	rsi,[g_jf_req]
	sub	rcx,rsi
	mov	edx,ecx
	cmp	dword [r13+JS_TLS],0
	je	.send
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_hout]
	lea	rdx,[g_jf_req]
	call	tlsc_seal
	mov	edx,eax
	lea	rsi,[g_jf_hout]
.send:
	call	jf_write
	test	eax,eax
	jz	.read_failed
	call	jf_read_all
	test	eax,eax
	jnz	.out
	call	jf_response
	jmp	.out
.read_failed:
	mov	eax,JW_READ
	jmp	.out
.no_name:
	mov	eax,JW_NAME
	jmp	.out
.no_connect:
	mov	eax,JW_CONNECT
.out:
	pop	r12
	pop	rbx
	ret

; ebx = which address. eax = 0 connected, g_jf_fd.
jf_connect:
	imul	r12,rbx,16
	lea	r12,[g_rs_result+RR_ADDRS+r12]
	sub	rsp,32
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,32
	rep	stosb
	mov	eax,[r13+JS_PORT]
	xchg	al,ah
	mov	[rsp+2],ax
	movzx	eax,byte [g_rs_result+RR_FAMILY+rbx]
	cmp	eax,6
	je	.six
	mov	word [rsp],AF_INET
	mov	eax,[r12]
	mov	[rsp+4],eax
	mov	edi,AF_INET
	mov	r8d,16
	jmp	.sock
.six:
	mov	word [rsp],AF_INET6
	mov	rax,[r12]
	mov	[rsp+8],rax
	mov	rax,[r12+8]
	mov	[rsp+16],rax
	mov	edi,AF_INET6
	mov	r8d,28
.sock:
	push	r8
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	r8
	test	eax,eax
	js	.fail
	mov	[g_jf_fd],eax
	push	r8
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[jf_iotv]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_jf_fd]
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[jf_iotv]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	pop	rdx
	mov	edi,[g_jf_fd]
	mov	rsi,rsp
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jz	.done
	mov	edi,[g_jf_fd]
	mov	dword [g_jf_fd],-1
	mov	eax,SYS_close
	syscall
.fail:
	mov	eax,1
.done:
	add	rsp,32
	ret

; rsi = bytes, edx = how many: eax = 1 all gone
jf_write:
	push	rbx
	push	r12
	mov	rbx,rsi
	mov	r12d,edx
.more:
	test	r12d,r12d
	jz	.ok
	mov	edi,[g_jf_fd]
	mov	rsi,rbx
	mov	edx,r12d
	mov	eax,SYS_write
	syscall
	test	rax,rax
	jle	.bad
	add	rbx,rax
	sub	r12d,eax
	jmp	.more
.ok:
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r12
	pop	rbx
	ret

; rdi = buffer, esi = room: eax = bytes, 0 at the end, -1 on an error or past the
; deadline
jf_read:
	push	rdi
	push	rsi
	call	monotonic_seconds
	pop	rdx
	pop	rsi
	cmp	rax,[g_jf_end]
	jae	.late
	mov	edi,[g_jf_fd]
	mov	eax,SYS_read
	syscall
	test	rax,rax
	jns	.out
.late:
	mov	eax,-1
.out:
	ret

; The handshake, whole. eax = 0, or JW_TLS, JW_CERT.
jf_tls:
	push	rbx
	push	r12
	push	r14
	push	r15
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_hout]
	mov	rdx,[r13+JS_HOST]
	mov	ecx,[r13+JS_HLEN]
	call	tlsc_client_hello
	test	eax,eax
	jz	.tls
	lea	rsi,[g_jf_hout]
	mov	edx,eax
	call	jf_write
	test	eax,eax
	jz	.tls
	lea	rsi,[g_jf_tc+TC_SHA]
	lea	rdi,[g_jf_snap]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	xor	r12d,r12d			; bytes received
	xor	r14d,r14d			; the records tried end here
.read:
	lea	eax,[r12d]
	cmp	eax,JF_MAX - 16384
	ja	.tls
	lea	rdi,[g_jf_hin+r12]
	mov	esi,16384
	call	jf_read
	test	eax,eax
	jle	.tls
	add	r12d,eax
.rec:
	lea	eax,[r14+5]
	cmp	eax,r12d
	ja	.read
	movzx	eax,word [g_jf_hin+r14+3]
	xchg	al,ah
	lea	eax,[r14+rax+5]
	cmp	eax,r12d
	ja	.read
	mov	r14d,eax
	lea	rsi,[g_jf_hin]
	mov	edx,r14d
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.tls
	lea	rsi,[g_jf_snap]
	lea	rdi,[g_jf_tc+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_hin]
	mov	edx,r14d
	lea	rcx,[g_jf_hdec]
	call	tlsc_server_flight
	test	eax,eax
	jz	.rec
	mov	r15d,eax
	lea	rsi,[g_jf_hdec]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.rec
	; the handshake's own proof, then whose certificate that is
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_hdec]
	mov	edx,r15d
	call	tlsc_verify
	test	eax,eax
	jz	.cert
	lea	rdi,[r13+JS_ANCHOR]
	mov	rsi,[g_jf_tc+TC_CLIST]
	mov	edx,[g_jf_tc+TC_CLISTLEN]
	call	cert_chain_verify
	test	eax,eax
	jz	.cert
	lea	rdi,[g_jf_time]
	call	alog_fmt_time
	lea	rsi,[g_jf_time]
	lea	rdi,[g_jf_time+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
.compact:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	.compact
	mov	rsi,[g_jf_tc+TC_LEAF]
	mov	edx,[g_jf_tc+TC_LEAFLEN]
	lea	rdi,[g_jf_time+32]
	call	cert_time_valid
	test	eax,eax
	jz	.cert
	mov	rdi,[r13+JS_HOST]
	mov	ecx,[r13+JS_HLEN]
	mov	rsi,[g_jf_tc+TC_LEAF]
	mov	edx,[g_jf_tc+TC_LEAFLEN]
	call	cert_match_host
	test	eax,eax
	jz	.cert
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_hout]
	call	tlsc_finish
	lea	rsi,[g_jf_hout]
	mov	edx,eax
	call	jf_write
	test	eax,eax
	jz	.tls
	; what came after the server Finished goes with the application records
	mov	ecx,r12d
	sub	ecx,r14d
	lea	rsi,[g_jf_hin+r14]
	lea	rdi,[g_jf_raw]
	mov	[g_jf_rawn],ecx
	rep	movsb
	xor	eax,eax
	jmp	.out
.cert:
	mov	eax,JW_CERT
	jmp	.out
.tls:
	mov	eax,JW_TLS
.out:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret

; To the end of the stream, then the records opened. eax = 0, or JW_READ.
; g_jf_body, g_jf_bodyn.
jf_read_all:
	push	rbx
	push	r12
	cmp	dword [r13+JS_TLS],0
	jne	.raw
	mov	dword [g_jf_rawn],0
.raw:
	mov	ebx,[g_jf_rawn]
.read:
	cmp	ebx,JF_MAX
	jae	.bad
	lea	rdi,[g_jf_raw+rbx]
	mov	esi,JF_MAX
	sub	esi,ebx
	call	jf_read
	test	eax,eax
	js	.bad
	jz	.eof
	add	ebx,eax
	jmp	.read
.eof:
	mov	dword [g_jf_notify],0
	cmp	dword [r13+JS_TLS],0
	jne	.records
	lea	rsi,[g_jf_raw]
	lea	rdi,[g_jf_body]
	mov	ecx,ebx
	mov	[g_jf_bodyn],ebx
	rep	movsb
	xor	eax,eax
	jmp	.out
.records:
	xor	r12d,r12d			; offset
	mov	dword [g_jf_bodyn],0
.record:
	cmp	r12d,ebx
	je	.done
	lea	eax,[r12+5]
	cmp	eax,ebx
	ja	.bad
	movzx	eax,word [g_jf_raw+r12+3]
	xchg	al,ah
	lea	eax,[r12+rax+5]
	cmp	eax,ebx
	ja	.bad
	lea	rdi,[g_jf_tc]
	lea	rsi,[g_jf_raw+r12]
	mov	r12d,eax
	cmp	byte [rsi],23
	jne	.record				; (a change_cipher_spec)
	call	tlsc_open
	test	eax,eax
	jz	.bad
	cmp	r8d,23
	je	.data
	cmp	r8d,21
	jne	.record				; (tickets)
	cmp	ecx,2
	jb	.record
	cmp	byte [rsi+1],0
	jne	.bad				; an alert other than close_notify
	mov	dword [g_jf_notify],1
	jmp	.record
.data:
	mov	eax,[g_jf_bodyn]
	lea	edx,[rax+rcx]
	cmp	edx,JF_MAX
	ja	.bad
	lea	rdi,[g_jf_body+rax]
	mov	[g_jf_bodyn],edx
	rep	movsb
	jmp	.record
.done:
	xor	eax,eax
	jmp	.out
.bad:
	mov	eax,JW_READ
.out:
	pop	r12
	pop	rbx
	ret

; g_jf_body holds a response: a 200 with its body whole. eax = 0, or JW_STATUS.
jf_response:
	push	rbx
	push	r12
	push	r14
	lea	rsi,[g_jf_body]
	mov	eax,[g_jf_bodyn]
	lea	r14,[rsi+rax]			; the end
	cmp	eax,16
	jb	.bad
	mov	rax,[rsi]
	shl	rax,8
	mov	rcx,'HTTP/1.'
	shl	rcx,8
	cmp	rax,rcx
	jne	.bad
	cmp	dword [rsi+8],' 200'
	jne	.bad
	mov	al,[rsi+12]
	cmp	al,' '
	je	@f
	cmp	al,13
	jne	.bad
@@:
	mov	rbx,-1				; Content-Length, -1 none
	xor	r12d,r12d			; chunked
.line:
	mov	rdi,rsi
	mov	rcx,r14
	sub	rcx,rdi
	jle	.bad
	mov	al,10
	repne	scasb
	jne	.bad
	mov	rsi,rdi				; the next line
	lea	rcx,[r14]
	sub	rcx,rsi
	cmp	rcx,2
	jb	.bad
	cmp	word [rsi],0x0A0D
	je	.head_end
	; a field: name lowered as it is compared
	lea	rdi,[.n_cl]
	mov	ecx,15
	call	.named
	jne	.te
	call	.number
	jc	.bad
	cmp	rbx,-1
	je	@f
	cmp	rax,rbx
	jne	.bad				; two lengths that differ
@@:
	mov	rbx,rax
	jmp	.line
.te:
	lea	rdi,[.n_te]
	mov	ecx,18
	call	.named
	jne	.line
	mov	r12d,1				; only chunked is known here
	push	rsi
	lea	rdi,[.v_ch]
	mov	ecx,8
	add	rsi,18
	call	.named_at
	pop	rsi
	jne	.bad
	jmp	.line
.head_end:
	add	rsi,2
	test	r12d,r12d
	jz	.not_chunked
	cmp	rbx,-1
	jne	.bad				; both: request smuggling's shape
	; in place
	mov	rdi,rsi
	mov	[g_jf_bodyp],rsi
.chunk:
	xor	edx,edx				; its size
	xor	ecx,ecx				; digits
.hex:
	cmp	rsi,r14
	jae	.bad
	movzx	eax,byte [rsi]
	sub	eax,'0'
	cmp	eax,9
	jbe	.digit
	movzx	eax,byte [rsi]
	or	eax,0x20
	sub	eax,'a' - 10
	cmp	eax,10
	jb	.ext
	cmp	eax,15
	ja	.ext
.digit:
	shl	edx,4
	or	edx,eax
	cmp	edx,JF_MAX
	ja	.bad
	inc	ecx
	inc	rsi
	jmp	.hex
.ext:
	test	ecx,ecx
	jz	.bad
.eol:
	cmp	rsi,r14
	jae	.bad
	lodsb
	cmp	al,10
	jne	.eol
	test	edx,edx
	jz	.chunks_end
	mov	rax,r14
	sub	rax,rsi
	lea	rcx,[rdx+2]
	cmp	rax,rcx
	jb	.bad
	mov	ecx,edx
	rep	movsb
	cmp	word [rsi],0x0A0D
	jne	.bad
	add	rsi,2
	jmp	.chunk
.chunks_end:
	mov	[g_jf_bodye],rdi
	jmp	.good
.not_chunked:
	mov	[g_jf_bodyp],rsi
	mov	rax,r14
	sub	rax,rsi
	cmp	rbx,-1
	je	.to_close
	cmp	rax,rbx
	jne	.bad
	jmp	.whole
.to_close:
	cmp	dword [r13+JS_TLS],0
	je	.whole
	cmp	dword [g_jf_notify],0		; only that says it is the end
	je	.bad
.whole:
	mov	[g_jf_bodye],r14
.good:
	xor	eax,eax
	jmp	.out
.bad:
	mov	eax,JW_STATUS
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret
; rdi = a lowercase name, ecx = its length: ZF when the line at rsi begins with it.
; Keeps rsi.
.named:
.named_at:
	mov	rax,r14
	sub	rax,rsi
	cmp	rax,rcx
	jb	.differs
	xor	r8d,r8d
.ch:
	movzx	eax,byte [rsi+r8]
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	ja	@f
	or	al,0x20
@@:
	cmp	al,[rdi+r8]
	jne	.differs
	inc	r8
	cmp	r8d,ecx
	jb	.ch
	xor	eax,eax				; (ZF)
	ret
.differs:
	or	eax,1				; (not ZF)
	ret
; rsi = a line "content-length: 123": rax = the number. CF: it is not one.
.number:
	lea	r8,[rsi+15]
	xor	eax,eax
	xor	ecx,ecx				; digits
.sp:
	cmp	r8,r14
	jae	.nan
	cmp	byte [r8],' '
	jne	.dig
	inc	r8
	jmp	.sp
.dig:
	cmp	r8,r14
	jae	.nan
	movzx	edx,byte [r8]
	sub	edx,'0'
	cmp	edx,9
	ja	.num_end
	imul	rax,rax,10
	add	rax,rdx
	cmp	rax,JF_MAX
	ja	.nan
	inc	ecx
	inc	r8
	jmp	.dig
.num_end:
	cmp	byte [r8],13
	jne	.nan
	test	ecx,ecx
	jz	.nan
	clc
	ret
.nan:
	stc
	ret
.n_cl	db 'content-length:'
.n_te	db 'transfer-encoding:'
.v_ch	db ' chunked'
