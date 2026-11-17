; `okena routes-api ADDR token=FILE [-c CONF]`: an HTTP API for the routes of
; `routes FILE` lines, as a process of its own, run as the user who may
; change those files (as `okena routes` is): the admin process gets no right
; to rewrite the configuration, and what reaches the metrics address cannot
; change what okena serves.
;
;   GET    /routes            the names and their files ("NAME<TAB>FILE" lines)
;   GET    /routes/NAME       what NAME holds (a route a line)
;   PUT    /routes/NAME       the body (one route, one line) put in: added, or
;                             in place of the route of its head
;   DELETE /routes/NAME       the route whose head is the body taken out
;
; Each request needs `Authorization: Bearer TOKEN` (FILE's token, 32 to 512
; printable bytes, compared in constant time). A change is `okena routes`
; itself, run as a child (no shell: its words as arguments) with the same
; configuration: checked whole before anything serves it, FILE rewritten
; under its lock, the running okena reloaded through its admin socket, FILE
; put back when either refuses. 200 with what it said; 422 with the errors
; when the change was not taken; 404 for a name or a head not there.
;
; ADDR is unix:/PATH (made 0600) or a loopback HOST:PORT: plain HTTP with a
; token goes nowhere else. To reach it from afar, a route of okena itself in
; front (TLS, allow lists, limits): `route /api/routes/* { allow 10.0.0.0/8;
; rewrite path /api/routes/{*} -> /routes/{*}; to unix:/run/okena/routes.sock }`.
; One request at a time (changes are one at a time anyway), each with 5 s to
; come in whole.

RA_HEAD_MAX	:= 8192
RA_BODY_MAX	:= 16384

cstring str_cmd_routes_api, 'routes-api',0
cstring str_ra_exe, '/proc/self/exe',0
cstring str_ra_okena, 'okena',0
cstring str_ra_list, 'routes',0
cstring str_ra_put, 'put',0
cstring str_ra_del, 'delete',0

bss
	align 8
	g_ra_fd		dd ?
	g_ra_conn	dd ?
	g_ra_toklen	dd ?
	g_ra_salen	dd ?
	g_ra_n		dd ?			; bytes of the request read
	g_ra_head	dd ?			; its head's length (to the blank line's end)
	g_ra_clen	dd ?
	g_ra_outlen	dd ?
	g_ra_cfg	dq ?			; -c CONF, 0 none
	g_ra_method	dq ?
	g_ra_mlen	dd ?
	g_ra_tlen	dd ?
	g_ra_target	dq ?
	g_ra_argv	rq 10
	g_ra_ad:	rb AD_SIZE
	g_ra_sa:	rb 112
	g_ra_tv		rq 2
	g_ra_tok:	rb 520
	g_ra_name:	rb 80
	g_ra_body:	rb RA_BODY_MAX + 8
	g_ra_req:	rb RA_HEAD_MAX + RA_BODY_MAX + 8
	g_ra_out:	rb 65536
	g_ra_resp:	rb 512
end bss

cli_routes_api:
	; ADDR token=FILE [-c CONF]
	mov	rcx,[g_argc]
	mov	qword [g_ra_cfg],0
	cmp	rcx,4
	je	.args
	cmp	rcx,6
	jne	.usage
	mov	rax,[g_argv]
	mov	rdi,[rax+32]
	lea	rsi,[str_flag_c]
	call	cstr_eq
	test	eax,eax
	jz	.usage
	mov	rax,[g_argv]
	mov	rax,[rax+40]
	mov	[g_ra_cfg],rax
.args:
	mov	edi,SIGPIPE			; (a client gone: EPIPE, not the end of us)
	lea	rsi,[sigact_ignore]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall
	call	ra_token
	call	ra_listen
	call	log_begin
	out_lit 'routes-api on '
	mov	rax,[g_argv]
	mov	rsi,[rax+16]
	call	out_cstr
	out_lit ' (GET /routes, GET|PUT|DELETE /routes/NAME)'
	call	log_end
.accept:
	mov	edi,[g_ra_fd]
	xor	esi,esi
	xor	edx,edx
	mov	r10d,SOCK_CLOEXEC
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.accept				; (EINTR, a connection gone before it was taken)
	mov	[g_ra_conn],eax
	; 5 s to come in whole, 5 s for the answer to go
	mov	qword [g_ra_tv],5
	mov	qword [g_ra_tv+8],0
	irp opt, SO_RCVTIMEO,SO_SNDTIMEO
		mov	edi,[g_ra_conn]
		mov	esi,SOL_SOCKET
		mov	edx,opt
		lea	r10,[g_ra_tv]
		mov	r8d,16
		mov	eax,SYS_setsockopt
		syscall
	end irp
	call	ra_request
	mov	edi,[g_ra_conn]
	mov	eax,SYS_close
	syscall
	jmp	.accept
.usage:
	call	log_begin
	out_lit 'usage: okena routes-api unix:/PATH|127.0.0.1:PORT token=FILE [-c CONF]'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; token=FILE: g_ra_tok, its length (trailing blanks off). Exits when not one.
ra_token:
	mov	rax,[g_argv]
	mov	rsi,[rax+24]
	cmp	dword [rsi],'toke'
	jne	.bad
	cmp	word [rsi+4],'n='
	jne	.bad
	lea	rsi,[rsi+6]
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.unreadable
	push	rax
	mov	edi,eax
	lea	rsi,[g_ra_tok]
	mov	edx,513
	xor	eax,eax				; SYS_read
	syscall
	mov	rcx,rax
	pop	rdi
	push	rcx
	mov	eax,SYS_close
	syscall
	pop	rcx
	test	rcx,rcx
	js	.unreadable
	cmp	ecx,512
	ja	.bad_token
@@:
	test	ecx,ecx
	jz	.bad_token
	movzx	eax,byte [g_ra_tok+rcx-1]
	cmp	al,' '
	ja	@f
	dec	ecx
	jmp	@b
@@:
	cmp	ecx,32
	jb	.bad_token
	xor	eax,eax
@@:
	movzx	edx,byte [g_ra_tok+rax]
	cmp	dl,0x21
	jb	.bad_token
	cmp	dl,0x7E
	ja	.bad_token
	inc	eax
	cmp	eax,ecx
	jb	@b
	mov	[g_ra_toklen],ecx
	ret
.bad:
	jmp	cli_routes_api.usage
.unreadable:
	call	log_begin
	out_lit 'routes-api: cannot read the token file'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad_token:
	call	log_begin
	out_lit 'routes-api: the token is 32 to 512 printable characters (openssl rand -hex 32)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ADDR: unix:/PATH (0600), or a loopback HOST:PORT. Exits when it cannot.
ra_listen:
	mov	rax,[g_argv]
	mov	rsi,[rax+16]
	cmp	dword [rsi],'unix'
	jne	.inet
	cmp	byte [rsi+4],':'
	jne	.inet
	add	rsi,5
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,100
	ja	.bad
	cmp	byte [rsi],'/'
	jne	.bad
	mov	word [g_ra_sa],AF_UNIX
	lea	rdi,[g_ra_sa+2]
	push	rcx
	rep	movsb
	mov	byte [rdi],0
	pop	rcx
	add	ecx,3
	mov	[g_ra_salen],ecx
	lea	rdi,[g_ra_sa+2]			; (one left by a run before: ours)
	mov	eax,SYS_unlink_
	syscall
	mov	edi,AF_UNIX
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.cannot
	mov	[g_ra_fd],eax
	mov	edi,0x3F			; umask 077 for the bind: 0600 from the start
	mov	eax,95				; SYS_umask
	syscall
	push	rax
	mov	edi,[g_ra_fd]
	lea	rsi,[g_ra_sa]
	mov	edx,[g_ra_salen]
	mov	eax,SYS_bind
	syscall
	pop	rdi
	push	rax
	mov	eax,95
	syscall
	pop	rax
	test	eax,eax
	js	.cannot
	lea	rdi,[g_ra_sa+2]
	mov	esi,384				; 0600
	mov	eax,SYS_chmod_
	syscall
	jmp	.listen
.inet:
	mov	rdi,rsi
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	lea	rdx,[g_ra_ad]
	xor	ecx,ecx
	call	parse_address
	jc	.bad
	; loopback only: 127.0.0.0/8, ::1
	mov	eax,[g_ra_ad+AD_KIND]
	cmp	eax,ADDR_V4
	jne	@f
	cmp	byte [g_ra_ad+AD_IP],127
	jne	.not_loopback
	jmp	.loopback
@@:
	cmp	eax,ADDR_V6
	jne	.not_loopback
	cmp	qword [g_ra_ad+AD_IP],0
	jne	.not_loopback
	mov	rax,0x0100000000000000
	cmp	qword [g_ra_ad+AD_IP+8],rax
	jne	.not_loopback
.loopback:
	cmp	dword [g_ra_ad+AD_PORT],0
	je	.bad
	lea	rdi,[g_ra_sa]
	lea	rsi,[g_ra_ad]
	call	sockaddr_build
	mov	[g_ra_salen],eax
	movzx	edi,word [g_ra_sa]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.cannot
	mov	[g_ra_fd],eax
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_ra_fd]
	lea	rsi,[g_ra_sa]
	mov	edx,[g_ra_salen]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.cannot
.listen:
	mov	edi,[g_ra_fd]
	mov	esi,16
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.cannot
	ret
.bad:
	jmp	cli_routes_api.usage
.not_loopback:
	call	log_begin
	out_lit 'routes-api: a loopback address or unix:/PATH only (a token over plain HTTP goes nowhere else: put okena with TLS in front)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.cannot:
	push	rax
	call	log_begin
	out_lit 'routes-api: cannot listen there (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; ------------------------------------------------------------ a request

; g_ra_conn: one request read, answered
ra_request:
	push	rbx
	push	r12
	push	r13
	mov	dword [g_ra_n],0
	; the head
.read:
	mov	edi,[g_ra_conn]
	mov	eax,[g_ra_n]
	lea	rsi,[g_ra_req+rax]
	mov	edx,RA_HEAD_MAX + RA_BODY_MAX
	sub	edx,eax
	jz	.too_large
	xor	eax,eax				; SYS_read
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	jle	.gone
	add	[g_ra_n],eax
	call	ra_head_end			; eax = the head's length, 0 not yet
	test	eax,eax
	jnz	.head
	cmp	dword [g_ra_n],RA_HEAD_MAX
	jae	.too_large
	jmp	.read
.head:
	mov	[g_ra_head],eax
	call	ra_parse_line
	jc	.bad_request
	; chunked: not here
	lea	rdi,[.te]
	mov	ecx,.te.len
	call	ra_hdr
	jnc	.length_required
	mov	dword [g_ra_clen],0
	lea	rdi,[.cl]
	mov	ecx,.cl.len
	call	ra_hdr
	jc	.bodied
	mov	rdi,rsi
	mov	esi,ecx
	call	parse_decimal
	jc	.bad_request
	cmp	rax,RA_BODY_MAX
	ja	.too_large
	mov	[g_ra_clen],eax
.bodied:
	; the rest of the body
	mov	eax,[g_ra_head]
	add	eax,[g_ra_clen]
	cmp	eax,[g_ra_n]
	jbe	.whole
	mov	edi,[g_ra_conn]
	mov	ecx,[g_ra_n]
	lea	rsi,[g_ra_req+rcx]
	mov	edx,eax
	sub	edx,ecx
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.bodied
	test	rax,rax
	jle	.gone
	add	[g_ra_n],eax
	jmp	.bodied
.whole:
	; who: the token, first
	call	ra_authorized
	jnz	.unauthorized
	call	ra_route
	jmp	.out
.length_required:
	mov	eax,411
	lea	rsi,[.m411]
	mov	ecx,.m411.len
	call	ra_answer_text
	call	ra_linger
	jmp	.out
.unauthorized:
	mov	eax,401
	lea	rsi,[.m401]
	mov	ecx,.m401.len
	call	ra_answer_text
	jmp	.out
.too_large:
	mov	eax,413
	lea	rsi,[.m413]
	mov	ecx,.m413.len
	call	ra_answer_text
	call	ra_linger
	jmp	.out
.bad_request:
	mov	eax,400
	lea	rsi,[.m400]
	mov	ecx,.m400.len
	call	ra_answer_text
	call	ra_linger
.gone:
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
cstring .te, 'transfer-encoding:'
cstring .cl, 'content-length:'
cstring .m400, 'a bad request',10
cstring .m401, 'Authorization: Bearer TOKEN, the token of token=FILE',10
cstring .m411, 'a body with Content-Length, not chunked',10
cstring .m413, 'too large: a head of 8 KiB, a body of 16 KiB at most',10

; answered before the request was read whole: our side shut, and what the
; client still sends read and dropped (4 MiB at most, within the 5 s), so it
; reads the answer rather than a reset in the middle of its body
ra_linger:
	mov	edi,[g_ra_conn]
	mov	esi,1				; SHUT_WR
	mov	eax,SYS_shutdown
	syscall
	push	rbx
	xor	ebx,ebx
.read:
	cmp	ebx,4 shl 20
	jae	.out
	mov	edi,[g_ra_conn]
	lea	rsi,[g_ra_out]
	mov	edx,65536
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	jle	.out
	add	ebx,eax
	jmp	.read
.out:
	pop	rbx
	ret

; eax = the head's length (to its blank line's end), 0 when not all here
ra_head_end:
	mov	ecx,[g_ra_n]
	cmp	ecx,4
	jb	.no
	sub	ecx,3
	xor	eax,eax
@@:
	cmp	dword [g_ra_req+rax],0x0A0D0A0D
	je	.yes
	inc	eax
	cmp	eax,ecx
	jb	@b
.no:
	xor	eax,eax
	ret
.yes:
	add	eax,4
	ret

; the request line: g_ra_method/mlen, g_ra_target/tlen. CF when not one.
ra_parse_line:
	lea	rsi,[g_ra_req]
	mov	[g_ra_method],rsi
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,' '
	je	@f
	sub	al,'A'
	cmp	al,25
	ja	.bad
	inc	ecx
	cmp	ecx,8
	ja	.bad
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	mov	[g_ra_mlen],ecx
	lea	rsi,[rsi+rcx+1]
	mov	[g_ra_target],rsi
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,' '
	je	@f
	cmp	al,0x21
	jb	.bad
	cmp	al,0x7E
	ja	.bad
	inc	ecx
	cmp	ecx,200
	ja	.bad
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	mov	[g_ra_tlen],ecx
	cmp	dword [rsi+rcx+1],'HTTP'
	jne	.bad
	cmp	word [rsi+rcx+5],'/1'
	jne	.bad
	clc
	ret
.bad:
	stc
	ret

; rdi/ecx = a field's name and its colon, in lower case: rsi/ecx = its value
; (blanks around it off). CF when the head has none.
ra_hdr:
	push	rbx
	push	r12
	mov	r12d,ecx
	lea	rsi,[g_ra_req]
	mov	ebx,[g_ra_head]
	add	rbx,rsi				; the head's end
.line:
	; the next line
@@:
	cmp	rsi,rbx
	jae	.no
	cmp	byte [rsi],10
	je	@f
	inc	rsi
	jmp	@b
@@:
	inc	rsi
	lea	rax,[rsi+r12]
	cmp	rax,rbx
	jae	.no
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,'A'
	jb	.low
	cmp	al,'Z'
	ja	.low
	or	al,0x20
.low:
	cmp	al,[rdi+rcx]
	jne	.line
	inc	ecx
	cmp	ecx,r12d
	jb	@b
	add	rsi,r12
@@:
	cmp	byte [rsi],' '
	je	.lead
	cmp	byte [rsi],9
	jne	@f
.lead:
	inc	rsi
	jmp	@b
@@:
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,13
	je	@f
	cmp	al,10
	je	@f
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.out_clc
	cmp	byte [rsi+rcx-1],' '
	jne	.out_clc
	dec	ecx
	jmp	@b
.out_clc:
	clc
	pop	r12
	pop	rbx
	ret
.no:
	stc
	pop	r12
	pop	rbx
	ret

; ZF when the head has `Authorization: Bearer TOKEN` (constant time)
ra_authorized:
	lea	rdi,[.authz]
	mov	ecx,.authz.len
	call	ra_hdr
	jc	.no
	cmp	ecx,7
	jbe	.no
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'bear'
	jne	.no
	mov	eax,[rsi+3]
	or	eax,0x20202020
	cmp	eax,'rer '
	jne	.no
	add	rsi,7
	sub	ecx,7
	cmp	ecx,[g_ra_toklen]
	jne	.no
	xor	eax,eax
	xor	edx,edx
@@:
	movzx	r8d,byte [rsi+rdx]
	xor	r8b,[g_ra_tok+rdx]
	or	eax,r8d
	inc	edx
	cmp	edx,ecx
	jb	@b
	test	eax,eax
	ret
.no:
	or	eax,1
	ret
cstring .authz, 'authorization:'

; the method and the target: `okena routes ...` run, its answer
ra_route:
	push	rbx
	push	r12
	mov	rsi,[g_ra_target]
	mov	ecx,[g_ra_tlen]
	cmp	ecx,7
	jb	.not_found
	cmp	dword [rsi],'/rou'
	jne	.not_found
	cmp	word [rsi+4],'te'
	jne	.not_found
	cmp	byte [rsi+6],'s'
	jne	.not_found
	; argv: okena routes [NAME [put|delete BODY]] [-c CONF]
	lea	rax,[str_ra_okena]
	mov	[g_ra_argv],rax
	lea	rax,[str_ra_list]
	mov	[g_ra_argv+8],rax
	mov	ebx,2				; words so far
	cmp	ecx,7
	je	.list
	cmp	byte [rsi+7],'/'
	jne	.not_found
	; NAME: [A-Za-z0-9._-], 1..64, not a flag
	lea	rsi,[rsi+8]
	sub	ecx,8
	jz	.not_found
	cmp	ecx,64
	ja	.not_found
	cmp	byte [rsi],'-'
	je	.not_found
	xor	edx,edx
@@:
	movzx	eax,byte [rsi+rdx]
	cmp	al,'-'
	je	.n_ok
	cmp	al,'.'
	je	.n_ok
	cmp	al,'_'
	je	.n_ok
	lea	r8d,[rax-'0']
	cmp	r8d,9
	jbe	.n_ok
	or	al,0x20
	sub	al,'a'
	cmp	al,25
	ja	.not_found
.n_ok:
	inc	edx
	cmp	edx,ecx
	jb	@b
	lea	rdi,[g_ra_name]
	rep	movsb
	mov	byte [rdi],0
	lea	rax,[g_ra_name]
	mov	[g_ra_argv+16],rax
	mov	ebx,3
	; GET, PUT, DELETE
	mov	rsi,[g_ra_method]
	mov	ecx,[g_ra_mlen]
	cmp	ecx,3
	jne	@f
	cmp	word [rsi],'GE'
	jne	.put_q
	cmp	byte [rsi+2],'T'
	je	.run
.put_q:
	cmp	word [rsi],'PU'
	jne	.not_allowed
	cmp	byte [rsi+2],'T'
	jne	.not_allowed
	lea	rax,[str_ra_put]
	jmp	.bodied
@@:
	cmp	ecx,6
	jne	.not_allowed
	cmp	dword [rsi],'DELE'
	jne	.not_allowed
	cmp	word [rsi+4],'TE'
	jne	.not_allowed
	lea	rax,[str_ra_del]
.bodied:
	mov	[g_ra_argv+24],rax
	call	ra_body				; CF: not one line
	jc	.bad_body
	lea	rax,[g_ra_body]
	mov	[g_ra_argv+32],rax
	mov	ebx,5
	jmp	.run
.list:
	mov	rsi,[g_ra_method]
	cmp	dword [g_ra_mlen],3
	jne	.not_allowed
	cmp	word [rsi],'GE'
	jne	.not_allowed
	cmp	byte [rsi+2],'T'
	jne	.not_allowed
.run:
	mov	rax,[g_ra_cfg]
	test	rax,rax
	jz	@f
	lea	rcx,[str_flag_c]
	mov	[g_ra_argv+rbx*8],rcx
	mov	[g_ra_argv+rbx*8+8],rax
	add	ebx,2
@@:
	mov	qword [g_ra_argv+rbx*8],0
	call	ra_run				; eax = its exit code, g_ra_out/len
	mov	r12d,eax
	call	ra_status			; eax = the status
	push	rax
	mov	ebx,eax
	lea	rsi,[g_ra_out]
	mov	ecx,[g_ra_outlen]
	call	ra_answer_text
	pop	rax
	call	ra_log
	jmp	.out
.not_found:
	mov	eax,404
	lea	rsi,[.m404]
	mov	ecx,.m404.len
	call	ra_answer_text
	jmp	.out
.not_allowed:
	mov	eax,405
	lea	rsi,[.m405]
	mov	ecx,.m405.len
	call	ra_answer_text
	jmp	.out
.bad_body:
	mov	eax,400
	lea	rsi,[.mbody]
	mov	ecx,.mbody.len
	call	ra_answer_text
.out:
	pop	r12
	pop	rbx
	ret
cstring .m404, 'no such path: /routes, /routes/NAME',10
cstring .m405, 'GET /routes; GET, PUT or DELETE /routes/NAME',10
cstring .mbody, 'the body: one line (PUT: a route; DELETE: its head), no control characters',10

; the body, one line (a CR LF at its end off): g_ra_body, NUL-ended. CF when
; empty, more than one line, a control character, or a flag's dash first.
ra_body:
	mov	ecx,[g_ra_clen]
	mov	esi,[g_ra_head]
	lea	rsi,[g_ra_req+rsi]
@@:
	test	ecx,ecx
	jz	.bad
	cmp	byte [rsi+rcx-1],10
	je	.trim
	cmp	byte [rsi+rcx-1],13
	jne	@f
.trim:
	dec	ecx
	jmp	@b
@@:
	cmp	byte [rsi],'-'
	je	.bad
	xor	eax,eax
@@:
	movzx	edx,byte [rsi+rax]
	cmp	dl,9
	je	.ok
	cmp	dl,0x20
	jb	.bad
	cmp	dl,0x7F
	je	.bad
.ok:
	inc	eax
	cmp	eax,ecx
	jb	@b
	lea	rdi,[g_ra_body]
	rep	movsb
	mov	byte [rdi],0
	clc
	ret
.bad:
	stc
	ret

; g_ra_argv: run as a child (this binary, no shell), its stdout and stderr
; into g_ra_out. eax = its exit code (-1: it could not be run).
ra_run:
	push	rbx
	push	r12
	sub	rsp,16
	mov	rdi,rsp
	mov	esi,O_CLOEXEC
	mov	eax,SYS_pipe2
	syscall
	test	eax,eax
	js	.cannot
	mov	eax,SYS_fork
	syscall
	test	eax,eax
	js	.cannot_close
	jnz	.parent
	; the child: its output to the pipe, then okena routes ...
	mov	edi,[rsp+4]
	mov	esi,1
	xor	edx,edx
	mov	eax,SYS_dup3
	syscall
	mov	edi,[rsp+4]
	mov	esi,2
	xor	edx,edx
	mov	eax,SYS_dup3
	syscall
	lea	rdi,[str_ra_exe]
	lea	rsi,[g_ra_argv]
	mov	rdx,[g_envp]
	mov	eax,SYS_execve_
	syscall
	mov	edi,127
	mov	eax,SYS_exit_group
	syscall
.parent:
	mov	r12d,eax			; the child
	mov	edi,[rsp+4]
	mov	eax,SYS_close
	syscall
	xor	ebx,ebx				; read so far
.read:
	mov	edi,[rsp]
	lea	rsi,[g_ra_out+rbx]
	mov	edx,65535
	sub	edx,ebx
	jz	.drain
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	jle	.read_done
	add	ebx,eax
	jmp	.read
.drain:						; (past 64 KiB: the rest read, not kept)
	mov	edi,[rsp]
	lea	rsi,[g_ra_resp]
	mov	edx,512
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.drain
	test	rax,rax
	jg	.drain
.read_done:
	mov	[g_ra_outlen],ebx
	mov	edi,[rsp]
	mov	eax,SYS_close
	syscall
	mov	dword [rsp+8],0
.wait:
	mov	edi,r12d
	lea	rsi,[rsp+8]
	xor	edx,edx
	xor	r10d,r10d
	mov	eax,SYS_wait4_
	syscall
	cmp	rax,-EINTR
	je	.wait
	mov	eax,[rsp+8]
	test	eax,0x7F
	jnz	.signaled
	shr	eax,8
	and	eax,0xFF
	jmp	.out
.signaled:
	mov	eax,-1
	jmp	.out
.cannot_close:
	mov	edi,[rsp]
	mov	eax,SYS_close
	syscall
	mov	edi,[rsp+4]
	mov	eax,SYS_close
	syscall
.cannot:
	mov	dword [g_ra_outlen],0
	mov	eax,-1
.out:
	add	rsp,16
	pop	r12
	pop	rbx
	ret

; r12d = the exit code, g_ra_out: eax = the status (200, 404, 422, 500)
ra_status:
	mov	eax,200
	test	r12d,r12d
	jz	.out
	mov	eax,500
	cmp	r12d,-1
	je	.out
	lea	rdi,[.no_name]
	mov	ecx,.no_name.len
	call	ra_said
	mov	eax,404
	je	.out
	lea	rdi,[.no_head]
	mov	ecx,.no_head.len
	call	ra_said
	mov	eax,404
	je	.out
	mov	eax,422
.out:
	ret
cstring .no_name, 'no `routes` file of that name'
cstring .no_head, 'no route of that head there'

; rdi/ecx: ZF when g_ra_out has it
ra_said:
	mov	edx,[g_ra_outlen]
	sub	edx,ecx
	jl	.no
	xor	eax,eax
.at:
	push	rcx
	push	rdi
	lea	rsi,[g_ra_out+rax]
	repe	cmpsb
	pop	rdi
	pop	rcx
	je	.yes
	inc	eax
	cmp	eax,edx
	jbe	.at
.no:
	or	eax,1
	ret
.yes:
	xor	eax,eax
	ret

; eax = status, rsi/ecx = body (text): the answer, and the connection's end
ra_answer_text:
	push	rbx
	push	r12
	push	r13
	mov	ebx,eax
	mov	r12,rsi
	mov	r13d,ecx
	lea	rdi,[g_ra_resp]
	memit 'HTTP/1.1 '
	mov	eax,ebx
	call	fmt_u64
	cmp	ebx,200
	jne	@f
	memit ' OK'
@@:
	cmp	ebx,400
	jne	@f
	memit ' Bad Request'
@@:
	cmp	ebx,401
	jne	@f
	memit ' Unauthorized',13,10,'WWW-Authenticate: Bearer realm="okena routes"'
@@:
	cmp	ebx,404
	jne	@f
	memit ' Not Found'
@@:
	cmp	ebx,405
	jne	@f
	memit ' Method Not Allowed',13,10,'Allow: GET, PUT, DELETE'
@@:
	cmp	ebx,411
	jne	@f
	memit ' Length Required'
@@:
	cmp	ebx,413
	jne	@f
	memit ' Content Too Large'
@@:
	cmp	ebx,422
	jne	@f
	memit ' Unprocessable Content'
@@:
	cmp	ebx,500
	jne	@f
	memit ' Internal Server Error'
@@:
	memit 13,10,'Content-Type: text/plain; charset=utf-8',13,10,'Cache-Control: no-store',13,10
	memit 'X-Content-Type-Options: nosniff',13,10,'Connection: close',13,10,'Content-Length: '
	mov	eax,r13d
	call	fmt_u64
	memit 13,10,13,10
	lea	rsi,[g_ra_resp]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	edi,[g_ra_conn]
	call	write_all
	mov	edi,[g_ra_conn]
	mov	rsi,r12
	mov	edx,r13d
	call	write_all
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = the status: a line for the log (a change, and who asked is the
; token's holder: the method, the target, how it went)
ra_log:
	push	rax
	call	log_begin
	out_lit 'routes-api: '
	mov	rsi,[g_ra_method]
	mov	edx,[g_ra_mlen]
	call	out_str
	out_lit ' '
	mov	rsi,[g_ra_target]
	mov	edx,[g_ra_tlen]
	call	out_str
	out_lit ': '
	pop	rax
	call	out_u64
	call	log_end
	ret
