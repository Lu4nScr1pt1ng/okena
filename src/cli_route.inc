; `okena route 'GET https://api.example.com/v1/users/42 x-canary:yes' [-c FILE]`:
; where a request would go, without starting anything. It goes through the code that
; routes real requests (http_route_on, match_pick), over a head built from the words
; given. There is no client, so a `client.ip` condition counts as not met, and that
; is said; and what depends on the moment (which server of a pool, a split) is not
; decided: the pool is shown with its servers.

CR_MAX		:= 8192

bss
	align 8
	g_cr_dry	dd ?			; no client here
	g_cr_port	dd ?
	g_cr_tls	dd ?
	g_cr_ip		dd ?			; a client.ip condition was looked at
	g_cr_head:	rb CR_MAX
	g_cr_rec:	rb 1 shl H_SHIFT
end bss

cli_route:
	mov	rax,[g_argv]
	mov	r12,[rax+16]			; the words
	test	r12,r12
	jz	.usage
	mov	edi,3
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	mov	dword [g_cr_dry],1
	mov	rsi,r12
	call	cr_head
	jc	.usage
	mov	r13d,eax			; its length
	lea	rdi,[g_cr_head]
	mov	esi,r13d
	call	http_head_end
	test	eax,eax
	jle	.usage
	lea	rdi,[g_cr_head]
	mov	esi,eax
	lea	rdx,[g_hm]
	call	http_parse_request
	test	eax,eax
	jnz	.usage
	call	cr_listener
	test	rax,rax
	jz	.no_listener
	mov	r14,rax
	mov	edi,1
	call	out_select
	out_lit 'listener  '
	mov	rsi,[r14+LS_TEXT]
	mov	edx,[r14+LS_TLEN]
	call	out_str
	mov	edi,10
	call	out_char
	mov	rax,r14
	call	http_route_on
	cmp	eax,-1
	je	.no_route
	cmp	eax,-2
	je	.unsafe
	imul	rcx,rax,RT_SIZE
	lea	r13,[g_routes+rcx]
	out_lit 'route     '
	mov	rsi,[r13+RT_PATH]
	mov	edx,[r13+RT_PLEN]
	call	out_str
	cmp	dword [r13+RT_PREFIX],1		; (a prefix's *; a regex's text is its own)
	jne	@f
	mov	edi,'*'
	call	out_char
@@:
	mov	edi,10
	call	out_char
	mov	rcx,r13
	cmp	dword [rcx+RT_MATCH],0
	je	.routed
	lea	r15,[g_cr_rec]
	call	match_pick
	cmp	rcx,r13
	je	.routed
	mov	r13,rcx
	lea	rax,[g_mroutes]
	sub	rcx,rax
	mov	rax,rcx
	xor	edx,edx
	mov	ecx,RT_SIZE
	div	rcx
	mov	rbx,rax
	out_lit 'match     a block of the route'
	mov	edi,10
	call	out_char
.routed:
	call	cr_action
	cmp	dword [g_cr_ip],0
	je	@f
	out_lit 'note      a client.ip condition was looked at: with no client, it does not hold'
	mov	edi,10
	call	out_char
@@:
	xor	edi,edi
	jmp	exit_process
.no_route:
	out_lit 'no route: 404'
	mov	edi,10
	call	out_char
	mov	edi,1
	jmp	exit_process
.unsafe:
	out_lit 'a path that cannot be normalized safely: 400'
	mov	edi,10
	call	out_char
	mov	edi,1
	jmp	exit_process
.no_listener:
	mov	edi,2
	call	out_select
	out_lit 'okena: no http listener in this configuration'
	mov	edi,10
	call	out_char
	mov	edi,1
	jmp	exit_process
.usage:
	mov	edi,2
	call	out_select
	out_lit "usage: okena route 'METHOD URL [name:value ...]' [-c FILE]"
	mov	edi,10
	call	out_char
	mov	edi,2
	jmp	exit_process

; rsi = "GET https://host:port/path?q name:value ...": g_cr_head, eax = its length.
; g_cr_port, g_cr_tls. CF: not that.
cr_head:
	lea	rdi,[g_cr_head]
	mov	dword [g_cr_port],0
	mov	dword [g_cr_tls],0
	; the method
@@:
	lodsb
	test	al,al
	jz	.bad
	cmp	al,' '
	je	@f
	stosb
	jmp	@b
@@:
	mov	al,' '
	stosb
	; scheme, host
	mov	r8,rdi				; (the host goes after the first line)
	xor	r9d,r9d				; its length
	cmp	byte [rsi],'/'
	je	.path
	mov	rax,[rsi]
	mov	rdx,0x0000FFFFFFFFFFFF
	and	rdx,rax
	mov	rcx,'http:/'
	cmp	rdx,rcx
	jne	.https
	add	rsi,7
	jmp	.host
.https:
	mov	rcx,'https://'
	cmp	rax,rcx
	jne	.bad
	mov	dword [g_cr_tls],1
	add	rsi,8
.host:
	mov	r8,rsi
@@:
	mov	al,[rsi]
	test	al,al
	jz	.host_end
	cmp	al,'/'
	je	.host_end
	cmp	al,' '
	je	.host_end
	cmp	al,':'
	je	.port
	inc	rsi
	inc	r9d
	jmp	@b
.port:
	mov	r10,rsi
	inc	rsi
	xor	eax,eax
@@:
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	@f
	imul	eax,eax,10
	add	eax,ecx
	inc	rsi
	jmp	@b
@@:
	mov	[g_cr_port],eax
.host_end:
	cmp	byte [rsi],'/'
	je	.path
	; no path
	mov	al,'/'
	stosb
	jmp	.line_end
.path:
@@:
	mov	al,[rsi]
	test	al,al
	jz	.line_end
	cmp	al,' '
	je	.line_end
	stosb
	inc	rsi
	jmp	@b
.line_end:
	mov	rax,' HTTP/1.'
	stosq
	mov	al,'1'
	stosb
	mov	ax,0x0A0D
	stosw
	mov	eax,'Host'
	stosd
	mov	ax,' :'
	xchg	al,ah
	stosw
	test	r9d,r9d
	jnz	@f
	lea	r8,[.none]
	mov	r9d,1
@@:
	push	rsi
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	pop	rsi
	mov	ax,0x0A0D
	stosw
	; fields
.field:
	lodsb
	cmp	al,' '
	je	.field
	test	al,al
	jz	.end
	mov	dl,0
.f:
	stosb
	cmp	al,':'
	jne	@f
	test	dl,dl
	jnz	@f
	mov	dl,1
	mov	al,' '
	stosb
@@:
	lodsb
	test	al,al
	jz	.f_end
	cmp	al,' '
	jne	.f
.f_end:
	mov	cx,0x0A0D
	mov	[rdi],cx
	add	rdi,2
	test	al,al
	jnz	.field
.end:
	mov	ax,0x0A0D
	stosw
	lea	rax,[g_cr_head]
	sub	rdi,rax
	mov	eax,edi
	cmp	eax,CR_MAX - 64
	ja	.bad
	clc
	ret
.bad:
	stc
	ret
.none	db 'x'

; rax = the http listener a request like that reaches: its port, or its kind; 0 none
cr_listener:
	mov	ecx,[g_cr_port]
	test	ecx,ecx
	jnz	@f
	mov	ecx,80
	cmp	dword [g_cr_tls],0
	je	@f
	mov	ecx,443
@@:
	xor	edx,edx				; the first of the right kind
	xor	r8d,r8d				; the first at all
	xor	eax,eax
.next:
	cmp	eax,[g_plan_listeners]
	jae	.done
	imul	r9,rax,LS_SIZE
	lea	r9,[g_listeners+r9]
	inc	eax
	cmp	dword [r9+LS_KIND],LK_HTTP
	jne	.next
	test	r8,r8
	jnz	@f
	mov	r8,r9
@@:
	cmp	[r9+LS_PORT],ecx
	jne	@f
	mov	rax,r9
	ret
@@:
	mov	r10d,[r9+LS_TLS]
	test	r10d,r10d
	setnz	r10b
	movzx	r10d,r10b
	cmp	r10d,[g_cr_tls]
	jne	.next
	test	rdx,rdx
	jnz	.next
	mov	rdx,r9
	jmp	.next
.done:
	mov	rax,rdx
	test	rax,rax
	cmovz	rax,r8
	ret

; r13 = the route: what it does
cr_action:
	mov	r12d,[r13+RT_ACT]
	test	r12d,r12d
	jz	.pool
	dec	r12d
	imul	r12,r12,RA_SIZE
	lea	r12,[g_acts+r12]
	mov	eax,[r12+RA_AUTH]
	test	eax,eax
	jz	.no_auth
	dec	eax
	imul	rax,rax,AU_SIZE
	mov	ebx,[g_auths+rax+AU_KIND]
	out_lit 'filter    auth '
	cmp	ebx,AK_APIKEY
	jne	@f
	out_lit 'api_key'
@@:
	cmp	ebx,AK_BASIC
	jne	@f
	out_lit 'basic'
@@:
	cmp	ebx,AK_JWT
	jne	@f
	out_lit 'jwt'
@@:
	cmp	ebx,AK_MTLS
	jne	@f
	out_lit 'mtls'
@@:
	cmp	ebx,AK_FORWARD
	jne	@f
	out_lit 'forward'
@@:
	mov	edi,10
	call	out_char
.no_auth:
	cmp	dword [r12+RA_LCOUNT],0
	je	@f
	out_lit 'filter    limit, '
	mov	eax,[r12+RA_LCOUNT]
	call	out_u64
	mov	edi,10
	call	out_char
@@:
	cmp	dword [r12+RA_CORS],0
	je	@f
	out_lit 'filter    cors'
	mov	edi,10
	call	out_char
@@:
	cmp	dword [r12+RA_FPCT],0
	je	@f
	out_lit 'filter    fault, '
	mov	eax,[r12+RA_FPCT]
	call	out_u64
	out_lit '%'
	mov	edi,10
	call	out_char
@@:
	cmp	dword [r12+RA_CACHE],0
	je	@f
	out_lit 'filter    cache'
	mov	edi,10
	call	out_char
@@:
	cmp	dword [r12+RA_ZMIN],0
	je	@f
	out_lit 'filter    compress'
	mov	edi,10
	call	out_char
@@:
	cmp	dword [r12+RA_MPCT],0
	je	@f
	out_lit 'filter    mirror, '
	mov	eax,[r12+RA_MPCT]
	call	out_u64
	out_lit '% to '
	mov	eax,[r12+RA_MPOOL]
	imul	rax,rax,PL_SIZE
	mov	rsi,[g_pools+rax+PL_NAME]
	mov	edx,[g_pools+rax+PL_NLEN]
	call	out_str
	mov	edi,10
	call	out_char
@@:
	mov	eax,[r12+RA_HPCT]
	or	rax,[r12+RA_HAFTER]
	jz	@f
	out_lit 'filter    hedge'
	mov	edi,10
	call	out_char
@@:
	mov	eax,[r12+RA_FILES]
	test	eax,eax
	jz	@f
	dec	eax
	imul	rax,rax,FI_SIZE
	push	rax
	out_lit 'files     '
	pop	rax
	mov	rsi,[g_files+rax+FI_ROOT]
	mov	edx,[g_files+rax+FI_RLEN]
	call	out_str
	mov	edi,10
	jmp	out_char
@@:
	mov	eax,[r12+RA_CODE]
	test	eax,eax
	jz	@f
	cmp	eax,300				; respond's statuses are 2xx, 4xx, 5xx;
	jb	.respond			; a redirect's are 3xx
	cmp	eax,400
	jae	.respond
	push	rax
	out_lit 'redirect  '
	pop	rax
	call	out_u64
	mov	edi,' '
	call	out_char
	mov	rsi,[r12+RA_TGT]
	mov	edx,[r12+RA_TLEN]
	call	out_str
	mov	edi,10
	jmp	out_char
.respond:					; okena answers: the status, the body
	push	rax
	out_lit 'respond   '
	pop	rax
	call	out_u64
	cmp	qword [r12+RA_RBODY],0
	je	.respond_end
	out_lit ' "'
	mov	rsi,[r12+RA_RBODY]
	mov	edx,[r12+RA_RBLEN]
	call	out_str
	mov	edi,'"'
	call	out_char
.respond_end:
	mov	edi,10
	jmp	out_char
@@:
	cmp	dword [r12+RA_SPLIT],0
	je	.pool
	out_lit 'split     among the pools of the route'
	mov	edi,10
	jmp	out_char
.pool:
	mov	eax,[r13+RT_POOL]
	cmp	eax,-1
	je	.out
	imul	r12,rax,PL_SIZE
	lea	r12,[g_pools+r12]
	out_lit 'pool      '
	mov	rsi,[r12+PL_NAME]
	mov	edx,[r12+PL_NLEN]
	test	rsi,rsi
	jz	@f
	call	out_str
@@:
	mov	edi,10
	call	out_char
	mov	ebx,[r12+PL_FIRST]
	mov	r12d,[r12+PL_COUNT]
.server:
	test	r12d,r12d
	jz	.out
	dec	r12d
	out_lit 'server    '
	imul	rax,rbx,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	call	out_str
	mov	edi,10
	call	out_char
	inc	ebx
	jmp	.server
.out:
	ret
