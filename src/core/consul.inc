; `discover consul service=NAME [api=HOST:PORT] [dc=DC] [tag=TAG] [token=PATH]
; [port=N] [max=64]`: a pool's servers are the instances of a Consul service
; whose health checks pass, as the agent's HTTP API lists them.
;
; The control process asks once a second (GET /v1/health/service/NAME?passing=1,
; over HTTP/1.0 so the answer comes whole and the connection ends) and
; publishes what changed, as for `discover file`. An instance is served at its
; service address, or its node's when it has none, on the service's port (or
; `port=` when it registered none), with its weight for passing checks. One whose
; address is a name, not an IP, is left out. The ACL token, when there is one,
; is read from its file each time, so that it may be rotated.
;
; Consul not answering, or answering what cannot be read, changes nothing: the
; servers known go on, and it is said once. An empty list is Consul saying none
; passes, and is believed. The API is the local agent's, over plain HTTP, as
; Consul has it by default (127.0.0.1:8500).

CS_SVC		:= 0			; q: the service's name
CS_SVCLEN	:= 8			; d
CS_DCLEN	:= 12			; d
CS_DC		:= 16			; q: dc=, 0 none
CS_TAG		:= 24			; q: tag=, 0 none
CS_TAGLEN	:= 32			; d
CS_TOKEN	:= 40			; q: the token's path, 0 none (as KB_TOKEN: kb_token reads it)
CS_TOKLEN	:= 48			; d
CS_SALEN	:= 64			; d
CS_SA		:= 72			; 28
CS_SIZE		:= 128
assert CS_TOKEN = KB_TOKEN & CS_TOKLEN = KB_TOKLEN

bss
	align 8
	g_plan_cs:	rb CS_SIZE * DISC_SOURCES	; per source (plan)
	g_cs_req:	rb KB_TOKEN_MAX + 2048
end bss

; ebx = a consul group: ask, and publish. eax = seconds to the next look.
disc_consul_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	r13d,[r12+GR_DISC]
	imul	r14,r13,CS_SIZE
	lea	r14,[g_plan_cs+r14]
	cmp	qword [g_dk_buf],0
	jne	@f
	xor	edi,edi
	mov	esi,DK_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.unreachable
	mov	[g_dk_buf],rax
@@:
	xor	edx,edx				; the token
	cmp	qword [r14+CS_TOKEN],0
	je	@f
	call	kb_token
	test	eax,eax
	jz	.no_token
	mov	edx,eax
@@:
	call	cs_request			; g_cs_req, r15d = its length
	; the agent
	movzx	edi,word [r14+CS_SA]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.unreachable
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO			; (a connect's too)
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	lea	rsi,[r14+CS_SA]
	mov	edx,[r14+CS_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.unreachable_close
	mov	edi,ebx
	lea	rsi,[g_cs_req]
	mov	edx,r15d
	call	dk_write_all
	jc	.unreachable_close
	; the whole answer, until it closes
	xor	r15d,r15d
.read:
	mov	edi,ebx
	mov	rsi,[g_dk_buf]
	add	rsi,r15
	mov	edx,DK_BUF - 1
	sub	edx,r15d
	jz	.unreadable_close
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	.unreachable_close
	jz	.read_all
	add	r15d,eax
	jmp	.read
.read_all:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	rsi,[g_dk_buf]
	cmp	r15d,16
	jb	.unreadable
	cmp	dword [rsi+8],' 200'
	jne	.status
	mov	rcx,r15
	mov	rdi,rsi
.head:
	cmp	rcx,4
	jb	.unreadable
	cmp	dword [rdi],0x0A0D0A0D
	je	.body
	inc	rdi
	dec	rcx
	jmp	.head
.body:
	lea	rsi,[rdi+4]
	mov	r13,[g_dk_buf]			; (r13: the end, for the parser)
	add	r13,r15
	call	cs_parse			; g_disc_new; CF when it cannot be read
	mov	r13d,[r12+GR_DISC]
	jc	.unreadable
	call	disc_publish
	mov	dword [g_disc_said+r13*4],0
	jmp	.out
.no_token:
	mov	eax,4
	cstring str_cs_tok, ': no token to read'
	lea	rsi,[str_cs_tok]
	mov	edx,str_cs_tok.len
	jmp	.tell
.status:
	cmp	dword [rsi+8],' 403'
	je	.forbidden
	mov	eax,3
	cstring str_cs_status, ': Consul refused the question (not 200)'
	lea	rsi,[str_cs_status]
	mov	edx,str_cs_status.len
	jmp	.tell
.forbidden:
	mov	eax,5
	cstring str_cs_403, ': Consul said 403: the ACL token is missing, or may not read the service'
	lea	rsi,[str_cs_403]
	mov	edx,str_cs_403.len
	jmp	.tell
.unreadable_close:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.unreadable:
	mov	eax,2
	lea	rsi,[str_dk_bad]
	mov	edx,str_dk_bad.len
	jmp	.tell
.unreachable_close:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.unreachable:
	mov	eax,1
	cstring str_cs_gone, ': no answer from the agent'
	lea	rsi,[str_cs_gone]
	mov	edx,str_cs_gone.len
.tell:
	cmp	[g_disc_said+r13*4],eax
	je	.out
	mov	[g_disc_said+r13*4],eax
	push	rsi
	push	rdx
	call	log_begin
	out_lit 'discover consul '
	mov	rsi,[r14+CS_SVC]
	mov	edx,[r14+CS_SVCLEN]
	call	out_str
	pop	rdx
	pop	rsi
	call	out_str
	out_lit '; keeping the servers known so far'
	mov	edi,AL_DISCOVERY
	call	log_end_alert
.out:
	mov	eax,1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r14 = source, edx = the token's length (in g_kb_tok), 0 none: the question
; in g_cs_req, r15d = its length
cs_request:
	push	rdx
	lea	rdi,[g_cs_req]
	cstring str_cs_get, 'GET /v1/health/service/'
	lea	rsi,[str_cs_get]
	mov	ecx,str_cs_get.len
	rep	movsb
	mov	rsi,[r14+CS_SVC]
	mov	ecx,[r14+CS_SVCLEN]
	call	cs_enc
	cstring str_cs_passing, '?passing=1'
	lea	rsi,[str_cs_passing]
	mov	ecx,str_cs_passing.len
	rep	movsb
	cmp	qword [r14+CS_DC],0
	je	@f
	mov	dword [rdi],'&dc='
	add	rdi,4
	mov	rsi,[r14+CS_DC]
	mov	ecx,[r14+CS_DCLEN]
	call	cs_enc
@@:
	cmp	qword [r14+CS_TAG],0
	je	@f
	mov	dword [rdi],'&tag'
	mov	byte [rdi+4],'='
	add	rdi,5
	mov	rsi,[r14+CS_TAG]
	mov	ecx,[r14+CS_TAGLEN]
	call	cs_enc
@@:
	cstring str_cs_http, ' HTTP/1.0',13,10,'Host: consul',13,10
	lea	rsi,[str_cs_http]
	mov	ecx,str_cs_http.len
	rep	movsb
	pop	rcx
	test	ecx,ecx
	jz	@f
	cstring str_cs_token, 'X-Consul-Token: '
	lea	rsi,[str_cs_token]
	push	rcx
	mov	ecx,str_cs_token.len
	rep	movsb
	pop	rcx
	lea	rsi,[g_kb_tok]
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
@@:
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[g_cs_req]
	sub	rdi,rax
	mov	r15d,edi
	ret

; rsi/ecx = bytes, rdi = out: percent-encoded but for letters, digits and -._~
cs_enc:
	test	ecx,ecx
	jz	.out
	movzx	eax,byte [rsi]
	inc	rsi
	dec	ecx
	mov	edx,eax
	or	edx,0x20
	cmp	edx,'a'
	jb	@f
	cmp	edx,'z'
	jbe	.plain
@@:
	cmp	al,'0'
	jb	@f
	cmp	al,'9'
	jbe	.plain
@@:
	cmp	al,'-'
	je	.plain
	cmp	al,'.'
	je	.plain
	cmp	al,'_'
	je	.plain
	cmp	al,'~'
	je	.plain
	mov	byte [rdi],'%'
	mov	edx,eax
	shr	edx,4
	mov	dl,[dk_request.hex+rdx]
	mov	[rdi+1],dl
	and	eax,15
	mov	al,[dk_request.hex+rax]
	mov	[rdi+2],al
	add	rdi,3
	jmp	cs_enc
.plain:
	stosb
	jmp	cs_enc
.out:
	ret

; rsi at the body, r13 its end, r12 = group: g_disc_new from the list. CF
; when it is not a list.
cs_parse:
	push	rbx
	push	r14
	push	r15
	mov	dword [g_disc_new+DX_COUNT],0
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],'['
	jne	.bad
	inc	rsi
.entry:
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],']'
	je	.done
	mov	rbx,rsi				; the entry's object
	call	cs_entry
	mov	rsi,rbx
	call	js_skip
	jc	.bad
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],','
	jne	@f
	inc	rsi
	jmp	.entry
@@:
	cmp	byte [rsi],']'
	jne	.bad
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret

; rbx = an entry ({"Node": {...}, "Service": {...}, "Checks": [...]}): into
; g_disc_new when it can be served
cs_entry:
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[r12+GR_SLOTS]
	jae	.no
	mov	rsi,rbx
	js_key 'Service'
	call	js_find
	jc	.no
	mov	r15,rsi				; the service's object
	; its port, or port=
	js_key 'Port'
	call	js_find
	jc	@f
	call	js_port
	jnc	.port
@@:
	xor	eax,eax
.port:
	mov	r14d,eax
	test	r14d,r14d
	jnz	@f
	mov	r14d,[r12+GR_PORT]		; (none registered: port=)
@@:
	test	r14d,r14d
	jz	.no
	; its weight when passing (1 when not said)
	mov	rsi,r15
	js_key 'Weights'
	call	js_find
	mov	eax,1
	jc	.weighed
	js_key 'Passing'
	call	js_find
	mov	eax,1
	jc	.weighed
	call	js_port
	jnc	@f
	mov	eax,1
@@:
	test	eax,eax
	jnz	.weighed
	inc	eax
.weighed:
	push	rax
	; its address, else its node's
	mov	rsi,r15
	js_key 'Address'
	call	js_find
	jc	.node
	call	js_ws
	call	js_str
	jc	.node
	test	ecx,ecx
	jnz	.address
.node:
	mov	rsi,rbx
	js_key 'Node'
	call	js_find
	jc	.no_weight
	js_key 'Address'
	call	js_find
	jc	.no_weight
	call	js_ws
	call	js_str
	jc	.no_weight
	test	ecx,ecx
	jz	.no_weight
.address:
	cmp	ecx,45
	ja	.no_weight
	; "a.b.c.d:P" or "[v6]:P"
	mov	rsi,rdi
	lea	rdi,[g_disc_tok]
	xor	r8d,r8d
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],':'
	sete	al
	or	r8b,al
	inc	edx
	jmp	@b
@@:
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],'['
	inc	rdi
@@:
	rep	movsb
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],']'
	inc	rdi
@@:
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,r14d
	call	dk_decimal
	lea	rsi,[g_disc_tok]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[g_disc_tok]
	lea	rdx,[g_disc_ad]
	xor	ecx,ecx
	call	parse_address
	jc	.no_weight			; (a name: left out)
	mov	eax,[g_disc_ad+AD_KIND]
	cmp	eax,ADDR_V4
	je	@f
	cmp	eax,ADDR_V6
	jne	.no_weight
@@:
	mov	eax,[g_disc_new+DX_COUNT]
	inc	dword [g_disc_new+DX_COUNT]
	imul	rax,rax,DE_SIZE
	lea	rdi,[g_disc_new+DX_E+rax]
	mov	rcx,[g_disc_ad+AD_IP]
	mov	[rdi+DE_ADDR],rcx
	mov	rcx,[g_disc_ad+AD_IP+8]
	mov	[rdi+DE_ADDR+8],rcx
	mov	dword [rdi+DE_FAMILY],6
	cmp	dword [g_disc_ad+AD_KIND],ADDR_V4
	jne	@f
	mov	dword [rdi+DE_FAMILY],4
@@:
	mov	[rdi+DE_PORT],r14d
	pop	rax
	mov	[rdi+DE_WEIGHT],eax
	mov	dword [rdi+DE_BACKUP],0
	ret
.no_weight:
	pop	rax
.no:
	ret
