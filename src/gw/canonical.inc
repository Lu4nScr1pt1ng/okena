; `canonical NAME` on an http listener: www and the apex are one site. A request
; whose Host is NAME with a "www." more, or NAME's without its "www.", is sent
; to NAME with a 301 (scheme, Host's port and target kept). Other names, and
; addresses, are left as they are: a health check by address is not moved.

; Listener: g_cmp_canon(len), from `canonical`
compile_canonical:
	mov	qword [g_cmp_canon],0
	mov	dword [g_cmp_canonlen],0
	mov	rdi,r12
	mov	ecx,DIR_CANONICAL
	call	find_child
	test	rax,rax
	jz	.out
	mov	rax,[rax+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[g_cmp_canon],rcx
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,253
	ja	.out
	mov	[g_cmp_canonlen],ecx
.out:
	ret

bss
	g_cmp_canon	dq ?
	g_cmp_canonlen	dd ?
end bss

; Before routing: CF clear and not back when it answered with the redirect.
canonical_redirect:
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	lea	r8,[g_listeners+rcx]
	mov	r9d,[r8+LS_CANONLEN]
	test	r9d,r9d
	jz	.no
	lea	rcx,[g_hm]
	mov	edx,[rcx+HM_HOST]
	cmp	edx,-1
	je	.no
	imul	rdx,rdx,HF_SIZE
	lea	rdx,[rcx+HM_HDRS+rdx]
	mov	rsi,[rdx+HF_VALUE]
	mov	r10d,[rdx+HF_VLEN]		; with its port
	mov	edx,r10d
	mov	ecx,edx				; without the port
@@:
	test	ecx,ecx
	jz	@f
	dec	ecx
	cmp	byte [rsi+rcx],']'
	je	@f
	cmp	byte [rsi+rcx],':'
	jne	@b
	mov	edx,ecx
@@:
	test	edx,edx
	jz	.no
	mov	r11d,edx			; the host's length, before a final dot
	cmp	byte [rsi+rdx-1],'.'
	jne	@f
	dec	edx
@@:
	mov	rdi,[r8+LS_CANON]
	; www.NAME: to NAME
	lea	eax,[r9+4]
	cmp	edx,eax
	jne	.apex
	call	.www_at_rsi
	jne	.apex
	push	rsi
	add	rsi,4
	mov	ecx,r9d
	call	.same
	pop	rsi
	je	.found
.apex:
	; NAME is www.HOST: to NAME
	lea	eax,[rdx+4]
	cmp	r9d,eax
	jne	.no
	push	rsi
	mov	rsi,rdi
	call	.www_at_rsi
	pop	rsi
	jne	.no
	push	rdi
	add	rdi,4
	mov	ecx,edx
	call	.same
	pop	rdi
	je	.found
.no:
	stc
	ret
; rsi: ZF when it starts with "www." (any case)
.www_at_rsi:
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'www.' or 0x20202020
	ret
; rsi, rdi, ecx bytes: ZF when the same, ignoring case. Keeps rsi, rdi.
.same:
	push	rdx
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	movzx	eax,byte [rsi+rdx]
	movzx	r11d,byte [rdi+rdx]
	or	eax,0x20
	or	r11d,0x20
	inc	edx
	cmp	eax,r11d
	je	@b
	pop	rdx
	ret					; (not ZF)
@@:
	pop	rdx
	xor	eax,eax
	ret
.found:
	; 301 scheme://NAME[:port]target
	push	rsi
	push	r10
	push	r8
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; its body is not read: close after
@@:
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	dword [r15+H_STATUS],301
	mov	edi,301
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 301 Moved Permanently',13,10,'Location: http'
	pop	r8
	cmp	dword [r8+LS_TLS],0
	je	@f
	mov	byte [rdi],'s'
	inc	rdi
@@:
	memit_x '://'
	mov	rsi,[r8+LS_CANON]
	mov	ecx,[r8+LS_CANONLEN]
	rep	movsb
	pop	r10				; the Host as written: its port, if any
	pop	rsi
	mov	ecx,r10d
@@:
	test	ecx,ecx
	jz	.target
	dec	ecx
	cmp	byte [rsi+rcx],']'
	je	.target
	cmp	byte [rsi+rcx],':'
	jne	@b
	sub	r10d,ecx
	add	rsi,rcx
	mov	ecx,r10d
	cmp	ecx,7
	ja	.target
	rep	movsb
.target:
	lea	rax,[g_hm]
	mov	rsi,[rax+HM_TARGET]
	mov	ecx,[rax+HM_TLEN]
	test	ecx,ecx
	jz	.slash
	cmp	byte [rsi],'/'
	jne	.slash
	cmp	ecx,4096
	ja	.slash
	rep	movsb
	jmp	@f
.slash:
	mov	byte [rdi],'/'
	inc	rdi
@@:
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
	xchg	rsi,rdi
	add	rsp,8				; (not back to the caller: sent)
	jmp	h_send
