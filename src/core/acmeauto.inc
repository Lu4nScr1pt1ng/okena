; Automatic HTTPS with nothing to say but `auto`:
;
;   http :443 { tls { auto } host example.com www.example.com { ... } }
;   http :80 { route /* { to pool app } }
;
; A certificate for each name of the listener's host blocks (a wildcard's only
; with DNS-01), as `acme NAME` lines would be; without `okena { acme ... }`, the
; directory /var/lib/okena/acme and Let's Encrypt.
;
; And for every name okena gets from the CA (auto's, `acme` lines'), a plain http
; listener answers 308 to https://NAME[:PORT]/the-same-target (the port the tls
; block's listener has, said unless 443), the ACME challenges first; `redirect off`
; in the tls block keeps plain http for its names.

rodata
	acme_le_dir	db 'https://acme-v02.api.letsencrypt.org/directory'
	acme_le_dir.len = $ - acme_le_dir
	acme_def_dir	db '/var/lib/okena/acme'
	acme_le_stg	db 'https://acme-staging-v02.api.letsencrypt.org/directory'
	acme_le_stg.len = $ - acme_le_stg
	acme_def_dir.len = $ - acme_def_dir
end rodata

; `auto` and no `okena { acme }`: Let's Encrypt, its files in /var/lib/okena/acme
acme_auto_defaults:
	cmp	dword [g_plan_acme+ACM_ON],0
	jne	.out
	lea	rax,[acme_def_dir]
	mov	[g_plan_acme+ACM_DIR],rax
	mov	dword [g_plan_acme+ACM_DIRL],acme_def_dir.len
	lea	rax,[acme_le_dir]
	mov	[g_plan_acme+ACM_CA],rax
	mov	dword [g_plan_acme+ACM_CAL],acme_le_dir.len
	mov	dword [g_plan_acme+ACM_ON],1
	lea	rax,[acme_le_stg]
	mov	[g_plan_acme+ACM_STG],rax
	mov	dword [g_plan_acme+ACM_STGL],acme_le_stg.len
.out:
	ret

; rbx = the okena acme node: staging=URL (a CA that issues certificates nobody
; trusts, with limits to spare), asked first after an order failed, so a name
; that keeps failing does not use up the CA's; Let's Encrypt's own when ca= is
; Let's Encrypt and none is said. staging=off: none.
compile_acme_staging:
	mov	rdi,rbx
	cstring .k_stg, 'staging',0
	lea	rsi,[.k_stg]
	call	node_option
	test	rax,rax
	jz	.le
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,3
	jne	@f
	cmp	word [rsi],'of'
	jne	@f
	cmp	byte [rsi+2],'f'
	je	.out
@@:
	cmp	ecx,9
	jb	.bad
	cmp	ecx,ACME_URL - 1
	ja	.bad
	mov	rdx,'https://'
	cmp	[rsi],rdx
	jne	.bad
	call	acme_safe
	jc	.bad
	mov	[g_plan_acme+ACM_STG],rsi
	mov	[g_plan_acme+ACM_STGL],ecx
.out:
	ret
.le:
	cmp	dword [g_plan_acme+ACM_CAL],acme_le_dir.len
	jne	.out
	mov	rsi,[g_plan_acme+ACM_CA]
	lea	rdi,[acme_le_dir]
	mov	ecx,acme_le_dir.len
	repe	cmpsb
	jne	.out
	lea	rax,[acme_le_stg]
	mov	[g_plan_acme+ACM_STG],rax
	mov	dword [g_plan_acme+ACM_STGL],acme_le_stg.len
	ret
.bad:
	call	log_begin
	out_lit 'acme: staging= is a CA',39,'s directory (https://), or off'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; the acme process starting: each certificate whose DIR/NAME/status says its
; last order failed, marked so (the staging CA first, across restarts too)
acme_failed_load:
	push	rbx
	xor	ebx,ebx
.cert:
	call	acme_more
	jc	.done
	cstring .f_status, '/status',0
	lea	rsi,[.f_status]
	call	acme_path
	call	acme_read
	jc	.next
	lea	rsi,[g_ac_file]
	mov	ecx,eax
	sub	ecx,8
	jle	.next
.look:
	cmp	dword [rsi],' fai'
	jne	@f
	cmp	dword [rsi+4],'led '
	jne	@f
	mov	byte [g_ac_failed+rbx],1
	jmp	.next
@@:
	inc	rsi
	dec	ecx
	jnz	.look
.next:
	inc	ebx
	jmp	.cert
.done:
	pop	rbx
	ret

; rdi = a listener node: eax = its port (HOST:PORT, :PORT or PORT), 0 none
acme_listener_port:
	xor	eax,eax
	mov	rcx,[rdi+N_ARGS]
	test	rcx,rcx
	jz	.out
	mov	rsi,[rcx+A_VAL]
	mov	ecx,[rcx+A_VLEN]
	mov	edx,ecx
@@:
	test	edx,edx
	jz	.digits
	cmp	byte [rsi+rdx-1],':'
	je	.digits
	dec	edx
	jmp	@b
.digits:
	cmp	edx,ecx
	jae	.out
	movzx	r8d,byte [rsi+rdx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	.bad
	imul	eax,eax,10
	add	eax,r8d
	cmp	eax,65535
	ja	.bad
	inc	edx
	jmp	.digits
.bad:
	xor	eax,eax
.out:
	ret

; rsi = a path, NUL-ended: it and its parents made (parents 0755, it edx), as
; mkdir -p does
mkdir_p:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	mov	ebx,1
.ch:
	movzx	eax,byte [r12+rbx]
	test	al,al
	jz	.last
	cmp	al,'/'
	jne	.next
	mov	byte [r12+rbx],0
	mov	edi,AT_FDCWD
	mov	rsi,r12
	mov	edx,0x1ED
	mov	eax,SYS_mkdirat_
	syscall
	mov	byte [r12+rbx],'/'
.next:
	inc	ebx
	jmp	.ch
.last:
	mov	edi,AT_FDCWD
	mov	rsi,r12
	mov	edx,r13d
	mov	eax,SYS_mkdirat_
	syscall
	pop	r13
	pop	r12
	pop	rbx
	ret

; A request on a plain http listener, after the challenges: a name okena has a
; certificate from the CA for gets 308 to https. ebx = session, r15 = state.
; CF: not one (on to the routes).
acme_redirect:
	cmp	dword [g_plan_acme+ACM_REDIRN],0
	je	.no
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_TLS],0
	jne	.no
	lea	rcx,[g_hm]
	mov	edx,[rcx+HM_HOST]
	cmp	edx,-1
	je	.no
	imul	rdx,rdx,HF_SIZE
	lea	rdx,[rcx+HM_HDRS+rdx]
	mov	rsi,[rdx+HF_VALUE]
	mov	edx,[rdx+HF_VLEN]
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
	cmp	byte [rsi+rdx-1],'.'
	jne	@f
	dec	edx
@@:
	; rsi/edx = the host: each certificate's names
	push	r12
	push	r13
	push	r14
	xor	r12d,r12d
.cert:
	cmp	r12d,[g_plan_acme+ACM_NCERT]
	jae	.none
	mov	eax,r12d
	shl	eax,4
	mov	r14d,[g_plan_acme+ACM_CERT+rax+12]
	test	r14d,r14d
	jz	.cert_next
	mov	r8,[g_plan_acme+ACM_CERT+rax]
	mov	r13d,[g_plan_acme+ACM_CERT+rax+8]
.name:
	mov	rdi,[r8+A_VAL]
	mov	ecx,[r8+A_VLEN]
	cmp	ecx,2
	jb	.exact
	cmp	word [rdi],'*.'
	jne	.exact
	; *.parent: one label more than parent
	sub	ecx,1				; ".parent"
	cmp	edx,ecx
	jbe	.name_next
	push	rsi
	push	rdx
	mov	eax,edx
	sub	eax,ecx				; the label's length
	lea	r9,[rsi+rax]
	push	rdi
	mov	rdi,rsi				; no dot in the label
	mov	ecx,eax
	mov	al,'.'
	repne	scasb
	pop	rdi
	je	.wild_no
	mov	rsi,r9
	inc	rdi
	mov	edx,[r8+A_VLEN]
	dec	edx
	call	.same
	pop	rdx
	pop	rsi
	je	.found
	jmp	.name_next
.wild_no:
	pop	rdx
	pop	rsi
	jmp	.name_next
.exact:
	cmp	ecx,edx
	jne	.name_next
	call	.same
	je	.found
.name_next:
	add	r8,A_SIZE
	dec	r13d
	jnz	.name
.cert_next:
	inc	r12d
	jmp	.cert
.none:
	pop	r14
	pop	r13
	pop	r12
.no:
	stc
	ret
; rsi/edx = host, rdi = the name (edx bytes): ZF when the same, ignoring case.
; Keeps rsi, rdx, rdi.
.same:
	xor	ecx,ecx
@@:
	cmp	ecx,edx
	jae	.same_yes
	movzx	eax,byte [rsi+rcx]
	movzx	r9d,byte [rdi+rcx]
	or	eax,0x20
	or	r9d,0x20
	cmp	eax,r9d
	jne	.same_no
	inc	ecx
	jmp	@b
.same_yes:
	xor	eax,eax				; (ZF)
	ret
.same_no:
	or	eax,1				; (not ZF)
	ret
.found:
	; 308 https://host[:port]target
	push	rsi
	push	rdx
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	dword [r15+H_STATUS],308
	mov	edi,308
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 308 Permanent Redirect',13,10,'Location: https://'
	pop	rcx
	pop	rsi
	rep	movsb
	cmp	r14d,443
	je	@f
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,r14d
	call	fmt_u64
@@:
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
	pop	r14
	pop	r13
	pop	r12
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	add	rsp,8				; (not back to the caller: sent)
	jmp	h_send
