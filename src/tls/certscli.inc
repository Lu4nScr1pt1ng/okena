; `okena certs [-c FILE]`: the certificates a configuration serves, one a line:
; their names, who issued them, until when (and how long that is), and where they
; come from: a file, the ACME CA (with what the acme process last did and when it
; renews: DIR/NAME/status, which it writes), one okena signs until the CA's comes,
; or on demand (DIR/on_demand.list).

bss
	align 8
	g_tls_src	rb MAX_TLS		; 0 a file, 1 ACME (its files), 2 ACME (signed here meanwhile), 3 the local CA, 4 local, no CA yet
	g_tls_acme	rb MAX_TLS		; (1, 2: which of acme's)
	g_cc_now	dq ?
	g_cc_from	db ?
	g_cc_buf:	rb 512
end bss

; rdi = out, rax = seconds since 1970: "YYYY-MM-DD HH:MM" (UTC), rdi past it
fmt_date:
	push	rdi
	call	x5_utctime			; g_x5_time: YYMMDDHHMMSSZ
	pop	rdi
	mov	word [rdi],'20'
	mov	ax,word [g_x5_time]
	mov	[rdi+2],ax
	mov	byte [rdi+4],'-'
	mov	ax,word [g_x5_time+2]
	mov	[rdi+5],ax
	mov	byte [rdi+7],'-'
	mov	ax,word [g_x5_time+4]
	mov	[rdi+8],ax
	mov	byte [rdi+10],' '
	mov	ax,word [g_x5_time+6]
	mov	[rdi+11],ax
	mov	byte [rdi+13],':'
	mov	ax,word [g_x5_time+8]
	mov	[rdi+14],ax
	add	rdi,16
	ret

; ------------------------------------------------- the acme process's status

; ebx = a certificate, edx = 1 when it was just got, 0 when the order failed:
; DIR/NAME/status, a line: what happened, when, and what comes next
acme_status_write:
	push	r12
	mov	r12d,edx
	lea	rdi,[g_cc_buf]
	push	rdi
	call	acme_now
	pop	rdi
	call	fmt_date
	test	r12d,r12d
	jz	.failed
	memit_x ' UTC: got from the CA; renewal on '
	push	rdi
	mov	rax,[g_ac_due+rbx*8]
	pop	rdi
	call	fmt_date
	jmp	.write
.failed:
	memit_x ' UTC: the order failed ('
	mov	rsi,[g_ac_why]
	call	fmt_cstr
	cmp	dword [g_ac_st],0
	je	@f
	memit_x ', HTTP '
	mov	eax,[g_ac_st]
	call	fmt_u64
@@:
	memit_x '); asked again on '
	push	rdi
	mov	rax,[g_ac_due+rbx*8]
	pop	rdi
	call	fmt_date
.write:
	memit_x ' UTC',10
	push	rdi
	cstring .f_status, '/status',0
	lea	rsi,[.f_status]
	call	acme_path
	pop	rdx
	lea	rsi,[g_cc_buf]
	sub	rdx,rsi
	call	acme_write
	pop	r12
	ret

; ------------------------------------------------------------------ the CLI

cli_certs:
	mov	edi,2
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	mov	edi,1
	call	out_select
	call	acme_now
	mov	[g_cc_now],rax
	out_lit 'NAMES                              ISSUER                    NOT AFTER          LEFT  FROM',10
	push	rbx
	xor	ebx,ebx
.entry:
	cmp	ebx,[g_plan_tls]
	jae	.on_demand
	imul	rax,rbx,TL_SIZE
	lea	r9,[g_tls+rax]
	cmp	dword [r9+TL_GROUP],0x40000000	; (a pool's client certificate)
	jae	.next
	mov	esi,[r9+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	mov	r8d,[r9+TL_CLEN]
	add	r8,rsi
	call	chain_entry
	jc	.next
	mov	rsi,rax
	mov	edx,ecx
	call	certs_line
	; where it comes from
	movzx	eax,byte [g_tls_src+rbx]
	test	eax,eax
	jnz	@f
	out_lit 'a file'
	jmp	.eol
@@:
	cmp	eax,3
	jne	@f
	out_lit 'the local CA'
	jmp	.eol
@@:
	cmp	eax,4
	jne	@f
	out_lit 'local (no local CA yet: signed here)'
	jmp	.eol
@@:
	cmp	eax,2
	jne	.acme
	out_lit 'acme (signed here until the CA',39,'s comes)'
	jmp	.eol
.acme:
	out_lit 'acme'
	movzx	eax,byte [g_tls_acme+rbx]
	push	rbx
	mov	ebx,eax
	call	certs_status
	pop	rbx
.eol:
	mov	edi,10
	call	out_char
.next:
	inc	ebx
	jmp	.entry
.on_demand:
	; the names DIR/on_demand.list holds
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.done
	mov	ebx,-1
	lea	rsi,[od_list_add.f_list]
	call	acme_path
	call	acme_read
	jc	.done
	cmp	eax,16000
	jbe	@f
	mov	eax,16000
@@:
	push	r12
	push	r13
	lea	r12,[g_ac_body]
	mov	r13d,eax
	lea	rsi,[g_ac_file]
	mov	rdi,r12
	mov	ecx,eax
	rep	movsb
	xor	ecx,ecx
.line:
	cmp	ecx,r13d
	jae	.lines_done
	mov	edx,ecx
@@:
	cmp	ecx,r13d
	jae	@f
	cmp	byte [r12+rcx],10
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	mov	eax,ecx
	sub	eax,edx
	jz	.line_next
	cmp	eax,253
	ja	.line_next
	; its certificate: DIR/NAME/cert.pem
	mov	[g_od_namel],eax
	mov	[g_od_nl],eax			; (as on-demand certificate 0: acme_path's)
	lea	rsi,[r12+rdx]
	lea	rdi,[g_od_names]
	mov	ecx,eax
	rep	movsb
	xor	eax,eax
	call	od_arg
	mov	ebx,ACME_CERTS
	lea	rsi,[acme_file_due.f_cert]
	call	acme_path
	call	acme_read
	jc	.line_next
	lea	rsi,[g_ac_file]
	mov	edx,eax
	lea	rdi,[g_ac_der]
	call	pem_first_cert
	test	eax,eax
	jz	.line_next
	lea	rsi,[g_ac_der]
	mov	edx,eax
	call	certs_line
	out_lit 'on demand'
	call	certs_status
	mov	edi,10
	call	out_char
.line_next:
	pop	rcx
	inc	ecx
	jmp	.line
.lines_done:
	pop	r13
	pop	r12
.done:
	pop	rbx
	call	out_flush
	xor	edi,edi
	jmp	exit_process

; ebx = one of acme's certificates: its DIR/NAME/status, after ": "
certs_status:
	cstring .f_status, '/status',0
	lea	rsi,[.f_status]
	call	acme_path
	call	acme_read
	jc	.none
	test	eax,eax
	jz	.none
	lea	rsi,[g_ac_file]
	mov	edx,eax
	cmp	byte [rsi+rdx-1],10
	jne	@f
	dec	edx
@@:
	push	rsi
	push	rdx
	out_lit ': '
	pop	rdx
	pop	rsi
	jmp	out_str
.none:
	out_lit ': nothing asked of the CA yet (or DIR not readable)'
	ret

; rsi/edx = a certificate's DER: its names (subjectAltName's dNSNames, or its
; CN), its issuer's CN (or "itself"), its notAfter, the days left: in columns
certs_line:
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13d,edx
	call	x509_locate
	test	eax,eax
	jz	.out
	; the names
	xor	r14d,r14d			; columns written
	mov	rsi,[g_x509_ext]
	test	rsi,rsi
	jz	.cn
.ext:
	cmp	rsi,[g_x509_extend]
	jae	.cn
	mov	rdx,[g_x509_extend]
	call	der_read
	jc	.cn
	push	r8
	lea	rdx,[rsi+rcx]
	call	der_read			; OID
	jc	.ext_next
	cmp	ecx,3
	jne	.ext_next
	cmp	word [rsi],0x1D55
	jne	.ext_next
	cmp	byte [rsi+2],0x11		; subjectAltName
	jne	.ext_next
	mov	rsi,r8
	call	der_read
	jc	.ext_next
	cmp	al,1
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.ext_next
@@:
	cmp	al,4
	jne	.ext_next
	lea	rdx,[rsi+rcx]
	call	der_read			; GeneralNames
	jc	.ext_next
	lea	rdx,[rsi+rcx]
.gn:
	cmp	rsi,rdx
	jae	.ext_next
	call	der_read
	jc	.ext_next
	push	r8
	push	rdx
	cmp	al,0x82				; dNSName
	jne	.gn_next
	test	r14d,r14d
	jz	@f
	push	rsi
	push	rcx
	mov	edi,' '
	call	out_char
	pop	rcx
	pop	rsi
	inc	r14d
@@:
	add	r14d,ecx
	mov	edx,ecx
	call	out_str
.gn_next:
	pop	rdx
	pop	rsi
	jmp	.gn
.ext_next:
	pop	rsi
	jmp	.ext
.cn:
	test	r14d,r14d
	jnz	.names_done
	mov	rsi,[g_x509_subj]
	mov	rdx,[g_x509_subjend]
	call	certs_cn
	add	r14d,eax
.names_done:
	mov	eax,35
	call	.pad
	; the issuer
	mov	rsi,[g_x509_iss]
	mov	rdx,[g_x509_issend]
	mov	rcx,[g_x509_subj]
	mov	rax,[g_x509_subjend]
	sub	rax,rcx
	mov	r8,rdx
	sub	r8,rsi
	cmp	rax,r8
	jne	.other
	push	rsi
	mov	rdi,rcx
	mov	rcx,r8
	repe	cmpsb
	pop	rsi
	jne	.other
	out_lit 'itself'
	mov	r14d,6
	jmp	.issued
.other:
	call	certs_cn
	mov	r14d,eax
.issued:
	mov	eax,26
	call	.pad
	; until
	mov	rsi,r12
	mov	edx,r13d
	call	x509_locate
	mov	rsi,[g_x509_val]
	mov	rdx,[g_x509_valend]
	call	der_read			; notBefore
	jc	.out
	mov	rsi,r8
	mov	rdx,[g_x509_valend]
	call	der_read			; notAfter
	jc	.out
	lea	rdi,[g_time_b]
	call	x509_time_norm
	jc	.out
	lea	rsi,[g_time_b]
	call	acme_epoch
	push	rax
	lea	rdi,[g_cc_buf]
	call	fmt_date
	lea	rsi,[g_cc_buf]
	mov	edx,16
	call	out_str
	pop	rax
	sub	rax,[g_cc_now]
	jb	.expired
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	push	rax				; right-aligned in 5
	mov	edi,' '
	call	out_char
	cmp	qword [rsp],1000
	jae	@f
	mov	edi,' '
	call	out_char
	cmp	qword [rsp],100
	jae	@f
	mov	edi,' '
	call	out_char
	cmp	qword [rsp],10
	jae	@f
	mov	edi,' '
	call	out_char
@@:
	pop	rax
	call	out_u64
	out_lit 'd  '
	jmp	.out
.expired:
	out_lit ' gone  '
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
; r14d = columns written, eax = the column's width: spaces to it (one at least)
.pad:
	push	rax
	mov	edi,' '
	call	out_char
	inc	r14d
	pop	rax
	cmp	r14d,eax
	jb	.pad
	ret

; rsi/rdx = a Name's content: its commonName written; eax = its length (0 none)
certs_cn:
.rdn:
	cmp	rsi,rdx
	jae	.none
	call	der_read			; SET
	jc	.none
	push	r8
	push	rdx
	lea	rdx,[rsi+rcx]
	call	der_read			; AttributeTypeAndValue
	jc	.next
	lea	rdx,[rsi+rcx]
	call	der_read			; type
	jc	.next
	cmp	ecx,3
	jne	.next
	cmp	word [rsi],0x0455
	jne	.next
	cmp	byte [rsi+2],3			; commonName
	jne	.next
	mov	rsi,r8
	call	der_read			; its string
	jc	.next
	add	rsp,16
	cmp	ecx,64
	jbe	@f
	mov	ecx,64
@@:
	push	rcx
	mov	edx,ecx
	call	out_str
	pop	rax
	ret
.next:
	pop	rdx
	pop	rsi
	jmp	.rdn
.none:
	xor	eax,eax
	ret
