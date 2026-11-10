; Certificates near their end: a gauge on /metrics for every certificate served,
; and an alert (`alerts { on certificate }`) for one with less than two weeks
; left.
;
;   okena_tls_certificate_not_after_seconds{name="a.example.com",source="acme",entry="3"} 1796000000
;
; source: file, acme, acme_pending (signed here until the CA's comes), local,
; local_pending. The supervisor looks once an hour (and at start): a file's or
; the CA's certificate with less than 14 days left (or past its end) is said in
; the log and to the alert targets, once a day each. ACME's are renewed at two
; thirds of their life, so one that gets here has failed for weeks; the local
; CA's and those signed meanwhile are short by design and not told.

CX_WARN		:= 14 * 86400

bss
	align 8
	g_cx_next	dq ?			; realtime second: the next look
	g_cx_day	rd MAX_TLS		; the day an entry was last told (+1)
	g_cx_namel	dd ?
	g_cx_name:	rb 128			; cert_summary: its first name
end bss

rodata
	cx_src_file	db 'file',0
	cx_src_acme	db 'acme',0
	cx_src_acmep	db 'acme_pending',0
	cx_src_local	db 'local',0
	cx_src_localp	db 'local_pending',0
	cx_srcs		dq cx_src_file, cx_src_acme, cx_src_acmep, cx_src_local, cx_src_localp
end rodata

; rsi/edx = a certificate (DER): rax = its notAfter (seconds since 1970; 0 when
; it cannot be read), g_cx_name/namel its first DNS name (else its CN)
cert_summary:
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	mov	dword [g_cx_namel],0
	call	x509_locate
	test	eax,eax
	jz	.bad
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
	cmp	al,0x82				; dNSName
	je	.take
	mov	rsi,r8
	jmp	.gn
.take:
	add	rsp,8
	call	.keep
	jmp	.when
.ext_next:
	pop	rsi
	jmp	.ext
.cn:
	mov	rsi,[g_x509_subj]		; its CN
	mov	rdx,[g_x509_subjend]
.rdn:
	cmp	rsi,rdx
	jae	.when
	call	der_read			; SET
	jc	.when
	push	r8
	push	rdx
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.rdn_next
	lea	rdx,[rsi+rcx]
	call	der_read			; type
	jc	.rdn_next
	cmp	ecx,3
	jne	.rdn_next
	cmp	word [rsi],0x0455
	jne	.rdn_next
	cmp	byte [rsi+2],3
	jne	.rdn_next
	mov	rsi,r8
	call	der_read
	jc	.rdn_next
	add	rsp,16
	call	.keep
	jmp	.when
.rdn_next:
	pop	rdx
	pop	rsi
	jmp	.rdn
.when:
	mov	rsi,r12
	mov	edx,r13d
	call	x509_locate
	mov	rsi,[g_x509_val]
	mov	rdx,[g_x509_valend]
	call	der_read			; notBefore
	jc	.bad
	mov	rsi,r8
	mov	rdx,[g_x509_valend]
	call	der_read			; notAfter
	jc	.bad
	lea	rdi,[g_time_b]
	call	x509_time_norm
	jc	.bad
	lea	rsi,[g_time_b]
	call	acme_epoch
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	ret
; rsi/ecx: kept as the name (128 bytes at most)
.keep:
	cmp	ecx,128
	jbe	@f
	mov	ecx,128
@@:
	mov	[g_cx_namel],ecx
	lea	rdi,[g_cx_name]
	rep	movsb
	ret

; ebx = a tls entry: rax = its leaf's notAfter (0: none, or a pool's client
; certificate), g_cx_name its name
cert_entry_summary:
	call	cert_entry_leaf
	jc	.none
	mov	rsi,rax
	mov	edx,ecx
	jmp	cert_summary
.none:
	xor	eax,eax
	ret

; ebx = a tls entry: rax/ecx = its leaf (DER). CF: none (or a pool's client
; certificate).
cert_entry_leaf:
	imul	rax,rbx,TL_SIZE
	lea	r9,[g_tls+rax]
	cmp	dword [r9+TL_GROUP],0x40000000
	jae	.out
	cmp	dword [r9+TL_CLEN],0
	je	.out
	mov	esi,[r9+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	mov	r8d,[r9+TL_CLEN]
	add	r8,rsi
	jmp	chain_entry
.out:
	stc
	ret

; /metrics: rdi = out. rdi past what it wrote.
cert_metrics:
	cmp	dword [g_plan_tls],0
	je	.out
	push	rbx
	push	r12
	mov	r12,rdi
	memit_x '# HELP okena_tls_certificate_not_after_seconds When each certificate served ends (seconds since 1970).',10
	memit_x '# TYPE okena_tls_certificate_not_after_seconds gauge',10
	mov	r12,rdi
	xor	ebx,ebx
.entry:
	cmp	ebx,[g_plan_tls]
	jae	.done
	call	cert_entry_summary
	test	rax,rax
	jz	.next
	push	rax
	mov	rdi,r12
	memit_x 'okena_tls_certificate_not_after_seconds{name="'
	lea	rsi,[g_cx_name]
	mov	edx,[g_cx_namel]
	call	fmt_label
	memit_x '",source="'
	movzx	eax,byte [g_tls_src+rbx]
	cmp	eax,4
	jbe	@f
	xor	eax,eax
@@:
	mov	rsi,[cx_srcs+rax*8]
	call	fmt_cstr
	memit_x '",entry="'
	mov	eax,ebx
	call	fmt_u64
	memit_x '"} '
	pop	rax
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	mov	r12,rdi
.next:
	inc	ebx
	jmp	.entry
.done:
	mov	rdi,r12
	pop	r12
	pop	rbx
.out:
	ret

; the supervisor, each second: once an hour, the certificates near their end
; said (and alerted), once a day each
cert_tick:
	call	acme_now
	cmp	rax,[g_cx_next]
	jb	.out
	push	rbx
	push	r12
	mov	r12,rax				; now
	add	rax,3600
	mov	[g_cx_next],rax
	xor	ebx,ebx
.entry:
	cmp	ebx,[g_plan_tls]
	jae	.done
	movzx	eax,byte [g_tls_src+rbx]
	cmp	eax,1				; a file's, or the CA's (not the short ones)
	ja	.next
	call	cert_entry_summary
	test	rax,rax
	jz	.next
	mov	rcx,rax
	sub	rcx,r12				; left
	cmp	rcx,CX_WARN
	jge	.next
	push	rax
	push	rcx
	mov	rax,r12
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	inc	eax				; today (+1)
	cmp	[g_cx_day+rbx*4],eax
	je	.said
	mov	[g_cx_day+rbx*4],eax
	call	log_begin
	out_lit 'certificate '
	lea	rsi,[g_cx_name]
	mov	edx,[g_cx_namel]
	call	out_str
	movzx	eax,byte [g_tls_src+rbx]
	test	eax,eax
	jnz	@f
	out_lit ' (a file)'
	jmp	.src
@@:
	out_lit ' (acme)'
.src:
	mov	rcx,[rsp]
	test	rcx,rcx
	jle	.ended
	out_lit ' ends in '
	mov	rax,[rsp]
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	call	out_u64
	out_lit ' days, on '
	jmp	.date
.ended:
	out_lit ' has ended, on '
.date:
	mov	rax,[rsp+8]
	lea	rdi,[g_cx_name]
	call	fmt_date
	lea	rsi,[g_cx_name]
	mov	edx,16
	call	out_str
	out_lit ' UTC'
	mov	edi,AL_CERT
	call	log_end_alert
.said:
	add	rsp,16
.next:
	inc	ebx
	jmp	.entry
.done:
	pop	r12
	pop	rbx
.out:
	ret
