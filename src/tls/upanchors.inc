; The anchors a pool's backends are verified against: `tls { trust FILE }`
; (every certificate in FILE, a bundle as well as one root), `trust system`
; (the system's roots: $SSL_CERT_FILE, else the distribution's bundle, read
; once per configuration however many pools name it) or none with
; `verify off`.
;
; Keys and subject hashes live in the plan (g_upa, g_upa_nh), copied on
; reload only as far as they are used. A chain is checked against the
; anchors whose subject is the issuer of its last certificate (one SHA-256
; of a name and, usually, one signature), as client_ca does: a bundle of
; 150 roots costs what one does.

UPA_MAX		:= 1024

bss
	align 8
	g_upa:		rb PK_SIZE * UPA_MAX	; anchor keys
	g_upa_nh	rq UPA_MAX		; their subject's hash (cca_name_hash)
	g_plan_upa	dd ?
	g_upa_sys	dd ?			; compiling: `trust system`'s first + 1, 0 not loaded
	g_upa_sysn	dd ?			; and how many
end bss

rodata
	upa_bundles	db '/etc/ssl/certs/ca-certificates.crt',0	; Debian, Ubuntu, Alpine, Arch
			db '/etc/pki/tls/certs/ca-bundle.crt',0		; Fedora, RHEL
			db '/etc/ssl/ca-bundle.pem',0			; openSUSE
			db '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',0
			db '/etc/ssl/cert.pem',0
			db 0
end rodata
cstring upa_env_file, 'SSL_CERT_FILE='

; rsi = PEM text, rdx = its end, ecx = 1 to skip what does not parse (a
; system bundle), 0 to refuse it. Each CERTIFICATE appended to g_upa.
; eax = the first, edx = how many; CF on a bad one (ecx = 0), or too many.
upa_load_text:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rsi
	mov	r13,rdx
	mov	r14d,[g_plan_upa]
	mov	r15d,ecx
.cert:
	lea	rdi,[pem_certificate]
	mov	rsi,r12
	mov	rdx,r13
	call	pem_next
	cmp	eax,-1
	je	.done
	mov	r12,rsi
	test	eax,eax
	js	.bad_one
	mov	ebx,eax				; DER length
	mov	ecx,[g_plan_upa]
	cmp	ecx,UPA_MAX
	jae	.bad
	imul	rdi,rcx,PK_SIZE
	lea	rdi,[g_upa+rdi]
	lea	rsi,[g_tls_der]
	mov	edx,ebx
	call	cert_pubkey
	test	eax,eax
	jz	.bad_one
	lea	rsi,[g_tls_der]
	mov	edx,ebx
	call	x509_locate
	test	eax,eax
	jz	.bad_one
	mov	rsi,[g_x509_subj]
	mov	rdx,[g_x509_subjend]
	sub	rdx,rsi
	call	cca_name_hash
	mov	ecx,[g_plan_upa]
	mov	[g_upa_nh+rcx*8],rax
	inc	dword [g_plan_upa]
	jmp	.cert
.bad_one:
	test	r15d,r15d
	jnz	.cert				; (a system bundle: the others still count)
.bad:
	stc
	jmp	.out
.done:
	mov	eax,r14d
	mov	edx,[g_plan_upa]
	sub	edx,r14d
	clc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = a path (NUL-terminated): its certificates, as upa_load_text (refused
; whole if one is broken). CF when it cannot be read or holds none.
upa_file:
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad
	mov	rsi,rax
	add	rdx,rax
	xor	ecx,ecx
	call	upa_load_text
	jc	.bad
	test	edx,edx
	jz	.bad
	ret
.bad:
	stc
	ret

; The system's roots, once per configuration: eax = first, edx = how many.
; CF when there are none.
upa_system:
	mov	eax,[g_upa_sys]
	test	eax,eax
	jz	.load
	dec	eax
	mov	edx,[g_upa_sysn]
	clc
	ret
.load:
	push	rbx
	lea	rdi,[upa_env_file]
	mov	esi,upa_env_file.len
	call	getenv
	test	rax,rax
	jz	.bundles
	mov	rdi,rax				; named: that one, and only it
	call	.one
	jmp	.out
.bundles:
	lea	rbx,[upa_bundles]
.next:
	cmp	byte [rbx],0
	je	.none
	mov	rdi,rbx
	call	.one
	jnc	.out
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	jmp	.next
.none:
	stc
.out:
	pop	rbx
	ret
; rdi = a bundle's path: CF when it gives no root
.one:
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.no
	mov	rsi,rax
	add	rdx,rax
	mov	ecx,1
	call	upa_load_text
	jc	.no
	test	edx,edx
	jz	.no
	lea	ecx,[rax+1]
	mov	[g_upa_sys],ecx
	mov	[g_upa_sysn],edx
	clc
	ret
.no:
	stc
	ret

; rcx = pool, rsi = a TLS 1.3 CertificateEntry list (leaf first), edx = its
; length: eax = 1 when it goes up to one of the pool's anchors (or the pool
; says `verify off`), else 0.
up_chain_verify:
	cmp	dword [rcx+PL_TLS_NOVERIFY],0
	jne	.yes
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rsi
	mov	r15d,edx
	mov	r12d,[rcx+PL_TLS_AFIRST]
	mov	r13d,r12d
	add	r13d,[rcx+PL_TLS_ACOUNT]
	; the last certificate: whose subject must its issuer be
	lea	r8,[rsi+rdx]
	xor	ebx,ebx
.last:
	push	r8
	call	chain_entry
	pop	r8
	jc	.no
	mov	rbx,rax
	mov	r9d,ecx
	mov	rsi,rdx
	cmp	rsi,r8
	jb	.last
	test	rbx,rbx
	jz	.no
	mov	rsi,rbx
	mov	edx,r9d
	call	x509_locate
	test	eax,eax
	jz	.no
	mov	rsi,[g_x509_iss]
	mov	rdx,[g_x509_issend]
	sub	rdx,rsi
	call	cca_name_hash
	mov	rbx,rax
.try:
	cmp	r12d,r13d
	jae	.no
	cmp	[g_upa_nh+r12*8],rbx
	jne	.next
	imul	rdi,r12,PK_SIZE
	lea	rdi,[g_upa+rdi]
	mov	rsi,r14
	mov	edx,r15d
	call	cert_chain_verify
	test	eax,eax
	jnz	.found
.next:
	inc	r12d
	jmp	.try
.found:
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.yes:
	mov	eax,1
	ret
