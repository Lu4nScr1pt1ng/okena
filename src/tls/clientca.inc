; `client_ca FILE [optional] [crl=FILE]`: the certificates a client's chain may
; end at, and what they revoked.
;
; Every certificate in FILE is an anchor (256 at most over all listeners): a
; client's chain goes up to one of them, found by name: the issuer of the
; chain's last certificate, as the anchor's subject (its DER, hashed). Two
; anchors of one name are both tried.
;
; crl=FILE: certificate revocation lists (RFC 5280 5), PEM (X509 CRL) or one in
; DER, each signed by one of the anchors (refused at load otherwise). The
; serials they list, with the name of who issued them, go into a table; a
; chain that has one of them, among the certificates an anchor signed, is
; refused. A list past its nextUpdate refuses every client of its CA until a
; fresh one is loaded (a reload), as nginx does: better shut than open.

CCA_MAX		:= 256
CRL_SLOTS	:= 1 shl 17			; open addressing, kept under half full
CRL_MAX		:= CRL_SLOTS / 2

bss
	align 8
	g_cca:		rb PK_SIZE * CCA_MAX	; the anchors' keys
	g_cca_nh	rq CCA_MAX		; their subject's hash (8 bytes, | 1)
	g_cca_next	rq CCA_MAX		; a CRL's nextUpdate (realtime), 0 none; -1 no CRL
	g_crl_tab	rq CRL_SLOTS		; hash(issuer name, serial) | 1, 0 empty
	g_plan_cca	dd ?
	g_plan_crln	dd ?
	g_cmp_cca	dd ?
	g_cc_ca		dd ?			; the anchor a chain went up to
	align 8
	g_cca_hash:	rb 32
	g_cca_buf:	rb 520
end bss

; rsi = a Name's content, edx = its length: rax = its hash (8 bytes, | 1)
cca_name_hash:
	lea	rdi,[g_cca_hash]
	call	sha256
	mov	rax,qword [g_cca_hash]
	or	rax,1
	ret

; rax = an issuer's name hash, rsi = a serial's content, ecx = its length: rax =
; the table's key. Keeps rbx, r12-r15.
crl_key:
	cmp	ecx,64
	jbe	@f
	mov	ecx,64
@@:
	mov	qword [g_cca_buf],rax
	lea	rdi,[g_cca_buf+8]
	mov	edx,ecx
	rep	movsb
	add	edx,8
	lea	rsi,[g_cca_buf]
	jmp	cca_name_hash

; rax = a key: CF when it is in the table (revoked). Keeps rbx, r12-r15.
crl_has:
	mov	rcx,rax
	and	ecx,CRL_SLOTS - 1
@@:
	mov	rdx,[g_crl_tab+rcx*8]
	test	rdx,rdx
	jz	.no
	cmp	rdx,rax
	je	.yes
	inc	ecx
	and	ecx,CRL_SLOTS - 1
	jmp	@b
.yes:
	stc
	ret
.no:
	clc
	ret

; rax = a key: put in the table. CF: it is full.
crl_put:
	cmp	dword [g_plan_crln],CRL_MAX
	jae	.full
	mov	rcx,rax
	and	ecx,CRL_SLOTS - 1
@@:
	mov	rdx,[g_crl_tab+rcx*8]
	test	rdx,rdx
	jz	.put
	cmp	rdx,rax
	je	.out				; (listed twice)
	inc	ecx
	and	ecx,CRL_SLOTS - 1
	jmp	@b
.put:
	mov	[g_crl_tab+rcx*8],rax
	inc	dword [g_plan_crln]
.out:
	clc
	ret
.full:
	stc
	ret

; rdi = a listener: `client_ca` into g_cca (all of FILE's certificates), its
; crl= into g_crl_tab; g_cmp_cca = the first anchor | how many << 16, and
; g_cmp_flags
compile_client_ca:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	.out
	mov	rdi,rax
	mov	ecx,DIR_CLIENT_CA
	call	find_child
	test	rax,rax
	jz	.out
	mov	rbx,rax
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	call	.read
	mov	r12,rax				; the text
	lea	r13,[rax+rdx]			; its end
	mov	r14d,[g_plan_cca]		; the first anchor
.cert:
	lea	rdi,[pem_certificate]
	mov	rsi,r12
	mov	rdx,r13
	call	pem_next
	cmp	eax,-1
	je	.certs
	cmp	eax,0
	jl	.bad
	mov	r12,rsi
	mov	r15d,eax
	mov	ecx,[g_plan_cca]
	cmp	ecx,CCA_MAX
	jae	.too_many
	imul	rdi,rcx,PK_SIZE
	lea	rdi,[g_cca+rdi]
	lea	rsi,[g_tls_der]
	mov	edx,r15d
	call	cert_pubkey
	test	eax,eax
	jz	.bad
	lea	rsi,[g_tls_der]
	mov	edx,r15d
	call	x509_locate
	test	eax,eax
	jz	.bad
	mov	rsi,[g_x509_subj]
	mov	rdx,[g_x509_subjend]
	sub	rdx,rsi
	call	cca_name_hash
	mov	ecx,[g_plan_cca]
	mov	[g_cca_nh+rcx*8],rax
	mov	qword [g_cca_next+rcx*8],-1
	inc	dword [g_plan_cca]
	jmp	.cert
.certs:
	mov	eax,[g_plan_cca]
	sub	eax,r14d
	jz	.bad				; (none in it)
	shl	eax,16
	or	eax,r14d
	mov	[g_cmp_cca],eax
	or	dword [g_cmp_flags],LSF_CCA or LSF_CCA_REQ
	cmp	dword [rbx+N_ARGC],2
	jb	@f
	mov	rax,[rbx+N_ARGS]
	cmp	dword [rax+A_SIZE+A_KIND],ARG_KV
	je	@f
	mov	rax,[rax+A_SIZE+A_VAL]
	cmp	byte [rax],'o'			; `optional`
	jne	@f
	and	dword [g_cmp_flags],not LSF_CCA_REQ
@@:
	mov	rdi,rbx
	cstring .k_crl, 'crl',0
	lea	rsi,[.k_crl]
	call	node_option
	test	rax,rax
	jz	.out
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	call	.read
	mov	r12,rax
	lea	r13,[rax+rdx]
	cstring .l_crl, 'X509 CRL',0
	mov	r15d,0				; lists taken
.crl:
	lea	rdi,[.l_crl]
	mov	rsi,r12
	mov	rdx,r13
	call	pem_next
	cmp	eax,-1
	je	.crls
	cmp	eax,0
	jl	.bad_crl
	mov	r12,rsi
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	crl_load
	inc	r15d
	jmp	.crl
.crls:
	test	r15d,r15d
	jnz	.out
	; no PEM: one list in DER
	mov	rsi,r12
	mov	rdx,r13
	sub	rdx,rsi
	cmp	rdx,4
	jb	.bad_crl
	cmp	byte [rsi],0x30
	jne	.bad_crl
	call	crl_load
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi/ecx = a path: rax = its text, rdx = its length (exits when it cannot be read)
.read:
	cmp	ecx,1000
	ja	.bad
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad
	ret
.too_many:
	call	log_begin
	out_lit 'client_ca: 256 certificates at most, over every listener'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'client_ca: a PEM file with certificates okena can read is needed'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad_crl:
	call	log_begin
	out_lit 'client_ca crl=: a file of certificate revocation lists (PEM, X509 CRL; or one in DER) is needed'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; In compile_client_ca (r14d = the listener's first anchor, its last below
; g_plan_cca): rsi/edx = a CRL (DER). Its issuer one of the anchors, its
; signature that one's, its times kept; its serials into the table. Exits with
; why when it is not.
crl_load:
	push	rbx
	push	r12
	push	r13
	push	r15
	sub	rsp,40				; times (14 + 14), a scratch
	mov	r12,rsi				; the list
	mov	r13d,edx
	lea	rdx,[rsi+rdx]
	call	der_read			; CertificateList
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; tbsCertList
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	r15,r8				; its end
	mov	rdx,r15
	call	der_read			; version (v2), or the signature algorithm
	jc	.bad
	cmp	al,2
	jne	@f
	mov	rsi,r8
	mov	rdx,r15
	call	der_read			; signature
	jc	.bad
@@:
	mov	rsi,r8
	mov	rdx,r15
	call	der_read			; issuer
	jc	.bad
	cmp	al,0x30
	jne	.bad
	push	r8
	mov	edx,ecx
	call	cca_name_hash
	pop	r8
	mov	rbx,rax				; the issuer's name hash
	; its anchor, and its signature
	mov	ecx,r14d
.anchor:
	cmp	ecx,[g_plan_cca]
	jae	.no_anchor
	cmp	[g_cca_nh+rcx*8],rbx
	jne	.next_anchor
	push	rcx
	push	r8
	imul	rdi,rcx,PK_SIZE
	lea	rdi,[g_cca+rdi]
	mov	rsi,r12
	mov	edx,r13d
	call	cert_verify			; (a CRL is signed as a certificate is)
	pop	r8
	pop	rcx
	test	eax,eax
	jnz	.signed
.next_anchor:
	inc	ecx
	jmp	.anchor
.signed:
	mov	[rsp+32],ecx			; the anchor
	mov	rsi,r8
	mov	rdx,r15
	call	der_read			; thisUpdate
	jc	.bad
	push	r8
	lea	rdi,[rsp+8]
	call	x509_time_norm
	pop	r8
	jc	.bad
	mov	qword [rsp+14],0		; nextUpdate: none said
	mov	rsi,r8
	cmp	rsi,r15
	jae	.times
	mov	rdx,r15
	call	der_read
	jc	.bad
	cmp	al,0x17				; nextUpdate (a time), else the list
	je	.next_update
	cmp	al,0x18
	jne	.list
.next_update:
	push	r8
	lea	rdi,[rsp+8+14]
	call	x509_time_norm
	pop	r8
	jc	.bad
	mov	rsi,r8
	cmp	rsi,r15
	jae	.times
	mov	rdx,r15
	call	der_read
	jc	.bad
.list:
	cmp	al,0x30				; revokedCertificates
	jne	.times
	lea	r15,[rsi+rcx]			; (its end, from here)
.entry:
	cmp	rsi,r15
	jae	.times
	mov	rdx,r15
	call	der_read			; one: SEQUENCE { serial, date, extensions }
	jc	.bad
	push	r8
	lea	rdx,[rsi+rcx]
	call	der_read			; userCertificate
	jc	.bad_pop
	cmp	al,2
	jne	.bad_pop
	mov	rax,rbx
	call	crl_key
	call	crl_put
	jc	.full
	pop	rsi
	jmp	.entry
.times:
	; its nextUpdate, kept for the anchor (the soonest, when it has several)
	mov	ecx,[rsp+32]
	xor	eax,eax
	cmp	byte [rsp+14],0
	je	@f
	lea	rsi,[rsp+14]
	call	acme_epoch
@@:
	mov	ecx,[rsp+32]
	mov	rdx,[g_cca_next+rcx*8]
	cmp	rdx,-1
	je	.set				; its first list
	test	rax,rax
	jz	.done				; (this one never ends: the other's stays)
	test	rdx,rdx
	jz	.set
	cmp	rax,rdx
	jae	.done
.set:
	mov	[g_cca_next+rcx*8],rax
	test	rax,rax
	jz	.done
	push	rax
	call	acme_now
	pop	rcx
	cmp	rax,rcx
	jbe	.done
	call	log_begin
	out_lit 'client_ca crl=: a list past its nextUpdate: the clients of its CA are refused until a fresh one comes (a reload)'
	call	log_end
.done:
	add	rsp,40
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad_pop:
	add	rsp,8
.bad:
	call	log_begin
	out_lit 'client_ca crl=: a list that does not parse'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.no_anchor:
	call	log_begin
	out_lit 'client_ca crl=: a list not signed by one of client_ca',39,'s certificates'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.full:
	call	log_begin
	out_lit 'client_ca crl=: 65536 revoked certificates at most, over every listener'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; In cc_flight (rbx = ts): the client's chain (g_cc_list) goes up to one of the
; listener's anchors (TS_ANCHOR, TS_ANCHORN), the one its last certificate names
; as issuer; g_cc_ca = that one. Then none of the certificates that anchor
; signed is revoked, and its list is current. eax = 1, else 0.
cc_chain_verify:
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,8
	mov	rsi,[g_cc_list]			; the last certificate
	mov	r8,rsi
	mov	eax,[g_cc_listn]
	add	r8,rax
	xor	r12d,r12d
.last:
	push	r8
	call	chain_entry
	pop	r8
	jc	.no
	mov	r12,rax
	mov	r13d,ecx
	mov	rsi,rdx
	cmp	rsi,r8
	jb	.last
	test	r12,r12
	jz	.no
	mov	rsi,r12
	mov	edx,r13d
	call	x509_locate
	test	eax,eax
	jz	.no
	mov	rsi,[g_x509_iss]
	mov	rdx,[g_x509_issend]
	sub	rdx,rsi
	call	cca_name_hash
	mov	r15,rax				; whom it names
	mov	rax,[rbx+TS_ANCHOR]
	lea	rcx,[g_cca]
	sub	rax,rcx
	xor	edx,edx
	mov	ecx,PK_SIZE
	div	rcx
	mov	r12d,eax			; the first anchor
	mov	r13d,eax
	add	r13d,[rbx+TS_ANCHORN]		; past the last
.try:
	cmp	r12d,r13d
	jae	.no
	cmp	[g_cca_nh+r12*8],r15
	jne	.next
	imul	rdi,r12,PK_SIZE
	lea	rdi,[g_cca+rdi]
	mov	rsi,[g_cc_list]
	mov	edx,[g_cc_listn]
	call	cert_chain_verify
	test	eax,eax
	jnz	.found
.next:
	inc	r12d
	jmp	.try
.found:
	mov	[g_cc_ca],r12d
	; its revocation list: current, and none of its certificates in it
	mov	rax,[g_cca_next+r12*8]
	cmp	rax,-1
	je	.yes				; none for this CA
	test	rax,rax
	jz	.listed
	push	rax
	call	acme_now
	pop	rcx
	cmp	rax,rcx
	ja	.no				; past its nextUpdate
.listed:
	mov	rsi,[g_cc_list]
	mov	r14,rsi
	mov	eax,[g_cc_listn]
	add	r14,rax				; the end
.each:
	cmp	rsi,r14
	jae	.yes
	mov	r8,r14
	call	chain_entry
	jc	.no
	push	rdx
	mov	rsi,rax
	mov	edx,ecx
	call	x509_locate
	test	eax,eax
	jz	.no_pop
	mov	rsi,[g_x509_iss]		; one the anchor signed?
	mov	rdx,[g_x509_issend]
	sub	rdx,rsi
	call	cca_name_hash
	cmp	rax,r15
	jne	.each_next
	mov	rsi,[g_x509_ser]
	mov	ecx,[g_x509_serlen]
	mov	rax,r15
	call	crl_key
	call	crl_has
	jc	.no_pop				; revoked
.each_next:
	pop	rsi
	jmp	.each
.yes:
	mov	eax,1
	jmp	.out
.no_pop:
	add	rsp,8
.no:
	xor	eax,eax
.out:
	add	rsp,8
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
