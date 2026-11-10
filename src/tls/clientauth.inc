; TLS 1.3 client certificates (RFC 8446 4.3.2, 4.4): `client_ca` on a listener.
;
; tls_hello adds a CertificateRequest to the flight, and leaves in TS what the
; client's flight needs: its finished key and the transcript through the server
; Finished. Here that flight is read: Certificate, CertificateVerify, Finished,
; in as many records as it takes. Nothing is opened in place, so that being called
; again with more is the same work over the same bytes.
;
; A listener that asks for certificates issues its ticket after the client's flight
; (cc_ticket), with who the client is and the listener's CAs (TKP_CCA, TKP_PEER):
; a resumption there is that client again, and a ticket of another listener (other
; CAs, or none) is not taken. It speaks TLS 1.3 only.
;
; The certificate: its chain up to one of the listener's anchors, none of it
; revoked (clientca.inc), every link in date, an
; extended key usage, if it has one, that allows client authentication, and a
; signature over this handshake. Who it is is the subject's commonName.

CC_MSG_MAX	:= 32768
CC_PREFIX	:= 98				; 64 spaces, the label, a zero

bss
	align 8
	; (`client_ca`'s anchors and lists: clientca.inc)
	align 8
	g_cc_list	dq ?
	g_cc_listn	dd ?
	g_cc_n		dd ?
	g_cc_nonce:	rb 16
	g_cc_aead:	rb AEAD_SIZE
	g_cc_sha:	rb SHA256_CTX_SIZE
	g_cc_sha2:	rb SHA256_CTX_SIZE
	g_cc_th:	rb 32
	g_cc_fin:	rb 32
	g_cc_dig:	rb 32
	g_cc_rth:	rb 32			; the transcript through the client Finished
	g_cc_rs:	rb 64
	g_cc_cv:	rb CC_PREFIX + 32
	g_cc_key:	rb PK_SIZE
	g_cc_time:	rb 64
	g_cc_rec:	rb TLS_RECORD_MAX + 512
	g_cc_msg:	rb CC_MSG_MAX
end bss

rodata
	cc_label	db 'TLS 1.3, client CertificateVerify',0
	CC_LABEL_LEN	:= $ - cc_label
	assert CC_PREFIX = 64 + CC_LABEL_LEN
end rodata

; rdi = ts, rsi = in, ecx = its length: as tls_finished
tls_client_flight:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbx,rdi
	mov	r12,rsi
	lea	r13,[rsi+rcx]
	mov	r14,rsi
	xor	ebp,ebp				; records opened
	mov	dword [g_cc_n],0
	lea	rdi,[g_cc_aead]
	lea	rsi,[rbx+TS_CHS_KEY]
	mov	edx,[rbx+TS_SUITE]
	call	aead_init
.record:
	mov	rax,r13
	sub	rax,r14
	cmp	rax,5
	jb	.more
	movzx	ecx,word [r14+3]
	rol	cx,8
	cmp	ecx,TLS_RECORD_MAX + 256
	ja	.fail
	lea	r15,[r14+5+rcx]
	cmp	r15,r13
	ja	.more
	cmp	byte [r14],20			; ChangeCipherSpec, compatibility mode
	jne	.sealed
	cmp	ecx,1
	jne	.fail
	mov	r14,r15
	jmp	.record
.sealed:
	cmp	byte [r14],23
	jne	.fail
	cmp	ecx,17
	jb	.fail
	mov	r8d,ecx
	lea	rsi,[r14+5]
	lea	rdi,[g_cc_rec]
	rep	movsb
	push	r8
	lea	rdi,[g_cc_nonce]
	lea	rsi,[rbx+TS_CHS_IV]
	mov	rdx,rbp
	call	tls_nonce
	pop	r9
	inc	rbp
	sub	r9,16
	push	r9
	lea	rdi,[g_cc_aead]
	lea	rsi,[g_cc_nonce]
	mov	rdx,r14
	mov	ecx,5
	lea	r8,[g_cc_rec]
	call	aead_open
	pop	r9
	test	eax,eax
	jz	.fail
	lea	rsi,[g_cc_rec]
	lea	rdi,[rsi+r9-1]
.unpad:
	cmp	rdi,rsi
	jb	.fail
	cmp	byte [rdi],0
	jne	@f
	dec	rdi
	jmp	.unpad
@@:
	cmp	byte [rdi],22			; handshake
	jne	.fail
	mov	rcx,rdi
	sub	rcx,rsi
	mov	eax,[g_cc_n]
	lea	edx,[rax+rcx]
	cmp	edx,CC_MSG_MAX
	ja	.fail
	mov	[g_cc_n],edx
	lea	rdi,[g_cc_msg+rax]
	rep	movsb
	mov	r14,r15
	call	cc_flight
	cmp	eax,1
	je	.done
	ja	.fail
	jmp	.record
.done:
	mov	rdx,r14
	sub	rdx,r12
	mov	eax,TH_DONE
	jmp	.wipe
.more:
	xor	edx,edx
	mov	eax,TH_MORE
	jmp	.keep
.fail:
	xor	edx,edx
	mov	eax,TH_FAIL
.wipe:
	push	rax
	push	rdx
	lea	rdi,[rbx+TS_CHS_KEY]
	mov	ecx,TS_RX_KEY - TS_CHS_KEY
	call	secure_zero
	lea	rdi,[rbx+TS_MCFK]
	mov	ecx,32
	call	secure_zero
	pop	rdx
	pop	rax
.keep:
	push	rax
	push	rdx
	lea	rdi,[g_cc_aead]
	mov	ecx,AEAD_SIZE
	call	secure_zero
	pop	rdx
	pop	rax
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbx = ts; g_cc_msg has g_cc_n bytes. eax = 0 not all here yet, 1 good, 2 not.
cc_flight:
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	lea	r12,[g_cc_msg]
	mov	eax,[g_cc_n]
	lea	r13,[r12+rax]
	call	.message
	jc	.more
	cmp	eax,11
	jne	.bad
	mov	r15,r12				; the Certificate
	lea	rsi,[r12+4]
	mov	rax,r14
	sub	rax,rsi
	cmp	rax,4
	jb	.bad
	cmp	byte [rsi],0			; certificate_request_context: ours is empty
	jne	.bad
	mov	eax,[rsi]
	bswap	eax
	and	eax,0xFFFFFF			; (u24, after the context byte)
	lea	rcx,[rsi+4]
	lea	rdx,[rcx+rax]
	cmp	rdx,r14
	jne	.bad
	mov	[g_cc_list],rcx
	mov	[g_cc_listn],eax
	mov	r12,r14
	xor	ebp,ebp				; the CertificateVerify
	test	eax,eax
	jnz	.needs_cv
	test	dword [rbx+TS_FLAGS],TF_CCA_REQ
	jnz	.bad
	jmp	.finished
.needs_cv:
	call	.message
	jc	.more
	cmp	eax,15
	jne	.bad
	mov	rbp,r12
	mov	r12,r14
.finished:
	call	.message
	jc	.more
	cmp	eax,20
	jne	.bad
	mov	rax,r14
	sub	rax,r12
	cmp	rax,36
	jne	.bad
	cmp	r14,r13
	jne	.bad				; nothing past a Finished
	; the transcript, the Finished first: it costs nothing and proves little,
	; but it is what keeps a stranger's garbage away from the signatures
	lea	rsi,[rbx+TS_MSHA]
	lea	rdi,[g_cc_sha]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_cc_sha]
	mov	rsi,r15
	mov	rdx,[g_cc_list]
	mov	eax,[g_cc_listn]
	add	rdx,rax
	sub	rdx,r15
	call	sha256_update
	call	.snapshot
	lea	rsi,[g_cc_th]
	lea	rdi,[g_cc_cv]
	mov	al,0x20
	mov	ecx,64
	rep	stosb
	lea	rsi,[cc_label]
	mov	ecx,CC_LABEL_LEN
	rep	movsb
	lea	rsi,[g_cc_th]
	mov	ecx,32
	rep	movsb
	test	rbp,rbp
	jz	@f
	lea	rdi,[g_cc_sha]
	mov	rsi,rbp
	mov	rdx,r12
	sub	rdx,rbp
	call	sha256_update
	call	.snapshot
@@:
	lea	rdi,[g_cc_fin]
	lea	rsi,[rbx+TS_MCFK]
	mov	edx,32
	lea	rcx,[g_cc_th]
	mov	r8d,32
	call	hmac_sha256
	lea	rdi,[g_cc_fin]
	lea	rsi,[r12+4]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.bad
	lea	rdi,[g_cc_sha]			; through the client Finished: what the
	mov	rsi,r12				; resumption secret covers (a ticket)
	mov	edx,36
	call	sha256_update
	call	.snapshot
	lea	rsi,[g_cc_th]
	lea	rdi,[g_cc_rth]
	mov	ecx,32
	rep	movsb
	mov	dword [rbx+TS_PEERL],0
	test	rbp,rbp
	jz	.good				; (none, and none is needed: `optional`)
	; whose certificate (cc_check_cert: the chain, its times, the leaf, who)
	call	cc_check_cert
	test	eax,eax
	jz	.bad
	mov	rdi,rbp
	call	cc_signature
	test	eax,eax
	jz	.bad
.good:
	call	cc_ticket
	mov	eax,1
	jmp	.out
.more:
	xor	eax,eax
	jmp	.out
.bad:
	mov	eax,2
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
; the handshake message at r12: eax = its type, r14 = its end; CF: not all here
.message:
	lea	rax,[r12+4]
	cmp	rax,r13
	ja	.short
	mov	eax,[r12]
	bswap	eax
	mov	ecx,eax
	and	ecx,0xFFFFFF
	shr	eax,24
	lea	r14,[r12+4+rcx]
	cmp	r14,r13
	ja	.short
	clc
	ret
.short:
	stc
	ret
; g_cc_th = the hash of the transcript so far, which goes on
.snapshot:
	lea	rsi,[g_cc_sha]
	lea	rdi,[g_cc_sha2]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_cc_sha2]
	lea	rsi,[g_cc_th]
	jmp	sha256_final

; rdi = the CertificateVerify message, with g_cc_cv signed content and g_cc_key the
; leaf's key: eax = 1 when the signature is good. A scheme that was not asked for
; is not one.
cc_signature:
	push	r14
	lea	rsi,[rdi+4]
	mov	eax,[rdi]
	bswap	eax
	and	eax,0xFFFFFF
	cmp	eax,4
	jb	.bad
	lea	r14,[rsi+rax]			; the end
	movzx	eax,word [rsi+2]		; the signature's length
	rol	ax,8
	lea	rcx,[rsi+rax+4]
	cmp	rcx,r14
	jne	.bad
	cmp	word [rsi],0x0304		; ecdsa_secp256r1_sha256
	je	.ecdsa
	cmp	word [rsi],0x0408		; rsa_pss_rsae_sha256
	je	.rsa
	cmp	word [rsi],0x0708		; ed25519
	je	.ed25519
	jmp	.bad
.digest:
	push	rsi
	push	rax
	lea	rdi,[g_cc_dig]
	lea	rsi,[g_cc_cv]
	mov	edx,CC_PREFIX + 32
	call	sha256
	pop	rax
	pop	rsi
	ret
.ed25519:
	cmp	dword [g_cc_key+PK_TYPE],3
	jne	.bad
	cmp	eax,64
	jne	.bad
	lea	rcx,[rsi+4]
	lea	rdi,[g_cc_key+PK_DATA]
	lea	rsi,[g_cc_cv]
	mov	edx,CC_PREFIX + 32
	call	ed25519_verify
	jmp	.out
.ecdsa:
	cmp	dword [g_cc_key+PK_TYPE],1
	jne	.bad
	call	.digest
	add	rsi,4
	mov	rdx,r14
	call	der_read			; SEQUENCE { r, s }
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; INTEGER r
	jc	.bad
	lea	rdi,[g_cc_rs]
	push	r8
	call	der_int_32
	pop	r8
	jc	.bad
	mov	rsi,r8
	call	der_read			; INTEGER s
	jc	.bad
	lea	rdi,[g_cc_rs+32]
	call	der_int_32
	jc	.bad
	lea	rdi,[g_cc_key+PK_DATA]
	lea	rsi,[g_cc_dig]
	lea	rdx,[g_cc_rs]
	lea	rcx,[g_cc_rs+32]
	call	p256_verify
	jmp	.out
.rsa:
	cmp	dword [g_cc_key+PK_TYPE],2
	jne	.bad
	cmp	eax,[g_cc_key+PK_NLEN]
	jne	.bad
	call	.digest
	lea	rdx,[rsi+4]
	lea	rdi,[g_cc_key+PK_DATA]
	mov	esi,[g_cc_key+PK_NLEN]
	mov	ecx,[g_cc_key+PK_E]
	lea	r8,[g_cc_dig]
	call	rsa_pss_verify
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r14
	ret

; rbx = ts, the client's flight good: a ticket (RFC 8446 4.6.1) in TS_TKT, sent
; once the handshake is done (TF_NST: http_tls_fin_in), as the first record
; under the server's application key. Sealed as tls_hello's are, and also
; with who the client is and the listener's CAs (a resumption there needs no
; certificate, and is taken nowhere else). Without the ticket keys: none.
cc_ticket:
	cmp	qword [g_tks],0
	je	.wipe
	tls_label [g_cc_fin], 32, [rbx+TS_RMS], lbl_res_master, [g_cc_rth], 32
	lea	rdi,[rbx+TS_TKT]
	mov	ecx,TK_SIZE
	xor	eax,eax
	rep	stosb
	tls_label [rbx+TS_TKT+TK_SEALED+TKP_PSK], 32, [g_cc_fin], lbl_resumption
	mov	byte [rbx+TS_TKT+TK_SEALED+TKP_VERSION],1
	mov	eax,[rbx+TS_TKNOW]
	mov	[rbx+TS_TKT+TK_SEALED+TKP_ISSUED],eax
	mov	rax,[rbx+TS_TKCERT]
	mov	[rbx+TS_TKT+TK_SEALED+TKP_CERT],rax
	mov	eax,[rbx+TS_TKCCA]
	mov	[rbx+TS_TKT+TK_SEALED+TKP_CCA],eax
	mov	ecx,[rbx+TS_PEERL]
	mov	[rbx+TS_TKT+TK_SEALED+TKP_PEERL],ecx
	lea	rsi,[rbx+TS_PEER]
	lea	rdi,[rbx+TS_TKT+TK_SEALED+TKP_PEER]
	rep	movsb
	lea	rdi,[rbx+TS_TKAGE]		; age_add, then the nonce
	mov	esi,4
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	mov	eax,[rbx+TS_TKAGE]
	mov	[rbx+TS_TKT+TK_SEALED+TKP_AGE_ADD],eax
	lea	rdi,[rbx+TS_TKT+TK_NONCE]
	mov	esi,12
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	mov	rdi,[g_tks]			; the current key
	mov	eax,[rdi+TKS_CUR]
	imul	eax,eax,TKS_SLOT
	lea	rdi,[rdi+TKS_SLOTS+rax]
	mov	eax,[rdi+TKS_ID]
	mov	[rbx+TS_TKT+TK_ID],eax
	add	rdi,TKS_GCM
	lea	rsi,[rbx+TS_TKT+TK_NONCE]
	lea	rdx,[rbx+TS_TKT+TK_ID]
	mov	ecx,4
	lea	r8,[rbx+TS_TKT+TK_SEALED]
	mov	r9d,TK_PT
	call	gcm_seal
	or	dword [rbx+TS_FLAGS],TF_NST
.wipe:
	lea	rdi,[g_cc_fin]
	mov	ecx,32
	call	secure_zero
	lea	rdi,[rbx+TS_RMS]
	mov	ecx,32
	jmp	secure_zero

; rbx = ts, g_cc_list/g_cc_listn = the client's certificates (1.3 entries): their
; chain up to one of the listener's anchors, nothing revoked (cc_chain_verify),
; every link in date, the leaf for client authentication, its key in g_cc_key,
; who it is in TS_PEER (its commonName, nothing that would break a header).
; eax = 1, else 0. (TLS 1.3's flight, and 1.2's: tls12_server.inc.)
cc_check_cert:
	push	r12
	push	r13
	call	cc_chain_verify		; (clientca.inc: one of its anchors, nothing revoked)
	test	eax,eax
	jz	.no
	lea	rdi,[g_cc_time]
	call	alog_fmt_time
	lea	rsi,[g_cc_time]
	lea	rdi,[g_cc_time+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
.compact:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	.compact
	mov	rsi,[g_cc_list]
	mov	edx,[g_cc_listn]
	lea	rdi,[g_cc_time+32]
	call	cert_chain_times
	test	eax,eax
	jz	.no
	; the leaf
	mov	rsi,[g_cc_list]
	mov	r8,rsi
	mov	eax,[g_cc_listn]
	add	r8,rax
	call	chain_entry
	jc	.no
	mov	r12,rax
	mov	r13d,ecx
	mov	rsi,rax
	mov	edx,ecx
	call	cert_client_usage
	test	eax,eax
	jz	.no
	lea	rdi,[g_cc_key]
	mov	rsi,r12
	mov	edx,r13d
	call	cert_pubkey
	test	eax,eax
	jz	.no
	mov	rsi,r12
	mov	edx,r13d
	call	cert_common_name
	test	ecx,ecx
	jz	.no
	cmp	ecx,MTLS_NAME_MAX
	ja	.no
	mov	rsi,rax
	mov	edx,ecx
.byte:
	mov	al,[rsi+rdx-1]
	cmp	al,0x20				; it goes into a header: nothing that ends one
	jb	.no
	cmp	al,0x7F
	je	.no
	dec	edx
	jnz	.byte
	mov	[rbx+TS_PEERL],ecx
	lea	rdi,[rbx+TS_PEER]
	rep	movsb
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	ret

; TLS 1.2's CertificateVerify: rdi = its body (the scheme, the signature), rsi =
; its end; g_cc_dig = the handshake's SHA-256 through the ClientKeyExchange,
; g_cc_key the leaf's key. eax = 1 when the signature is good under a scheme
; the CertificateRequest named (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,
; rsa_pkcs1_sha256).
cc12_signature:
	push	r14
	mov	r14,rsi
	lea	rax,[rdi+4]
	cmp	rax,r14
	ja	.bad
	movzx	eax,word [rdi+2]
	rol	ax,8
	lea	rcx,[rdi+4+rax]
	cmp	rcx,r14
	jne	.bad
	mov	rsi,rdi
	cmp	word [rsi],0x0304		; ecdsa_secp256r1_sha256
	je	.ecdsa
	cmp	word [rsi],0x0408		; rsa_pss_rsae_sha256
	je	.pss
	cmp	word [rsi],0x0104		; rsa_pkcs1_sha256
	je	.pkcs1
	jmp	.bad
.ecdsa:
	cmp	dword [g_cc_key+PK_TYPE],1
	jne	.bad
	add	rsi,4
	mov	rdx,r14
	call	der_read			; SEQUENCE { r, s }
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; INTEGER r
	jc	.bad
	lea	rdi,[g_cc_rs]
	push	r8
	call	der_int_32
	pop	r8
	jc	.bad
	mov	rsi,r8
	call	der_read			; INTEGER s
	jc	.bad
	lea	rdi,[g_cc_rs+32]
	call	der_int_32
	jc	.bad
	lea	rdi,[g_cc_key+PK_DATA]
	lea	rsi,[g_cc_dig]
	lea	rdx,[g_cc_rs]
	lea	rcx,[g_cc_rs+32]
	call	p256_verify
	jmp	.out
.pss:
	call	.rsa_args
	jc	.bad
	call	rsa_pss_verify
	jmp	.out
.pkcs1:
	call	.rsa_args
	jc	.bad
	call	rsa_pkcs1_verify
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r14
	ret
; rsi = the body, eax = the signature's length: rsa_*_verify's arguments
.rsa_args:
	cmp	dword [g_cc_key+PK_TYPE],2
	jne	.no
	cmp	eax,[g_cc_key+PK_NLEN]
	jne	.no
	lea	rdx,[rsi+4]
	lea	rdi,[g_cc_key+PK_DATA]
	mov	esi,[g_cc_key+PK_NLEN]
	mov	ecx,[g_cc_key+PK_E]
	lea	r8,[g_cc_dig]
	clc
	ret
.no:
	stc
	ret
