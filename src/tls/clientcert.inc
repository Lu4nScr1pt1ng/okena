; TLS 1.3 client certificates, the client's side: an origin that asks okena for
; one (a pool's `tls { cert; key }`: authenticated origin pulls). Reached from
; tlsc_finish (client.inc), in its frame, and back to it to seal.

; the server asked for a certificate (RFC 8446 4.4.2): Certificate (ours, or none),
; CertificateVerify (when there is one), Finished, in one record from r13 + 5;
; [rsp + 8] its plaintext's length. The application keys still come from the
; transcript through the server Finished (TC_THX, kept here in TC_THSF).
CV_AREA		:= 240				; content (130), digest (32), signature (64): aligned
tlsc_client_auth:
	lea	rsi,[rbx+TC_THX]
	lea	rdi,[rbx+TC_THSF]
	mov	ecx,32
	rep	movsb
	push	r14
	push	r15
	lea	r14,[r13+5]			; where the next message goes
	; Certificate: type 11, u24 length, context, u24 list length, list
	mov	r15d,[rbx+TC_CID]
	test	r15d,r15d
	jz	@f
	dec	r15d
	imul	r15,r15,TL_SIZE
	lea	r15,[g_tls+r15]
@@:
	lea	rdi,[r14+4]
	movzx	ecx,byte [rbx+TC_CRCTX]
	lea	rsi,[rbx+TC_CRCTX]
	inc	ecx
	rep	movsb				; the context, as it came
	xor	ecx,ecx
	test	r15,r15
	jz	@f
	mov	ecx,[r15+TL_CLEN]
@@:
	mov	eax,ecx
	bswap	eax
	shr	eax,8
	mov	[rdi],ax
	shr	eax,16
	mov	[rdi+2],al
	add	rdi,3
	test	ecx,ecx
	jz	@f
	mov	esi,[r15+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	rep	movsb				; (u24 length | DER | u16 0, each: as TLS 1.3 has them)
@@:
	mov	byte [r14],11
	mov	rax,rdi
	sub	rax,r14
	sub	eax,4
	bswap	eax
	shr	eax,8
	mov	[r14+1],ax
	shr	eax,16
	mov	[r14+3],al
	mov	rsi,r14
	mov	edx,edi
	sub	edx,r14d
	mov	r14,rdi
	tc_add
	test	r15,r15
	jz	.fin
	; CertificateVerify over 64 spaces | "TLS 1.3, client CertificateVerify" | 0 | TH
	tc_snapshot				; through our Certificate
	sub	rsp,CV_AREA
	lea	rsi,[tls13_cv_cprefix]
	mov	rdi,rsp
	mov	ecx,TLS13_CV_PREFIX
	rep	movsb
	lea	rsi,[rbx+TC_THX]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rsp+TLS13_CV_PREFIX + 32]	; its digest
	mov	rsi,rsp
	mov	edx,TLS13_CV_PREFIX + 32
	call	sha256
	cmp	dword [r15+TL_KEYTYPE],1
	je	.cv_rsa
	cmp	dword [r15+TL_KEYTYPE],2
	je	.cv_ed
	lea	rdi,[rsp+TLS13_CV_PREFIX + 64]
	lea	rsi,[r15+TL_KEY]
	lea	rdx,[rsp+TLS13_CV_PREFIX + 32]
	call	p256_sign
	test	eax,eax
	jz	.cv_failed
	lea	rdi,[r14+8]
	lea	rsi,[rsp+TLS13_CV_PREFIX + 64]
	call	ecdsa_der
	mov	edx,eax
	mov	word [r14+4],0x0304		; ecdsa_secp256r1_sha256
	jmp	.cv_len
.cv_ed:
	lea	rdi,[r14+8]
	lea	rsi,[r15+TL_KEY]
	lea	rdx,[r15+TL_PUB]
	mov	rcx,rsp
	mov	r8d,TLS13_CV_PREFIX + 32
	call	ed25519_sign
	mov	edx,64
	mov	word [r14+4],0x0708		; ed25519
	jmp	.cv_len
.cv_rsa:
	lea	rdi,[r14+8]
	lea	rsi,[r15+TL_RSA_N]
	mov	edx,[r15+TL_RSA_NLEN]
	lea	rcx,[r15+TL_RSA_D]
	lea	r8,[rsp+TLS13_CV_PREFIX + 32]
	call	rsa_pss_sign
	mov	edx,[r15+TL_RSA_NLEN]
	mov	word [r14+4],0x0408		; rsa_pss_rsae_sha256
.cv_len:
	add	rsp,CV_AREA
	mov	byte [r14],15
	lea	ecx,[rdx+4]
	mov	eax,ecx
	bswap	eax
	shr	eax,8
	mov	[r14+1],ax
	shr	eax,16
	mov	[r14+3],al
	mov	eax,edx
	xchg	al,ah
	mov	[r14+6],ax
	mov	rsi,r14
	add	edx,8
	add	r14,rdx
	tc_add
.fin:
	; Finished over the transcript through what we sent
	tc_snapshot
	lea	rdi,[rbx+TC_FIN]
	lea	rsi,[rbx+TC_CFK]
	mov	edx,32
	lea	rcx,[rbx+TC_THX]
	mov	r8d,32
	call	hmac_sha256
	mov	dword [r14],0x20000014
	lea	rdi,[r14+4]
	lea	rsi,[rbx+TC_FIN]
	mov	ecx,32
	rep	movsb
	mov	byte [rdi],22			; inner content type
	inc	rdi
	lea	rax,[r13+5]
	sub	rdi,rax
	mov	[rsp+16],edi			; (under r14, r15: the plaintext's length)
	; the application keys: from the transcript through the server Finished
	lea	rsi,[rbx+TC_THSF]
	lea	rdi,[rbx+TC_THX]
	mov	ecx,32
	rep	movsb
	pop	r15
	pop	r14
	jmp	tlsc_finish.seal
.cv_failed:
	add	rsp,CV_AREA
	mov	dword [rsp+16],0
	pop	r15
	pop	r14
	add	rsp,8
	pop	r13
	pop	r12
	pop	rbx
	xor	eax,eax
	ret

