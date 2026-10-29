; Certificates and private keys for `tls { cert FILE; key FILE }`.
;
; Read where the configuration is compiled (okena check, the start, and
; the reload's compiler child, so a bad file rejects a reload). PEM files
; (RFC 7468): the certificate file holds the chain, the server's own
; certificate first; the key file an EC P-256 private key, SEC 1 ("EC
; PRIVATE KEY") or PKCS #8 ("PRIVATE KEY"). The key must belong to the
; certificate: the public key derived from it is compared with the
; certificate's. The chain is stored as TLS 1.3's certificate_list
; (RFC 8446 4.4.2: uint24 length, the DER, empty extensions per entry),
; ready to send.


bss
	align 8
	g_plan_tls	dd ?
	g_tls_used	dd ?
	g_tls:		rb TL_SIZE * MAX_TLS
	g_tls_store:	rb TLS_STORE
	; scratch while loading
	g_tls_path	rb 1024
	g_tls_b64	rb TLS_DER_MAX * 2
	g_tls_der	rb TLS_DER_MAX
	g_tls_kder	rb 4096
	g_tls_cpub	rb 72			; the certificate's public key
	g_tls_kpub	rb 72			; the key's
	g_tls_d		rb 32
end bss

rodata
	oid_ec_public_key	db 0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01		; 1.2.840.10045.2.1
	oid_prime256v1		db 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07	; 1.2.840.10045.3.1.7
	oid_rsa_encryption	db 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01	; 1.2.840.113549.1.1.1
end rodata

; ------------------------------------------------------------------ DER

; rsi = element, rdx = end of the enclosing content. al = tag, rsi = its
; content, ecx = content length, r8 = the next element. CF when it does
; not fit or the length is not a definite one of at most 3 bytes.
der_read:
	lea	rax,[rsi+2]
	cmp	rax,rdx
	ja	.bad
	movzx	eax,byte [rsi]
	movzx	ecx,byte [rsi+1]
	add	rsi,2
	test	cl,0x80
	jz	.content
	and	ecx,0x7F
	jz	.bad				; indefinite: not DER
	cmp	ecx,3
	ja	.bad
	lea	r8,[rsi+rcx]
	cmp	r8,rdx
	ja	.bad
	mov	r9d,ecx
	xor	ecx,ecx
@@:
	shl	ecx,8
	mov	cl,[rsi]
	inc	rsi
	dec	r9d
	jnz	@b
.content:
	lea	r8,[rsi+rcx]
	cmp	r8,rdx
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; rsi/ecx = an OID's content, rdi/edx = the expected bytes: ZF when equal.
der_oid_is:
	cmp	ecx,edx
	jne	.out
	push	rsi
	push	rdi
	push	rcx
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
.out:
	ret

; ------------------------------------------------------------------ PEM

; rsi = text, rdx = its end, rdi = "BEGIN " label wanted (NUL-terminated,
; e.g. "CERTIFICATE"). The next block with that label decoded into
; g_tls_der: eax = DER length, rsi = after the block; eax = -1 when there
; is none left, -2 when its base64 is broken or it is too large.
pem_next:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdx				; end
	mov	r13,rdi				; label
.find:
	; "-----BEGIN "
	lea	rax,[rsi+11]
	cmp	rax,r12
	ja	.none
	cmp	dword [rsi],'----'
	jne	.step
	cmp	dword [rsi+4],'-BEG'
	jne	.step
	cmp	dword [rsi+7],'GIN '
	jne	.step
	lea	rbx,[rsi+11]			; the label
	mov	rdi,r13
	mov	rcx,rbx
@@:
	mov	al,[rdi]
	test	al,al
	jz	@f
	cmp	rcx,r12
	jae	.step
	cmp	al,[rcx]
	jne	.step
	inc	rdi
	inc	rcx
	jmp	@b
@@:
	lea	rax,[rcx+5]
	cmp	rax,r12
	ja	.step
	cmp	dword [rcx],'----'
	jne	.step
	cmp	byte [rcx+4],'-'
	jne	.step
	lea	rsi,[rcx+5]			; the body
	; gather base64 characters up to "-----END"
	lea	rdi,[g_tls_b64]
	xor	r14d,r14d
.body:
	cmp	rsi,r12
	jae	.broken
	mov	al,[rsi]
	cmp	al,'-'
	je	.end
	inc	rsi
	cmp	al,' '
	jbe	.body				; spaces, CR, LF, tabs
	cmp	r14d,TLS_DER_MAX * 4 / 3
	jae	.broken
	mov	[rdi+r14],al
	inc	r14d
	jmp	.body
.end:
	; past the END line
@@:
	cmp	rsi,r12
	jae	@f
	mov	al,[rsi]
	inc	rsi
	cmp	al,10
	jne	@b
@@:
	push	rsi
	lea	rdi,[g_tls_der]
	lea	rsi,[g_tls_b64]
	mov	edx,r14d
	call	base64_decode
	pop	rsi
	cmp	rax,-1
	je	.broken
	jmp	.out
.step:
	inc	rsi
	jmp	.find
.none:
	mov	eax,-1
	jmp	.out
.broken:
	mov	eax,-2
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring pem_certificate, 'CERTIFICATE',0
cstring pem_ec_key, 'EC PRIVATE KEY',0
cstring pem_pkcs8_key, 'PRIVATE KEY',0
cstring pem_rsa_key, 'RSA PRIVATE KEY',0
cstring pem_enc_key, 'ENCRYPTED PRIVATE KEY',0

; ------------------------------------------------------------ extraction

TLS_OK		:= 0
TLS_E_DER	:= 1				; not a certificate / key in DER
TLS_E_RSA	:= 2				; an RSA key: not yet
TLS_E_CURVE	:= 3				; EC, but not P-256
TLS_E_KEYVAL	:= 4				; a key out of range

; rsi = certificate DER, edx = length: its subject public key into
; g_tls_cpub. eax = TLS_*.
cert_public_key:
	push	rbx
	lea	rdx,[rsi+rdx]
	call	der_read			; Certificate SEQUENCE
	jc	.der
	cmp	al,0x30
	jne	.der
	mov	rdx,r8
	call	der_read			; tbsCertificate
	jc	.der
	cmp	al,0x30
	jne	.der
	mov	rdx,r8
	call	der_read			; [0] version, or the serial
	jc	.der
	mov	ebx,5				; serial, signature, issuer, validity, subject
	cmp	al,0xA0
	jne	@f
	inc	ebx				; skip the version too
@@:
	mov	rsi,r8
	dec	ebx
	jz	.spki
@@:
	call	der_read
	jc	.der
	mov	rsi,r8
	dec	ebx
	jnz	@b
.spki:
	call	der_read			; SubjectPublicKeyInfo
	jc	.der
	cmp	al,0x30
	jne	.der
	push	r8
	mov	rdx,r8
	call	der_read			; AlgorithmIdentifier
	jc	.der_pop
	cmp	al,0x30
	jne	.der_pop
	mov	rbx,r8				; then the BIT STRING
	push	rdx
	mov	rdx,r8
	call	der_read			; algorithm OID
	jc	.der_pop2
	cmp	al,6
	jne	.der_pop2
	lea	rdi,[oid_rsa_encryption]
	mov	edx,9
	call	der_oid_is
	je	.rsa
	lea	rdi,[oid_ec_public_key]
	mov	edx,7
	call	der_oid_is
	jne	.curve
	mov	rsi,r8
	mov	rdx,rbx
	call	der_read			; the named curve
	jc	.der_pop2
	lea	rdi,[oid_prime256v1]
	mov	edx,8
	call	der_oid_is
	jne	.curve
	pop	rdx
	mov	rsi,rbx
	call	der_read			; BIT STRING: 00 04 X Y
	pop	r9
	jc	.der
	cmp	al,3
	jne	.der
	cmp	ecx,66
	jne	.der
	cmp	word [rsi],0x0400
	jne	.der
	inc	rsi
	lea	rdi,[g_tls_cpub]
	mov	ecx,65
	rep	movsb
	mov	eax,TLS_OK
	pop	rbx
	ret
.rsa:
	add	rsp,16
	mov	eax,TLS_E_RSA
	pop	rbx
	ret
.curve:
	add	rsp,16
	mov	eax,TLS_E_CURVE
	pop	rbx
	ret
.der_pop2:
	add	rsp,8
.der_pop:
	add	rsp,8
.der:
	mov	eax,TLS_E_DER
	pop	rbx
	ret

; rsi = SEC 1 ECPrivateKey DER, edx = length: d into g_tls_d. eax = TLS_*.
key_sec1:
	lea	rdx,[rsi+rdx]
	call	der_read			; SEQUENCE
	jc	.der
	cmp	al,0x30
	jne	.der
	mov	rdx,r8
	call	der_read			; version 1
	jc	.der
	cmp	al,2
	jne	.der
	cmp	ecx,1
	jne	.der
	cmp	byte [rsi],1
	jne	.der
	mov	rsi,r8
	call	der_read			; privateKey OCTET STRING
	jc	.der
	cmp	al,4
	jne	.der
	cmp	ecx,32
	ja	.der
	; right-aligned in 32 bytes
	lea	rdi,[g_tls_d]
	push	rcx
	push	rsi
	xor	eax,eax
	mov	ecx,32
	rep	stosb
	pop	rsi
	pop	rcx
	lea	rdi,[g_tls_d+32]
	sub	rdi,rcx
	rep	movsb
	; [0] parameters, when present, must name P-256
	mov	rsi,r8
	cmp	rsi,rdx
	jae	.ok
	call	der_read
	jc	.der
	cmp	al,0xA0
	jne	.ok
	mov	rdx,r8
	call	der_read
	jc	.der
	cmp	al,6
	jne	.der
	lea	rdi,[oid_prime256v1]
	mov	edx,8
	call	der_oid_is
	jne	.curve
.ok:
	mov	eax,TLS_OK
	ret
.curve:
	mov	eax,TLS_E_CURVE
	ret
.der:
	mov	eax,TLS_E_DER
	ret

; rsi = PKCS #8 PrivateKeyInfo DER, edx = length. eax = TLS_*.
key_pkcs8:
	push	rbx
	lea	rdx,[rsi+rdx]
	call	der_read			; SEQUENCE
	jc	.der
	cmp	al,0x30
	jne	.der
	mov	rdx,r8
	call	der_read			; version 0
	jc	.der
	cmp	al,2
	jne	.der
	mov	rsi,r8
	call	der_read			; AlgorithmIdentifier
	jc	.der
	cmp	al,0x30
	jne	.der
	mov	rbx,r8				; then the key
	push	rdx
	mov	rdx,r8
	call	der_read
	jc	.der_pop
	lea	rdi,[oid_rsa_encryption]
	mov	edx,9
	call	der_oid_is
	je	.rsa
	lea	rdi,[oid_ec_public_key]
	mov	edx,7
	call	der_oid_is
	jne	.curve
	mov	rsi,r8
	mov	rdx,rbx
	call	der_read
	jc	.der_pop
	lea	rdi,[oid_prime256v1]
	mov	edx,8
	call	der_oid_is
	jne	.curve
	pop	rdx
	mov	rsi,rbx
	call	der_read			; OCTET STRING { ECPrivateKey }
	jc	.der
	cmp	al,4
	jne	.der
	mov	edx,ecx
	pop	rbx
	jmp	key_sec1
.rsa:
	add	rsp,8
	mov	eax,TLS_E_RSA
	pop	rbx
	ret
.curve:
	add	rsp,8
	mov	eax,TLS_E_CURVE
	pop	rbx
	ret
.der_pop:
	add	rsp,8
.der:
	mov	eax,TLS_E_DER
	pop	rbx
	ret

; ------------------------------------------------------------- compiling

; rdi = a directive node with one path argument: read its file. rax =
; contents, rdx = end; exits with a diagnostic when it cannot be read.
tls_read_arg:
	push	rbx
	mov	rbx,rdi
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	.long
	lea	rdi,[g_tls_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_tls_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.cannot
	add	rdx,rax
	pop	rbx
	ret
.long:
	mov	rax,-ENAMETOOLONG
.cannot:
	push	rax
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'cannot read '
	lea	rsi,[g_tls_path]
	call	out_cstr
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	jmp	tls_error_end

; rdi = node: begin a diagnostic at its first argument.
tls_error_at:
	mov	rax,[rdi+N_ARGS]
	push	rax
	mov	rdi,rax
	call	arg_value_span
	pop	rax
	mov	edx,[rax+A_LINE]
	jmp	cfg_error

tls_error_end:
	call	cfg_diag_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = listener node. eax = its tls entry + 1, or 0 without a tls block.
TC_CERT		:= 0
TC_KEY		:= 8
compile_tls:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,16
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	.none
	mov	r12,rax
	mov	rdi,r12
	mov	ecx,DIR_CERT
	call	find_child
	mov	[rsp+TC_CERT],rax
	mov	rdi,r12
	mov	ecx,DIR_KEY
	call	find_child
	mov	[rsp+TC_KEY],rax
	mov	ecx,[g_plan_tls]
	cmp	ecx,MAX_TLS
	jae	plan_too_many
	inc	dword [g_plan_tls]
	imul	r13,rcx,TL_SIZE
	lea	r13,[g_tls+r13]
	push	rcx
	; the chain
	mov	rdi,[rsp+8+TC_CERT]
	call	tls_read_arg
	mov	r14,rax				; text
	mov	r15,rdx				; its end
	mov	eax,[g_tls_used]
	mov	[r13+TL_CHAIN],eax
	xor	ebx,ebx				; certificates
.cert:
	mov	rsi,r14
	mov	rdx,r15
	lea	rdi,[pem_certificate]
	call	pem_next
	cmp	eax,-1
	je	.chain_done
	cmp	eax,-2
	je	.cert_broken
	mov	r14,rsi
	test	ebx,ebx
	jnz	.append
	; the server's own certificate: its public key
	push	rax
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	cert_public_key
	mov	ecx,eax
	pop	rax
	test	ecx,ecx
	jnz	.cert_kind
.append:
	; uint24 length | DER | uint16 0 (no extensions)
	mov	ecx,[g_tls_used]
	lea	edx,[rcx+rax+5]
	cmp	edx,TLS_STORE
	ja	.too_big
	lea	rdi,[g_tls_store+rcx]
	mov	edx,eax
	shr	edx,16
	mov	[rdi],dl
	mov	[rdi+1],ah
	mov	[rdi+2],al
	add	rdi,3
	lea	rsi,[g_tls_der]
	mov	ecx,eax
	rep	movsb
	mov	word [rdi],0
	add	rdi,2
	lea	rax,[g_tls_store]
	sub	rdi,rax
	mov	[g_tls_used],edi
	inc	ebx
	jmp	.cert
.chain_done:
	test	ebx,ebx
	jz	.no_cert
	mov	eax,[g_tls_used]
	sub	eax,[r13+TL_CHAIN]
	mov	[r13+TL_CLEN],eax
	cmp	eax,TLS_CHAIN_MAX
	ja	.chain_big
	lea	rsi,[g_tls_cpub]
	lea	rdi,[r13+TL_PUB]
	mov	ecx,65
	rep	movsb
	; the key
	mov	rdi,[rsp+8+TC_KEY]
	call	tls_read_arg
	mov	r14,rax
	mov	r15,rdx
	mov	rsi,r14
	mov	rdx,r15
	lea	rdi,[pem_ec_key]
	call	pem_next
	cmp	eax,0
	jl	.try_pkcs8
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	key_sec1
	jmp	.key_parsed
.try_pkcs8:
	mov	rsi,r14
	mov	rdx,r15
	lea	rdi,[pem_pkcs8_key]
	call	pem_next
	cmp	eax,0
	jl	.no_key
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	key_pkcs8
.key_parsed:
	test	eax,eax
	jnz	.key_kind
	; derived public key = the certificate's?
	lea	rdi,[g_tls_kpub]
	lea	rsi,[g_tls_d]
	call	p256_public
	lea	rdi,[g_tls_kpub]
	lea	rsi,[r13+TL_PUB]
	mov	edx,65
	call	ct_equal
	test	eax,eax
	jz	.mismatch
	lea	rsi,[g_tls_d]
	lea	rdi,[r13+TL_KEY]
	mov	ecx,32
	rep	movsb
	lea	rdi,[g_tls_d]
	mov	ecx,32
	call	secure_zero
	pop	rax
	inc	eax
	jmp	.out
.none:
	xor	eax,eax
.out:
	add	rsp,16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; diagnostics: at the cert line or the key line
macro tls_fail which*, text&
	mov	rdi,[rsp+8+which]
	call	tls_error_at
	out_lit text
	jmp	tls_error_end
end macro
.cert_broken:
	tls_fail TC_CERT, 'a CERTIFICATE block whose base64 is broken (or one over 64 KiB)'
.no_cert:
	tls_fail TC_CERT, 'no CERTIFICATE block in this file (PEM expected)'
.too_big:
	tls_fail TC_CERT, 'the certificate chains of this configuration pass 1 MiB'
.chain_big:
	tls_fail TC_CERT, 'this certificate chain passes 24 KiB (send the server certificate and its intermediates, not the root)'
.cert_kind:
	cmp	ecx,TLS_E_RSA
	je	.cert_rsa
	cmp	ecx,TLS_E_CURVE
	je	.cert_curve
	tls_fail TC_CERT, 'the first certificate cannot be read (DER)'
.cert_rsa:
	tls_fail TC_CERT, 'an RSA certificate: okena signs with ECDSA P-256 for now (openssl ecparam -name prime256v1)'
.cert_curve:
	tls_fail TC_CERT, 'the certificate''s key is not on P-256 (prime256v1), the curve okena signs with'
.no_key:
	tls_fail TC_KEY, 'no EC PRIVATE KEY or PRIVATE KEY block in this file (an encrypted key is not supported)'
.key_kind:
	cmp	eax,TLS_E_RSA
	je	.key_rsa
	cmp	eax,TLS_E_CURVE
	je	.key_curve
	tls_fail TC_KEY, 'the private key cannot be read (DER)'
.key_rsa:
	tls_fail TC_KEY, 'an RSA key: okena signs with ECDSA P-256 for now'
.key_curve:
	tls_fail TC_KEY, 'the key is not on P-256 (prime256v1)'
.mismatch:
	tls_fail TC_KEY, 'this key does not belong to the certificate (their public keys differ)'

; Until the TLS handshake is built, a listener with a tls block must not
; serve its port in plaintext: refuse to start (or to reload) with it.
; okena check loads and checks the files already.
tls_refuse_serving:
	cmp	dword [g_plan_tls],0
	je	.ok
	call	log_begin
	out_lit 'tls { } is read and checked (okena check), but the TLS handshake is not built yet: refusing to serve these ports in plaintext'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.ok:
	ret
