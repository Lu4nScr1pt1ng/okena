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
	mov	rdi,[rdi+N_ARGS]
; rdi = an argument (a path): the same.
tls_read_val:
	push	rbx
	mov	rax,rdi
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
	mov	rdi,[rdi+N_ARGS]
; rdi = an argument: the error points at it.
tls_error_arg:
	mov	rax,rdi
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

; rdi = listener node. eax = its first tls entry + 1 (the default
; certificate; the others follow it, one per cert line), or 0 without a
; tls block.
compile_tls:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,8
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	.none
	mov	r12,rax				; the tls block
	mov	r13d,[g_plan_tls]		; the group: its first entry
	mov	rdi,r12
	mov	ecx,DIR_KEY
	call	find_child
	xor	r14d,r14d			; the block's key line, for a lone cert
	test	rax,rax
	jz	@f
	mov	r14,[rax+N_ARGS]
@@:
	lea	rdx,[dir_table + D_SIZE*DIR_CERT]
	mov	rbx,[r12+N_CHILD]
.cert:
	test	rbx,rbx
	jz	.done
	cmp	[rbx+N_DEF],rdx
	jne	.next
	; key=FILE on the line, else the block's key
	mov	rsi,r14
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rbx+N_ARGC]
@@:
	dec	ecx
	jz	.key_found
	add	rax,A_SIZE
	cmp	dword [rax+A_KIND],ARG_KV
	jne	@b
	mov	rsi,rax
.key_found:
	mov	rdi,[rbx+N_ARGS]
	mov	edx,r13d
	push	rdx
	call	compile_cert
	pop	rdx
	lea	rdx,[dir_table + D_SIZE*DIR_CERT]
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.cert
.done:
	lea	eax,[r13+1]
	jmp	.out
.none:
	xor	eax,eax
.out:
	add	rsp,8
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = the cert line's path, rsi = its key's path (arguments), edx = the
; group (its listener's first entry): one tls entry, its names indexed.
TC_CERT		:= 0
TC_KEY		:= 8
TC_GROUP	:= 16
compile_cert:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,32
	mov	[rsp+TC_CERT],rdi
	mov	[rsp+TC_KEY],rsi
	mov	[rsp+TC_GROUP],edx
	mov	ecx,[g_plan_tls]
	cmp	ecx,MAX_TLS
	jae	plan_too_many
	inc	dword [g_plan_tls]
	imul	r13,rcx,TL_SIZE
	lea	r13,[g_tls+r13]
	push	rcx
	; the chain
	mov	eax,[rsp+8+TC_GROUP]
	mov	[r13+TL_GROUP],eax
	mov	rdi,[rsp+8+TC_CERT]
	call	tls_read_val
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
	; its names (subjectAltName dNSName), for SNI
	push	rax				; the DER's length
	mov	eax,[rsp+8]			; this entry's index
	mov	[g_tls_cur_tl],eax
	mov	eax,[rsp+16+TC_GROUP]
	mov	[g_tls_cur_group],eax
	lea	rsi,[g_tls_der]
	mov	edx,[rsp]
	call	cert_names
	pop	rax
	jc	.names_full
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
	call	tls_read_val
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
	add	rsp,32
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; diagnostics: at the cert line or the key line
macro tls_fail which*, text&
	mov	rdi,[rsp+8+which]
	call	tls_error_arg
	out_lit text
	jmp	tls_error_end
end macro
.cert_broken:
	tls_fail TC_CERT, 'a CERTIFICATE block whose base64 is broken (or one over 64 KiB)'
.no_cert:
	tls_fail TC_CERT, 'no CERTIFICATE block in this file (PEM expected)'
.too_big:
	tls_fail TC_CERT, 'the certificate chains of this configuration pass 1 MiB'
.names_full:
	tls_fail TC_CERT, 'the certificates of this configuration name more than 4096 hosts'
.chain_big:
	tls_fail TC_CERT, 'this certificate chain passes 20 KiB (send the server certificate and its intermediates, not the root)'
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

; ------------------------------------------------------- ticket keys
;
; okena { ticket_keys FILE }: session ticket keys shared by a fleet. One
; key a line, 32 bytes of base64 (openssl rand -base64 32): the first seals
; new tickets, a second (the previous one) still opens them. The AES key
; and its id come from SHA-256 of the line, so every instance reading the
; file has the same. Rotating is the operator's: a new first line, then a
; reload; without the file, okena rotates its own keys every hour.
TKF_KEYS	:= 4				; 2 x (key 16, id 4)
TKF_KEY		:= 20
TKF_SIZE	:= TKF_KEYS + 2 * TKF_KEY

bss
	align 8
	g_plan_tkeys:	rb TKF_SIZE		; d: how many, then the keys
end bss

; rdi = the ticket_keys directive.
compile_ticket_keys:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,40
	mov	rbx,rdi
	call	tls_read_arg			; rax = text, rdx = its end
	mov	r12,rax
	mov	r13,rdx
.line:
	cmp	r12,r13
	jae	.done
	movzx	eax,byte [r12]
	cmp	al,' '
	jbe	.skip				; blank lines, spaces, CR, LF
	mov	rsi,r12				; a line: up to LF or a space
.scan:
	cmp	r12,r13
	jae	.got
	cmp	byte [r12],' '
	jbe	.got
	inc	r12
	jmp	.scan
.got:
	cmp	dword [g_plan_tkeys],2
	jae	.too_many
	mov	edx,r12d
	sub	edx,esi
	cmp	edx,64
	ja	.bad
	lea	rdi,[g_tls_kder]
	call	base64_decode
	cmp	rax,32
	jne	.bad
	mov	rdi,rsp
	lea	rsi,[g_tls_kder]
	mov	edx,32
	call	sha256
	mov	eax,[g_plan_tkeys]
	imul	eax,eax,TKF_KEY
	lea	rdi,[g_plan_tkeys+TKF_KEYS+rax]
	mov	rsi,rsp
	mov	ecx,TKF_KEY			; key = H[0..16], id = H[16..20]
	rep	movsb
	inc	dword [g_plan_tkeys]
	mov	rdi,rsp
	mov	ecx,32
	call	secure_zero
	lea	rdi,[g_tls_kder]
	mov	ecx,32
	call	secure_zero
	jmp	.line
.skip:
	inc	r12
	jmp	.line
.done:
	cmp	dword [g_plan_tkeys],0
	je	.empty
	add	rsp,40
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'a line of this file is not 32 bytes of base64 (make one with: openssl rand -base64 32)'
	jmp	tls_error_end
.too_many:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'at most two keys: the one that seals new tickets, then the previous one'
	jmp	tls_error_end
.empty:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'no key in this file (one a line: openssl rand -base64 32)'
	jmp	tls_error_end

; Supervisor, with the plan in place (the start, each reload): the file's
; keys into the shared slots, the current and the previous; without a
; file, back to keys of okena's own when the last plan had one.
tls_tickets_apply:
	cmp	qword [g_tks],0
	je	.done
	push	rbx
	mov	rbx,[g_tks]
	cmp	dword [g_plan_tkeys],0
	je	.own
	mov	dword [g_tk_fixed],1
	mov	dword [g_tk_life],TICKET_ROTATE	; the operator rotates: an hour, then the previous key's
	mov	edi,[rbx+TKS_CUR]
	lea	rsi,[g_plan_tkeys+TKF_KEYS]
	call	tls_ticket_set
	mov	edi,[rbx+TKS_CUR]		; the previous slot: (cur + 2) mod 3
	add	edi,2
	cmp	edi,3
	jb	@f
	sub	edi,3
@@:
	cmp	dword [g_plan_tkeys],2
	jb	.no_previous
	lea	rsi,[g_plan_tkeys+TKF_KEYS+TKF_KEY]
	call	tls_ticket_set
	pop	rbx
	ret
.no_previous:
	imul	eax,edi,TKS_SLOT
	mov	dword [rbx+TKS_SLOTS+rax+TKS_ID],0
	pop	rbx
	ret
.own:
	cmp	dword [g_tk_fixed],0
	je	.kept
	mov	dword [g_tk_fixed],0		; the file is gone: fresh keys, rotated again
	mov	eax,[g_tk_period]
	mov	[g_tk_life],eax
	mov	edi,[rbx+TKS_CUR]
	call	tls_ticket_fill
	mov	edi,[rbx+TKS_CUR]
	add	edi,2
	cmp	edi,3
	jb	@f
	sub	edi,3
@@:
	imul	eax,edi,TKS_SLOT
	mov	dword [rbx+TKS_SLOTS+rax+TKS_ID],0
	call	tls_now_s
	add	eax,[g_tk_period]
	mov	[g_tk_next],eax
.kept:
	pop	rbx
.done:
	ret

; ---------------------------------------------------------------- SNI

oid_subject_alt_name	:= 0x111D55		; 2.5.29.17, its three content bytes

bss
	align 8
	g_tls_ntab:	rb TN_CAP * TN_SIZE
	g_tls_nstore:	rb TN_STORE
	g_tls_nused	dd ?			; bytes in g_tls_nstore
	g_tls_ncount	dd ?			; names
	g_tls_cur_tl	dd ?			; while compiling: the entry being read
	g_tls_cur_group	dd ?
end bss

; rsi = name (lowercase), ecx = length, edx = group: eax = its hash
; (FNV-1a mixed with the group, never 0). Keeps rsi, rcx, rdx.
tls_name_hash:
	push	rcx
	push	rsi
	mov	eax,0x811C9DC5
.byte:
	test	ecx,ecx
	jz	.mixed
	movzx	r8d,byte [rsi]
	xor	eax,r8d
	imul	eax,eax,0x01000193
	inc	rsi
	dec	ecx
	jmp	.byte
.mixed:
	imul	r8d,edx,0x9E3779B1
	xor	eax,r8d
	or	eax,eax
	jnz	@f
	inc	eax
@@:
	pop	rsi
	pop	rcx
	ret

; rsi = name (lowercase), ecx = length, edx = group: eax = its entry, or
; -1. Keeps rsi, rcx, rdx.
tls_name_find:
	push	rbx
	push	r12
	call	tls_name_hash
	mov	r12d,eax
	mov	ebx,eax
.probe:
	and	ebx,TN_CAP - 1
	imul	r9d,ebx,TN_SIZE
	lea	r9,[g_tls_ntab+r9]
	mov	eax,[r9+TN_HASH]
	test	eax,eax
	jz	.none
	cmp	eax,r12d
	jne	.next
	cmp	[r9+TN_LEN],ecx
	jne	.next
	movzx	eax,word [r9+TN_GROUP]
	cmp	eax,edx
	jne	.next
	push	rsi
	push	rcx
	push	rdi
	mov	edi,[r9+TN_OFF]
	lea	rdi,[g_tls_nstore+rdi]
	repe	cmpsb
	pop	rdi
	pop	rcx
	pop	rsi
	jne	.next
	movzx	eax,word [r9+TN_TL]
	jmp	.out
.next:
	inc	ebx
	jmp	.probe
.none:
	mov	eax,-1
.out:
	pop	r12
	pop	rbx
	ret

; rsi = a dNSName, ecx = its length: indexed for g_tls_cur_group, naming
; g_tls_cur_tl. A name the group has already keeps its first certificate.
; CF when the table is full.
tls_name_add:
	test	ecx,ecx
	jz	.ok
	cmp	ecx,253
	ja	.ok				; not a host name
	cmp	dword [g_tls_ncount],TN_CAP / 2
	jae	.full
	mov	eax,[g_tls_nused]
	lea	edx,[rax+rcx]
	cmp	edx,TN_STORE
	ja	.full
	; lowercase into the store
	lea	rdi,[g_tls_nstore+rax]
	push	rdi
	push	rcx
@@:
	mov	al,[rsi]
	lea	edx,[rax-'A']
	cmp	dl,25
	ja	.lower
	or	al,0x20
.lower:
	mov	[rdi],al
	inc	rsi
	inc	rdi
	dec	ecx
	jnz	@b
	pop	rcx
	pop	rsi				; the stored copy
	mov	edx,[g_tls_cur_group]
	call	tls_name_find
	cmp	eax,-1
	jne	.ok				; named already: the first certificate keeps it
	call	tls_name_hash
	mov	r8d,eax
.probe:
	and	eax,TN_CAP - 1
	imul	r9d,eax,TN_SIZE
	lea	r9,[g_tls_ntab+r9]
	cmp	dword [r9+TN_HASH],0
	je	.slot
	inc	eax
	jmp	.probe
.slot:
	mov	[r9+TN_HASH],r8d
	mov	[r9+TN_GROUP],dx
	mov	eax,[g_tls_cur_tl]
	mov	[r9+TN_TL],ax
	mov	eax,[g_tls_nused]
	mov	[r9+TN_OFF],eax
	mov	[r9+TN_LEN],ecx
	add	[g_tls_nused],ecx
	inc	dword [g_tls_ncount]
.ok:
	clc
	ret
.full:
	stc
	ret

; rsi = a certificate (DER), edx = its length: its subjectAltName
; dNSNames into the table. CF when the table is full; a certificate whose
; extensions cannot be read simply names nothing.
cert_names:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rdx,[rsi+rdx]
	call	der_read			; Certificate
	jc	.done
	mov	rdx,r8
	call	der_read			; tbsCertificate
	jc	.done
	mov	r12,r8				; its end
	mov	rdx,r8
	call	der_read			; [0] version, or the serial
	jc	.done
	mov	ebx,6				; serial .. subjectPublicKeyInfo
	cmp	al,0xA0
	jne	@f
	inc	ebx
@@:
	mov	rsi,r8
	dec	ebx
	jz	.fields
@@:
	mov	rdx,r12
	call	der_read
	jc	.done
	mov	rsi,r8
	dec	ebx
	jnz	@b
.fields:					; [1], [2], then [3] extensions
	cmp	rsi,r12
	jae	.done
	mov	rdx,r12
	call	der_read
	jc	.done
	cmp	al,0xA3
	je	.extensions
	mov	rsi,r8
	jmp	.fields
.extensions:
	mov	rdx,r8
	call	der_read			; SEQUENCE OF Extension
	jc	.done
	mov	r13,r8				; their end
.extension:
	cmp	rsi,r13
	jae	.done
	mov	rdx,r13
	call	der_read			; Extension
	jc	.done
	mov	r14,r8				; the next one
	mov	rdx,r8
	call	der_read			; extnID
	jc	.done
	cmp	al,6
	jne	.skip
	cmp	ecx,3
	jne	.skip
	mov	eax,[rsi]
	and	eax,0xFFFFFF
	cmp	eax,oid_subject_alt_name
	jne	.skip
	mov	rsi,r8
	call	der_read			; critical, or the value
	jc	.done
	cmp	al,1
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.done
@@:
	cmp	al,4				; OCTET STRING
	jne	.skip
	mov	rdx,r8
	call	der_read			; GeneralNames
	jc	.done
	mov	r15,r8
.name:
	cmp	rsi,r15
	jae	.skip
	mov	rdx,r15
	call	der_read
	jc	.done
	push	r8
	cmp	al,0x82				; [2] dNSName
	jne	@f
	call	tls_name_add
	jc	.full
@@:
	pop	rsi
	jmp	.name
.skip:
	mov	rsi,r14
	jmp	.extension
.full:
	pop	rsi
	stc
	jmp	.out
.done:
	clc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Workers, in the handshake: rdi = the listener's default entry, rsi = the
; client's server_name, edx = its length: rax = the entry whose
; certificate names it (exactly, then as *.parent), or the default.
tls_cert_for_sni:
	push	rdi
	call	tls_cert_named
	pop	rdi
	test	rax,rax
	cmovz	rax,rdi
	ret

; rdi = an entry of the listener, rsi = a host name, edx = its length:
; rax = the entry whose certificate names it, or 0.
tls_cert_named:
	push	rbx
	sub	rsp,272
	mov	rbx,rdi
	test	edx,edx
	jz	.default
	cmp	edx,253
	ja	.default
	mov	ecx,edx
	lea	rdi,[rsp+8]			; lowercase, one byte of room before it
	push	rcx
@@:
	mov	al,[rsi]
	lea	r8d,[rax-'A']
	cmp	r8b,25
	ja	.lower
	or	al,0x20
.lower:
	mov	[rdi],al
	inc	rsi
	inc	rdi
	dec	ecx
	jnz	@b
	pop	rcx
	mov	edx,[rbx+TL_GROUP]
	lea	rsi,[rsp+8]
	call	tls_name_find
	cmp	eax,-1
	jne	.found
	; *.parent: the first label replaced
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	.default
	cmp	byte [rsp+8+rax],'.'
	je	@f
	inc	eax
	jmp	@b
@@:
	test	eax,eax
	jz	.default
	lea	rsi,[rsp+8+rax-1]
	mov	byte [rsi],'*'
	sub	ecx,eax
	inc	ecx
	call	tls_name_find
	cmp	eax,-1
	je	.default
.found:
	imul	rax,rax,TL_SIZE
	lea	rax,[g_tls+rax]
	jmp	.out
.default:
	xor	eax,eax
.out:
	add	rsp,272
	pop	rbx
	ret

; ------------------------------------------------------- passthrough
;
; tcp { tls passthrough { sni NAME... to pool P; default ... } }: the
; names go into the SNI table under a group of the listener's own
; (0x8000 | its first entry), each naming its pool.

; rdi = tcp listener node: eax = a pool (the default, else the first
; sni line's); g_cmp_pt = its group | (default pool + 1) << 16.
compile_passthrough:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	listener_passthrough
	mov	rbx,rax
	mov	r13d,[g_plan_listeners]
	or	r13d,0x8000
	mov	[g_tls_cur_group],r13d
	mov	r14d,-1				; the first sni line's pool
	xor	r15d,r15d			; the default's + 1
	mov	r12,[rbx+N_CHILD]
.line:
	test	r12,r12
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_SNI]
	cmp	[r12+N_DEF],rax
	je	.sni
	lea	rax,[dir_table + D_SIZE*DIR_DEFAULT]
	cmp	[r12+N_DEF],rax
	jne	.next
	cmp	dword [r12+N_ARGC],3
	jne	.next				; reject
	mov	rax,[r12+N_ARGS]
	mov	rdi,[rax+2*A_SIZE+A_VAL]
	mov	esi,[rax+2*A_SIZE+A_VLEN]
	call	plan_pool_index
	lea	r15d,[rax+1]
	jmp	.next
.sni:
	mov	ecx,[r12+N_ARGC]
	dec	ecx
	imul	rcx,rcx,A_SIZE
	add	rcx,[r12+N_ARGS]
	mov	rdi,[rcx+A_VAL]
	mov	esi,[rcx+A_VLEN]
	call	plan_pool_index
	cmp	r14d,-1
	jne	@f
	mov	r14d,eax
@@:
	mov	[g_tls_cur_tl],eax
	mov	rbx,[r12+N_ARGS]		; (rbx is free now: the block's lines are in r12)
	mov	ecx,[r12+N_ARGC]
	sub	ecx,3
.name:
	push	rcx
	mov	rsi,[rbx+A_VAL]
	mov	ecx,[rbx+A_VLEN]
	call	tls_name_add
	pop	rcx
	jc	.full
	add	rbx,A_SIZE
	dec	ecx
	jnz	.name
.next:
	mov	r12,[r12+N_NEXT]
	jmp	.line
.done:
	mov	eax,r15d
	shl	eax,16
	or	eax,r13d
	mov	[g_cmp_pt],eax
	mov	eax,r14d
	test	r15d,r15d
	jz	@f
	lea	eax,[r15-1]
@@:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.full:
	mov	rdi,r12
	call	tls_error_at
	out_lit 'the names of this configuration (certificates and sni lines) pass 4096'
	jmp	tls_error_end

; rsi = a host name, ecx = its length, edx = a group: eax = what the
; group's table says for it (exactly, then as *.parent), or -1.
tls_name_lookup:
	push	rbx
	sub	rsp,264
	test	ecx,ecx
	jz	.none
	cmp	ecx,253
	ja	.none
	mov	ebx,edx
	lea	rdi,[rsp+8]			; lowercase, one byte of room before it
	push	rcx
@@:
	mov	al,[rsi]
	lea	r8d,[rax-'A']
	cmp	r8b,25
	ja	.lower
	or	al,0x20
.lower:
	mov	[rdi],al
	inc	rsi
	inc	rdi
	dec	ecx
	jnz	@b
	pop	rcx
	mov	edx,ebx
	lea	rsi,[rsp+8]
	call	tls_name_find
	cmp	eax,-1
	jne	.out
	xor	eax,eax				; *.parent: the first label replaced
@@:
	cmp	eax,ecx
	jae	.none
	cmp	byte [rsp+8+rax],'.'
	je	@f
	inc	eax
	jmp	@b
@@:
	test	eax,eax
	jz	.none
	lea	rsi,[rsp+8+rax-1]
	mov	byte [rsi],'*'
	sub	ecx,eax
	inc	ecx
	call	tls_name_find
	jmp	.out
.none:
	mov	eax,-1
.out:
	add	rsp,264
	pop	rbx
	ret

; edi = a listener's LS_PT, rsi = the client's server_name, ecx = its
; length (0 = none): eax = the pool, or -1 to refuse the connection.
tls_passthrough_pool:
	push	rbx
	mov	ebx,edi
	movzx	edx,bx
	call	tls_name_lookup
	cmp	eax,-1
	jne	.out
	mov	eax,ebx
	shr	eax,16
	dec	eax				; the default, or -1 (reject)
.out:
	pop	rbx
	ret
