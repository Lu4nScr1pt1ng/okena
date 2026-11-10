; TLS 1.2 server handshake (RFC 5246 + RFC 8422). The ClientHello read in
; full: of its suites, the first this offers (ECDHE with the certificate's key,
; ECDSA or RSA, and AES-128-GCM or ChaCha20-Poly1305, RFC 7905), the client's
; order kept; x25519 when it has it, else secp256r1; the signature as its
; signature_algorithms allow (ecdsa_secp256r1_sha256; rsa_pss_rsae_sha256, else
; rsa_pkcs1_sha256); the extended master secret (RFC 7627) when it offers it;
; renegotiation_info (RFC 5746) only when it said it knows it (never a
; renegotiation). Nothing in common: a handshake_failure alert.
; Built on the tls12.inc primitives (PRF, key schedule, record layer).

; --- TLS 1.2 server handshake (RFC 5246 + RFC 8422), ECDHE_ECDSA with
; x25519 and AES-128-GCM. Mirrors the 1.3 tls_hello/tls_finished shape but
; with the 1.2 flow: the server sends ServerHello, Certificate,
; ServerKeyExchange (signed) and ServerHelloDone; the client answers with
; ClientKeyExchange, ChangeCipherSpec and Finished; the server finishes
; with ChangeCipherSpec and Finished. A T2 block holds the state. ---

; credentials the caller passes: the stored 1.3 certificate_list and the
; server certificate's P-256 private key.
C12_LIST	:= 0				; q: pointer to the certificate_list (1.3 framing)
C12_LEN		:= 8				; d: its length
C12_KEY		:= 16				; q: pointer to the EC private key (32, big endian)
C12_KEYTYPE	:= 24				; d: 0 = EC P-256, 1 = RSA
C12_RSA_N	:= 32				; q: pointer to the RSA modulus (big endian)
C12_RSA_NLEN	:= 40				; d: its length in bytes
C12_RSA_D	:= 48				; q: pointer to the RSA private exponent
C12_ALPN	:= 56				; d: 1 = answer ALPN with h2 (the caller found it offered)
C12_OCSP	:= 60				; d: an OCSP answer to staple (g_oc_tmp), its length; 0 none
C12_SIZE	:= 64

T2_ESK		:= 0				; ephemeral x25519 private key
T2_CR		:= 32				; client random
T2_SR		:= 64				; server random
T2_EPK		:= 96				; ephemeral public key (65, P-256)
T2_SHA		:= T2_EPK + 72			; the handshake transcript (SHA-256 ctx)
T2_SHARED	:= T2_SHA + SHA256_CTX_SIZE	; the ECDH shared secret (premaster)
T2_MASTER	:= T2_SHARED + 32		; master secret (48)
T2_CWK		:= T2_MASTER + 48		; key_block: client write key (16; 32 ChaCha20),
T2_SWK		:= T2_CWK + 32			; server write key,
T2_CWIV		:= T2_SWK + 32			; client write IV (4 salt; 12 ChaCha20),
T2_SWIV		:= T2_CWIV + 12			; server write IV
T2_RXGCM	:= T2_SWIV + 12			; client -> server records (an AEAD context)
T2_TXGCM	:= T2_RXGCM + AEAD_SIZE		; server -> client records
T2_SUITE	:= T2_TXGCM + AEAD_SIZE		; d: 0 AES-128-GCM, 1 ChaCha20-Poly1305
T2_GROUP	:= T2_SUITE + 4			; d: 0 secp256r1, 1 x25519
T2_SIG		:= T2_GROUP + 4			; d: the SignatureScheme (as on the wire)
T2_EMS		:= T2_SIG + 4			; d: extended master secret
T2_RENEG	:= T2_EMS + 4			; d: the client knows renegotiation_info
T2_FULL		:= T2_RENEG + 4

; append [rsi, edx) to the transcript (T2_SHA); rbp = t2
macro t2_add
	lea	rdi,[rbp+T2_SHA]
	call	sha256_update
end macro

; rdi = t2, rsi = credentials (a C12 block), rdx = ClientHello records,
; ecx = length, r8 = out, r9d = out room. eax = the server flight length
; (ServerHello..ServerHelloDone), or 0 on error. x25519 ECDHE is chosen;
; the client is assumed to offer TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
; x25519 and ecdsa_secp256r1_sha256 (the default of a 1.2 client).
tls12_hello:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,392				; [rsp]=r|s(64), [rsp+112]=digest/limbs(32), [rsp+256]=a SHA-256 ctx (16-aligned)
	mov	rbp,rdi				; t2
	mov	r15,rsi				; credentials
	mov	r12,r8				; out
	; parse the ClientHello: client_random and session id
	lea	rsi,[rdx+5]			; past the record header
	mov	r13,rsi				; handshake message start
	movzx	eax,byte [rsi+1]		; u24 length
	shl	eax,16
	movzx	ecx,word [rsi+2]
	rol	cx,8
	or	eax,ecx
	lea	r14,[rsi+4+rax]			; message end (for the transcript)
	lea	rdi,[rbp+T2_CR]			; client_random (after type4,version2)
	lea	rsi,[r13+4+2]
	mov	ecx,32
	rep	movsb
	lea	rbx,[r13+4+2+32]		; session id: u8 length, bytes
	call	tls12_offers			; what the client offers: suite, group, signature
	jc	.refuse
	call	sha256_init_t2			; start the transcript
	mov	rsi,r13				; add the ClientHello message
	mov	edx,r14d
	sub	edx,r13d
	t2_add
	; server random and the ephemeral key
	lea	rdi,[rbp+T2_SR]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,32
	jne	.fail
.esk:
	lea	rdi,[rbp+T2_ESK]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,32
	jne	.fail
	cmp	dword [rbp+T2_GROUP],0
	jne	.esk_x
	lea	rdi,[rsp+112]			; secp256r1: a scalar in [1, n-1]
	lea	rsi,[rbp+T2_ESK]
	call	be_to_limbs
	lea	rdi,[rsp+112]
	call	scalar_in_range
	test	eax,eax
	jz	.esk
	lea	rdi,[rbp+T2_EPK]
	lea	rsi,[rbp+T2_ESK]
	call	p256_public
	jmp	.esk_done
.esk_x:
	lea	rdi,[rbp+T2_EPK]
	lea	rsi,[rbp+T2_ESK]
	call	x25519_base
.esk_done:
	; ---- ServerHello ----
	lea	r13,[r12+5]			; the handshake message (after a record header)
	mov	byte [r13],2			; server_hello
	mov	word [r13+4],0x0303		; version
	lea	rdi,[r13+6]
	lea	rsi,[rbp+T2_SR]			; server random
	mov	ecx,32
	rep	movsb
	movzx	eax,byte [rbx]			; echo the session id
	mov	[rdi],al
	inc	rdi
	lea	rsi,[rbx+1]
	mov	ecx,eax
	rep	movsb
	; the suite: ECDHE_ECDSA or ECDHE_RSA, AES-128-GCM or ChaCha20-Poly1305
	mov	eax,[r15+C12_KEYTYPE]
	shl	eax,1
	add	eax,[rbp+T2_SUITE]
	mov	ax,[tls12_suites+rax*2]
	xchg	al,ah
	mov	[rdi],ax
	mov	byte [rdi+2],0			; compression
	lea	r10,[rdi+3]			; extensions' length (worked out at the end)
	add	rdi,5
	cmp	dword [rbp+T2_RENEG],0		; renegotiation_info (RFC 5746), empty
	je	@f
	mov	dword [rdi],0x010001ff		; ff01, length 1: an empty renegotiated_connection
	mov	byte [rdi+4],0
	add	rdi,5
@@:
	cmp	dword [rbp+T2_EMS],0		; extended_master_secret (RFC 7627)
	je	@f
	mov	dword [rdi],0x00001700
	add	rdi,4
@@:
	cmp	dword [r15+C12_ALPN],0
	je	@f
	mov	dword [rdi],0x05001000		; ALPN (16), 5 bytes,
	mov	dword [rdi+4],0x68020300	; a 3-byte list, "h2"
	mov	byte [rdi+8],'2'
	add	rdi,9
@@:
	cmp	dword [r15+C12_OCSP],0		; status_request, empty: a staple follows
	je	@f
	mov	dword [rdi],0x00000500
	add	rdi,4
@@:
	mov	rax,rdi				; the extensions' length
	sub	rax,r10
	sub	eax,2
	xchg	al,ah
	mov	[r10],ax
	mov	rax,rdi				; body end
	sub	rax,r13
	sub	eax,4				; body length
	put24	r13+1, eax
	call	.record				; wrap + transcript; r13..rdi -> next r13
	; ---- Certificate (1.2: no context, no per-entry extensions) ----
	mov	byte [r13],11
	lea	r14,[r13+4+3]			; first entry (after u24 cert_list length)
	mov	r8,[r15+C12_LIST]		; the stored 1.3 certificate_list
	mov	r9d,[r15+C12_LEN]
	add	r9,r8				; its end
	mov	rdi,r14
.cert_copy:
	cmp	r8,r9
	jae	.cert_done
	mov	eax,[r8]			; u24 cert length (big endian in low 3)
	bswap	eax
	shr	eax,8
	lea	ecx,[eax+3]			; copy u24 length + DER
	mov	rsi,r8
	rep	movsb				; (ecx bytes)
	lea	r8,[r8+3+rax+2]			; skip the entry's u16 extensions
	jmp	.cert_copy
.cert_done:
	mov	eax,edi
	sub	eax,r14d			; certificate_list length
	put24	r13+4, eax
	mov	eax,edi
	sub	eax,r13d
	sub	eax,4				; message body length
	put24	r13+1, eax
	call	.record
	; ---- CertificateStatus: the OCSP answer (RFC 6066 8) ----
	mov	edx,[r15+C12_OCSP]
	test	edx,edx
	jz	@f
	mov	byte [r13],22
	lea	ecx,[rdx+4]
	put24	r13+1, ecx
	mov	byte [r13+4],1			; ocsp
	put24	r13+5, edx
	lea	rdi,[r13+8]
	lea	rsi,[g_oc_tmp]
	mov	ecx,edx
	rep	movsb
	call	.record
@@:
	; ---- ServerKeyExchange: ECDHE params + the signature ----
	mov	byte [r13],12
	mov	byte [r13+4],3			; curve_type named_curve
	mov	word [r13+5],0x1700		; secp256r1 (0x0017): a point of 65
	mov	byte [r13+7],65
	mov	ecx,65
	cmp	dword [rbp+T2_GROUP],0
	je	@f
	mov	word [r13+5],0x1D00		; x25519 (0x001D): 32 bytes
	mov	byte [r13+7],32
	mov	ecx,32
@@:
	push	rcx
	lea	rdi,[r13+8]
	lea	rsi,[rbp+T2_EPK]
	rep	movsb
	pop	rcx
	add	ecx,4				; the params' length (69 or 36)
	push	rcx
	; signed: client_random | server_random | the params, its SHA-256
	lea	rdi,[rsp+256+8]
	call	sha256_init
	lea	rdi,[rsp+256+8]
	lea	rsi,[rbp+T2_CR]
	mov	edx,64				; (client random, then server random)
	call	sha256_update
	lea	rdi,[rsp+256+8]
	lea	rsi,[r13+4]
	mov	edx,[rsp]
	call	sha256_update
	lea	rdi,[rsp+256+8]
	lea	rsi,[rsp+112+8]
	call	sha256_final			; the digest at [rsp+112] (as before)
	pop	r11				; the params' length
	lea	r9,[r13+4+r11]			; the signature's place: scheme, length, it
	mov	eax,[rbp+T2_SIG]
	xchg	al,ah
	mov	[r9],ax
	push	r9
	cmp	dword [r15+C12_KEYTYPE],1
	je	.ske_rsa
	lea	rdi,[rsp+8]			; r||s
	mov	rsi,[r15+C12_KEY]
	lea	rdx,[rsp+8+112]
	call	p256_sign
	test	eax,eax
	jz	.ske_fail
	mov	rdi,[rsp]
	add	rdi,4				; the DER signature
	lea	rsi,[rsp+8]
	call	ecdsa_der			; eax = DER length
	jmp	.ske_len
.ske_rsa:
	mov	rdi,[rsp]
	add	rdi,4				; the signature, written in place
	mov	rsi,[r15+C12_RSA_N]
	mov	edx,[r15+C12_RSA_NLEN]
	mov	rcx,[r15+C12_RSA_D]
	lea	r8,[rsp+8+112]			; digest
	cmp	dword [rbp+T2_SIG],0x0804
	je	.ske_pss
	call	rsa_pkcs1_sign
	jmp	.ske_rsa_done
.ske_pss:
	call	rsa_pss_sign
.ske_rsa_done:
	mov	eax,[r15+C12_RSA_NLEN]		; signature length = nbytes
.ske_len:
	pop	r9
	lea	rdi,[r9+4+rax]			; the cursor past it (.record frames from it)
	mov	edx,eax
	rol	dx,8
	mov	[r9+2],dx			; signature length (u16)
	lea	rcx,[r13+4]
	sub	r9,rcx				; the params' length
	lea	eax,[rax+r9+4]			; body = params + scheme(2) + length(2) + sig
	put24	r13+1, eax
	call	.record
	; ---- ServerHelloDone ----
	mov	byte [r13],14
	mov	byte [r13+1],0
	mov	word [r13+2],0
	lea	rdi,[r13+4]
	call	.record
	mov	eax,r13d			; r13 is 5 past the last message (a reserved header)
	sub	eax,r12d
	sub	eax,5
	jmp	.out
.ske_fail:
	add	rsp,8
.fail:
	xor	eax,eax
	jmp	.out
.refuse:
	; nothing in common: a handshake_failure alert (fatal), then close
	mov	dword [r12],0x00030315		; 15 03 03 00 02: an alert record of 2,
	mov	byte [r12+4],2
	mov	word [r12+5],0x2802		; fatal (2), handshake_failure (40)
	mov	eax,-7				; (negative: the alert's length, sent before
.out:						; the caller closes)
	add	rsp,392
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; wrap [r13, rdi) (one handshake message) as a record at [r13-5]: write the
; 5-byte header before it, add the message to the transcript, and set r13
; to the next message's body (leaving 5 bytes for its header). rdi follows.
.record:
	mov	edx,edi				; message length
	sub	edx,r13d
	mov	byte [r13-5],22			; handshake record
	mov	word [r13-4],0x0303
	mov	eax,edx
	rol	ax,8
	mov	[r13-2],ax
	push	rdi				; the message end (t2_add clobbers rdi)
	mov	rsi,r13
	t2_add					; transcript the handshake message
	pop	rdi
	lea	r13,[rdi+5]			; next message body (past its header)
	mov	rdi,r13
	ret

; the suites, as on the wire: ECDSA's AES-128-GCM and ChaCha20-Poly1305, then RSA's
tls12_suites	dw 0xC02B, 0xCCA9, 0xC02F, 0xCCA8

; In tls12_hello: rbx = the ClientHello's session id, r14 = its end, rbp = t2,
; r15 = the credentials. T2_SUITE, T2_GROUP, T2_SIG, T2_EMS and T2_RENEG from
; what it offers. CF: nothing in common (or a ClientHello that does not parse).
; Keeps rbx, rbp, r12-r15.
tls12_offers:
	xor	eax,eax
	mov	[rbp+T2_EMS],eax
	mov	[rbp+T2_RENEG],eax
	mov	rsi,rbx
	movzx	eax,byte [rsi]			; past the session id
	lea	rsi,[rsi+1+rax]
	lea	rax,[rsi+2]
	cmp	rax,r14
	ja	.bad
	; cipher_suites: the first of ours, in the client's order
	movzx	ecx,word [rsi]
	xchg	cl,ch
	add	rsi,2
	lea	r8,[rsi+rcx]
	cmp	r8,r14
	ja	.bad
	mov	r9d,-1
	mov	r10d,[r15+C12_KEYTYPE]		; (0 EC, 1 RSA)
.suite:
	lea	rax,[rsi+2]
	cmp	rax,r8
	ja	.suites_done
	movzx	eax,word [rsi]
	xchg	al,ah
	add	rsi,2
	cmp	eax,0x00FF			; TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	jne	@f
	mov	dword [rbp+T2_RENEG],1
	jmp	.suite
@@:
	cmp	r9d,-1
	jne	.suite
	movzx	edx,word [tls12_suites+r10*4]
	cmp	eax,edx
	jne	@f
	xor	r9d,r9d
	jmp	.suite
@@:
	movzx	edx,word [tls12_suites+r10*4+2]
	cmp	eax,edx
	jne	.suite
	mov	r9d,1
	jmp	.suite
.suites_done:
	cmp	r9d,-1
	je	.bad
	mov	[rbp+T2_SUITE],r9d
	mov	rsi,r8
	cmp	rsi,r14				; compression_methods
	jae	.bad
	movzx	eax,byte [rsi]
	lea	rsi,[rsi+1+rax]
	mov	r9d,1				; groups: 1 secp256r1, 2 x25519 (none said: secp256r1)
	xor	r10d,r10d			; signatures: 1 ecdsa_secp256r1_sha256, 2 rsa_pkcs1_sha256, 4 rsa_pss_rsae_sha256
	lea	rax,[rsi+2]
	cmp	rax,r14
	ja	.decide				; (no extensions)
	movzx	ecx,word [rsi]
	xchg	cl,ch
	add	rsi,2
	lea	r8,[rsi+rcx]
	cmp	r8,r14
	ja	.bad
.ext:
	lea	rax,[rsi+4]
	cmp	rax,r8
	ja	.decide
	movzx	eax,word [rsi]
	xchg	al,ah
	movzx	ecx,word [rsi+2]
	xchg	cl,ch
	add	rsi,4
	lea	rdx,[rsi+rcx]			; its end
	cmp	rdx,r8
	ja	.bad
	cmp	eax,10
	je	.groups
	cmp	eax,13
	je	.sigs
	cmp	eax,23
	jne	@f
	mov	dword [rbp+T2_EMS],1
	jmp	.next
@@:
	cmp	eax,0xff01
	jne	.next
	test	ecx,ecx				; renegotiation_info: empty (a first handshake)
	jz	.bad
	cmp	byte [rsi],0
	jne	.bad
	mov	dword [rbp+T2_RENEG],1
.next:
	mov	rsi,rdx
	jmp	.ext
.groups:
	xor	r9d,r9d
	add	rsi,2
.group:
	lea	rax,[rsi+2]
	cmp	rax,rdx
	ja	.next
	movzx	eax,word [rsi]
	add	rsi,2
	cmp	eax,0x1700			; secp256r1 (0x0017, read as it lies)
	jne	@f
	or	r9d,1
@@:
	cmp	eax,0x1D00			; x25519 (0x001D)
	jne	.group
	or	r9d,2
	jmp	.group
.sigs:
	add	rsi,2
.sig:
	lea	rax,[rsi+2]
	cmp	rax,rdx
	ja	.next
	movzx	eax,word [rsi]
	add	rsi,2
	cmp	eax,0x0304			; 0x0403
	jne	@f
	or	r10d,1
@@:
	cmp	eax,0x0104			; 0x0401
	jne	@f
	or	r10d,2
@@:
	cmp	eax,0x0408			; 0x0804
	jne	.sig
	or	r10d,4
	jmp	.sig
.decide:
	mov	dword [rbp+T2_GROUP],1		; x25519 first
	test	r9d,2
	jnz	@f
	mov	dword [rbp+T2_GROUP],0
	test	r9d,1
	jz	.bad
@@:
	cmp	dword [r15+C12_KEYTYPE],1
	je	.rsa
	test	r9d,1				; an ECDSA certificate is on secp256r1: its
	jz	.bad				; groups name the certificate's too (RFC 8422 5.1)
	test	r10d,1
	jz	.bad
	mov	dword [rbp+T2_SIG],0x0403
	clc
	ret
.rsa:
	mov	dword [rbp+T2_SIG],0x0804	; PSS, else PKCS #1 v1.5
	test	r10d,4
	jnz	@f
	mov	dword [rbp+T2_SIG],0x0401
	test	r10d,2
	jz	.bad
@@:
	clc
	ret
.bad:
	stc
	ret

; sha256_init for the transcript, preserving the registers tls12_hello holds
sha256_init_t2:
	push	rbx
	push	rsi
	push	rdx
	lea	rdi,[rbp+T2_SHA]
	call	sha256_init
	pop	rdx
	pop	rsi
	pop	rbx
	ret

; rdi = t2, rsi = the client's records after the flight (ClientKeyExchange,
; ChangeCipherSpec, the encrypted Finished), ecx = length, r8 = out.
; eax = the server flight length (ChangeCipherSpec and the encrypted
; Finished), or 0 on error. On success the T2 block holds the write keys
; and record contexts for the application data (client seq 1, server seq 1).
tls12_finished:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,200				; sha ctx(112), hash(32)@112, cvd(12)@144, sfin(16)@156 (16-aligned)
	mov	rbp,rdi
	mov	r12,r8				; out
	mov	r14,rsi				; record cursor
	; --- ClientKeyExchange (handshake record) ---
	cmp	byte [r14],22
	jne	.fail
	movzx	r13d,word [r14+3]
	rol	r13w,8				; its record length
	lea	rsi,[r14+5]			; the handshake message
	mov	edx,r13d
	t2_add					; add CKE to the transcript
	cmp	dword [rbp+T2_GROUP],0
	jne	.cke_x
	cmp	byte [r14+5+4],65
	jne	.fail
	lea	rdi,[rbp+T2_SHARED]		; premaster = ECDH(ESK, client pubkey)
	lea	rsi,[rbp+T2_ESK]
	lea	rdx,[r14+5+4+1]			; past msg header (4) and pubkey length (1)
	call	p256_ecdh
	test	eax,eax
	jz	.fail
	jmp	.cke_done
.cke_x:
	cmp	byte [r14+5+4],32
	jne	.fail
	lea	rdi,[rbp+T2_SHARED]
	lea	rsi,[rbp+T2_ESK]
	lea	rdx,[r14+5+4+1]
	call	x25519
	mov	rax,[rbp+T2_SHARED]		; all zero: a small-order point
	or	rax,[rbp+T2_SHARED+8]
	or	rax,[rbp+T2_SHARED+16]
	or	rax,[rbp+T2_SHARED+24]
	jz	.fail
.cke_done:
	lea	r14,[r14+5+r13]			; next record
	cmp	byte [r14],20			; skip ChangeCipherSpec
	jne	@f
	movzx	eax,word [r14+3]
	rol	ax,8
	lea	r14,[r14+5+rax]
@@:
	cmp	byte [r14],22			; the encrypted Finished record
	jne	.fail
	; master secret (RFC 7627: over the session hash, through the
	; ClientKeyExchange, when both said so) and the key block
	cmp	dword [rbp+T2_EMS],0
	je	.classic
	lea	rsi,[rbp+T2_SHA]
	lea	rdi,[rsp]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rsp]
	lea	rsi,[rsp+112]
	call	sha256_final
	lea	rdi,[rbp+T2_MASTER]
	lea	rsi,[rbp+T2_SHARED]
	lea	rcx,[rsp+112]
	call	tls12_master_ems
	jmp	.keys
.classic:
	lea	rdi,[rbp+T2_MASTER]
	lea	rsi,[rbp+T2_SHARED]
	mov	edx,32
	lea	rcx,[rbp+T2_CR]
	lea	r8,[rbp+T2_SR]
	call	tls12_master
.keys:
	lea	rdi,[rbp+T2_SHARED]		; (the premaster: done with)
	mov	ecx,32
	call	secure_zero
	mov	esi,40				; AES-128-GCM: keys of 16, salts of 4
	cmp	dword [rbp+T2_SUITE],0
	je	@f
	mov	esi,88				; ChaCha20-Poly1305: keys of 32, IVs of 12
@@:
	lea	rdi,[rsp]
	lea	rdx,[rbp+T2_MASTER]
	lea	rcx,[rbp+T2_SR]
	lea	r8,[rbp+T2_CR]
	call	tls12_key_block
	cmp	dword [rbp+T2_SUITE],0
	jne	.kb_cp
	movdqu	xmm0,[rsp]
	movdqu	[rbp+T2_CWK],xmm0
	movdqu	xmm0,[rsp+16]
	movdqu	[rbp+T2_SWK],xmm0
	mov	eax,[rsp+32]
	mov	[rbp+T2_CWIV],eax
	mov	eax,[rsp+36]
	mov	[rbp+T2_SWIV],eax
	jmp	.kb_done
.kb_cp:
	lea	rsi,[rsp]
	lea	rdi,[rbp+T2_CWK]
	mov	ecx,64				; the two keys (CWK, SWK adjoin)
	rep	movsb
	lea	rdi,[rbp+T2_CWIV]
	mov	ecx,24				; and the two IVs
	rep	movsb
.kb_done:
	lea	rdi,[rsp]
	mov	ecx,88
	call	secure_zero
	lea	rdi,[rbp+T2_RXGCM]
	lea	rsi,[rbp+T2_CWK]
	mov	edx,[rbp+T2_SUITE]
	call	aead_init
	lea	rdi,[rbp+T2_TXGCM]
	lea	rsi,[rbp+T2_SWK]
	mov	edx,[rbp+T2_SUITE]
	call	aead_init
	; expected client verify_data over the transcript through CKE
	lea	rsi,[rbp+T2_SHA]
	lea	rdi,[rsp]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rsp]
	lea	rsi,[rsp+112]
	call	sha256_final
	lea	rdi,[rsp+144]
	lea	rsi,[rbp+T2_MASTER]
	lea	rdx,[tls12_lbl_cfin]
	mov	ecx,15
	lea	r8,[rsp+112]
	call	tls12_verify_data
	; decrypt the Finished record in place and check it
	movzx	esi,word [r14+3]
	rol	si,8
	lea	rdi,[r14+5]
	lea	rdx,[rbp+T2_RXGCM]
	lea	rcx,[rbp+T2_CWIV]
	xor	r8,r8				; client record sequence 0
	mov	r9d,22
	call	tls12_aopen
	cmp	eax,16				; Finished = 4-byte header + 12 verify_data
	jne	.fail
	mov	rbx,rdx				; the Finished handshake message
	cmp	dword [rbx],0x0c000014		; type 20, length 12
	jne	.fail
	lea	rdi,[rbx+4]
	lea	rsi,[rsp+144]
	mov	edx,12
	call	ct_equal
	test	eax,eax
	jz	.fail
	mov	rsi,rbx				; add the client Finished to the transcript
	mov	edx,16
	t2_add
	; server verify_data over the transcript through the client Finished
	lea	rsi,[rbp+T2_SHA]
	lea	rdi,[rsp]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rsp]
	lea	rsi,[rsp+112]
	call	sha256_final
	mov	dword [rsp+156],0x0c000014	; server Finished message header
	lea	rdi,[rsp+160]
	lea	rsi,[rbp+T2_MASTER]
	lea	rdx,[tls12_lbl_sfin]
	mov	ecx,15
	lea	r8,[rsp+112]
	call	tls12_verify_data
	; flight: ChangeCipherSpec, then the encrypted Finished
	mov	byte [r12],20			; CCS record
	mov	word [r12+1],0x0303
	mov	word [r12+3],0x0100		; length 1
	mov	byte [r12+5],1
	lea	rdi,[r12+6+5]			; seal the Finished after CCS and a record header
	lea	rsi,[rbp+T2_TXGCM]
	lea	rdx,[rbp+T2_SWIV]
	xor	rcx,rcx				; server record sequence 0
	mov	r8d,22
	lea	r9,[rsp+156]
	mov	r10d,16
	call	tls12_aseal			; eax = record payload length
	mov	byte [r12+6],22
	mov	word [r12+6+1],0x0303
	mov	edx,eax
	rol	dx,8
	mov	[r12+6+3],dx
	lea	eax,[rax+11]			; CCS (6) + record header (5) + payload
	jmp	.out
.fail:
	xor	eax,eax
.out:
	add	rsp,200
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = t2, rsi = TX crypto_info out (40), rdx = RX crypto_info out (40):
; fills two struct tls12_crypto_info_aes_gcm_128 for the kernel's TLS 1.2
; (version 0x0303), TX from the server write key/IV and RX from the client
; write key/IV, both at record sequence 1 (after the Finished). The layout
; is proven against the kernel in tests/tls/server12.asm.
tls12_ktls_info:
	cmp	dword [rdi+T2_SUITE],0
	jne	.chacha
	call	.aes
	mov	eax,40
	ret
.chacha:
	; struct tls12_crypto_info_chacha20_poly1305: info, iv[12], key[32], rec_seq[8]
	mov	dword [rsi],0x00360303		; TLS 1.2, CHACHA20_POLY1305
	push	rsi
	push	rdi
	lea	r8,[rdi+T2_SWIV]
	lea	r9,[rdi+T2_SWK]
	call	.cp_one
	pop	rdi
	pop	rsi
	mov	dword [rdx],0x00360303
	mov	rsi,rdx
	lea	r8,[rdi+T2_CWIV]
	lea	r9,[rdi+T2_CWK]
	call	.cp_one
	mov	eax,56
	ret
.cp_one:
	mov	rax,[r8]
	mov	[rsi+4],rax
	mov	eax,[r8+8]
	mov	[rsi+12],eax
	movdqu	xmm0,[r9]
	movdqu	[rsi+16],xmm0
	movdqu	xmm0,[r9+16]
	movdqu	[rsi+32],xmm0
	mov	qword [rsi+48],0		; rec_seq = 1
	mov	byte [rsi+55],1
	ret
.aes:
	mov	dword [rsi],0x00330303		; TLS 1.2, AES_GCM_128
	mov	qword [rsi+4],0			; iv = explicit nonce, big-endian 1
	mov	byte [rsi+11],1
	movdqu	xmm0,[rdi+T2_SWK]
	movdqu	[rsi+12],xmm0
	mov	eax,[rdi+T2_SWIV]
	mov	[rsi+28],eax			; salt = server write IV
	mov	qword [rsi+32],0		; rec_seq = 1
	mov	byte [rsi+39],1
	mov	dword [rdx],0x00330303
	mov	qword [rdx+4],0
	mov	byte [rdx+11],1
	movdqu	xmm0,[rdi+T2_CWK]
	movdqu	[rdx+12],xmm0
	mov	eax,[rdi+T2_CWIV]
	mov	[rdx+28],eax			; salt = client write IV
	mov	qword [rdx+32],0
	mov	byte [rdx+39],1
	ret

; rdi = out[48], rsi = premaster[32], rcx = the session hash[32]: the extended
; master secret (RFC 7627): PRF(premaster, "extended master secret", hash)
tls12_master_ems:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,rcx
	sub	rsp,64
	lea	rdi,[rsp]
	lea	rsi,[.label]
	mov	ecx,22
	rep	movsb
	mov	rsi,rbx
	mov	ecx,32
	rep	movsb
	mov	rdi,r12
	mov	esi,48
	mov	rdx,r13
	mov	ecx,32
	lea	r8,[rsp]
	mov	r9d,54
	call	p_sha256
	add	rsp,64
	pop	r13
	pop	r12
	pop	rbx
	ret
.label	db 'extended master secret'

; A 1.2 record with the suite's AEAD (T2_RXGCM / T2_TXGCM): AES-128-GCM as
; tls12_seal and tls12_open do it (RFC 5288: a salt and an explicit nonce);
; ChaCha20-Poly1305 as RFC 7905 has it: no explicit nonce, the nonce the
; 12-byte IV xor the sequence number, the additional data the same 13 bytes.

; rdi = out, rsi = the AEAD context, rdx = write IV, rcx = sequence, r8d =
; content type, r9 = plaintext, r10d = its length: the record's payload at
; out. eax = its length.
tls12_aseal:
	cmp	dword [rsi+AEAD_TYPE],0
	je	tls12_seal
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	ebx,r10d
	sub	rsp,32				; [rsp]=nonce(12), [rsp+16]=aad(13)
	call	tls12_cp_nonce
	push	rdi
	mov	rdi,r12				; the plaintext, in place
	mov	rsi,r9
	mov	ecx,ebx
	rep	movsb
	pop	rdi
	mov	rdi,r13
	lea	rsi,[rsp]
	lea	rdx,[rsp+16]
	mov	ecx,13
	mov	r8,r12
	mov	r9d,ebx
	call	aead_seal
	lea	eax,[rbx+16]
	add	rsp,32
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = the record's payload, esi = its length, rdx = the AEAD context, rcx =
; write IV, r8 = sequence, r9d = content type: opened in place. eax = the
; plaintext's length, rdx = where it is; -1 for a bad tag or a short record.
tls12_aopen:
	cmp	dword [rdx+AEAD_TYPE],0
	jne	.cp
	push	rdi
	call	tls12_open
	pop	rdx
	add	rdx,8				; (past the explicit nonce)
	ret
.cp:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rdx
	mov	ebx,esi
	sub	ebx,16
	js	.bad
	sub	rsp,32
	mov	r10d,ebx			; (the aad's length: the plaintext's)
	mov	rdx,rcx
	mov	rcx,r8
	mov	r8d,r9d
	call	tls12_cp_nonce
	mov	rdi,r13
	lea	rsi,[rsp]
	lea	rdx,[rsp+16]
	mov	ecx,13
	mov	r8,r12
	mov	r9d,ebx
	call	aead_open
	add	rsp,32
	test	eax,eax
	jz	.bad
	mov	eax,ebx
	mov	rdx,r12
	jmp	.out
.bad:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; for tls12_aseal / tls12_aopen (their frame: [rsp+8] nonce, [rsp+8+16] aad):
; rdx = IV(12), rcx = sequence, r8d = type, r10d = plaintext length
tls12_cp_nonce:
	mov	rax,[rdx]
	mov	[rsp+8],rax
	mov	eax,[rdx+8]
	mov	[rsp+8+8],eax
	mov	rax,rcx
	bswap	rax
	xor	[rsp+8+4],rax			; IV xor (0^4 | seq, big endian)
	mov	[rsp+8+16],rax			; aad: seq, type, version, length
	mov	byte [rsp+8+16+8],r8b
	mov	word [rsp+8+16+9],0x0303
	mov	eax,r10d
	rol	ax,8
	mov	[rsp+8+16+11],ax
	ret
