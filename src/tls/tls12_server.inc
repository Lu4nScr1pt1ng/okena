; TLS 1.2 server handshake (RFC 5246 + RFC 8422). The ClientHello read in
; full: of its suites, the first this offers (ECDHE with the certificate's key,
; ECDSA or RSA, and AES-128-GCM, ChaCha20-Poly1305 (RFC 7905) or AES-256-GCM
; with SHA-384 as its PRF and transcript hash), the client's order kept; x25519 when it has it, else secp256r1; the signature as its
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
C12_ALPN	:= 56				; d: answer ALPN with 1 h2, 2 http/1.1 (the caller chose), 0 none
C12_OCSP	:= 60				; d: an OCSP answer to staple (g_oc_tmp), its length; 0 none
C12_CERTID	:= 64				; q: 8 bytes of the certificate's key (a ticket names it)
C12_CCA		:= 72				; d: client certificates: 0 none, 1 optional, 2 required
C12_TS		:= 80				; q: the session's TS (anchors, who the client is), 0 none
C12_SIZE	:= 88

; TLS 1.2 session tickets (RFC 5077), sealed with the 1.3 tickets' keys (one
; rotation, one fleet file); their own version and size, so neither takes the
; other's: key id (4) | nonce (12) | sealed (TK12_PT) | tag (16)
TK12P_VERSION	:= 0				; b: 2
TK12P_SUITE	:= 1				; b
TK12P_EMS	:= 2				; b
TK12P_ISSUED	:= 4				; d: seconds (CLOCK_MONOTONIC)
TK12P_CERT	:= 8				; q
TK12P_MASTER	:= 16				; 48
TK12P_CCA	:= 64				; d: the listener's client_ca (TKP_CCA's), 0 none
TK12P_PEERL	:= 68				; d: who the client's certificate said
TK12P_PEER	:= 72				; (MTLS_NAME_MAX)
TK12_PT		:= 136
TK12_SIZE	:= TK_SEALED + TK12_PT + 16	; 168

T12_HS_MAX	:= 20480			; the client's second flight, its handshake messages

bss
	g_t12_hs:	rb T12_HS_MAX
	g_t12_mend	dq ?			; (the message being read: its end)
end bss

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
T2_SUITE	:= T2_TXGCM + AEAD_SIZE		; d: T12_* (the AEAD type: aead_init's)
T2_GROUP	:= T2_SUITE + 4			; d: 0 secp256r1, 1 x25519
T2_SIG		:= T2_GROUP + 4			; d: the SignatureScheme (as on the wire)
T2_EMS		:= T2_SIG + 4			; d: extended master secret
T2_RENEG	:= T2_EMS + 4			; d: the client knows renegotiation_info
T2_RESUMED	:= T2_RENEG + 4			; d: an abbreviated handshake, from a ticket
T2_TKWANT	:= T2_RESUMED + 4		; d: the client takes tickets: one is issued
T2_TKLEN	:= T2_TKWANT + 4		; d: its session_ticket extension's length
T2_TKP		:= T2_TKLEN + 4			; q: its ticket (in the ClientHello)
T2_CERTID	:= T2_TKP + 8			; q: C12_CERTID
T2_TICKET	:= T2_CERTID + 8		; TK12_SIZE
T2_CCA		:= T2_TICKET + TK12_SIZE	; d: C12_CCA
T2_TS		:= T2_CCA + 4			; q: C12_TS
T2_SH		:= T2_TS + 8			; the transcript's hash through the ClientKeyExchange
T2_TXSEQ	:= T2_SH + 32			; q: records sealed here (user space), from 1
T2_RXSEQ	:= T2_TXSEQ + 8			; q: and opened
T2_SHA384	:= T2_RXSEQ + 8			; the transcript with SHA-384 too (its suites' PRF)
T2_SH384	:= T2_SHA384 + SHA512_CTX_SIZE	; and the session hash with it (48)
T2_FULL		:= T2_SH384 + 48

T12_AES128	:= 0				; TLS_ECDHE_*_WITH_AES_128_GCM_SHA256
T12_CHACHA	:= 1				; TLS_ECDHE_*_WITH_CHACHA20_POLY1305_SHA256
T12_AES256	:= 2				; TLS_ECDHE_*_WITH_AES_256_GCM_SHA384
T12_SUITES	:= 3

; append [rsi, edx) to the transcript (T2_SHA, and T2_SHA384); rbp = t2
macro t2_add
	call	t2_add_fn
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
	mov	rax,[r15+C12_CERTID]
	mov	[rbp+T2_CERTID],rax
	mov	eax,[r15+C12_CCA]
	mov	[rbp+T2_CCA],eax
	mov	rax,[r15+C12_TS]
	mov	[rbp+T2_TS],rax
	call	tls12_offers			; what the client offers: suite, group, signature
	jc	.refuse
	call	tls12_resume_try		; its ticket, when good: T2_RESUMED
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
	xor	eax,eax			; the session id: the client's, echoed, when
	cmp	dword [rbp+T2_RESUMED],0	; resuming (RFC 5077 3.4); else none (no
	je	@f				; session is kept here: tickets only)
	movzx	eax,byte [rbx]
@@:
	mov	[rdi],al
	inc	rdi
	lea	rsi,[rbx+1]
	mov	ecx,eax
	rep	movsb
	; the suite: ECDHE_ECDSA or ECDHE_RSA, AES-128-GCM or ChaCha20-Poly1305
	imul	eax,[r15+C12_KEYTYPE],T12_SUITES
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
	cmp	dword [rbp+T2_RESUMED],0	; session_ticket, empty: one will come
	jne	@f
	cmp	dword [rbp+T2_TKWANT],0
	je	@f
	mov	dword [rdi],0x00002300
	add	rdi,4
@@:
	cmp	dword [r15+C12_ALPN],1
	jne	@f
	mov	dword [rdi],0x05001000		; ALPN (16), 5 bytes,
	mov	dword [rdi+4],0x68020300	; a 3-byte list, "h2"
	mov	byte [rdi+8],'2'
	add	rdi,9
@@:
	cmp	dword [r15+C12_ALPN],2
	jne	@f
	mov	dword [rdi],0x0b001000		; ALPN (16), 11 bytes,
	mov	word [rdi+4],0x0900		; a 9-byte list, "http/1.1"
	mov	byte [rdi+6],8
	mov	rax,'http/1.1'
	mov	[rdi+7],rax
	add	rdi,15
@@:
	cmp	dword [rbp+T2_RESUMED],0
	jne	@f
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
	cmp	dword [rbp+T2_RESUMED],0
	jne	.resumed
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
	; ---- CertificateRequest (client_ca): ECDSA or RSA, the schemes a
	; CertificateVerify may use, no names of CAs (the client offers its own)
	cmp	dword [r15+C12_CCA],0
	je	@f
	mov	dword [r13],0x0D00000D		; certificate_request, 13:
	mov	dword [r13+4],0x00014002	; types (2): ecdsa_sign, rsa_sign; schemes (6):
	mov	dword [r13+8],0x08030406	; 0403, 0804,
	mov	dword [r13+12],0x00010404	; 0401; certificate_authorities: none
	mov	byte [r13+16],0
	lea	rdi,[r13+17]
	call	.record
@@:
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
.resumed:
	; abbreviated (RFC 5077 3.1): the keys from the ticket's master secret
	; and these randoms, then the server's ChangeCipherSpec and Finished
	call	tls12_keys
	lea	rdi,[r13-5]
	call	tls12_server_fin
	lea	rcx,[r13-5]
	sub	rcx,r12
	add	eax,ecx
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
tls12_suites	dw 0xC02B, 0xCCA9, 0xC02C, 0xC02F, 0xCCA8, 0xC030	; T12_SUITES a key type

; In tls12_hello: rbx = the ClientHello's session id, r14 = its end, rbp = t2,
; r15 = the credentials. T2_SUITE, T2_GROUP, T2_SIG, T2_EMS and T2_RENEG from
; what it offers. CF: nothing in common (or a ClientHello that does not parse).
; Keeps rbx, rbp, r12-r15.
tls12_offers:
	xor	eax,eax
	mov	[rbp+T2_EMS],eax
	mov	[rbp+T2_RENEG],eax
	mov	[rbp+T2_TKWANT],eax
	mov	[rbp+T2_TKLEN],eax
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
	imul	edx,r10d,T12_SUITES * 2		; the suites for the certificate's key
	xor	ecx,ecx
.suite_try:
	cmp	ax,[tls12_suites+rdx+rcx*2]
	je	.suite_ours
	inc	ecx
	cmp	ecx,T12_SUITES
	jb	.suite_try
	jmp	.suite
.suite_ours:
	mov	r9d,ecx				; (T12_*: the table's order)
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
	cmp	eax,35				; session_ticket (RFC 5077): empty, or one
	jne	@f
	mov	[rbp+T2_TKP],rsi
	mov	[rbp+T2_TKLEN],ecx
	cmp	qword [g_tks],0
	je	.next
	mov	dword [rbp+T2_TKWANT],1
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
	lea	rdi,[rbp+T2_SHA384]
	call	sha384_init
	pop	rdx
	pop	rsi
	pop	rbx
	ret

; rbp = t2, rsi/edx = bytes: into both transcripts. Keeps rbx, rbp, r8-r15.
t2_add_fn:
	push	r8
	push	r9
	push	r10
	push	r11
	push	rsi
	push	rdx
	lea	rdi,[rbp+T2_SHA]
	call	sha256_update
	pop	rdx
	pop	rsi
	lea	rdi,[rbp+T2_SHA384]
	mov	edx,edx
	call	sha512_update
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	ret

; rbp = t2: the PRF's hash for its suite (g_prf384). Keeps the registers but rax.
t2_prf:
	xor	eax,eax
	cmp	dword [rbp+T2_SUITE],T12_AES256
	sete	al
	mov	[g_prf384],eax
	ret

; rbp = t2: the transcript so far, hashed with its suite's PRF hash, into
; g_t2_dig (32 or 48); the PRF set for it. Keeps rbx, rbp, r12-r15.
bss
	g_t2_dig	rb 48
end bss
t2_digest:
	call	t2_prf
	sub	rsp,SHA512_CTX_SIZE + 8
	cmp	dword [g_prf384],0
	jne	.h384
	lea	rsi,[rbp+T2_SHA]
	mov	rdi,rsp
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	mov	rdi,rsp
	lea	rsi,[g_t2_dig]
	call	sha256_final
	jmp	.out
.h384:
	lea	rsi,[rbp+T2_SHA384]
	mov	rdi,rsp
	mov	ecx,SHA512_CTX_SIZE
	rep	movsb
	mov	rdi,rsp
	lea	rsi,[g_t2_dig]
	call	sha384_final
.out:
	add	rsp,SHA512_CTX_SIZE + 8
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
	; --- the client's handshake messages, up to its ChangeCipherSpec (in as
	; many records as it took): [Certificate,] ClientKeyExchange,
	; [CertificateVerify] ---
	xor	ebx,ebx				; gathered
.gather:
	cmp	byte [r14],20
	je	.gathered
	cmp	byte [r14],22
	jne	.fail
	movzx	ecx,word [r14+3]
	rol	cx,8
	lea	eax,[rbx+rcx]
	cmp	eax,T12_HS_MAX
	ja	.fail
	lea	rsi,[r14+5]
	lea	rdi,[g_t12_hs+rbx]
	add	ebx,ecx
	lea	r14,[r14+5+rcx]
	rep	movsb
	jmp	.gather
.gathered:
	lea	r13,[g_t12_hs]			; the messages
	lea	r15,[g_t12_hs+rbx]		; their end
	mov	dword [g_cc_listn],0
	cmp	dword [rbp+T2_CCA],0
	je	.cke
	; Certificate: its list, as TLS 1.3 entries (with an empty extensions
	; field each) for the checks the 1.3 flight has
	call	.message
	jc	.fail
	cmp	eax,11
	jne	.fail
	mov	rsi,r13
	mov	edx,r8d
	t2_add
	mov	r11,[g_t12_mend]
	lea	rsi,[r13+4+3]			; past its header and the list's length
	lea	rdi,[g_cc_msg]
	mov	[g_cc_list],rdi
.entry:
	lea	rax,[rsi+3]
	cmp	rax,r11
	ja	.entries
	movzx	eax,byte [rsi]
	shl	eax,16
	movzx	ecx,word [rsi+1]
	rol	cx,8
	or	eax,ecx
	lea	rcx,[rsi+3+rax]
	cmp	rcx,r11
	ja	.fail
	lea	rcx,[rdi+3+rax+2]
	lea	rdx,[g_cc_msg+CC_MSG_MAX]
	cmp	rcx,rdx
	ja	.fail
	lea	ecx,[eax+3]
	rep	movsb
	mov	word [rdi],0
	add	rdi,2
	jmp	.entry
.entries:
	cmp	rsi,r11
	jne	.fail
	lea	rax,[g_cc_msg]
	sub	rdi,rax
	mov	[g_cc_listn],edi
	mov	r13,r11				; the next message
	test	edi,edi
	jnz	.cke
	cmp	dword [rbp+T2_CCA],2		; none sent, where one is required
	je	.fail
.cke:
	call	.message
	jc	.fail
	cmp	eax,16
	jne	.fail
	mov	rsi,r13
	mov	edx,r8d
	t2_add					; add CKE to the transcript
	mov	r11,[g_t12_mend]
	push	r11
	lea	rsi,[rbp+T2_SHA]		; the hash through it: the session hash (RFC
	lea	rdi,[rsp+8]			; 7627), and what a CertificateVerify signs
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rsp+8]
	lea	rsi,[rbp+T2_SH]
	call	sha256_final
	cmp	dword [rbp+T2_SUITE],T12_AES256
	jne	.sh_done
	sub	rsp,SHA512_CTX_SIZE		; and with SHA-384, its suites' session hash
	lea	rsi,[rbp+T2_SHA384]
	mov	rdi,rsp
	mov	ecx,SHA512_CTX_SIZE
	rep	movsb
	mov	rdi,rsp
	lea	rsi,[rbp+T2_SH384]
	call	sha384_final
	add	rsp,SHA512_CTX_SIZE
.sh_done:
	pop	r11
	cmp	dword [rbp+T2_GROUP],0
	jne	.cke_x
	cmp	byte [r13+4],65
	jne	.fail
	lea	rdi,[rbp+T2_SHARED]		; premaster = ECDH(ESK, client pubkey)
	lea	rsi,[rbp+T2_ESK]
	lea	rdx,[r13+4+1]			; past msg header (4) and pubkey length (1)
	push	r11
	call	p256_ecdh
	pop	r11
	test	eax,eax
	jz	.fail
	jmp	.cke_done
.cke_x:
	cmp	byte [r13+4],32
	jne	.fail
	lea	rdi,[rbp+T2_SHARED]
	lea	rsi,[rbp+T2_ESK]
	lea	rdx,[r13+4+1]
	push	r11
	call	x25519
	pop	r11
	mov	rax,[rbp+T2_SHARED]		; all zero: a small-order point
	or	rax,[rbp+T2_SHARED+8]
	or	rax,[rbp+T2_SHARED+16]
	or	rax,[rbp+T2_SHARED+24]
	jz	.fail
.cke_done:
	mov	r13,r11
	cmp	dword [g_cc_listn],0
	je	.messages_done
	; CertificateVerify: the certificate checked (chain, times, who), then
	; its signature over the handshake through the ClientKeyExchange
	call	.message
	jc	.fail
	cmp	eax,15
	jne	.fail
	push	r11
	mov	rbx,[rbp+T2_TS]
	call	cc_check_cert
	test	eax,eax
	jz	.fail_pop
	lea	rsi,[rbp+T2_SH]
	lea	rdi,[g_cc_dig]
	mov	ecx,32
	rep	movsb
	lea	rdi,[r13+4]
	mov	rsi,[rsp]			; (its end)
	call	cc12_signature
	test	eax,eax
	jz	.fail_pop
	mov	rsi,r13
	mov	rdx,[rsp]
	sub	rdx,r13
	t2_add
	pop	r13
.messages_done:
	cmp	r13,r15
	jne	.fail				; nothing else before the ChangeCipherSpec
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
	call	t2_prf
	cmp	dword [rbp+T2_EMS],0
	je	.classic
	lea	rdi,[rbp+T2_MASTER]
	lea	rsi,[rbp+T2_SHARED]
	lea	rcx,[rbp+T2_SH]			; (the session hash, through the CKE)
	cmp	dword [g_prf384],0
	je	.ems_h
	lea	rcx,[rbp+T2_SH384]
.ems_h:
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
	call	tls12_keys
	; expected client verify_data over the transcript through CKE
	call	t2_digest
	lea	rdi,[rsp+144]
	lea	rsi,[rbp+T2_MASTER]
	lea	rdx,[tls12_lbl_cfin]
	mov	ecx,15
	lea	r8,[g_t2_dig]
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
	; a NewSessionTicket (RFC 5077 3.3), when the client takes them, then the
	; server's ChangeCipherSpec and Finished
	xor	ebx,ebx
	cmp	dword [rbp+T2_TKWANT],0
	je	@f
	mov	rdi,r12
	call	tls12_ticket_new
	mov	ebx,eax
@@:
	lea	rdi,[r12+rbx]
	call	tls12_server_fin
	add	eax,ebx
	jmp	.out
.fail_pop:
	add	rsp,8
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
; the message at r13 (r15 = the end): eax = its type, r8d = its length with
; the header, r11 = its end. CF: it does not fit.
.message:
	lea	rax,[r13+4]
	cmp	rax,r15
	ja	.message_short
	mov	eax,[r13]
	bswap	eax
	mov	r8d,eax
	and	r8d,0xFFFFFF
	shr	eax,24
	lea	r11,[r13+4+r8]
	cmp	r11,r15
	ja	.message_short
	mov	[g_t12_mend],r11
	add	r8d,4
	clc
	ret
.message_short:
	stc
	ret

; rdi = t2, rsi = TX crypto_info out (40), rdx = RX crypto_info out (40):
; fills two struct tls12_crypto_info_aes_gcm_128 for the kernel's TLS 1.2
; (version 0x0303), TX from the server write key/IV and RX from the client
; write key/IV, both at record sequence 1 (after the Finished). The layout
; is proven against the kernel in tests/tls/server12.asm.
tls12_ktls_info:
	cmp	dword [rdi+T2_SUITE],T12_AES256
	je	.aes256
	cmp	dword [rdi+T2_SUITE],T12_AES128
	jne	.chacha
	call	.aes
	mov	eax,40
	ret
.aes256:
	; struct tls12_crypto_info_aes_gcm_256: info, iv[8], key[32], salt[4], rec_seq[8]
	push	rdx
	lea	r8,[rdi+T2_SWK]
	mov	r9d,[rdi+T2_SWIV]
	call	.a256_one
	pop	rsi
	lea	r8,[rdi+T2_CWK]
	mov	r9d,[rdi+T2_CWIV]
	call	.a256_one
	mov	eax,56
	ret
.a256_one:
	mov	dword [rsi],0x00340303		; TLS 1.2, AES_GCM_256
	mov	qword [rsi+4],0			; iv = explicit nonce, big-endian 1
	mov	byte [rsi+11],1
	movdqu	xmm0,[r8]
	movdqu	[rsi+12],xmm0
	movdqu	xmm0,[r8+16]
	movdqu	[rsi+28],xmm0
	mov	[rsi+44],r9d			; salt = the write IV
	mov	qword [rsi+48],0		; rec_seq = 1
	mov	byte [rsi+55],1
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
	sub	rsp,80
	lea	rdi,[rsp]
	lea	rsi,[.label]
	mov	ecx,22
	rep	movsb
	mov	rsi,rbx
	mov	ecx,32
	cmp	dword [g_prf384],0
	je	.hlen_ok
	mov	ecx,48
.hlen_ok:
	lea	r9d,[rcx+22]
	rep	movsb
	mov	rdi,r12
	mov	esi,48
	mov	rdx,r13
	mov	ecx,32
	lea	r8,[rsp]
	call	p_sha256
	add	rsp,80
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
	cmp	dword [rsi+AEAD_TYPE],AEAD_CHACHA
	jne	tls12_seal			; AES-GCM, 128 or 256: an explicit nonce
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
	cmp	dword [rdx+AEAD_TYPE],AEAD_CHACHA
	je	.cp
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

; rbp = t2: the key block from T2_MASTER and the randoms, into the write keys
; and IVs (the suite's sizes), and the two AEAD contexts set up
tls12_keys:
	call	t2_prf
	sub	rsp,104
	mov	esi,40				; AES-128-GCM: keys of 16, salts of 4
	cmp	dword [rbp+T2_SUITE],T12_AES128
	je	@f
	mov	esi,72				; AES-256-GCM: keys of 32, salts of 4
	cmp	dword [rbp+T2_SUITE],T12_AES256
	je	@f
	mov	esi,88				; ChaCha20-Poly1305: keys of 32, IVs of 12
@@:
	lea	rdi,[rsp]
	lea	rdx,[rbp+T2_MASTER]
	lea	rcx,[rbp+T2_SR]
	lea	r8,[rbp+T2_CR]
	call	tls12_key_block
	cmp	dword [rbp+T2_SUITE],T12_AES256
	je	.aes256
	cmp	dword [rbp+T2_SUITE],T12_AES128
	jne	.cp
	movdqu	xmm0,[rsp]
	movdqu	[rbp+T2_CWK],xmm0
	movdqu	xmm0,[rsp+16]
	movdqu	[rbp+T2_SWK],xmm0
	mov	eax,[rsp+32]
	mov	[rbp+T2_CWIV],eax
	mov	eax,[rsp+36]
	mov	[rbp+T2_SWIV],eax
	jmp	.done
.aes256:
	lea	rsi,[rsp]
	lea	rdi,[rbp+T2_CWK]
	mov	ecx,64				; the two keys (CWK, SWK adjoin)
	rep	movsb
	mov	eax,[rsp+64]
	mov	[rbp+T2_CWIV],eax
	mov	eax,[rsp+68]
	mov	[rbp+T2_SWIV],eax
	jmp	.done
.cp:
	lea	rsi,[rsp]
	lea	rdi,[rbp+T2_CWK]
	mov	ecx,64				; the two keys (CWK, SWK adjoin)
	rep	movsb
	lea	rdi,[rbp+T2_CWIV]
	mov	ecx,24				; and the two IVs
	rep	movsb
.done:
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
	add	rsp,104
	ret

; rbp = t2, rdi = out: the server's ChangeCipherSpec and Finished (over the
; transcript so far, which then has it), sealed at sequence 0. eax = bytes.
tls12_server_fin:
	push	rbx
	push	r12
	sub	rsp,168				; ctx(112), hash(32) @112, Finished(16) @144
	mov	r12,rdi
	call	t2_digest
	mov	dword [rsp+144],0x0c000014	; Finished, 12
	lea	rdi,[rsp+148]
	lea	rsi,[rbp+T2_MASTER]
	lea	rdx,[tls12_lbl_sfin]
	mov	ecx,15
	lea	r8,[g_t2_dig]
	call	tls12_verify_data
	lea	rsi,[rsp+144]			; (an abbreviated handshake's client
	mov	edx,16				; Finished covers it)
	t2_add
	mov	byte [r12],20			; ChangeCipherSpec
	mov	word [r12+1],0x0303
	mov	word [r12+3],0x0100
	mov	byte [r12+5],1
	lea	rdi,[r12+6+5]
	lea	rsi,[rbp+T2_TXGCM]
	lea	rdx,[rbp+T2_SWIV]
	xor	ecx,ecx
	mov	r8d,22
	lea	r9,[rsp+144]
	mov	r10d,16
	call	tls12_aseal
	mov	byte [r12+6],22
	mov	word [r12+6+1],0x0303
	mov	edx,eax
	rol	dx,8
	mov	[r12+6+3],dx
	add	eax,11				; CCS (6) + record header (5) + payload
	add	rsp,168
	pop	r12
	pop	rbx
	ret

; rbp = t2, rdi = out: a NewSessionTicket record (RFC 5077 3.3), its message in
; the transcript. eax = bytes.
tls12_ticket_new:
	push	rbx
	push	r12
	sub	rsp,8
	mov	r12,rdi
	lea	rbx,[rbp+T2_TICKET]
	mov	rdi,rbx
	mov	ecx,TK12_SIZE
	xor	eax,eax
	rep	stosb
	mov	byte [rbx+TK_SEALED+TK12P_VERSION],2
	mov	eax,[rbp+T2_SUITE]
	mov	[rbx+TK_SEALED+TK12P_SUITE],al
	mov	eax,[rbp+T2_EMS]
	mov	[rbx+TK_SEALED+TK12P_EMS],al
	call	tls_now_s
	mov	[rbx+TK_SEALED+TK12P_ISSUED],eax
	mov	rax,[rbp+T2_CERTID]
	mov	[rbx+TK_SEALED+TK12P_CERT],rax
	lea	rsi,[rbp+T2_MASTER]
	lea	rdi,[rbx+TK_SEALED+TK12P_MASTER]
	mov	ecx,48
	rep	movsb
	mov	rsi,[rbp+T2_TS]			; client_ca: its CAs, who the client is
	test	rsi,rsi
	jz	@f
	mov	eax,[rsi+TS_TKCCA]
	mov	[rbx+TK_SEALED+TK12P_CCA],eax
	mov	ecx,[rsi+TS_PEERL]
	mov	[rbx+TK_SEALED+TK12P_PEERL],ecx
	add	rsi,TS_PEER
	lea	rdi,[rbx+TK_SEALED+TK12P_PEER]
	rep	movsb
@@:
	lea	rdi,[rbx+TK_NONCE]
	mov	esi,12
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	mov	rdi,[g_tks]			; the current key
	mov	eax,[rdi+TKS_CUR]
	imul	eax,eax,TKS_SLOT
	lea	rdi,[rdi+TKS_SLOTS+rax]
	mov	eax,[rdi+TKS_ID]
	mov	[rbx+TK_ID],eax
	add	rdi,TKS_GCM
	lea	rsi,[rbx+TK_NONCE]
	lea	rdx,[rbx+TK_ID]
	mov	ecx,4
	lea	r8,[rbx+TK_SEALED]
	mov	r9d,TK12_PT
	call	gcm_seal
	; the record: 22 03 03 | 4 + 4 + 2 + TK12_SIZE
	mov	byte [r12],22
	mov	word [r12+1],0x0303
	mov	eax,4 + 4 + 2 + TK12_SIZE
	rol	ax,8
	mov	[r12+3],ax
	mov	byte [r12+5],4			; new_session_ticket
	mov	eax,4 + 2 + TK12_SIZE
	put24	r12+6, eax
	mov	eax,[g_tk_life]			; ticket_lifetime_hint: as long as it is taken
	add	eax,eax
	bswap	eax
	mov	[r12+9],eax
	mov	word [r12+13],(TK12_SIZE shr 8) or ((TK12_SIZE and 255) shl 8)
	lea	rdi,[r12+15]
	mov	rsi,rbx
	mov	ecx,TK12_SIZE
	rep	movsb
	lea	rsi,[r12+5]
	mov	edx,4 + 4 + 2 + TK12_SIZE
	t2_add
	mov	rdi,rbx				; (the plaintext master secret: gone)
	mov	ecx,TK12_SIZE
	call	secure_zero
	mov	eax,5 + 4 + 4 + 2 + TK12_SIZE
	add	rsp,8
	pop	r12
	pop	rbx
	ret

; in tls12_hello, after tls12_offers: rbx = the session id. The client's ticket,
; when it opens under a current key, is ours (version 2), not past its life,
; for this certificate, of the suite chosen and the same extended master
; secret (RFC 7627 5.3), and the client sent a session id to have echoed:
; T2_RESUMED, its master secret in T2_MASTER. Keeps rbx, rbp, r12-r15.
tls12_resume_try:
	mov	dword [rbp+T2_RESUMED],0
	cmp	qword [g_tks],0
	je	.out
	cmp	dword [rbp+T2_TKLEN],TK12_SIZE
	jne	.out
	cmp	byte [rbx],0
	je	.out
	mov	rsi,[rbp+T2_TKP]
	lea	rdi,[rbp+T2_TICKET]
	mov	ecx,TK12_SIZE
	rep	movsb
	mov	eax,[rbp+T2_TICKET+TK_ID]
	call	tls_ticket_key			; rdi = its key, or CF
	jc	.no
	lea	rsi,[rbp+T2_TICKET+TK_NONCE]
	lea	rdx,[rbp+T2_TICKET+TK_ID]
	mov	ecx,4
	lea	r8,[rbp+T2_TICKET+TK_SEALED]
	mov	r9d,TK12_PT
	call	gcm_open
	test	eax,eax
	jz	.no
	lea	r8,[rbp+T2_TICKET+TK_SEALED]
	cmp	byte [r8+TK12P_VERSION],2
	jne	.no
	movzx	eax,byte [r8+TK12P_SUITE]
	cmp	eax,[rbp+T2_SUITE]
	jne	.no
	movzx	eax,byte [r8+TK12P_EMS]
	cmp	eax,[rbp+T2_EMS]
	jne	.no
	mov	rax,[r8+TK12P_CERT]
	cmp	rax,[rbp+T2_CERTID]
	jne	.no
	call	tls_now_s
	lea	r8,[rbp+T2_TICKET+TK_SEALED]
	sub	eax,[r8+TK12P_ISSUED]
	mov	ecx,[g_tk_life]
	add	ecx,ecx
	cmp	eax,ecx
	ja	.no
	xor	eax,eax				; the listener's CAs, as the ticket's (0: none)
	mov	rdi,[rbp+T2_TS]
	test	rdi,rdi
	jz	@f
	mov	eax,[rdi+TS_TKCCA]
@@:
	cmp	eax,[r8+TK12P_CCA]
	jne	.no
	test	eax,eax
	jz	@f
	mov	ecx,[r8+TK12P_PEERL]		; who the client is, as it was
	cmp	ecx,MTLS_NAME_MAX
	jbe	.peer
	xor	ecx,ecx
.peer:
	mov	[rdi+TS_PEERL],ecx
	lea	rsi,[r8+TK12P_PEER]
	add	rdi,TS_PEER
	rep	movsb
	lea	r8,[rbp+T2_TICKET+TK_SEALED]
@@:
	lea	rsi,[r8+TK12P_MASTER]
	lea	rdi,[rbp+T2_MASTER]
	mov	ecx,48
	rep	movsb
	mov	dword [rbp+T2_RESUMED],1
.no:
	lea	rdi,[rbp+T2_TICKET]
	mov	ecx,TK12_SIZE
	call	secure_zero
.out:
	ret

; rdi = t2 of an abbreviated handshake, rsi = the client's records after the
; server's Finished (ChangeCipherSpec, its encrypted Finished), ecx = their
; length: eax = 1 when its Finished is right (over the ClientHello, the
; ServerHello and the server's Finished), else 0
tls12_resumed_fin:
	push	rbx
	push	rbp
	push	r14
	sub	rsp,160				; ctx(112), hash(32) @112, expected(12) @144
	mov	rbp,rdi
	mov	r14,rsi
	cmp	byte [r14],20			; ChangeCipherSpec
	jne	.fail
	movzx	eax,word [r14+3]
	rol	ax,8
	lea	r14,[r14+5+rax]
	cmp	byte [r14],22
	jne	.fail
	call	t2_digest
	lea	rdi,[rsp+144]
	lea	rsi,[rbp+T2_MASTER]
	lea	rdx,[tls12_lbl_cfin]
	mov	ecx,15
	lea	r8,[g_t2_dig]
	call	tls12_verify_data
	movzx	esi,word [r14+3]
	rol	si,8
	lea	rdi,[r14+5]
	lea	rdx,[rbp+T2_RXGCM]
	lea	rcx,[rbp+T2_CWIV]
	xor	r8d,r8d
	mov	r9d,22
	call	tls12_aopen
	cmp	eax,16
	jne	.fail
	cmp	dword [rdx],0x0c000014
	jne	.fail
	lea	rdi,[rdx+4]
	lea	rsi,[rsp+144]
	mov	edx,12
	call	ct_equal
	test	eax,eax
	jz	.fail
	mov	eax,1
	jmp	.out
.fail:
	xor	eax,eax
.out:
	add	rsp,160
	pop	r14
	pop	rbp
	pop	rbx
	ret
