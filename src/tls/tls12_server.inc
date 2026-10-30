; TLS 1.2 server handshake (RFC 5246 + RFC 8422): ECDHE_ECDSA with x25519
; and AES-128-GCM. Built on the tls12.inc primitives (PRF, key schedule,
; record layer). Decoupled from the certificate store via a C12 block.

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
C12_KEY		:= 16				; q: pointer to the private key (32, big endian)

T2_ESK		:= 0				; ephemeral x25519 private key
T2_CR		:= 32				; client random
T2_SR		:= 64				; server random
T2_EPK		:= 96				; ephemeral public key (65, P-256)
T2_SHA		:= T2_EPK + 72			; the handshake transcript (SHA-256 ctx)
T2_SHARED	:= T2_SHA + SHA256_CTX_SIZE	; the ECDH shared secret (premaster)
T2_MASTER	:= T2_SHARED + 32		; master secret (48)
T2_CWK		:= T2_MASTER + 48		; key_block: client write key (16),
T2_SWK		:= T2_CWK + 16			; server write key (16),
T2_CWIV		:= T2_SWK + 16			; client write IV (4),
T2_SWIV		:= T2_CWIV + 4			; server write IV (4)
T2_RXGCM	:= T2_SWIV + 4			; client -> server records
T2_TXGCM	:= T2_RXGCM + GCM_SIZE		; server -> client records
T2_FULL		:= T2_TXGCM + GCM_SIZE

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
	sub	rsp,248				; [rsp]=sign input(133), [rsp+112]=rs(64), [rsp+136]=digest (16-aligned)
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
	call	sha256_init_t2			; start the transcript
	mov	rsi,r13				; add the ClientHello message
	mov	edx,r14d
	sub	edx,r13d
	t2_add
	; server random and the ephemeral private key
	lea	rdi,[rbp+T2_SR]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,32
	jne	.fail
	lea	rdi,[rbp+T2_ESK]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,32
	jne	.fail
	lea	rdi,[rbp+T2_EPK]
	lea	rsi,[rbp+T2_ESK]
	call	p256_public
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
	mov	word [rdi],0x2BC0		; cipher TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	mov	byte [rdi+2],0			; compression
	mov	word [rdi+3],0x0500		; extensions length 5
	mov	byte [rdi+5],0xff		; renegotiation_info (RFC 5746), empty
	mov	byte [rdi+6],0x01
	mov	byte [rdi+7],0x00
	mov	byte [rdi+8],0x01
	mov	byte [rdi+9],0x00
	add	rdi,10
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
	; ---- ServerKeyExchange: ECDHE params + ECDSA signature ----
	mov	byte [r13],12
	mov	byte [r13+4],3			; curve_type named_curve
	mov	word [r13+5],0x1700		; named_curve secp256r1 (0x0017)
	mov	byte [r13+7],65			; public key length
	lea	rdi,[r13+8]
	lea	rsi,[rbp+T2_EPK]
	mov	ecx,65
	rep	movsb				; past the 69-byte params
	; signature over client_random | server_random | ecdh_params(69)
	lea	rdi,[rsp]
	lea	rsi,[rbp+T2_CR]
	mov	ecx,32
	rep	movsb
	lea	rsi,[rbp+T2_SR]
	mov	ecx,32
	rep	movsb
	lea	rsi,[r13+4]			; the 69-byte params
	mov	ecx,69
	rep	movsb
	lea	rdi,[rsp+136]			; digest (sign input is 133 bytes)
	lea	rsi,[rsp]
	mov	edx,133
	call	sha256
	lea	rdi,[rsp+112]			; r||s
	mov	rsi,[r15+C12_KEY]
	lea	rdx,[rsp+136]
	call	p256_sign
	test	eax,eax
	jz	.fail
	mov	word [r13+4+69],0x0304		; ecdsa_secp256r1_sha256 (0x0403)
	lea	rdi,[r13+4+69+2+2]		; the DER signature
	lea	rsi,[rsp+112]
	call	ecdsa_der			; eax = DER length
	mov	edx,eax
	rol	dx,8
	mov	[r13+4+69+2],dx			; signature length (u16)
	lea	eax,[rax+69+4]			; body = params(69) + sigalg(2) + len(2) + DER
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
.fail:
	xor	eax,eax
.out:
	add	rsp,248
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
	lea	rdi,[rbp+T2_SHARED]		; premaster = ECDH(ESK, client pubkey)
	lea	rsi,[rbp+T2_ESK]
	lea	rdx,[r14+5+4+1]			; past msg header (4) and pubkey length (1)
	call	p256_ecdh
	test	eax,eax
	jz	.fail
	lea	r14,[r14+5+r13]			; next record
	cmp	byte [r14],20			; skip ChangeCipherSpec
	jne	@f
	movzx	eax,word [r14+3]
	rol	ax,8
	lea	r14,[r14+5+rax]
@@:
	cmp	byte [r14],22			; the encrypted Finished record
	jne	.fail
	; master secret and the key block
	lea	rdi,[rbp+T2_MASTER]
	lea	rsi,[rbp+T2_SHARED]
	mov	edx,32
	lea	rcx,[rbp+T2_CR]
	lea	r8,[rbp+T2_SR]
	call	tls12_master
	lea	rdi,[rbp+T2_CWK]
	mov	esi,40
	lea	rdx,[rbp+T2_MASTER]
	lea	rcx,[rbp+T2_SR]
	lea	r8,[rbp+T2_CR]
	call	tls12_key_block
	lea	rdi,[rbp+T2_RXGCM]
	lea	rsi,[rbp+T2_CWK]
	call	gcm_init
	lea	rdi,[rbp+T2_TXGCM]
	lea	rsi,[rbp+T2_SWK]
	call	gcm_init
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
	call	tls12_open
	cmp	eax,16				; Finished = 4-byte header + 12 verify_data
	jne	.fail
	lea	rbx,[r14+5+8]			; the Finished handshake message
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
	call	tls12_seal			; eax = record payload length
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
