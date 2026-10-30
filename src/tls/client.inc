; TLS 1.3 client handshake, for TLS towards upstreams (RFC 8446 as the
; client): TLS_AES_128_GCM_SHA256, X25519MLKEM768, x25519 and secp256r1
; key shares,
; ecdsa_secp256r1_sha256 signatures. The crypto is the same as the server
; side (src/tls/handshake.inc); here okena opens the connection.
;
; This first piece generates the ClientHello and keeps the ephemeral keys
; and the transcript in a TC block; the rest (ServerHello, the server's
; flight, verification, Finished) follows.
;
;   tlsc_client_hello(rdi ts, rsi out, rdx sni, ecx sni length): the
;       ClientHello record is written to out (eax = its length), its
;       handshake bytes added to the transcript, the ephemeral x25519,
;       P-256 and ML-KEM-768 private keys and the client random kept in ts
;       (a TC_FULL block). out needs room for ~1650 bytes plus the SNI.

TC_X25519_SK	:= 0				; ephemeral private keys
TC_P256_SK	:= 32
TC_RANDOM	:= 64				; client random (32), then a session id (32)
TC_SID		:= 96
TC_SHA		:= 128				; the transcript (SHA256_CTX)
TC_X25519_PK	:= TC_SHA + SHA256_CTX_SIZE	; the public keys sent
TC_P256_PK	:= TC_X25519_PK + 32		; 65 bytes
TC_SIZE		:= TC_P256_PK + 72

; append literal bytes at rdi (advancing rdi); clobbers rsi, rcx
macro ch_lit bytes&
	local s, e
	jmp	e
	s db bytes
	e:
	lea	rsi,[s]
	mov	ecx,e - s
	rep	movsb
end macro

; rdi = ts, rsi = out, rdx = sni, ecx = sni length. eax = record length.
tlsc_client_hello:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi				; ts
	mov	r12,rsi				; out (record start)
	mov	r13,rdx				; sni
	mov	r14d,ecx			; sni length
	; client random, session id, and two ephemeral private keys
	lea	rdi,[rbx+TC_RANDOM]
	mov	esi,64				; random (32) | session id (32)
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,64
	jne	.fail
	lea	rdi,[rbx+TC_X25519_SK]
	mov	esi,64				; x25519 sk (32) | p256 sk (32)
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,64
	jne	.fail
	lea	rdi,[rbx+TC_X25519_PK]		; x25519 public
	lea	rsi,[rbx+TC_X25519_SK]
	call	x25519_base
	lea	rdi,[rbx+TC_P256_PK]		; P-256 public (04|X|Y)
	lea	rsi,[rbx+TC_P256_SK]
	call	p256_public
	lea	rdi,[rbx+TC_MLSEED]		; the ML-KEM-768 key pair's seed
	mov	esi,64
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,64
	jne	.fail
	mov	dword [rbx+TC_KXLEN],0

	; the handshake message, after the 5-byte record header
	lea	rdi,[r12+5]
	mov	byte [rdi],1			; client_hello
	add	rdi,4				; its u24 length, filled at the end
	mov	r15,rdi				; body start (for the length)
	mov	word [rdi],0x0303		; legacy_version
	add	rdi,2
	lea	rsi,[rbx+TC_RANDOM]		; random
	mov	ecx,32
	rep	movsb
	mov	byte [rdi],32			; legacy_session_id
	inc	rdi
	lea	rsi,[rbx+TC_SID]
	mov	ecx,32
	rep	movsb
	; cipher_suites: TLS_AES_128_GCM_SHA256 (1.3), then ECDHE_ECDSA and
	; ECDHE_RSA with AES-128-GCM (1.2, for a backend that has no 1.3)
	ch_lit 0x00,0x06,0x13,0x01,0xC0,0x2B,0xC0,0x2F
	ch_lit 0x01,0x00			; compression: null
	; extensions: a u16 length, filled at the end
	mov	r8,rdi				; extensions length slot
	add	rdi,2
	; supported_versions (43): TLS 1.3, then TLS 1.2
	ch_lit 0x00,0x2B,0x00,0x05,0x04,0x03,0x04,0x03,0x03
	; supported_groups (10): X25519MLKEM768, x25519, secp256r1
	ch_lit 0x00,0x0A,0x00,0x08,0x00,0x06,0x11,0xEC,0x00,0x1D,0x00,0x17
	; signature_algorithms (13): ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,
	; rsa_pkcs1_sha256 (the last for a legacy 1.2 backend)
	ch_lit 0x00,0x0D,0x00,0x08,0x00,0x06,0x04,0x03,0x08,0x04,0x04,0x01
	; key_share (51): X25519MLKEM768 (1216), x25519 (32) and secp256r1 (65):
	; 1220 + 36 + 69 = 1325 bytes of shares
	ch_lit 0x00,0x33,0x05,0x2F,0x05,0x2D
	ch_lit 0x11,0xEC,0x04,0xC0		; X25519MLKEM768, 1216 bytes:
	push	r8
	lea	rsi,[rbx+TC_MLDK]		; the ML-KEM-768 key written in place
	lea	rdx,[rbx+TC_MLSEED]
	push	rdi
	call	mlkem768_keygen
	pop	rdi
	pop	r8
	add	rdi,MLKEM_EK
	lea	rsi,[rbx+TC_X25519_PK]		; then the same x25519 key as below
	mov	ecx,32
	rep	movsb
	ch_lit 0x00,0x1D,0x00,0x20		; x25519 group, 32 bytes
	lea	rsi,[rbx+TC_X25519_PK]
	mov	ecx,32
	rep	movsb
	ch_lit 0x00,0x17,0x00,0x41		; secp256r1 group, 65 bytes
	lea	rsi,[rbx+TC_P256_PK]
	mov	ecx,65
	rep	movsb
	; ALPN (16): http/1.1
	ch_lit 0x00,0x10,0x00,0x0B,0x00,0x09,0x08,'h','t','t','p','/','1','.','1'
	; server_name (0), when there is one
	test	r14d,r14d
	jz	.ext_done
	mov	word [rdi],0x0000		; extension type server_name
	lea	eax,[r14+5]			; ext length = name + 5
	rol	ax,8
	mov	[rdi+2],ax
	lea	eax,[r14+3]			; server_name_list length
	rol	ax,8
	mov	[rdi+4],ax
	mov	byte [rdi+6],0			; host_name
	mov	eax,r14d			; name length (u16)
	rol	ax,8
	mov	[rdi+7],ax
	add	rdi,9
	mov	rsi,r13
	mov	ecx,r14d
	rep	movsb
.ext_done:
	; extensions length
	mov	eax,edi
	sub	eax,r8d
	sub	eax,2
	rol	ax,8
	mov	[r8],ax
	; handshake u24 length
	mov	eax,edi
	sub	eax,r15d
	mov	rcx,r15
	mov	byte [rcx-3],0
	rol	ax,8
	mov	[rcx-2],ax
	; record header: handshake (22), TLS 1.0, length
	mov	eax,edi
	sub	eax,r12d
	sub	eax,5
	mov	r14d,eax			; the payload length (before the byte swap below)
	mov	r13d,edi			; the write end (sha clobbers rax, rdi)
	mov	byte [r12],22
	mov	word [r12+1],0x0103
	rol	ax,8
	mov	[r12+3],ax
	; transcript: the handshake message (record payload)
	lea	rdi,[rbx+TC_SHA]
	call	sha256_init
	lea	rdi,[rbx+TC_SHA]
	lea	rsi,[r12+5]
	mov	edx,r14d
	call	sha256_update
	mov	eax,r13d			; the record's total length
	sub	eax,r12d
	jmp	.out
.fail:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; --- the server's flight: ServerHello, then its encrypted handshake ---
; more TC fields, after the ClientHello ones
TC_SHARED	:= TC_SIZE			; ECDH shared secret
TC_HS		:= TC_SHARED + 32		; handshake secret
TC_SHT		:= TC_HS + 32			; server handshake traffic secret
TC_SKEY		:= TC_SHT + 32			; server handshake key (16), IV (12)
TC_SIV		:= TC_SKEY + 16
TC_NONCE	:= TC_SIV + 12
TC_SSEQ		:= TC_NONCE + 12		; q: server record sequence
TC_TH		:= TC_SSEQ + 8			; a transcript hash
TC_CHT		:= TC_TH + 32			; client handshake traffic secret
TC_SFK		:= TC_CHT + 32			; server / client finished keys
TC_CFK		:= TC_SFK + 32
TC_LEAFPUB	:= TC_CFK + 32			; the leaf certificate's P-256 key (65)
TC_CV		:= TC_LEAFPUB + 72		; the CertificateVerify signed content (130)
TC_DIG		:= TC_CV + 136			; its SHA-256
TC_FIN		:= TC_DIG + 32			; a computed Finished / HMAC
TC_THX		:= TC_FIN + 32			; a transcript-hash snapshot
TC_GCM		:= TC_THX + 32			; a SHA scratch; then the client-hs seal context
TC_TMP		:= TC_GCM + GCM_SIZE		; key-schedule scratch
TC_MS		:= TC_TMP + 32			; master secret
TC_CAPK		:= TC_MS + 32			; client application key (16), IV (12)
TC_CAPIV	:= TC_CAPK + 16
TC_SAPK		:= TC_CAPIV + 12		; server application key (16), IV (12)
TC_SAPIV	:= TC_SAPK + 16
TC_NONCE2	:= TC_SAPIV + 12		; a nonce scratch (12)
TC_TXSEQ	:= TC_NONCE2 + 16		; q: client app records sent
TC_RXSEQ	:= TC_TXSEQ + 8			; q: server app records opened
TC_TXGCM	:= TC_RXSEQ + 8			; client / server application contexts
TC_RXGCM	:= TC_TXGCM + GCM_SIZE
TC_LEAF		:= TC_RXGCM + GCM_SIZE		; the leaf certificate DER (ptr, len)
TC_LEAFLEN	:= TC_LEAF + 8
TC_CLIST	:= TC_LEAFLEN + 8		; the CertificateEntry list (ptr, len)
TC_CLISTLEN	:= TC_CLIST + 8
TC_LEAFKEY	:= TC_CLISTLEN + 8		; the leaf public key (EC or RSA), a PK blob
; TLS 1.2 client state (a 1.2 backend; the fields above are the 1.3 path)
TC12_SRAND	:= TC_LEAFKEY + PK_SIZE		; server random (32)
TC12_MASTER	:= TC12_SRAND + 32		; master secret (48)
TC12_KB		:= TC12_MASTER + 48		; key_block: cwk(16) swk(16) civ(4) siv(4)
TC12_CWK	:= TC12_KB
TC12_SWK	:= TC12_KB + 16
TC12_CIV	:= TC12_KB + 32
TC12_SIV	:= TC12_KB + 36
TC12_TX		:= TC12_KB + 40			; client-write GCM context
TC12_RX		:= TC12_TX + GCM_SIZE		; server-write GCM context
; the post-quantum hybrid (X25519MLKEM768)
TC_MLDK		:= TC12_RX + GCM_SIZE		; the ML-KEM-768 decapsulation key (2400)
TC_MLSEED	:= TC_MLDK + MLKEM_DK		; d | z (64)
TC_SH64		:= TC_MLSEED + 64		; the hybrid secret: ML-KEM's | x25519's
TC_KXLEN	:= TC_SH64 + 64			; d: the key exchange is done (the flight
						; is processed again as it arrives): the
						; secret's length (32 at TC_SHARED, 64 at
						; TC_SH64), 0 before
TC_FULL		:= TC_KXLEN + 8

; rdi = tc, rsi = in (the server's bytes), edx = in length, rcx = out:
; parses the ServerHello, computes the ECDH secret, derives the server
; handshake key, and decrypts the server's flight into out (the handshake
; messages, concatenated). eax = plaintext length, or 0 on error.
TF_TC		:= 0
TF_IN		:= 8
TF_END		:= 16
TF_OUT		:= 24
TF_OP		:= 32				; out cursor
TF_FR		:= 40				; frame size (16-aligned) + 8
tlsc_server_flight:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,48
	mov	[rsp+TF_TC],rdi
	mov	rbx,rdi				; tc
	mov	[rsp+TF_IN],rsi
	lea	rax,[rsi+rdx]
	mov	[rsp+TF_END],rax
	mov	[rsp+TF_OUT],rcx
	mov	[rsp+TF_OP],rcx
	; first record: ServerHello (plaintext handshake, type 22)
	mov	r12,rsi				; record cursor
	cmp	byte [r12],22
	jne	.bad
	movzx	r13d,word [r12+3]		; record length
	rol	r13w,8
	lea	rax,[r12+5+r13]
	cmp	rax,[rsp+TF_END]
	ja	.bad
	lea	r14,[r12+5]			; ServerHello handshake message
	cmp	byte [r14],2			; server_hello
	jne	.bad
	; transcript: add the ServerHello message, snapshot TH
	lea	rdi,[rbx+TC_SHA]
	mov	rsi,r14
	mov	edx,r13d
	call	sha256_update
	lea	rsi,[rbx+TC_SHA]		; copy and finalize into TC_TH
	lea	rdi,[rbx+TC_GCM]		; borrow TC_GCM as a SHA ctx scratch
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_TH]
	call	sha256_final
	; find the key_share in the ServerHello body
	lea	rsi,[r14+4+2+32]		; past msg header, version, random
	lea	rax,[r12+5+r13]			; message end
	movzx	ecx,byte [rsi]			; session id echo
	lea	rsi,[rsi+rcx+1]
	add	rsi,3				; cipher_suite (2), compression (1)
	lea	rdx,[rsi+2]
	cmp	rdx,rax
	ja	.bad
	movzx	ecx,word [rsi]			; extensions length
	rol	cx,8
	add	rsi,2
	lea	r15,[rsi+rcx]			; extensions end
	cmp	r15,rax
	ja	.bad
.ext:
	lea	rax,[rsi+4]
	cmp	rax,r15
	ja	.bad
	movzx	eax,word [rsi]			; ext type
	rol	ax,8
	movzx	ecx,word [rsi+2]		; ext length
	rol	cx,8
	add	rsi,4
	cmp	eax,51				; key_share
	je	.key_share
	add	rsi,rcx
	cmp	rsi,r15
	jb	.ext
	jmp	.bad				; no key_share
.key_share:
	; { group(2), key_length(2), key }
	movzx	eax,word [rsi]			; group
	rol	ax,8
	movzx	ecx,word [rsi+2]		; key length
	rol	cx,8
	add	rsi,4				; rsi = the server's public key
	cmp	dword [rbx+TC_KXLEN],0		; the key exchange ran on an earlier pass
	jne	.secret_done
	cmp	eax,0x11EC
	je	.hybrid
	cmp	eax,0x001D
	je	.x25519
	cmp	eax,0x0017
	jne	.bad
	; secp256r1: 65-byte key
	cmp	ecx,65
	jne	.bad
	lea	rdi,[rbx+TC_SHARED]
	mov	rdx,rsi
	lea	rsi,[rbx+TC_P256_SK]
	call	p256_ecdh
	test	eax,eax
	jz	.bad
	mov	dword [rbx+TC_KXLEN],32
	jmp	.secret_done
.hybrid:
	; X25519MLKEM768: the ML-KEM-768 ciphertext (1088), then the server's
	; x25519 key; the secret is ML-KEM's | x25519's
	cmp	ecx,MLKEM_CT + 32
	jne	.bad
	push	rsi
	lea	rdi,[rbx+TC_SH64]
	mov	rdx,rsi
	lea	rsi,[rbx+TC_MLDK]
	call	mlkem768_decaps
	pop	rdx
	add	rdx,MLKEM_CT
	lea	rdi,[rbx+TC_SH64+32]
	lea	rsi,[rbx+TC_X25519_SK]
	call	x25519
	lea	rdi,[rbx+TC_MLDK]		; the key pair has done its work
	xor	eax,eax
	mov	ecx,(MLKEM_DK + 64) / 8
	rep	stosq
	mov	rax,[rbx+TC_SH64+32]		; an all-zero x25519 secret: a small-order point
	or	rax,[rbx+TC_SH64+40]
	or	rax,[rbx+TC_SH64+48]
	or	rax,[rbx+TC_SH64+56]
	jz	.bad
	mov	dword [rbx+TC_KXLEN],64
	jmp	.secret_done
.x25519:
	cmp	ecx,32
	jne	.bad
	lea	rdi,[rbx+TC_SHARED]
	mov	rdx,rsi
	lea	rsi,[rbx+TC_X25519_SK]
	call	x25519
	mov	dword [rbx+TC_KXLEN],32
.secret_done:
	; handshake_secret = HKDF-Extract(derived_early, shared)
	lea	rdi,[rbx+TC_HS]
	lea	rsi,[tls13_derived_early]
	mov	edx,32
	lea	rcx,[rbx+TC_SHARED]
	mov	r8d,32
	cmp	dword [rbx+TC_KXLEN],64
	jne	@f
	lea	rcx,[rbx+TC_SH64]
	mov	r8d,64
@@:
	call	hkdf_extract
	; server and client handshake traffic secrets, the server key/IV
	tls_label [rbx+TC_SHT], 32, [rbx+TC_HS], lbl_s_hs, [rbx+TC_TH], 32
	tls_label [rbx+TC_CHT], 32, [rbx+TC_HS], lbl_c_hs, [rbx+TC_TH], 32
	tls_label [rbx+TC_SKEY], 16, [rbx+TC_SHT], lbl_key
	tls_label [rbx+TC_SIV], 12, [rbx+TC_SHT], lbl_iv
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_SKEY]
	call	gcm_init
	mov	qword [rbx+TC_SSEQ],0
	; decrypt every record after the ServerHello
	mov	r12,[rsp+TF_IN]
	movzx	eax,word [r12+3]
	rol	ax,8
	lea	r12,[r12+5+rax]			; past the ServerHello record
.record:
	mov	rax,[rsp+TF_END]
	sub	rax,r12
	cmp	rax,5
	jb	.done
	cmp	byte [r12],20			; ChangeCipherSpec: ignore
	je	.ccs
	cmp	byte [r12],23			; application_data (encrypted handshake)
	jne	.done
	movzx	r13d,word [r12+3]
	rol	r13w,8
	lea	rax,[r12+5+r13]
	cmp	rax,[rsp+TF_END]
	ja	.done
	cmp	r13d,17				; at least a tag + one byte
	jb	.done
	; nonce from SIV and the sequence
	lea	rdi,[rbx+TC_NONCE]
	lea	rsi,[rbx+TC_SIV]
	mov	rdx,[rbx+TC_SSEQ]
	call	tls_nonce
	inc	qword [rbx+TC_SSEQ]
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_NONCE]
	mov	rdx,r12				; aad = the 5-byte record header
	mov	ecx,5
	lea	r8,[r12+5]			; ciphertext
	lea	r9d,[r13-16]			; its length (payload - tag)
	call	gcm_open
	test	eax,eax
	jz	.bad
	; strip trailing zero padding and the content-type byte
	lea	rsi,[r12+5]
	lea	rdi,[rsi+r13-16-1]		; last plaintext byte
@@:
	cmp	rdi,rsi
	jb	.record_next
	cmp	byte [rdi],0
	jne	.got_type
	dec	rdi
	jmp	@b
.got_type:
	cmp	byte [rdi],22			; handshake content
	jne	.record_next			; (alert or app data: skip)
	mov	rcx,rdi
	sub	rcx,rsi				; handshake bytes in this record
	mov	rdi,[rsp+TF_OP]
	rep	movsb
	mov	[rsp+TF_OP],rdi
.record_next:
	lea	r12,[r12+5+r13]
	jmp	.record
.ccs:
	movzx	eax,word [r12+3]
	rol	ax,8
	lea	r12,[r12+5+rax]
	jmp	.record
.done:
	mov	rax,[rsp+TF_OP]
	sub	rax,[rsp+TF_OUT]
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,48
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; snapshot the running transcript (TC_SHA) hash into [rbx+TC_THX], using
; TC_GCM as scratch; leaves TC_SHA able to continue
macro tc_snapshot
	lea	rsi,[rbx+TC_SHA]
	lea	rdi,[rbx+TC_GCM]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_THX]
	call	sha256_final
end macro

; add [rsi, edx) to the transcript
macro tc_add
	lea	rdi,[rbx+TC_SHA]
	call	sha256_update
end macro

; rdi = tc, rsi = the decrypted server flight (handshake messages), edx =
; its length: verifies the CertificateVerify signature (over the transcript
; through Certificate, under the leaf key) and the server Finished (over
; the transcript through CertificateVerify, under the server finished key).
; eax = 1 when both verify, else 0. The transcript (TC_SHA, holding
; ClientHello || ServerHello) is extended through the server Finished.
tlsc_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12,rsi				; cursor
	lea	r13,[rsi+rdx]			; end
	; finished keys
	tls_label [rbx+TC_SFK], 32, [rbx+TC_SHT], lbl_finished
	tls_label [rbx+TC_CFK], 32, [rbx+TC_CHT], lbl_finished
	xor	r15d,r15d			; got-leaf flag
.msg:
	lea	rax,[r12+4]
	cmp	rax,r13
	ja	.bad
	mov	eax,[r12]			; type | u24 length (big endian)
	bswap	eax
	movzx	ecx,al				; (al = low byte of length after bswap)
	mov	edx,eax
	and	edx,0x00FFFFFF			; length
	shr	eax,24				; type
	lea	r14,[r12+4+rdx]			; message end
	cmp	r14,r13
	ja	.bad
	cmp	eax,11
	je	.cert
	cmp	eax,15
	je	.certverify
	cmp	eax,20
	je	.finished
	; EncryptedExtensions or anything else: just transcript it
	mov	rsi,r12
	mov	edx,r14d
	sub	edx,r12d
	tc_add
	jmp	.next
.cert:
	; Certificate: context(u8=0), certificate_list(u24){ cert(u24)+ext(u16) }
	lea	rsi,[r12+4]			; after handshake header
	movzx	eax,byte [rsi]			; certificate_request_context length
	lea	rsi,[rsi+rax+1]			; rsi = certificate_list length (u24)
	mov	eax,[rsi]
	bswap	eax
	shr	eax,8				; certificate_list length
	mov	[rbx+TC_CLISTLEN],eax
	lea	rcx,[rsi+3]
	mov	[rbx+TC_CLIST],rcx		; the CertificateEntry list
	mov	eax,[rsi+3]			; the first cert's u24 length
	bswap	eax
	shr	eax,8				; leaf cert DER length
	lea	rsi,[rsi+6]			; the leaf DER
	mov	[rbx+TC_LEAF],rsi
	mov	[rbx+TC_LEAFLEN],eax
	mov	ecx,eax
	push	rsi
	push	rcx
	lea	rdi,[rbx+TC_LEAFKEY]
	mov	edx,ecx
	call	cert_pubkey
	pop	rcx
	pop	rsi
	test	eax,eax
	jz	.bad
	mov	r15d,1
	; transcript the whole Certificate message
	mov	rsi,r12
	mov	edx,r14d
	sub	edx,r12d
	tc_add
	jmp	.next
.certverify:
	test	r15d,r15d
	jz	.bad				; no certificate seen
	; TH through Certificate -> TC_THX
	tc_snapshot
	; signed content = 64*0x20 | "...CertificateVerify" | 0x00 | TH
	lea	rdi,[rbx+TC_CV]
	lea	rsi,[tls13_cv_prefix]
	mov	ecx,TLS13_CV_PREFIX
	rep	movsb
	lea	rsi,[rbx+TC_THX]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbx+TC_DIG]
	lea	rsi,[rbx+TC_CV]
	mov	edx,TLS13_CV_PREFIX + 32
	call	sha256
	; CV body: SignatureScheme(2), signature length(2), signature
	lea	rsi,[r12+4]
	cmp	word [rsi],0x0304		; ecdsa_secp256r1_sha256 (0x0403)
	je	.cv_ecdsa
	cmp	word [rsi],0x0408		; rsa_pss_rsae_sha256 (0x0804)
	je	.cv_rsa
	jmp	.bad
.cv_ecdsa:
	cmp	dword [rbx+TC_LEAFKEY+PK_TYPE],1
	jne	.bad
	add	rsi,4				; past scheme + length
	mov	rdx,r14
	call	der_read			; SEQUENCE { r, s }
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; INTEGER r
	jc	.bad
	lea	rdi,[rbx+TC_CV]			; r||s scratch (TC_CV is free now)
	push	r8
	call	der_int_32
	pop	r8
	jc	.bad
	mov	rsi,r8
	call	der_read			; INTEGER s
	jc	.bad
	lea	rdi,[rbx+TC_CV+32]
	call	der_int_32
	jc	.bad
	lea	rdi,[rbx+TC_LEAFKEY+PK_DATA]	; the leaf EC point
	lea	rsi,[rbx+TC_DIG]
	lea	rdx,[rbx+TC_CV]
	lea	rcx,[rbx+TC_CV+32]
	call	p256_verify
	test	eax,eax
	jz	.bad
	jmp	.cv_ok
.cv_rsa:
	cmp	dword [rbx+TC_LEAFKEY+PK_TYPE],2
	jne	.bad
	lea	rdx,[rsi+4]			; the raw RSA-PSS signature
	lea	rdi,[rbx+TC_LEAFKEY+PK_DATA]	; modulus
	mov	esi,[rbx+TC_LEAFKEY+PK_NLEN]
	mov	ecx,[rbx+TC_LEAFKEY+PK_E]
	lea	r8,[rbx+TC_DIG]
	call	rsa_pss_verify
	test	eax,eax
	jz	.bad
.cv_ok:
	; transcript the CertificateVerify message
	mov	rsi,r12
	mov	edx,r14d
	sub	edx,r12d
	tc_add
	jmp	.next
.finished:
	; server Finished = HMAC(SFK, TH through CertificateVerify)
	tc_snapshot
	lea	rdi,[rbx+TC_FIN]
	lea	rsi,[rbx+TC_SFK]
	mov	edx,32
	lea	rcx,[rbx+TC_THX]
	mov	r8d,32
	call	hmac_sha256
	lea	rdi,[rbx+TC_FIN]		; compare with the message body (32 bytes)
	lea	rsi,[r12+4]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.bad
	mov	rsi,r12				; transcript the server Finished
	mov	edx,r14d
	sub	edx,r12d
	tc_add
	jmp	.done
.next:
	mov	r12,r14
	jmp	.msg
.done:
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = out: completes the handshake. Writes the client
; Finished as one encrypted record to out (eax = its length), and derives
; the application traffic keys, leaving the client (TX) and server (RX)
; application GCM contexts in tc, sequence numbers zero. Must be called
; right after tlsc_verify (the transcript is through the server Finished).
tlsc_finish:
	push	rbx
	push	r12
	push	r13
	sub	rsp,8
	mov	rbx,rdi
	mov	r13,rsi				; out
	; TH through the server Finished
	tc_snapshot				; -> TC_THX
	; client Finished = HMAC(client finished key, TH)
	lea	rdi,[rbx+TC_FIN]
	lea	rsi,[rbx+TC_CFK]
	mov	edx,32
	lea	rcx,[rbx+TC_THX]
	mov	r8d,32
	call	hmac_sha256
	; the inner plaintext: 20 00 00 14 | HMAC(32) | content type 22
	mov	dword [r13+5],0x20000014		; handshake 0x14, u24 length 32
	lea	rdi,[r13+5+4]
	lea	rsi,[rbx+TC_FIN]
	mov	ecx,32
	rep	movsb
	mov	byte [r13+5+36],22		; inner content type
	; client handshake key/IV from the client handshake traffic secret
	tls_label [rbx+TC_CAPK], 16, [rbx+TC_CHT], lbl_key
	tls_label [rbx+TC_CAPIV], 12, [rbx+TC_CHT], lbl_iv
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_CAPK]
	call	gcm_init
	; record header: application_data, length = 37 + 16 tag
	mov	dword [r13],0x00030317
	mov	word [r13+3],0x3500		; length 0x0035 = 53
	lea	rdi,[rbx+TC_NONCE2]		; nonce (seq 0)
	lea	rsi,[rbx+TC_CAPIV]
	xor	edx,edx
	call	tls_nonce
	lea	rdi,[rbx+TC_GCM]
	lea	rsi,[rbx+TC_NONCE2]
	mov	rdx,r13
	mov	ecx,5
	lea	r8,[r13+5]
	mov	r9d,37
	call	gcm_seal
	mov	r12d,58				; 5 header + 37 plaintext + 16 tag
	; application keys: master secret, then c/s ap traffic
	tls_label [rbx+TC_TMP], 32, [rbx+TC_HS], lbl_derived, [sha256_empty], 32
	lea	rdi,[rbx+TC_MS]
	lea	rsi,[rbx+TC_TMP]
	mov	edx,32
	lea	rcx,[tls13_zero32]
	mov	r8d,32
	call	hkdf_extract
	tls_label [rbx+TC_TMP], 32, [rbx+TC_MS], lbl_c_ap, [rbx+TC_THX], 32
	tls_label [rbx+TC_CAPK], 16, [rbx+TC_TMP], lbl_key
	tls_label [rbx+TC_CAPIV], 12, [rbx+TC_TMP], lbl_iv
	tls_label [rbx+TC_TMP], 32, [rbx+TC_MS], lbl_s_ap, [rbx+TC_THX], 32
	tls_label [rbx+TC_SAPK], 16, [rbx+TC_TMP], lbl_key
	tls_label [rbx+TC_SAPIV], 12, [rbx+TC_TMP], lbl_iv
	lea	rdi,[rbx+TC_TXGCM]
	lea	rsi,[rbx+TC_CAPK]
	call	gcm_init
	lea	rdi,[rbx+TC_RXGCM]
	lea	rsi,[rbx+TC_SAPK]
	call	gcm_init
	mov	qword [rbx+TC_TXSEQ],0
	mov	qword [rbx+TC_RXSEQ],0
	mov	eax,r12d
	add	rsp,8
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = out, rdx = data, ecx = data length: seals the data as one
; application_data record (content type 23) in out. eax = record length.
tlsc_seal:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r13,rsi				; out
	mov	r14,rdx				; data
	mov	r12d,ecx			; length
	lea	rdi,[r13+5]			; plaintext = data | content type 23
	mov	rsi,r14
	mov	ecx,r12d
	rep	movsb
	mov	byte [r13+5+r12],23
	lea	eax,[r12+17]			; + type + tag
	mov	dword [r13],0x00030317
	rol	ax,8
	mov	[r13+3],ax
	lea	rdi,[rbx+TC_NONCE2]
	lea	rsi,[rbx+TC_CAPIV]
	mov	rdx,[rbx+TC_TXSEQ]
	call	tls_nonce
	inc	qword [rbx+TC_TXSEQ]
	lea	rdi,[rbx+TC_TXGCM]
	lea	rsi,[rbx+TC_NONCE2]
	mov	rdx,r13
	mov	ecx,5
	lea	r8,[r13+5]
	lea	r9d,[r12+1]
	call	gcm_seal
	lea	eax,[r12+22]			; 5 + data + 1 + 16
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = record (a full TLS record): opens it in place with the
; server application key. eax = 1 and rsi = plaintext, ecx = its length,
; r8d = content type on success; eax = 0 on a bad tag or short record.
tlsc_open:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	r12,rsi				; record
	movzx	r13d,word [r12+3]
	rol	r13w,8
	cmp	r13d,17
	jb	.bad
	lea	rdi,[rbx+TC_NONCE2]
	lea	rsi,[rbx+TC_SAPIV]
	mov	rdx,[rbx+TC_RXSEQ]
	call	tls_nonce
	inc	qword [rbx+TC_RXSEQ]
	lea	rdi,[rbx+TC_RXGCM]
	lea	rsi,[rbx+TC_NONCE2]
	mov	rdx,r12
	mov	ecx,5
	lea	r8,[r12+5]
	lea	r9d,[r13-16]
	call	gcm_open
	test	eax,eax
	jz	.bad
	; strip padding and the content type
	lea	rsi,[r12+5]
	lea	rdi,[rsi+r13-16-1]
.unpad:
	cmp	rdi,rsi
	jb	.bad
	movzx	r8d,byte [rdi]
	test	r8d,r8d
	jnz	@f
	dec	rdi
	jmp	.unpad
@@:
	mov	rcx,rdi
	sub	rcx,rsi
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = TX crypto_info out, rdx = RX crypto_info out: fills two
; struct tls12_crypto_info_aes_gcm_128 (40 bytes each) from the application
; keys for the kernel's TLS, both at record sequence 0. TX seals what the
; client sends (the client application key); RX opens what the server sends
; (the server application key). Layout matches the server side in tls.inc.
tlsc_ktls_info:
	mov	r9,rdi				; tc
	lea	rax,[r9+TC_CAPK]		; client key(16) then IV(12)
	mov	rcx,rsi
	xor	r8d,r8d
	call	.fill
	lea	rax,[r9+TC_SAPK]		; server key(16) then IV(12)
	mov	rcx,rdx
	xor	r8d,r8d
	call	.fill
	ret
; rax = key(16)+IV(12), rcx = out(40), r8 = the next record sequence.
; Preserves r9, rsi, rdx for the caller.
.fill:
	mov	dword [rcx],0x00330304		; TLS 1.3, TLS_CIPHER_AES_GCM_128
	mov	r10,[rax+16+4]			; iv: the IV's last 8 bytes
	mov	[rcx+4],r10
	movdqu	xmm0,[rax]			; key: 16 bytes
	movdqu	[rcx+12],xmm0
	mov	r10d,[rax+16]			; salt: the IV's first 4 bytes
	mov	[rcx+28],r10d
	bswap	r8
	mov	[rcx+32],r8			; rec_seq, big endian
	ret

; rsi = decrypted handshake messages, edx = their length: eax = 1 when the
; bytes end exactly on a complete Finished (handshake type 20) -- the whole
; server flight is present -- and 0 when more is still needed. Lets the
; engine drive tlsc_server_flight incrementally (restoring the post-
; ClientHello transcript before each call makes that call idempotent).
tlsc_flight_complete:
	xor	ecx,ecx				; offset
.msg:
	lea	r10d,[rcx+4]
	cmp	r10d,edx
	ja	.no				; not even a message header
	movzx	r8d,byte [rsi+rcx]		; handshake type
	movzx	eax,byte [rsi+rcx+1]		; u24 body length
	shl	eax,16
	movzx	r9d,byte [rsi+rcx+2]
	shl	r9d,8
	or	eax,r9d
	movzx	r9d,byte [rsi+rcx+3]
	or	eax,r9d
	lea	ecx,[rcx+4+rax]			; end of this message
	cmp	ecx,edx
	ja	.no				; its body is not all here yet
	cmp	r8d,20				; Finished
	jne	.next
	cmp	ecx,edx
	je	.yes				; the last, complete message
.next:
	cmp	ecx,edx
	jb	.msg
	jmp	.no
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; ============================ TLS 1.2 client ============================
; A backend that has no TLS 1.3 picks a 1.2 ECDHE suite. The ClientHello
; (tlsc_client_hello) already offered it; these complete the handshake.

; rdi = tc, rsi = the server flight (ServerHello, Certificate, ServerKey-
; Exchange, ServerHelloDone, as plaintext records), edx = its length,
; rcx = out: verifies the ServerKeyExchange signature under the leaf key,
; derives the 1.2 keys, and writes the client flight (ClientKeyExchange,
; ChangeCipherSpec, the encrypted Finished) to out. eax = the client flight
; length, or 0. Sets TC_LEAF/TC_LEAFLEN and TC_CLIST/TC_CLISTLEN for the
; caller's chain verification (as the 1.3 path does).
tlsc12_flight:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,128
	mov	rbx,rdi				; tc
	mov	[rsp+0],rcx			; out base
	mov	r12,rsi				; record cursor
	lea	r13,[rsi+rdx]			; flight end
	xor	r15d,r15d			; flags: 1 SH, 2 cert, 4 SKE, 8 SHD
.rec:
	lea	rax,[r12+5]
	cmp	rax,r13
	ja	.parsed
	cmp	byte [r12],22			; handshake record
	jne	.bad
	movzx	ecx,word [r12+3]
	rol	cx,8
	lea	r14,[r12+5]			; message cursor
	lea	rax,[r14+rcx]			; payload end
	cmp	rax,r13
	ja	.bad
	mov	r12,rax				; next record
	mov	[rsp+16],rax			; payload end
.msg:
	mov	rax,[rsp+16]
	lea	rcx,[r14+4]
	cmp	rcx,rax
	ja	.rec				; header spills: next record
	movzx	ecx,byte [r14+1]		; u24 body length
	shl	ecx,16
	movzx	edx,byte [r14+2]
	shl	edx,8
	or	ecx,edx
	movzx	edx,byte [r14+3]
	or	ecx,edx
	lea	rdx,[r14+4+rcx]			; message end
	cmp	rdx,rax
	ja	.bad
	mov	[rsp+24],rdx			; message end
	lea	edx,[rcx+4]			; transcript the whole message
	mov	rsi,r14
	tc_add
	movzx	eax,byte [r14]
	cmp	al,2
	je	.sh
	cmp	al,11
	je	.cert
	cmp	al,12
	je	.ske
	cmp	al,14
	jne	.msg_next
	or	r15d,8
.msg_next:
	mov	r14,[rsp+24]
	cmp	r14,[rsp+16]
	jb	.msg
	jmp	.rec
.sh:
	lea	rsi,[r14+4+2]			; server random (after version)
	lea	rdi,[rbx+TC12_SRAND]
	mov	ecx,32
	rep	movsb
	or	r15d,1
	jmp	.msg_next
.cert:
	lea	rsi,[r14+4]			; certificate_list length (u24)
	mov	eax,[rsi]
	bswap	eax
	shr	eax,8
	mov	[rbx+TC_CLISTLEN],eax
	lea	rcx,[rsi+3]
	mov	[rbx+TC_CLIST],rcx
	mov	eax,[rsi+3]			; first cert length (u24)
	bswap	eax
	shr	eax,8
	lea	rsi,[rsi+6]			; leaf DER
	mov	[rbx+TC_LEAF],rsi
	mov	[rbx+TC_LEAFLEN],eax
	mov	edx,eax
	lea	rdi,[rbx+TC_LEAFKEY]
	call	cert_pubkey			; rsi = leaf DER, edx = length
	test	eax,eax
	jz	.bad
	or	r15d,2
	jmp	.msg_next
.ske:
	lea	rsi,[r14+4]
	mov	[rsp+32],rsi			; params (ECDHParams) start
	cmp	byte [rsi],3			; named_curve
	jne	.bad
	movzx	eax,word [rsi+1]		; named_curve
	rol	ax,8
	mov	[rsp+40],eax
	movzx	ecx,byte [rsi+3]		; public key length
	mov	[rsp+56],ecx
	lea	rax,[rsi+4]
	mov	[rsp+48],rax			; server public key
	lea	edx,[rcx+4]
	mov	[rsp+64],edx			; params length = 4 + key
	lea	rsi,[rsi+4+rcx]			; SignatureAndHashAlgorithm
	movzx	eax,word [rsi]
	mov	[rsp+88],eax
	movzx	ecx,word [rsi+2]		; signature length
	rol	cx,8
	mov	[rsp+80],ecx
	lea	rax,[rsi+4]
	mov	[rsp+72],rax			; signature
	or	r15d,4
	jmp	.msg_next
.parsed:
	cmp	r15d,15
	jne	.bad
	; signed content = client_random | server_random | ECDHParams -> TC_CV
	lea	rdi,[rbx+TC_CV]
	lea	rsi,[rbx+TC_RANDOM]
	mov	ecx,32
	rep	movsb
	lea	rsi,[rbx+TC12_SRAND]
	mov	ecx,32
	rep	movsb
	mov	rsi,[rsp+32]
	mov	ecx,[rsp+64]
	rep	movsb
	lea	rdi,[rbx+TC_DIG]		; its SHA-256
	lea	rsi,[rbx+TC_CV]
	mov	edx,[rsp+64]
	add	edx,64
	call	sha256
	mov	eax,[rsp+88]			; sigalg (stored little-endian word)
	cmp	eax,0x0304			; ecdsa_secp256r1_sha256
	je	.v_ecdsa
	cmp	eax,0x0104			; rsa_pkcs1_sha256
	je	.v_pkcs1
	cmp	eax,0x0408			; rsa_pss_rsae_sha256
	je	.v_pss
	jmp	.bad
.v_ecdsa:
	cmp	dword [rbx+TC_LEAFKEY+PK_TYPE],1
	jne	.bad
	mov	rsi,[rsp+72]
	mov	rdx,[rsp+72]
	add	rdx,[rsp+80]			; signature end
	call	der_read			; SEQUENCE
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; INTEGER r
	jc	.bad
	lea	rdi,[rbx+TC_CV]			; r || s (TC_CV is free; digest is in TC_DIG)
	push	r8
	call	der_int_32
	pop	r8
	jc	.bad
	mov	rsi,r8
	call	der_read			; INTEGER s
	jc	.bad
	lea	rdi,[rbx+TC_CV+32]
	call	der_int_32
	jc	.bad
	lea	rdi,[rbx+TC_LEAFKEY+PK_DATA]
	lea	rsi,[rbx+TC_DIG]
	lea	rdx,[rbx+TC_CV]
	lea	rcx,[rbx+TC_CV+32]
	call	p256_verify
	test	eax,eax
	jz	.bad
	jmp	.ecdh
.v_pkcs1:
	cmp	dword [rbx+TC_LEAFKEY+PK_TYPE],2
	jne	.bad
	lea	rdi,[rbx+TC_LEAFKEY+PK_DATA]
	mov	esi,[rbx+TC_LEAFKEY+PK_NLEN]
	mov	rdx,[rsp+72]
	mov	ecx,[rbx+TC_LEAFKEY+PK_E]
	lea	r8,[rbx+TC_DIG]
	call	rsa_pkcs1_verify
	test	eax,eax
	jz	.bad
	jmp	.ecdh
.v_pss:
	cmp	dword [rbx+TC_LEAFKEY+PK_TYPE],2
	jne	.bad
	lea	rdi,[rbx+TC_LEAFKEY+PK_DATA]
	mov	esi,[rbx+TC_LEAFKEY+PK_NLEN]
	mov	rdx,[rsp+72]
	mov	ecx,[rbx+TC_LEAFKEY+PK_E]
	lea	r8,[rbx+TC_DIG]
	call	rsa_pss_verify
	test	eax,eax
	jz	.bad
.ecdh:
	mov	eax,[rsp+40]			; named_curve
	cmp	eax,0x0017			; secp256r1
	je	.ecdh_p256
	cmp	eax,0x001D			; x25519
	jne	.bad
	cmp	dword [rsp+56],32
	jne	.bad
	lea	rdi,[rbx+TC_SHARED]
	lea	rsi,[rbx+TC_X25519_SK]
	mov	rdx,[rsp+48]
	call	x25519
	jmp	.keys
.ecdh_p256:
	cmp	dword [rsp+56],65
	jne	.bad
	lea	rdi,[rbx+TC_SHARED]
	lea	rsi,[rbx+TC_P256_SK]
	mov	rdx,[rsp+48]
	call	p256_ecdh
	test	eax,eax
	jz	.bad
.keys:
	lea	rdi,[rbx+TC12_MASTER]		; master secret
	lea	rsi,[rbx+TC_SHARED]
	mov	edx,32
	lea	rcx,[rbx+TC_RANDOM]
	lea	r8,[rbx+TC12_SRAND]
	call	tls12_master
	lea	rdi,[rbx+TC12_CWK]		; key block
	mov	esi,40
	lea	rdx,[rbx+TC12_MASTER]
	lea	rcx,[rbx+TC12_SRAND]
	lea	r8,[rbx+TC_RANDOM]
	call	tls12_key_block
	lea	rdi,[rbx+TC12_TX]		; client-write / server-write GCM
	lea	rsi,[rbx+TC12_CWK]
	call	gcm_init
	lea	rdi,[rbx+TC12_RX]
	lea	rsi,[rbx+TC12_SWK]
	call	gcm_init
	; ---- ClientKeyExchange ----
	mov	r14,[rsp+0]			; out base
	mov	byte [r14],22			; record: handshake
	mov	word [r14+1],0x0303
	mov	byte [r14+5],16			; client_key_exchange
	mov	eax,[rsp+40]
	cmp	eax,0x0017
	je	.cke_p256
	mov	byte [r14+9],32			; ECPoint: u8 length + point (x25519)
	lea	rdi,[r14+10]
	lea	rsi,[rbx+TC_X25519_PK]
	mov	ecx,32
	rep	movsb
	mov	ecx,33
	jmp	.cke_len
.cke_p256:
	mov	byte [r14+9],65
	lea	rdi,[r14+10]
	lea	rsi,[rbx+TC_P256_PK]
	mov	ecx,65
	rep	movsb
	mov	ecx,66
.cke_len:
	mov	byte [r14+6],0			; message u24 length
	mov	byte [r14+7],0
	mov	[r14+8],cl
	lea	eax,[rcx+4]			; CKE message length
	mov	edx,eax
	rol	dx,8
	mov	[r14+3],dx			; record length
	push	rax
	lea	rsi,[r14+5]			; transcript the CKE message
	mov	edx,eax
	tc_add
	pop	rax
	lea	r14,[r14+5+rax]			; past the CKE record
	; ---- Finished (client finished) ----
	tc_snapshot				; TC_THX = Hash(ClientHello..CKE)
	mov	dword [rbx+TC_FIN],0x0c000014	; Finished message header
	lea	rdi,[rbx+TC_FIN+4]
	lea	rsi,[rbx+TC12_MASTER]
	lea	rdx,[tls12_lbl_cfin]
	mov	ecx,15
	lea	r8,[rbx+TC_THX]
	call	tls12_verify_data
	lea	rsi,[rbx+TC_FIN]		; add the Finished message to the transcript
	mov	edx,16
	tc_add
	mov	byte [r14],20			; ChangeCipherSpec
	mov	word [r14+1],0x0303
	mov	word [r14+3],0x0100
	mov	byte [r14+5],1
	add	r14,6
	mov	byte [r14],22			; the encrypted Finished record
	mov	word [r14+1],0x0303
	lea	rdi,[r14+5]
	lea	rsi,[rbx+TC12_TX]
	lea	rdx,[rbx+TC12_CIV]
	xor	rcx,rcx				; client record sequence 0
	mov	r8d,22
	lea	r9,[rbx+TC_FIN]
	mov	r10d,16
	call	tls12_seal
	mov	edx,eax
	rol	dx,8
	mov	[r14+3],dx
	lea	r14,[r14+5+rax]
	mov	rax,r14
	sub	rax,[rsp+0]			; client flight length
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,128
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = the server's ChangeCipherSpec + encrypted Finished,
; edx = length: opens and verifies the server Finished. eax = 1 / 0.
tlsc12_server_finished:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r12,rsi
	lea	r13,[rsi+rdx]
	xor	r14d,r14d			; ChangeCipherSpec seen
.rec:
	lea	rax,[r12+5]
	cmp	rax,r13
	ja	.bad
	movzx	ecx,word [r12+3]		; record payload length
	rol	cx,8
	cmp	byte [r12],20			; ChangeCipherSpec
	jne	@f
	mov	r14d,1
	lea	r12,[r12+5+rcx]
	jmp	.rec
@@:
	cmp	byte [r12],22			; handshake
	jne	.bad
	test	r14d,r14d
	jnz	.fin
	; a plaintext handshake message before the CCS (a NewSessionTicket):
	; fold it into the transcript (RFC 5077: the server Finished covers it)
	lea	rsi,[r12+5]
	mov	edx,ecx
	lea	r14,[r12+5+rcx]			; keep across tc_add
	tc_add
	mov	r12,r14
	xor	r14d,r14d
	jmp	.rec
.fin:
	lea	rdi,[r12+5]			; the encrypted Finished, opened in place
	mov	esi,ecx
	lea	rdx,[rbx+TC12_RX]
	lea	rcx,[rbx+TC12_SIV]
	xor	r8,r8				; server record sequence 0
	mov	r9d,22
	call	tls12_open
	cmp	eax,16
	jne	.bad
	cmp	dword [r12+5+8],0x0c000014	; Finished header (type 20, length 12)
	jne	.bad
	tc_snapshot				; TC_THX = Hash through the client Finished
	lea	rdi,[rbx+TC_FIN]
	lea	rsi,[rbx+TC12_MASTER]
	lea	rdx,[tls12_lbl_sfin]
	mov	ecx,15
	lea	r8,[rbx+TC_THX]
	call	tls12_verify_data
	lea	rdi,[rbx+TC_FIN]
	lea	rsi,[r12+5+8+4]			; the received verify_data
	mov	edx,12
	call	ct_equal
	test	eax,eax
	jz	.bad
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tc, rsi = TX crypto_info out (40), rdx = RX crypto_info out (40):
; fills two struct tls12_crypto_info_aes_gcm_128 for kTLS 1.2, TX from the
; client write key/IV and RX from the server write key/IV, both at record
; sequence 1 (after the Finished exchange).
tlsc12_ktls_info:
	mov	dword [rsi],0x00330303
	mov	qword [rsi+4],0
	mov	byte [rsi+11],1
	movdqu	xmm0,[rdi+TC12_CWK]
	movdqu	[rsi+12],xmm0
	mov	eax,[rdi+TC12_CIV]
	mov	[rsi+28],eax
	mov	qword [rsi+32],0
	mov	byte [rsi+39],1
	mov	dword [rdx],0x00330303
	mov	qword [rdx+4],0
	mov	byte [rdx+11],1
	movdqu	xmm0,[rdi+TC12_SWK]
	movdqu	[rdx+12],xmm0
	mov	eax,[rdi+TC12_SIV]
	mov	[rdx+28],eax
	mov	qword [rdx+32],0
	mov	byte [rdx+39],1
	ret

; rsi = the server flight (its first record is the ServerHello), edx = its
; length: eax = 1 when the server negotiated TLS 1.2 (no supported_versions
; naming 0x0304 in the ServerHello), 0 when it chose TLS 1.3. A short or
; malformed ServerHello reads as TLS 1.3 (the existing path rejects it).
tlsc_is_tls12:
	lea	r9,[rsi+rdx]			; flight end
	lea	rax,[rsi+5]
	cmp	rax,r9
	ja	.v13
	cmp	byte [rsi],22			; handshake record
	jne	.v13
	movzx	ecx,word [rsi+3]
	rol	cx,8
	lea	r8,[rsi+5+rcx]			; record end
	cmp	r8,r9
	ja	.v13
	lea	rsi,[rsi+5]			; ServerHello message
	cmp	byte [rsi],2
	jne	.v13
	lea	rsi,[rsi+4+2+32]		; past header, version, random
	movzx	eax,byte [rsi]			; session id echo
	lea	rsi,[rsi+rax+1]
	add	rsi,3				; cipher (2), compression (1)
	lea	rax,[rsi+2]
	cmp	rax,r8
	ja	.v12				; no extensions block: TLS 1.2
	movzx	ecx,word [rsi]			; extensions length
	rol	cx,8
	add	rsi,2
	lea	r8,[rsi+rcx]			; extensions end (bounded by the record)
.ext:
	lea	rax,[rsi+4]
	cmp	rax,r8
	ja	.v12
	movzx	eax,word [rsi]			; ext type
	rol	ax,8
	movzx	ecx,word [rsi+2]		; ext length
	rol	cx,8
	add	rsi,4
	cmp	eax,43				; supported_versions
	jne	@f
	cmp	word [rsi],0x0403		; 0x0304 on the wire -> TLS 1.3
	je	.v13
@@:
	add	rsi,rcx
	cmp	rsi,r8
	jb	.ext
.v12:
	mov	eax,1
	ret
.v13:
	xor	eax,eax
	ret

; rdi = out, rsi = a TLS 1.2 certificate_list (u24 cert | ... with no
; extensions), edx = its length: rewrites it in the 1.3 framing that
; cert_chain_verify parses (u24 cert | u16 0 extensions) into out. eax = the
; rewritten length.
tlsc12_reframe_chain:
	mov	r10,rdi				; out start
	lea	r9,[rsi+rdx]			; list end
.e:
	lea	rax,[rsi+3]
	cmp	rax,r9
	ja	.done
	mov	eax,[rsi]
	bswap	eax
	shr	eax,8				; certificate length
	lea	ecx,[rax+3]			; u24 length prefix + the DER
	lea	rax,[rsi+rcx]
	cmp	rax,r9
	ja	.done
	rep	movsb				; copy; rsi -> next entry, rdi -> after cert
	mov	word [rdi],0			; u16 extensions = 0
	add	rdi,2
	cmp	rsi,r9
	jb	.e
.done:
	mov	rax,rdi
	sub	rax,r10
	ret
