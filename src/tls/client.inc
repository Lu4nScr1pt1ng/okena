; TLS 1.3 client handshake, for TLS towards upstreams (RFC 8446 as the
; client): TLS_AES_128_GCM_SHA256, x25519 and secp256r1 key shares,
; ecdsa_secp256r1_sha256 signatures. The crypto is the same as the server
; side (src/tls/handshake.inc); here okena opens the connection.
;
; This first piece generates the ClientHello and keeps the ephemeral keys
; and the transcript in a TC block; the rest (ServerHello, the server's
; flight, verification, Finished) follows.
;
;   tlsc_client_hello(rdi ts, rsi out, rdx sni, ecx sni length): the
;       ClientHello record is written to out (eax = its length), its
;       handshake bytes added to the transcript, the ephemeral x25519 and
;       P-256 private keys and the client random kept in ts. out needs
;       room for ~400 bytes plus the SNI.

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
	ch_lit 0x00,0x02,0x13,0x01		; cipher_suites: TLS_AES_128_GCM_SHA256
	ch_lit 0x01,0x00			; compression: null
	; extensions: a u16 length, filled at the end
	mov	r8,rdi				; extensions length slot
	add	rdi,2
	; supported_versions (43): TLS 1.3
	ch_lit 0x00,0x2B,0x00,0x03,0x02,0x03,0x04
	; supported_groups (10): x25519, secp256r1
	ch_lit 0x00,0x0A,0x00,0x06,0x00,0x04,0x00,0x1D,0x00,0x17
	; signature_algorithms (13): ecdsa_secp256r1_sha256
	ch_lit 0x00,0x0D,0x00,0x04,0x00,0x02,0x04,0x03
	; key_share (51): x25519 (32) and secp256r1 (65)
	ch_lit 0x00,0x33,0x00,0x6B,0x00,0x69
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
TC_GCM		:= TC_TH + 32
TC_FULL		:= TC_GCM + GCM_SIZE

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
	jmp	.secret_done
.x25519:
	cmp	ecx,32
	jne	.bad
	lea	rdi,[rbx+TC_SHARED]
	mov	rdx,rsi
	lea	rsi,[rbx+TC_X25519_SK]
	call	x25519
.secret_done:
	; handshake_secret = HKDF-Extract(derived_early, shared)
	lea	rdi,[rbx+TC_HS]
	lea	rsi,[tls13_derived_early]
	mov	edx,32
	lea	rcx,[rbx+TC_SHARED]
	mov	r8d,32
	call	hkdf_extract
	; server handshake traffic secret, key, IV
	tls_label [rbx+TC_SHT], 32, [rbx+TC_HS], lbl_s_hs, [rbx+TC_TH], 32
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
