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
	mov	byte [r12],22
	mov	word [r12+1],0x0103
	rol	ax,8
	mov	[r12+3],ax
	mov	r13d,edi			; save the write end (sha clobbers rdi)
	; transcript: the handshake message (record payload)
	lea	rdi,[rbx+TC_SHA]
	call	sha256_init
	lea	rdi,[rbx+TC_SHA]
	lea	rsi,[r12+5]
	mov	edx,eax
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
