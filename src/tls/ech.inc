; Encrypted Client Hello (draft-ietf-tls-esni, version 0xfe0d), TLS 1.3 server:
; `okena { ech PUBLIC_NAME KEYFILE... }`.
;
; A client that has okena's ECHConfigList (from the DNS HTTPS record, `okena ech
; print` writes it) sends a ClientHelloOuter naming PUBLIC_NAME, and in its
; encrypted_client_hello extension the real ClientHello, sealed with HPKE
; (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) to one of the keys.
; okena opens it, rebuilds the ClientHelloInner (its ech_outer_extensions taken
; from the outer one), and the handshake goes on with that: its name chooses the
; certificate, it is in the transcript, and the ServerHello's random ends with
; the accept confirmation. One it cannot open (another key, a GREASE one, a
; config_id not known) goes on with the outer one, and EncryptedExtensions
; carries retry_configs: the client, seeing the certificate of PUBLIC_NAME, takes
; the new keys and tries again.
;
; The keys are X25519 private keys in PEM (PKCS #8: `openssl genpkey -algorithm
; X25519`, or `okena ech new FILE`); the first is the one published, the others
; still opened (a key being retired). Not here: ECH after a HelloRetryRequest
; (such a handshake is refused: browsers send an x25519 share at once).

ECH_MAX		:= 4
ECC_SK		:= 0			; the private key (32)
ECC_PK		:= 32			; the public key (32)
ECC_ID		:= 64			; d: config_id
ECC_CFGLEN	:= 68			; d
ECC_CFG		:= 72			; the ECHConfig, as written (version, length, contents)
ECC_CFG_MAX	:= 512
ECC_SIZE		:= ECC_CFG + ECC_CFG_MAX
ECH_LIST_MAX	:= 2 + ECH_MAX * ECC_CFG_MAX
assert CH_MAX * 3 <= H_TLS_ROOM

bss
	align 8
	g_plan_echn	dd ?				; keys
	g_plan_echlen	dd ?				; the ECHConfigList's length (its own 2 bytes in)
	g_plan_ech	rb ECC_SIZE * ECH_MAX
	g_plan_echlist	rb ECH_LIST_MAX
	; the HPKE context of the hello being opened
	g_eh_dh		rb 32
	g_eh_prk	rb 32
	g_eh_shared	rb 32
	g_eh_secret	rb 32
	g_eh_key	rb 16
	g_eh_nonce	rb 16
	g_eh_ctx	rb 65			; mode | psk_id_hash | info_hash
	align 8
	g_eh_gcm	rb GCM_SIZE
	g_eh_buf	rb 2048			; a labeled extract's or expand's input (info at +1024)
	g_eh_cfg	dq ?			; the config it was sealed to
	g_eh_payload	dq ?
	g_eh_plen	dd ?
	g_eh_alen	dd ?
	g_eh_oexts	dq ?			; the outer hello's extensions (their length first)
	g_eh_ocur	dq ?
	g_eh_inner	dd ?
	g_eh_second	dd ?			; the hello after a HelloRetryRequest
	g_eh_cfgid	dd ?
end bss

rodata
	eh_v1		db 'HPKE-v1'
	eh_kem		db 'KEM',0x00,0x20
	eh_suite	db 'HPKE',0x00,0x20,0x00,0x01,0x00,0x01
	eh_x25519_der	db 0x30,0x2E,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2B,0x65,0x6E,0x04,0x22,0x04,0x20
	lbl_ech_accept	db 'ech accept confirmation',0
end rodata

; ------------------------------------------------------------- the plan

; rbx = the `ech` node (okena block): PUBLIC_NAME KEYFILE...
compile_ech:
	push	r12
	push	r13
	push	r14
	mov	r12,[rbx+N_ARGS]
	mov	r13d,[rbx+N_ARGC]
	cmp	r13d,2
	jb	plan_bad_ech
	cmp	r13d,ECH_MAX + 1
	ja	plan_bad_ech
	; the public name: a host name (the outer ClientHello's SNI)
	mov	rcx,[r12+A_VAL]
	mov	edx,[r12+A_VLEN]
	cmp	edx,200
	ja	plan_bad_ech
	call	gw_sub_ok			; (a-z 0-9 . -)
	jc	plan_bad_ech
	mov	dword [g_plan_echn],0
	mov	r14d,1
.key:
	cmp	r14d,r13d
	jae	.list
	imul	rax,r14,A_SIZE
	mov	rsi,[r12+rax+A_VAL]
	mov	ecx,[r12+rax+A_VLEN]
	cmp	ecx,4000
	ja	plan_bad_ech
	lea	rdi,[g_trust_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_ech_key
	mov	rsi,rax
	lea	rdx,[rax+rdx]
	lea	rdi,[pem_pkcs8_key]
	call	pem_next			; g_tls_der
	cmp	eax,48
	jne	plan_ech_key
	lea	rsi,[g_tls_der]
	lea	rdi,[eh_x25519_der]
	mov	ecx,16
	repe	cmpsb
	jne	plan_ech_key
	; its config: the key, its public half, an id, the ECHConfig
	mov	eax,[g_plan_echn]
	imul	rdi,rax,ECC_SIZE
	lea	rdi,[g_plan_ech+rdi]
	push	rdi
	lea	rsi,[g_tls_der+16]
	mov	ecx,32
	rep	movsb
	mov	rdi,[rsp]
	lea	rsi,[rdi+ECC_SK]
	lea	rdi,[rdi+ECC_PK]
	call	x25519_base
	pop	rdi
	movzx	eax,byte [rdi+ECC_PK]		; config_id: the key's first byte, not one before
.id:
	xor	ecx,ecx
@@:
	cmp	ecx,[g_plan_echn]
	jae	@f
	imul	rdx,rcx,ECC_SIZE
	cmp	dword [g_plan_ech+rdx+ECC_ID],eax
	je	.taken
	inc	ecx
	jmp	@b
.taken:
	inc	al
	jmp	.id
@@:
	mov	[rdi+ECC_ID],eax
	mov	rcx,[r12+A_VAL]			; (the name)
	mov	edx,[r12+A_VLEN]
	call	ech_config_make
	inc	dword [g_plan_echn]
	inc	r14d
	jmp	.key
.list:
	; the ECHConfigList: every config, the first the one published
	lea	rdi,[g_plan_echlist+2]
	xor	ecx,ecx
@@:
	cmp	ecx,[g_plan_echn]
	jae	@f
	imul	rax,rcx,ECC_SIZE
	lea	rsi,[g_plan_ech+rax+ECC_CFG]
	push	rcx
	mov	ecx,dword [g_plan_ech+rax+ECC_CFGLEN]
	rep	movsb
	pop	rcx
	inc	ecx
	jmp	@b
@@:
	lea	rax,[g_plan_echlist]
	sub	rdi,rax
	mov	[g_plan_echlen],edi
	sub	edi,2
	mov	eax,edi
	xchg	al,ah
	mov	word [g_plan_echlist],ax
	pop	r14
	pop	r13
	pop	r12
	ret

; rdi = a config (ECC_SK, ECC_PK, ECC_ID set), rcx/edx = the public name: its ECHConfig
ech_config_make:
	push	rdi
	lea	r8,[rdi+ECC_CFG]
	mov	word [r8],0x0DFE		; version 0xfe0d
	mov	eax,[rdi+ECC_ID]
	mov	[r8+4],al			; config_id
	mov	word [r8+5],0x2000		; kem_id DHKEM(X25519, HKDF-SHA256)
	mov	word [r8+7],0x2000		; its public key: 32 bytes
	lea	rsi,[rdi+ECC_PK]
	lea	rdi,[r8+9]
	push	rcx
	mov	ecx,32
	rep	movsb
	pop	rcx
	mov	word [rdi],0x0400		; cipher_suites: 4 bytes,
	mov	dword [rdi+2],0x01000100	; HKDF-SHA256, AES-128-GCM
	mov	byte [rdi+6],0			; maximum_name_length (the client pads as it will)
	mov	[rdi+7],dl			; public_name
	add	rdi,8
	mov	rsi,rcx
	mov	ecx,edx
	rep	movsb
	mov	word [rdi],0			; no extensions
	add	rdi,2
	mov	rax,rdi
	sub	rax,r8				; all of it
	lea	ecx,[rax-4]
	xchg	cl,ch
	mov	[r8+2],cx			; the contents' length
	pop	rdi
	mov	[rdi+ECC_CFGLEN],eax
	ret

plan_bad_ech:
	call	log_begin
	out_lit 'ech takes a public name (the name a client shows in the clear) and 1 to 4 key files'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
plan_ech_key:
	call	log_begin
	out_lit 'ech: '
	lea	rsi,[g_trust_path]
	call	out_cstr
	out_lit ' is not an X25519 private key in PEM (openssl genpkey -algorithm X25519, or okena ech new FILE)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------ HPKE

; rsi/ecx = a label, r8/r9d = ikm, rdx/r10d = salt, rax/ebx = the suite id (eh_kem,
; 5 bytes, or eh_suite, 10): rdi = prk[32]. LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" |
; suite | label | ikm).
eh_extract:
	push	rdi
	push	rdx
	push	r10
	lea	rdi,[g_eh_buf]
	push	rsi
	push	rcx
	lea	rsi,[eh_v1]
	mov	ecx,7
	rep	movsb
	mov	rsi,rax
	mov	ecx,ebx
	rep	movsb
	pop	rcx
	pop	rsi
	rep	movsb
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	lea	r8,[g_eh_buf]
	sub	rdi,r8
	mov	r8,rdi				; ikm length
	lea	rcx,[g_eh_buf]
	pop	rdx				; salt length
	pop	rsi				; salt
	pop	rdi				; prk
	jmp	hkdf_extract

; r12d = L, rsi/ecx = a label, r8/r9d = info, rdx = prk, rax/ebx = suite, rdi = out:
; LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) | "HPKE-v1" | suite
; | label | info, L)
eh_expand:
	push	rdi
	push	rdx
	lea	rdi,[g_eh_buf]
	mov	edx,r12d
	xchg	dl,dh
	mov	[rdi],dx
	add	rdi,2
	push	rsi
	push	rcx
	lea	rsi,[eh_v1]
	mov	ecx,7
	rep	movsb
	mov	rsi,rax
	mov	ecx,ebx
	rep	movsb
	pop	rcx
	pop	rsi
	rep	movsb
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	lea	rcx,[g_eh_buf]
	mov	r8,rdi
	sub	r8,rcx				; info length
	pop	rdx
	pop	rdi
	mov	esi,r12d
	jmp	hkdf_expand

macro eh_label name*, text*
	local s
	cstring s, text
	lea	rsi,[s]
	mov	ecx,s.len
end macro

; r14 = the config, rsi = enc (32): g_eh_key, g_eh_nonce (HPKE's base mode, for
; info "tls ech" 0 ECHConfig). CF when the DH gives nothing.
eh_setup:
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r15,rsi				; enc
	; DHKEM's Decap: dh, then ExtractAndExpand with kem_context = enc | pkR
	lea	rdi,[g_eh_dh]
	lea	rdx,[r15]
	lea	rsi,[r14+ECC_SK]
	call	x25519
	lea	rsi,[g_eh_dh]			; (all zero: a point of small order)
	xor	eax,eax
	mov	ecx,32
@@:
	or	al,[rsi]
	inc	rsi
	dec	ecx
	jnz	@b
	test	al,al
	jz	.bad
	lea	rax,[eh_kem]
	mov	ebx,5
	lea	rdi,[g_eh_prk]
	xor	edx,edx
	xor	r10d,r10d
	eh_label lbl, 'eae_prk'
	lea	r8,[g_eh_dh]
	mov	r9d,32
	call	eh_extract
	lea	rdi,[g_eh_ctx]			; (scratch: kem_context)
	mov	rsi,r15
	mov	ecx,32
	rep	movsb
	lea	rsi,[r14+ECC_PK]
	mov	ecx,32
	rep	movsb
	mov	r12d,32
	lea	rax,[eh_kem]
	mov	ebx,5
	lea	rdi,[g_eh_shared]
	lea	rdx,[g_eh_prk]
	eh_label lbl2, 'shared_secret'
	lea	r8,[g_eh_ctx]
	mov	r9d,64
	call	eh_expand
	; the key schedule: psk_id_hash, info_hash, then the secret
	lea	rax,[eh_suite]
	mov	ebx,10
	lea	rdi,[g_eh_ctx+1]
	xor	edx,edx
	xor	r10d,r10d
	eh_label lbl3, 'psk_id_hash'
	xor	r9d,r9d
	call	eh_extract
	; info = "tls ech" 0 ECHConfig, past what eh_extract writes
	lea	rdi,[g_eh_buf+1024]
	mov	rax,'tls ech'
	mov	[rdi],rax
	mov	byte [rdi+7],0
	add	rdi,8
	lea	rsi,[r14+ECC_CFG]
	mov	ecx,[r14+ECC_CFGLEN]
	rep	movsb
	lea	r9,[g_eh_buf+1024]
	sub	rdi,r9
	mov	r9d,edi
	lea	rax,[eh_suite]
	mov	ebx,10
	lea	rdi,[g_eh_ctx+33]
	xor	edx,edx
	xor	r10d,r10d
	eh_label lbl4, 'info_hash'
	lea	r8,[g_eh_buf+1024]
	call	eh_extract
	mov	byte [g_eh_ctx],0		; mode_base
	lea	rax,[eh_suite]
	mov	ebx,10
	lea	rdi,[g_eh_secret]
	lea	rdx,[g_eh_shared]
	mov	r10d,32
	eh_label lbl5, 'secret'
	xor	r9d,r9d
	call	eh_extract
	mov	r12d,16
	lea	rax,[eh_suite]
	mov	ebx,10
	lea	rdi,[g_eh_key]
	lea	rdx,[g_eh_secret]
	eh_label lbl6, 'key'
	lea	r8,[g_eh_ctx]
	mov	r9d,65
	call	eh_expand
	mov	r12d,12
	lea	rax,[eh_suite]
	mov	ebx,10
	lea	rdi,[g_eh_nonce]
	lea	rdx,[g_eh_secret]
	eh_label lbl7, 'base_nonce'
	lea	r8,[g_eh_ctx]
	mov	r9d,65
	call	eh_expand
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ the hello

; r12 = a ClientHello message (handshake header first), [rbp+HL_MLEN] its length,
; [rbp+HL_ROOM] the room at r12: eax = 0 no ECH in it, 1 opened (the
; ClientHelloInner now at r12, HL_MLEN its length, HL_ECHRND its random), 2 not
; opened (go on with the outer one: retry_configs), 3 malformed (illegal_parameter).
ech_open:
	push	rbx
	push	r13
	push	r14
	push	r15
	cmp	dword [g_plan_echn],0
	je	.none
	cmp	dword [rbp+HL_ROOM],CH_MAX * 3
	jb	.none
	; the outer hello's extensions: where encrypted_client_hello is
	mov	eax,[rbp+HL_MLEN]
	lea	r13,[r12+rax]			; its end
	lea	rsi,[r12+4+34]
	call	.skip8				; legacy_session_id
	jc	.none
	call	.skip16				; cipher_suites
	jc	.none
	call	.skip8				; legacy_compression_methods
	jc	.none
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.none
	mov	[g_eh_oexts],rsi		; (the outer's extensions, their length first)
	add	rsi,2
.ext:
	lea	rax,[rsi+4]
	cmp	rax,r13
	ja	.none
	movzx	eax,word [rsi]
	rol	ax,8
	movzx	ecx,word [rsi+2]
	rol	cx,8
	lea	rdx,[rsi+4+rcx]
	cmp	rdx,r13
	ja	.none
	cmp	eax,0xFE0D
	je	.found
	mov	rsi,rdx
	jmp	.ext
.found:
	; outer (0): cipher_suite, config_id, enc, payload
	add	rsi,4
	mov	r15,rdx				; the extension's end
	cmp	ecx,1
	jb	.malformed
	cmp	byte [rsi],0
	jne	.none				; (inner (1) in an outer hello: as none)
	cmp	ecx,10
	jb	.malformed
	cmp	dword [rsi+1],0x01000100	; HKDF-SHA256, AES-128-GCM
	jne	.reject
	movzx	ebx,byte [rsi+5]		; config_id
	movzx	ecx,word [rsi+6]
	rol	cx,8
	lea	rax,[rsi+8+rcx+2]
	cmp	rax,r15
	ja	.malformed
	cmp	dword [g_eh_second],0
	jne	.second
	cmp	ecx,32
	jne	.reject
	lea	r8,[rsi+8]			; enc
	movzx	ecx,word [rsi+8+32]
	rol	cx,8
	lea	r9,[rsi+8+32+2]			; payload
	lea	rax,[r9+rcx]
	cmp	rax,r15
	jne	.malformed
	cmp	ecx,17
	jb	.malformed
	mov	[g_eh_payload],r9
	mov	[g_eh_plen],ecx
	; the config with that id
	xor	ecx,ecx
@@:
	cmp	ecx,[g_plan_echn]
	jae	.reject
	imul	rax,rcx,ECC_SIZE
	lea	r14,[g_plan_ech+rax]
	cmp	[r14+ECC_ID],ebx
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	[g_eh_cfgid],ebx
	mov	rsi,r8
	call	eh_setup			; g_eh_key, g_eh_nonce
	jc	.reject
	jmp	.opened_ctx
.second:
	; after a HelloRetryRequest: no enc, the same config, the context kept (its
	; nonce for the second message: sequence 1)
	test	ecx,ecx
	jnz	.malformed
	mov	rax,[rbp+HL_TS]
	movzx	edx,byte [rax+TS_TKT+28]
	cmp	ebx,edx
	jne	.malformed
	movzx	ecx,word [rsi+8]
	rol	cx,8
	lea	r9,[rsi+8+2]
	lea	rdx,[r9+rcx]
	cmp	rdx,r15
	jne	.malformed
	cmp	ecx,17
	jb	.malformed
	mov	[g_eh_payload],r9
	mov	[g_eh_plen],ecx
	lea	rsi,[rax+TS_TKT]
	lea	rdi,[g_eh_key]
	mov	ecx,28
	rep	movsb
	xor	byte [g_eh_nonce+11],1
.opened_ctx:
	; the AAD: the outer hello (no handshake header), its payload zeroed
	mov	ecx,[rbp+HL_MLEN]
	sub	ecx,4
	mov	[g_eh_alen],ecx
	lea	rsi,[r12+4]
	lea	rdi,[r12+CH_MAX]
	rep	movsb
	mov	rdi,[g_eh_payload]
	sub	rdi,r12
	add	rdi,r12
	add	rdi,CH_MAX - 4			; (the same place in the copy)
	mov	ecx,[g_eh_plen]
	xor	eax,eax
	rep	stosb
	; the payload opened in a copy of its own
	mov	rsi,[g_eh_payload]
	lea	rdi,[r12+CH_MAX * 2]
	mov	ecx,[g_eh_plen]
	rep	movsb
	lea	rdi,[g_eh_gcm]
	lea	rsi,[g_eh_key]
	call	gcm_init
	lea	rdi,[g_eh_gcm]
	lea	rsi,[g_eh_nonce]
	lea	rdx,[r12+CH_MAX]
	mov	ecx,[g_eh_alen]
	lea	r8,[r12+CH_MAX * 2]
	mov	r9d,[g_eh_plen]
	sub	r9d,16
	call	gcm_open
	test	eax,eax
	jz	.second_failed
	; EncodedClientHelloInner -> ClientHelloInner, built where the AAD was
	mov	r8,r12
	add	r8,CH_MAX * 2			; the plaintext
	mov	r9d,[g_eh_plen]
	sub	r9d,16
	add	r9,r8				; its end
	lea	rdi,[r12+CH_MAX + 4]		; (the header after)
	mov	rsi,r8
	lea	rax,[rsi+35]
	cmp	rax,r9
	ja	.malformed
	movsw					; legacy_version
	push	rsi
	lea	rdi,[rbp+HL_ECHRND]		; its random, for the confirmation
	mov	ecx,32
	rep	movsb
	pop	rsi
	lea	rdi,[r12+CH_MAX + 4 + 2]
	mov	ecx,32
	rep	movsb				; random
	cmp	byte [rsi],0			; legacy_session_id: empty, the outer's taken
	jne	.malformed
	inc	rsi
	push	rsi
	lea	rsi,[r12+4+34]
	movzx	ecx,byte [rsi]
	inc	ecx
	rep	movsb
	pop	rsi
	; cipher_suites, legacy_compression_methods as they are
	lea	rax,[rsi+2]
	cmp	rax,r9
	ja	.malformed
	movzx	ecx,word [rsi]
	rol	cx,8
	add	ecx,2
	lea	rax,[rsi+rcx]
	cmp	rax,r9
	ja	.malformed
	rep	movsb
	cmp	rsi,r9
	jae	.malformed
	movzx	ecx,byte [rsi]
	inc	ecx
	lea	rax,[rsi+rcx]
	cmp	rax,r9
	ja	.malformed
	rep	movsb
	; the extensions: ech_outer_extensions replaced by the outer's, in order
	lea	rax,[rsi+2]
	cmp	rax,r9
	ja	.malformed
	movzx	ecx,word [rsi]
	rol	cx,8
	add	rsi,2
	lea	r10,[rsi+rcx]			; their end
	cmp	r10,r9
	ja	.malformed
	; (what follows them is padding: zeros only)
	mov	rax,r10
@@:
	cmp	rax,r9
	jae	@f
	cmp	byte [rax],0
	jne	.malformed
	inc	rax
	jmp	@b
@@:
	mov	r11,rdi				; where their length goes
	add	rdi,2
	mov	rax,[g_eh_oexts]		; the outer's, a cursor in them (in order)
	add	rax,2
	mov	[g_eh_ocur],rax
	mov	dword [g_eh_inner],0
.iext:
	cmp	rsi,r10
	jae	.iexts_done
	lea	rax,[rsi+4]
	cmp	rax,r10
	ja	.malformed
	movzx	eax,word [rsi]
	rol	ax,8
	movzx	ecx,word [rsi+2]
	rol	cx,8
	lea	rdx,[rsi+4+rcx]
	cmp	rdx,r10
	ja	.malformed
	cmp	eax,0xFD00			; ech_outer_extensions
	je	.outer_refs
	cmp	eax,0xFE0D
	jne	.copy
	cmp	ecx,1				; its own: inner (1)
	jne	.malformed
	cmp	byte [rsi+4],1
	jne	.malformed
	mov	dword [g_eh_inner],1
.copy:
	lea	ecx,[rcx+4]
	rep	movsb
	jmp	.iext
.outer_refs:
	; u8 length, u16 types: each the next of that type in the outer hello
	push	rdx
	add	rsi,4
	movzx	ecx,byte [rsi]
	inc	rsi
	test	ecx,1
	jnz	.refs_bad
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	jne	.refs_bad
	shr	ecx,1
.ref:
	test	ecx,ecx
	jz	.refs_done
	movzx	eax,word [rsi]
	add	rsi,2
	rol	ax,8
	cmp	eax,0xFE0D
	je	.refs_bad			; (not ECH itself)
	push	rsi
	push	rcx
	call	.outer_take			; copies it, CF: not there (in order)
	pop	rcx
	pop	rsi
	jc	.refs_bad
	dec	ecx
	jmp	.ref
.refs_done:
	pop	rsi				; (past it)
	jmp	.iext
.refs_bad:
	pop	rdx
	jmp	.malformed
.iexts_done:
	cmp	dword [g_eh_inner],0
	je	.malformed			; an inner hello says so
	mov	rax,rdi
	sub	rax,r11
	sub	eax,2
	xchg	al,ah
	mov	[r11],ax
	; its header, then it, in place of the outer one
	lea	rsi,[r12+CH_MAX]
	mov	rcx,rdi
	sub	rcx,rsi
	mov	byte [rsi],1
	lea	eax,[rcx-4]
	put24	rsi+1, eax
	cmp	ecx,CH_MAX
	ja	.malformed
	mov	[rbp+HL_MLEN],ecx
	mov	rdi,r12
	rep	movsb
	mov	eax,1
	jmp	.out
.none:
	xor	eax,eax
	jmp	.out
.second_failed:
	cmp	dword [g_eh_second],0
	jne	.malformed			; (the second must open: decrypt_error)
.reject:
	mov	eax,2
	jmp	.out
.malformed:
	mov	eax,3
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
; rsi at a u8 length: past it and what it counts. CF when past r13.
.skip8:
	cmp	rsi,r13
	jae	.skip_bad
	movzx	ecx,byte [rsi]
	lea	rsi,[rsi+rcx+1]
	cmp	rsi,r13
	ja	.skip_bad
	clc
	ret
.skip16:
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.skip_bad
	movzx	ecx,word [rsi]
	rol	cx,8
	lea	rsi,[rsi+rcx+2]
	cmp	rsi,r13
	ja	.skip_bad
	clc
	ret
.skip_bad:
	stc
	ret
; eax = an extension type, rdi = out: the next one of that type in the outer hello
; (from g_eh_ocur), copied whole; the cursor past it. CF when there is none.
.outer_take:
	mov	rsi,[g_eh_ocur]
.ot:
	lea	rdx,[rsi+4]
	cmp	rdx,r13
	ja	.ot_none
	movzx	edx,word [rsi]
	rol	dx,8
	movzx	ecx,word [rsi+2]
	rol	cx,8
	lea	r8,[rsi+4+rcx]
	cmp	edx,eax
	je	.ot_take
	mov	rsi,r8
	jmp	.ot
.ot_take:
	lea	ecx,[rcx+4]
	rep	movsb
	mov	[g_eh_ocur],rsi
	clc
	ret
.ot_none:
	stc
	ret

; rbp = the hello's frame, r12 + 5 = the ServerHello (its random at +6), edx =
; its length, ECH taken: the last 8 bytes of its random are the accept
; confirmation, HKDF-Expand-Label(HKDF-Extract(0, inner random), "ech accept
; confirmation", H(ClientHelloInner .. ServerHello with them zero), 8)
ech_confirm:
	push	rbx
	push	rdx
	xor	eax,eax
	mov	[r12+5+6+24],rax
	lea	rsi,[rbp+HL_SHA]		; the transcript so far, then this ServerHello
	lea	rdi,[rbp+HL_SHA2]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[r12+5]
	mov	edx,[rsp]
	call	sha256_update
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[rbp+HL_TMP]
	call	sha256_final
	lea	rdi,[g_eh_prk]
	lea	rsi,[sha256_zero32]
	mov	edx,32
	lea	rcx,[rbp+HL_ECHRND]
	mov	r8d,32
	call	hkdf_extract
	lea	rdi,[r12+5+6+24]
	mov	esi,8
	lea	rdx,[g_eh_prk]
	lea	rcx,[lbl_ech_accept]
	lea	r8,[rbp+HL_TMP]
	mov	r9d,32
	call	tls13_expand_label
	pop	rdx
	pop	rbx
	ret

rodata
	sha256_zero32	db 32 dup 0
end rodata

; r14 = the end of EncryptedExtensions so far, r13 its start, ECH not opened:
; retry_configs (encrypted_client_hello with the ECHConfigList) added; r14 past it
ech_retry_configs:
	mov	word [r14],0x0DFE
	mov	eax,[g_plan_echlen]
	xchg	al,ah
	mov	[r14+2],ax
	lea	rdi,[r14+4]
	lea	rsi,[g_plan_echlist]
	mov	ecx,[g_plan_echlen]
	rep	movsb
	mov	rax,rdi
	sub	rax,r14				; what was added
	mov	r14,rdi
	; EncryptedExtensions' own lengths: the message's, its extensions'
	movzx	ecx,byte [r13+1]
	shl	ecx,16
	movzx	edx,word [r13+2]
	xchg	dl,dh
	or	ecx,edx
	add	ecx,eax
	put24	r13+1, ecx
	movzx	ecx,word [r13+4]
	xchg	cl,ch
	add	ecx,eax
	xchg	cl,ch
	mov	[r13+4],cx
	ret

; ------------------------------------------------------------ the command

; `okena ech new FILE`: an X25519 key, in PEM (0600, never over a file);
; `okena ech print [-c FILE]`: the configuration's ECHConfigList in base64, for the
; DNS HTTPS record (its ech= parameter)
cli_ech:
	cmp	qword [g_argc],3
	jb	.usage
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	cstring .w_new, 'new',0
	lea	rsi,[.w_new]
	call	cstr_eq
	test	eax,eax
	jnz	.new
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	cstring .w_print, 'print',0
	lea	rsi,[.w_print]
	call	cstr_eq
	test	eax,eax
	jz	.usage
	mov	edi,3
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	cmp	dword [g_plan_echn],0
	je	.none
	mov	edi,1
	call	out_select
	lea	rdi,[g_x5_pem]			; (a scratch of the size)
	lea	rsi,[g_plan_echlist]
	mov	edx,[g_plan_echlen]
	call	base64_encode
	lea	rsi,[g_x5_pem]
	mov	edx,eax
	call	out_str
	mov	edi,10
	call	out_char
	call	out_flush
	xor	edi,edi
	jmp	exit_process
.none:
	call	log_begin
	out_lit 'ech print: the configuration has no `ech` in its okena block'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.new:
	cmp	qword [g_argc],4
	jb	.usage
	; 32 random bytes after the PKCS #8 prefix of an X25519 key
	lea	rdi,[g_x5_der]
	lea	rsi,[eh_x25519_der]
	mov	ecx,16
	rep	movsb
	lea	rdi,[g_x5_der+16]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,32
	jne	.failed
	lea	rdi,[g_x5_pem]
	lea	rsi,[g_x5_der]
	mov	ecx,48
	lea	rdx,[pem_pkcs8_key]
	call	x5_pem
	lea	rax,[g_x5_pem]
	sub	rdi,rax
	push	rdi
	mov	rax,[g_argv]
	mov	rsi,[rax+24]
	mov	edi,AT_FDCWD
	mov	edx,O_WRONLY or O_CREAT or 0x80 or O_CLOEXEC	; (O_EXCL: never over one)
	mov	r10d,0x180			; 0600
	mov	eax,SYS_openat
	syscall
	pop	rdx
	test	eax,eax
	js	.failed
	push	rax
	mov	edi,eax
	lea	rsi,[g_x5_pem]
	call	write_all
	pop	rdi
	mov	eax,SYS_close
	syscall
	call	log_begin
	out_lit 'ech: a new key in '
	mov	rax,[g_argv]
	mov	rsi,[rax+24]
	call	out_cstr
	out_lit '; okena ech print gives what goes in the DNS once it is in the configuration'
	call	log_end
	xor	edi,edi
	jmp	exit_process
.failed:
	call	log_begin
	out_lit 'ech new: the file cannot be made (is it there already?)'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process
.usage:
	call	log_begin
	out_lit 'usage: okena ech new FILE | okena ech print [-c FILE]'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = past a HelloRetryRequest's extensions, r12 + 5 = the message, rbp the hello's
; frame: ECH opened, its encrypted_client_hello with the confirmation
; (HKDF-Expand-Label(HKDF-Extract(0, ClientHelloInner1.random), "hrr ech accept
; confirmation", H(message_hash(ClientHelloInner1) | HelloRetryRequest with it
; zero), 8)), the HPKE context kept for the second hello (TS_TKT, unused until
; the flight); not opened, TF_ECHREJ. rdi past what was added.
ech_hrr:
	mov	rax,[rbp+HL_TS]
	cmp	dword [rbp+HL_ECH],2
	jne	@f
	or	dword [rax+TS_FLAGS],TF_ECHREJ
	ret
@@:
	cmp	dword [rbp+HL_ECH],1
	jne	.out
	push	rdi
	movzx	ecx,byte [r12+5+4+2+32]		; (the legacy_session_id's length)
	mov	byte [r12+rcx+5+4+2+32+1+4],24	; the extensions: 12 + 12
	mov	dword [rdi],0x08000DFE		; encrypted_client_hello, 8 bytes, zero
	mov	qword [rdi+4],0
	; H(transcript so far | this HelloRetryRequest with them zero)
	lea	rsi,[rbp+HL_SHA]
	lea	rdi,[rbp+HL_SHA2]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[r12+5]
	mov	edx,[rbp+HL_HRRLEN]
	call	sha256_update
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[rbp+HL_TMP]
	call	sha256_final
	lea	rdi,[g_eh_prk]
	lea	rsi,[sha256_zero32]
	mov	edx,32
	lea	rcx,[rbp+HL_ECHRND]
	mov	r8d,32
	call	hkdf_extract
	mov	rdi,[rsp]
	add	rdi,4
	mov	esi,8
	lea	rdx,[g_eh_prk]
	lea	rcx,[lbl_ech_hrr]
	lea	r8,[rbp+HL_TMP]
	mov	r9d,32
	call	tls13_expand_label
	; the context, for the second hello
	mov	rax,[rbp+HL_TS]
	lea	rdi,[rax+TS_TKT]
	lea	rsi,[g_eh_key]
	mov	ecx,28
	rep	movsb
	mov	ecx,[g_eh_cfgid]
	mov	[rax+TS_TKT+28],cl
	or	dword [rax+TS_FLAGS],TF_ECHHRR
	pop	rdi
	add	rdi,12
.out:
	ret

rodata
	lbl_ech_hrr	db 'hrr ech accept confirmation',0
end rodata
