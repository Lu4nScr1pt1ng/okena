; Known-answer harness for src/crypto (not part of okena). Reads stdin:
; the first byte selects the function, the rest is its input; prints the
; result in hex on stdout.
;   's' SHA-256 of the rest              'S' the same on the scalar path
;   '8' SHA-512 of the rest
;   '3' SHA3-256, '5' SHA3-512 of the rest; '6' SHAKE128, '7' SHAKE256: out len (2, LE), message
;   'q' ML-KEM-768 encapsulation: ek (1184), m (32) -> ciphertext | shared secret
;   'A' Ed25519 public key: seed; 'F' sign: seed, message; 'f' verify: public, sig, message
;   'c' ChaCha20: key, nonce, counter (4, LE), data; 'y' ChaCha20-Poly1305 seal: key (32),
;       iv (12), aad len (2), aad, plaintext; 'Z' its open (ciphertext | tag, 'FAIL' if wrong)
;   'e' Poly1305: key (32), message (a multiple of 16) -> tag
;   '4' four-way Keccak: rate, prefix (32), four lane-4 qwords -> two SHAKE blocks of each
;   'L' ML-KEM-768 key generation: d | z (64) -> ek | dk; 'O' decapsulation: dk, ct -> secret
;   'h' HMAC: key length (2, LE), key, message
;   'k' HKDF: salt len (2), salt, ikm len (2), ikm, info len (2), info, out len (2)
;   'l' Expand-Label: secret (32), label len (1), label, ctx len (1), ctx, out len (2)
;   'x' X25519: scalar (32), u (32)
;   'g' AES-128-GCM seal: key (16), iv (12), aad len (2), aad, plaintext
;   'P' P-256 public key: d (32) -> 04 | X | Y
;   'E' P-256 ECDSA (RFC 6979): d (32), digest (32) -> the DER signature
;   'M' mont_mul mod p, 'a' mod_add, 'b' mod_sub: a, b (4 limbs each, little endian)
;   'I' mod_inv mod p: a (4 limbs, Montgomery form); 'D' G + G (projective, raw)
;   'u' x25519_base: scalar (32) -> the public key, as x25519(scalar, 9)
;   'B' benchmark: op ('x', 'u', 'E', 'v' ECDSA verify, ...), count (4, LE), the op's input -> ns per op
;   'G' AES-128-GCM open: key, iv, aad len, aad, ciphertext | tag; 'FAIL' if wrong

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/limits.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/crypto/ct.inc'
include '../../src/crypto/sha256.inc'
include '../../src/crypto/sha512.inc'
include '../../src/crypto/keccak.inc'
include '../../src/crypto/mlkem.inc'
include '../../src/crypto/hmac.inc'
include '../../src/crypto/hkdf.inc'
include '../../src/crypto/x25519.inc'
include '../../src/crypto/ed25519.inc'
include '../../src/crypto/aesgcm.inc'
include '../../src/crypto/chacha.inc'
include '../../src/crypto/p256.inc'
include '../../src/crypto/rsa.inc'
include '../../src/tls/x509.inc'
include '../../src/tls/keyschedule.inc'
include '../../src/tls/client.inc'
include '../../src/tls/tls12.inc'

INPUT_MAX := 1 shl 22

bss
	align 16
	g_in_len	dq ?
	g_out:		rb 70000
	g_label:	rb 256
	align 16
	g_gcm:		rb GCM_SIZE
	g_gmode		db ?
	g_tc:		rb TC_FULL
	align 32
	g_x4:		rb KECCAK_X4
	g_cp:		rb CP_SIZE + 64 + PY_SIZE
	g_gcm12:	rb 512
	g_der:		rb 8192
	g_anchor:	rb PK_SIZE
	g_in:		rb INPUT_MAX + 64
end bss

start:
	call	crypto_init
	xor	ebx,ebx
.read:
	xor	edi,edi
	lea	rsi,[g_in+rbx]
	mov	edx,INPUT_MAX
	sub	edx,ebx
	jz	.got
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.got
	add	rbx,rax
	jmp	.read
.got:
	mov	[g_in_len],rbx
	test	rbx,rbx
	jz	.fail
	movzx	eax,byte [g_in]
	lea	rsi,[g_in+1]			; the input
	lea	rdx,[rbx-1]			; its length
	cmp	al,'v'				; 'v' first: without VAES (the SSE paths)
	jne	@f
	mov	byte [g_cpu_vaes],0
	movzx	eax,byte [rsi]
	inc	rsi
	dec	rdx
@@:
	cmp	al,'s'
	je	.sha
	cmp	al,'3'
	je	.sha3_256
	cmp	al,'8'
	je	.sha512
	cmp	al,'5'
	je	.sha3_512
	cmp	al,'6'
	je	.shake128
	cmp	al,'7'
	je	.shake256
	cmp	al,'q'
	je	.mlkem_encaps
	cmp	al,'L'
	je	.mlkem_keygen
	cmp	al,'O'
	je	.mlkem_decaps
	cmp	al,'4'
	je	.keccak_x4
	cmp	al,'c'
	je	.chacha
	cmp	al,'A'
	je	.ed_public
	cmp	al,'F'
	je	.ed_sign
	cmp	al,'f'
	je	.ed_verify
	cmp	al,'e'
	je	.poly1305
	cmp	al,'y'
	je	.cp_seal
	cmp	al,'Z'
	je	.cp_open
	cmp	al,'S'
	je	.sha_scalar
	cmp	al,'h'
	je	.hmac
	cmp	al,'k'
	je	.hkdf
	cmp	al,'l'
	je	.label
	cmp	al,'x'
	je	.x25519
	cmp	al,'u'
	je	.x25519_base
	cmp	al,'D'
	je	.ecdh
	cmp	al,'V'
	je	.ecdsa_verify
	cmp	al,'C'
	je	.cert_verify
	cmp	al,'H'
	je	.client_hello
	cmp	al,'T'
	je	.cert_time
	cmp	al,'N'
	je	.cert_host
	cmp	al,'K'
	je	.cert_chain
	cmp	al,'p'
	je	.cert_pem
	cmp	al,'R'
	je	.tls_prf
	cmp	al,'r'
	je	.tls12_ks
	cmp	al,'2'
	je	.tls12_rec
	cmp	al,'X'
	je	.bn_modexp
	cmp	al,'Y'
	je	.rsa_verify
	cmp	al,'W'
	je	.rsa_pss
	cmp	al,'z'
	je	.rsa_sign
	cmp	al,'U'
	je	.rsa_pkcs1sign
	cmp	al,'j'
	je	.rsa_key
	cmp	al,'J'
	je	.rsa_keysign
	cmp	al,'g'
	je	.gcm
	cmp	al,'G'
	je	.gcm
	cmp	al,'P'
	je	.p256_pub
	cmp	al,'M'
	je	.mont
	cmp	al,'Q'
	je	.msqr
	cmp	al,'B'
	je	.bench
	cmp	al,'I'
	je	.minv
	cmp	al,'a'
	je	.madd
	cmp	al,'b'
	je	.msub
	cmp	al,'D'
	je	.dbl
	cmp	al,'E'
	je	.p256_sign
.fail:
	mov	edi,2
	mov	eax,SYS_exit_group
	syscall
.sha_scalar:
	mov	byte [g_cpu_shani],0
.sha:
	lea	rdi,[g_out]
	call	sha256
	mov	esi,32
	jmp	.print
.sha512:
	lea	rdi,[g_out]
	call	sha512
	mov	esi,64
	jmp	.print
.sha3_256:
	lea	rdi,[g_out]
	call	sha3_256
	mov	esi,32
	jmp	.print
.sha3_512:
	lea	rdi,[g_out]
	call	sha3_512
	mov	esi,64
	jmp	.print
.mlkem_encaps:					; ek (1184), m (32) -> ct | shared secret
	lea	rcx,[rsi+MLKEM_EK]
	mov	rdx,rsi
	lea	rdi,[g_out]
	lea	rsi,[g_out+MLKEM_CT]
	call	mlkem768_encaps
	test	eax,eax
	jz	.fail
	mov	esi,MLKEM_CT + MLKEM_SS
	jmp	.print
.mlkem_keygen:					; d | z (64) -> ek | dk
	mov	rdx,rsi
	lea	rdi,[g_out]
	lea	rsi,[g_out+MLKEM_EK]
	call	mlkem768_keygen
	mov	esi,MLKEM_EK + MLKEM_DK
	jmp	.print
.mlkem_decaps:					; dk (2400), ct (1088) -> shared secret
	lea	rdx,[rsi+MLKEM_DK]
	lea	rdi,[g_out]
	call	mlkem768_decaps
	mov	esi,MLKEM_SS
	jmp	.print
.ed_public:					; seed (32) -> public key
	lea	rdi,[g_out]
	call	ed25519_public
	mov	esi,32
	jmp	.print
.ed_sign:					; seed (32), message -> signature (64)
	lea	r12,[rdx-32]
	mov	r13,rsi
	lea	rdi,[g_out+64]
	call	ed25519_public
	lea	rdi,[g_out]
	mov	rsi,r13
	lea	rdx,[g_out+64]
	lea	rcx,[r13+32]
	mov	r8,r12
	call	ed25519_sign
	mov	esi,64
	jmp	.print
.ed_verify:					; public (32), signature (64), message -> 01 / 00
	lea	rdx,[rdx-96]
	lea	rcx,[rsi+32]
	mov	rdi,rsi
	lea	rsi,[rsi+96]
	call	ed25519_verify
	mov	[g_out],al
	mov	esi,1
	jmp	.print
.chacha:					; key (32), nonce (12), counter (4), data
	lea	r12,[rdx-48]			; -> the data XORed with the key stream
	mov	r13,rsi
	lea	rdi,[g_out]
	lea	rsi,[r13+48]
	mov	rcx,r12
	rep	movsb
	mov	rdi,r13
	lea	rsi,[r13+32]
	mov	edx,[r13+44]
	lea	rcx,[g_out]
	mov	r8,r12
	call	chacha20_xor
	mov	esi,r12d
	jmp	.print
.poly1305:					; key (32), message (a multiple of 16) -> tag
	lea	r12,[rdx-32]
	mov	r13,rsi
	lea	rdi,[g_cp+64]
	call	poly_init
	lea	rdi,[g_cp+64]
	lea	rsi,[r13+32]
	mov	rdx,r12
	call	poly_padded
	lea	rdi,[g_cp+64]
	lea	rsi,[g_out]
	call	poly_final
	mov	esi,16
	jmp	.print
.cp_seal:					; key (32), iv (12), aad len (2), aad, plaintext
	mov	byte [g_gmode],0
	jmp	.cp
.cp_open:					; the same, ciphertext | tag; 'FAIL' when wrong
	mov	byte [g_gmode],1
.cp:
	push	rsi
	push	rdx
	lea	rdi,[g_cp]
	call	cp_init
	pop	rdx
	pop	rsi
	movzx	ecx,word [rsi+44]		; aad length
	lea	rbx,[rsi+46]			; aad
	lea	r9,[rdx-46]
	sub	r9,rcx				; the text's length
	lea	r12,[rbx+rcx]
	push	rcx
	push	rsi
	lea	rdi,[g_out]
	mov	rsi,r12
	mov	rcx,r9
	rep	movsb
	pop	rsi
	pop	rcx
	lea	rsi,[rsi+32]			; iv
	mov	rdx,rbx
	lea	r8,[g_out]
	lea	rdi,[g_cp]
	cmp	byte [g_gmode],0
	jne	.cp_o
	push	r9
	call	cp_seal
	pop	rsi
	add	esi,16
	jmp	.print
.cp_o:
	sub	r9,16
	push	r9
	call	cp_open
	pop	rsi
	test	eax,eax
	jz	.cp_fail
	jmp	.print
.cp_fail:
	mov	dword [g_out],'FAIL'
	mov	edi,1
	lea	rsi,[g_out]
	mov	edx,4
	mov	eax,1
	syscall
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall
.keccak_x4:					; rate (1 byte), prefix (32), lanes 4 (4 x 8)
	movzx	r12d,byte [rsi]			; -> two blocks of each of the four
	lea	rdx,[rsi+33]
	inc	rsi
	lea	rdi,[g_x4]
	mov	ecx,r12d
	call	keccak_x4_init
	lea	r13,[g_out]
	xor	ebx,ebx
.x4a:
	mov	esi,ebx
	mov	rdx,r13
	mov	ecx,r12d
	call	keccak_x4_extract
	add	r13,r12
	add	r13,r12				; leave room for the second block
	inc	ebx
	cmp	ebx,4
	jb	.x4a
	call	keccak_f1600_x4
	lea	r13,[g_out]
	add	r13,r12
	xor	ebx,ebx
.x4b:
	mov	esi,ebx
	mov	rdx,r13
	mov	ecx,r12d
	call	keccak_x4_extract
	add	r13,r12
	add	r13,r12
	inc	ebx
	cmp	ebx,4
	jb	.x4b
	lea	esi,[r12*8]
	jmp	.print
.shake128:					; out length (2, LE), message
	mov	r8d,SHAKE128_RATE
	jmp	.shake
.shake256:
	mov	r8d,SHAKE256_RATE
.shake:
	movzx	ebx,word [rsi]
	lea	rcx,[rdx-2]
	lea	rdx,[rsi+2]
	lea	rdi,[g_out]
	mov	esi,ebx
	call	shake
	mov	esi,ebx
	jmp	.print
.hmac:
	movzx	ecx,word [rsi]			; key length
	add	rsi,2
	sub	rdx,2
	lea	r8,[rdx]
	sub	r8,rcx				; message length
	lea	rdi,[g_out]
	mov	rax,rsi
	add	rax,rcx				; the message
	mov	rdx,rcx				; key length
	mov	rcx,rax
	call	hmac_sha256
	mov	esi,32
	jmp	.print
.hkdf:
	; salt
	movzx	edx,word [rsi]
	lea	rbx,[rsi+2]			; salt
	mov	r12,rdx
	lea	rsi,[rbx+rdx]
	movzx	ecx,word [rsi]			; ikm
	lea	r13,[rsi+2]
	mov	r14,rcx
	lea	rsi,[r13+rcx]
	movzx	ecx,word [rsi]			; info
	lea	r15,[rsi+2]
	mov	rbp,rcx
	lea	rsi,[r15+rcx]
	movzx	eax,word [rsi]			; out length
	push	rax
	sub	rsp,40
	mov	rdi,rsp				; prk
	mov	rsi,rbx
	mov	rdx,r12
	mov	rcx,r13
	mov	r8,r14
	call	hkdf_extract
	lea	rdi,[g_out]
	mov	esi,[rsp+40]
	mov	rdx,rsp
	mov	rcx,r15
	mov	r8,rbp
	call	hkdf_expand
	add	rsp,40
	pop	rsi
	jmp	.print
.label:
	mov	rbx,rsi				; secret
	movzx	ecx,byte [rsi+32]		; label
	lea	rsi,[rsi+33]
	lea	rdi,[g_label]
	rep	movsb
	mov	byte [rdi],0
	movzx	r9d,byte [rsi]			; context
	lea	r8,[rsi+1]
	movzx	esi,word [r8+r9]		; out length
	push	rsi
	lea	rdi,[g_out]
	mov	rdx,rbx
	lea	rcx,[g_label]
	call	tls13_expand_label
	pop	rsi
	jmp	.print
.gcm:
	mov	[g_gmode],al
	mov	rbx,rsi				; key
	mov	r12,rdx				; bytes
	lea	rdi,[g_gcm]
	call	gcm_init
	movzx	ecx,word [rbx+28]		; aad length
	lea	rdx,[rbx+30]			; aad
	lea	r8,[rdx+rcx]			; the text
	mov	r9,r12
	sub	r9,30
	sub	r9,rcx				; its length
	cmp	byte [g_gmode],'g'
	je	.seal
	sub	r9,16				; (the tag follows)
	push	r8
	push	r9
	lea	rdi,[g_gcm]
	lea	rsi,[rbx+16]
	call	gcm_open
	pop	r9
	pop	r8
	test	eax,eax
	jz	.wrong
	jmp	.text_out
.seal:
	push	r8
	push	r9
	lea	rdi,[g_gcm]
	lea	rsi,[rbx+16]
	call	gcm_seal
	pop	r9
	pop	r8
	add	r9,16				; with the tag
.text_out:
	; copy the text to g_out (at most its size) and print it
	mov	rsi,r8
	lea	rdi,[g_out]
	mov	rcx,r9
	rep	movsb
	mov	esi,r9d
	jmp	.print
.wrong:
	lea	rsi,[.fail_text]
	mov	edx,5
	mov	edi,1
	mov	eax,SYS_write
	syscall
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall
.fail_text db 'FAIL',10
.madd:
	lea	rdi,[g_out]
	lea	rdx,[rsi+32]
	lea	rcx,[p256_p]
	call	mod_add
	mov	esi,32
	jmp	.print
.msub:
	lea	rdi,[g_out]
	lea	rdx,[rsi+32]
	lea	rcx,[p256_p]
	call	mod_sub
	mov	esi,32
	jmp	.print
.minv:
	lea	rdi,[g_out]
	lea	rcx,[p256_p]
	call	mod_inv
	mov	esi,32
	jmp	.print
.dbl:
	; (debug) G + G, projective, Montgomery form
	lea	rdi,[g_out]
	lea	rsi,[p256_g_m]
	lea	rdx,[p256_g_m]
	call	p256_add
	mov	esi,96
	jmp	.print
.bench:
	movzx	r12d,byte [rsi]			; which
	mov	r13d,[rsi+1]			; how many
	lea	r14,[rsi+5]			; its input
	call	.now
	mov	r15,rax
.again:
	cmp	r12b,'m'
	jne	.not_m
	mov	rdi,r14				; in place: a chain of dependent products
	mov	rsi,r14
	mov	rdx,r14
	call	fe_mul
	jmp	.counted
.not_m:
	cmp	r12b,'q'
	jne	.not_q
	mov	rdi,r14
	mov	rsi,r14
	call	fe_sq
	jmp	.counted
.not_q:
	cmp	r12b,'w'
	jne	.not_w
	mov	rdi,r14				; P-256 Montgomery multiply, in place
	mov	rsi,r14
	mov	rdx,r14
	lea	rcx,[p256_p]
	call	mont_mul
	jmp	.counted
.not_w:
	cmp	r12b,'K'
	jne	.not_K
	lea	rdi,[g_out]			; ML-KEM-768 encapsulation: ek, m
	lea	rsi,[g_out+MLKEM_CT]
	mov	rdx,r14
	lea	rcx,[r14+MLKEM_EK]
	call	mlkem768_encaps
	jmp	.counted
.not_K:
	cmp	r12b,'e'
	jne	.not_e
	lea	rdi,[g_out]			; Ed25519 sign: seed (32), public (32), 64-byte message
	mov	rsi,r14
	lea	rdx,[r14+32]
	lea	rcx,[r14+64]
	mov	r8d,64
	call	ed25519_sign
	jmp	.counted
.not_e:
	cmp	r12b,'V'
	jne	.not_V
	mov	rdi,r14				; Ed25519 verify: public, signature, 64-byte message
	lea	rsi,[r14+96]
	mov	edx,64
	lea	rcx,[r14+32]
	call	ed25519_verify
	jmp	.counted
.not_V:
	cmp	r12b,'v'
	jne	.not_v
	mov	rdi,r14				; ECDSA P-256 verify: pubkey(65) digest(32) r(32) s(32)
	lea	rsi,[r14+65]
	lea	rdx,[r14+97]
	lea	rcx,[r14+129]
	call	p256_verify
	jmp	.counted
.not_v:
	cmp	r12b,'p'
	jne	.not_p
	lea	rdi,[g_cp]			; ChaCha20-Poly1305 seal of 16 KiB in place
	mov	rsi,r14				; key (32) then iv (12) in the input
	call	cp_init
	lea	rdi,[g_cp]
	lea	rsi,[r14+32]
	xor	edx,edx
	xor	ecx,ecx
	lea	r8,[g_out]
	mov	r9d,16384
	call	cp_seal
	jmp	.counted
.not_p:
	cmp	r12b,'F'
	jne	.not_F
	mov	rdi,r14				; Keccak-f[1600], in place
	call	keccak_f1600
	jmp	.counted
.not_F:
	cmp	r12b,'L'
	jne	.not_L
	lea	rdi,[g_out]			; ML-KEM-768 key generation: d | z
	lea	rsi,[g_out+MLKEM_EK]
	mov	rdx,r14
	call	mlkem768_keygen
	jmp	.counted
.not_L:
	cmp	r12b,'O'
	jne	.not_O
	lea	rdi,[g_out]			; ML-KEM-768 decapsulation: dk, ct
	mov	rsi,r14
	lea	rdx,[r14+MLKEM_DK]
	call	mlkem768_decaps
	jmp	.counted
.not_O:
	cmp	r12b,'i'
	jne	.not_i
	lea	rdi,[g_out]			; inversion mod p
	mov	rsi,r14
	lea	rcx,[p256_p]
	call	mod_inv
	jmp	.counted
.not_i:
	cmp	r12b,'n'
	jne	.not_n
	lea	rdi,[g_out]			; inversion mod n
	mov	rsi,r14
	lea	rcx,[p256_n]
	call	mod_inv
	jmp	.counted
.not_n:
	cmp	r12b,'g'
	jne	.not_g
	lea	rdi,[g_out]			; k * G
	mov	rsi,r14
	call	p256_mul_g
	jmp	.counted
.not_g:
	cmp	r12b,'x'
	jne	@f
	lea	rdi,[g_out]
	mov	rsi,r14
	lea	rdx,[r14+32]
	call	x25519
	jmp	.counted
@@:
	cmp	r12b,'c'
	jne	.not_c
	lea	rdi,[g_gcm]			; AES-128-GCM: key (16), IV (12), 16 KiB sealed in place
	mov	rsi,r14
	call	gcm_init
	lea	rdi,[g_gcm]
	lea	rsi,[r14+16]
	xor	edx,edx
	xor	ecx,ecx
	lea	r8,[r14+28]
	mov	r9d,16384
	call	gcm_seal
	jmp	.counted
.not_c:
	cmp	r12b,'u'
	jne	@f
	lea	rdi,[g_out]
	mov	rsi,r14
	call	x25519_base
	jmp	.counted
@@:
	lea	rdi,[g_label]
	mov	rsi,r14
	lea	rdx,[r14+32]
	call	p256_sign
.counted:
	dec	r13d
	jnz	.again
	call	.now
	sub	rax,r15				; total ns (the caller divides)
	lea	rdi,[g_in]
	call	out_u64_to
	jmp	.write_line
.now:
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000000
	add	rax,[rsp+8]
	add	rsp,16
	ret
.msqr:
	lea	rdi,[g_out]
	lea	rcx,[p256_p]
	call	mont_sqr
	mov	esi,32
	jmp	.print
.mont:
	; (debug) a, b: 4 limbs each, little endian; mont_mul mod p
	lea	rdi,[g_out]
	lea	rdx,[rsi+32]
	lea	rcx,[p256_p]
	call	mont_mul
	mov	esi,32
	jmp	.print
.p256_pub:
	lea	rdi,[g_out]
	call	p256_public
	mov	esi,65
	jmp	.print
.p256_sign:
	mov	rbx,rsi
	lea	rdi,[g_label]			; r | s
	lea	rdx,[rsi+32]
	call	p256_sign
	test	eax,eax
	jz	.wrong
	lea	rdi,[g_out]
	lea	rsi,[g_label]
	call	ecdsa_der
	mov	esi,eax
	jmp	.print
.x25519:
	lea	rdi,[g_out]
	lea	rdx,[rsi+32]
	call	x25519
	mov	esi,32
	jmp	.print
.x25519_base:
	lea	rdi,[g_out]
	call	x25519_base
	mov	esi,32
	jmp	.print
.client_hello:				; the rest of the input is the SNI
	mov	rdx,rsi				; sni (g_in+1)
	mov	ecx,dword [g_in_len]
	dec	ecx				; sni length = input - mode byte
	lea	rdi,[g_tc]
	lea	rsi,[g_out]
	call	tlsc_client_hello
	lea	rdi,[g_out]
	mov	esi,eax
	jmp	.print
.cert_verify:				; issuer_cert_len(u16) issuer_cert cert_len(u16) cert
	movzx	edx,word [rsi]			; issuer cert length
	lea	r12,[rsi+2]			; issuer cert
	lea	r13,[r12+rdx]			; the certificate to verify follows
	lea	rdi,[g_anchor]
	mov	rsi,r12
	call	cert_pubkey
	test	eax,eax
	jz	.cv_no
	movzx	edx,word [r13]			; cert length
	lea	rsi,[r13+2]
	lea	rdi,[g_anchor]
	call	cert_verify
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.cv_no:
	mov	byte [g_out],0
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.cert_time:				; now(14 ascii) cert_len(u16 le) cert_der
	movzx	edx,word [rsi+14]
	mov	rdi,rsi				; now
	lea	rsi,[rsi+16]			; cert der
	call	cert_time_valid
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.cert_host:				; hostlen(1) host cert_len(u16 le) cert_der
	movzx	ecx,byte [rsi]			; host length
	lea	rdi,[rsi+1]			; host
	movzx	edx,word [rsi+rcx+1]		; cert length
	lea	rsi,[rsi+rcx+3]			; cert der
	call	cert_match_host
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.cert_chain:				; anchor_cert_len(u16) anchor_cert list_len(u16) list
	movzx	edx,word [rsi]			; anchor cert length
	lea	r12,[rsi+2]			; anchor cert
	lea	r13,[r12+rdx]			; the CertificateEntry list follows
	lea	rdi,[g_anchor]
	mov	rsi,r12
	call	cert_pubkey
	test	eax,eax
	jz	.cv_no
	movzx	edx,word [r13]			; list length
	lea	rsi,[r13+2]
	lea	rdi,[g_anchor]
	call	cert_chain_verify
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.cert_pem:				; pem_len(u16 le) pem list_len(u16 le) list
	movzx	edx,word [rsi]			; PEM length
	lea	r12,[rsi+2]			; PEM text
	lea	r13,[r12+rdx]			; the chain that follows
	mov	rsi,r12
	lea	rdi,[g_der]
	call	pem_first_cert			; -> DER in g_der, eax = its length
	test	eax,eax
	jz	.pem_fail
	lea	rsi,[g_der]			; extract the anchor public key (EC or RSA)
	mov	edx,eax
	lea	rdi,[g_anchor]
	call	cert_pubkey
	test	eax,eax
	jz	.pem_fail
	movzx	edx,word [r13]			; the chain length
	lea	rsi,[r13+2]			; the chain
	lea	rdi,[g_anchor]
	call	cert_chain_verify
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.tls_prf:				; outlen(u16 le) seclen(u16 le) secret seedlen(u16 le) seed
	movzx	r13d,word [rsi]			; output length
	movzx	r14d,word [rsi+2]		; secret length
	lea	r15,[rsi+4]			; secret
	movzx	eax,word [rsi+r14+4]		; seed length
	lea	r8,[rsi+r14+6]			; seed
	mov	r9d,eax
	lea	rdi,[g_out]
	mov	esi,r13d
	mov	rdx,r15
	mov	ecx,r14d
	call	p_sha256
	lea	rdi,[g_out]
	mov	esi,r13d
	jmp	.print
.tls12_ks:				; premaster(32) cr(32) sr(32) hash(32)
	mov	r15,rsi				; input
	lea	rdi,[g_out]			; master_secret -> g_out[0..48]
	lea	rsi,[r15]
	mov	edx,32
	lea	rcx,[r15+32]			; client random
	lea	r8,[r15+64]			; server random
	call	tls12_master
	lea	rdi,[g_out+48]			; key_block(40) -> g_out[48..88]
	mov	esi,40
	lea	rdx,[g_out]			; master
	lea	rcx,[r15+64]			; server random
	lea	r8,[r15+32]			; client random
	call	tls12_key_block
	lea	rdi,[g_out+88]			; client finished verify_data
	lea	rsi,[g_out]
	lea	rdx,[tls12_lbl_cfin]
	mov	ecx,15
	lea	r8,[r15+96]			; transcript hash
	call	tls12_verify_data
	lea	rdi,[g_out+100]			; server finished verify_data
	lea	rsi,[g_out]
	lea	rdx,[tls12_lbl_sfin]
	mov	ecx,15
	lea	r8,[r15+96]
	call	tls12_verify_data
	lea	rdi,[g_out]
	mov	esi,112
	jmp	.print
.tls12_rec:				; key(16) salt(4) seq(8) type(1) ptlen(u16 le) pt
	mov	r15,rsi				; input
	lea	rdi,[g_gcm12]
	lea	rsi,[r15]			; key
	call	gcm_init
	movzx	ebx,word [r15+29]		; plaintext length
	lea	rdi,[g_out]			; seal -> g_out
	lea	rsi,[g_gcm12]
	lea	rdx,[r15+16]			; salt
	mov	rcx,[r15+20]			; seq
	movzx	r8d,byte [r15+28]		; type
	lea	r9,[r15+31]			; plaintext
	mov	r10d,ebx
	call	tls12_seal
	mov	r13d,eax			; record length
	; round-trip: open it back in place, must succeed and match
	lea	rdi,[g_out]
	mov	esi,r13d
	lea	rdx,[g_gcm12]
	lea	rcx,[r15+16]
	mov	r8,[r15+20]
	movzx	r9d,byte [r15+28]
	call	tls12_open
	cmp	eax,ebx
	jne	.rec_fail
	; output = the sealed record (so the host checks the exact bytes)
	lea	rdi,[g_out]			; re-seal for a clean ciphertext to print
	lea	rsi,[g_gcm12]
	lea	rdx,[r15+16]
	mov	rcx,[r15+20]
	movzx	r8d,byte [r15+28]
	lea	r9,[r15+31]
	mov	r10d,ebx
	call	tls12_seal
	lea	rdi,[g_out]
	mov	esi,eax
	jmp	.print
.bn_modexp:				; n(1) base(n*8) explen(u16 le) exp(BE) mod(n*8)
	movzx	r13d,byte [rsi]			; n limbs
	lea	r14,[rsi+1]			; base
	lea	rax,[r13*8]
	movzx	r12d,word [r14+rax]		; explen
	lea	r15,[r14+rax+2]			; exp (BE)
	lea	rdi,[r15+r12]			; mod
	push	rdi
	lea	rdi,[g_out]
	mov	rsi,r14
	mov	rdx,r15
	mov	ecx,r12d
	pop	r8
	mov	r9d,r13d
	call	bn_modexp
	lea	rdi,[g_out]
	lea	esi,[r13*8]
	jmp	.print
.rsa_verify:				; nbytes(u16 le) n_be sig_be e(u32 le) hash(32)
	movzx	r13d,word [rsi]			; nbytes
	lea	r14,[rsi+2]			; n (be)
	lea	r15,[r14+r13]			; sig (be)
	mov	rdi,r14
	mov	esi,r13d
	mov	rdx,r15
	mov	ecx,[r15+r13]			; e
	lea	r8,[r15+r13+4]			; hash
	call	rsa_pkcs1_verify
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.rsa_pss:				; nbytes(u16 le) n_be sig_be e(u32 le) hash(32)
	movzx	r13d,word [rsi]
	lea	r14,[rsi+2]			; n
	lea	r15,[r14+r13]			; sig
	mov	rdi,r14
	mov	esi,r13d
	mov	rdx,r15
	mov	ecx,[r15+r13]			; e
	lea	r8,[r15+r13+4]			; hash
	call	rsa_pss_verify
	mov	[g_out],al
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.rsa_sign:				; nbytes(u16 le) n_be d_be hash(32) -> sig_be
	movzx	r13d,word [rsi]			; nbytes
	lea	r14,[rsi+2]			; n
	lea	r15,[r14+r13]			; d
	lea	r8,[r15+r13]			; hash
	lea	rdi,[g_out]
	mov	rsi,r14
	mov	edx,r13d
	mov	rcx,r15
	call	rsa_pss_sign
	lea	rdi,[g_out]
	mov	esi,r13d
	jmp	.print
.rsa_pkcs1sign:				; nbytes(u16 le) n_be d_be hash(32) -> sig_be
	movzx	r13d,word [rsi]			; nbytes
	lea	r14,[rsi+2]			; n
	lea	r15,[r14+r13]			; d
	lea	r8,[r15+r13]			; hash
	lea	rdi,[g_out]
	mov	rsi,r14
	mov	edx,r13d
	mov	rcx,r15
	call	rsa_pkcs1_sign
	lea	rdi,[g_out]
	mov	esi,r13d
	jmp	.print
.rsa_key:				; keylen(u16 le) key_der -> n(nbytes)|d(nbytes)
	movzx	edx,word [rsi]			; key length
	lea	rsi,[rsi+2]			; key der
	lea	rdi,[g_out]			; n
	lea	rcx,[g_out+1024]		; d
	call	rsa_key_parse
	test	eax,eax
	jz	.rsa_key_fail
	mov	r13d,eax			; nbytes
	; pack n (g_out) then d (g_out+1024) into g_out contiguously
	lea	rdi,[g_out+r13]
	lea	rsi,[g_out+1024]
	mov	ecx,r13d
	rep	movsb
	lea	rdi,[g_out]
	lea	esi,[r13*2]
	jmp	.print
.rsa_key_fail:
	mov	byte [g_out],0
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.rsa_keysign:				; keylen(u16 le) key_der hash(32) -> sig
	movzx	edx,word [rsi]			; key length
	lea	r14,[rsi+2]			; key der
	lea	r15,[r14+rdx]			; hash follows the key
	mov	rsi,r14
	lea	rdi,[g_der+2048]		; n out
	lea	rcx,[g_der+4096]		; d out
	call	rsa_key_parse
	test	eax,eax
	jz	.rsa_key_fail
	mov	r13d,eax			; nbytes
	lea	rdi,[g_out]			; sign
	lea	rsi,[g_der+2048]		; n
	mov	edx,r13d
	lea	rcx,[g_der+4096]		; d
	mov	r8,r15				; hash
	call	rsa_pss_sign
	lea	rdi,[g_out]
	mov	esi,r13d
	jmp	.print
.rec_fail:
	mov	byte [g_out],0xEE
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.pem_fail:
	mov	byte [g_out],0
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.ecdsa_verify:				; pubkey(65) digest(32) r(32) s(32)
	mov	rdi,rsi
	lea	r8,[rsi+65]
	lea	r9,[rsi+65+32]
	lea	r10,[rsi+65+64]
	mov	rsi,r8
	mov	rdx,r9
	mov	rcx,r10
	call	p256_verify
	mov	[g_out],al			; 01 valid, 00 invalid
	lea	rdi,[g_out]
	mov	esi,1
	jmp	.print
.ecdh:
	lea	rdi,[g_out]			; scalar (32) then peer point (65)
	lea	rdx,[rsi+32]
	call	p256_ecdh
	test	eax,eax
	jz	.wrong
	lea	rdi,[g_out]
	mov	esi,32
.print:
	; g_out, esi bytes, as hex
	lea	rdi,[g_in]
	lea	r8,[g_out]
	xor	ecx,ecx
.hex:
	cmp	ecx,esi
	jae	.write
	movzx	eax,byte [r8+rcx]
	mov	edx,eax
	shr	eax,4
	mov	al,[.digits+rax]
	mov	[rdi],al
	and	edx,15
	mov	dl,[.digits+rdx]
	mov	[rdi+1],dl
	add	rdi,2
	inc	ecx
	jmp	.hex
.write_line:
.write:
	mov	byte [rdi],10
	inc	rdi
	lea	rsi,[g_in]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	edi,1
	mov	eax,SYS_write
	syscall
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall
.digits	db '0123456789abcdef'

; rax = value, rdi = output: decimal. rdi = after it.
out_u64_to:
	sub	rsp,24
	lea	rsi,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	rcx
	add	dl,'0'
	dec	rsi
	mov	[rsi],dl
	test	rax,rax
	jnz	@b
	lea	rcx,[rsp+24]
	sub	rcx,rsi
	rep	movsb
	add	rsp,24
	ret

segment readable
	rodata_emit

segment readable writeable
	bss_emit
