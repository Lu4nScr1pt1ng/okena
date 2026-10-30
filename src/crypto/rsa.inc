; RSA (PKCS#1): big-integer modular exponentiation over variable-size
; moduli, for RSA signatures (verification first, then signing). Numbers
; are little-endian arrays of 64-bit limbs; n (the limb count) is passed
; in. Montgomery arithmetic (CIOS) provides the modular multiply.
;
;   bn_n0inv(rdi mod) -> rax = -mod[0]^-1 mod 2^64
;   bn_mont_mul(rdi out, rsi a, rdx b, rcx mod, r8 n0inv, r9d n): out =
;       a*b*R^-1 mod mod, R = 2^(64n). a, b < mod.
;   bn_rr(rdi out, rsi mod, edx n): out = R^2 mod mod
;   bn_modexp(rdi out, rsi base, rdx exp, ecx explen, r8 mod, r9d n):
;       out = base^exp mod mod. base < mod. exp is big-endian bytes.

; rdi = mod (little-endian limbs). rax = -mod[0]^-1 mod 2^64 (Newton).
bn_n0inv:
	mov	rcx,[rdi]			; n0 (odd)
	mov	rax,rcx				; x = n0 (good to 3 bits)
	mov	r8d,5				; 3,6,12,24,48,>=64 bits: 5 steps
.step:
	mov	r9,rcx
	imul	r9,rax				; n0*x
	neg	r9
	add	r9,2				; 2 - n0*x
	imul	rax,r9				; x *= (2 - n0*x)
	dec	r8d
	jnz	.step
	neg	rax				; -n0^-1
	ret

; rdi = out, rsi = a, rdx = b, rcx = mod, r8 = n0inv, r9d = n (limbs).
; out = a*b*R^-1 mod mod (CIOS). Needs a, b < mod.
bn_mont_mul:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rsi				; a
	mov	r13,rdx				; b
	mov	r14,rcx				; mod
	mov	r15,r8				; n0inv
	mov	ebp,r9d				; n
	mov	rbx,rdi				; out
	; t = stack array of n+2 limbs, zeroed
	lea	eax,[rbp+2]
	lea	rax,[rax*8+16]
	and	rax,-16
	sub	rsp,rax
	mov	rdi,rsp
	lea	ecx,[rbp+2]
	xor	eax,eax
	rep	stosq
	; for i in 0..n-1
	xor	r8d,r8d				; i
.outer:
	mov	r9,[r13+r8*8]			; bi = b[i]
	; carry/accumulate: t[j] += a[j]*bi
	xor	ecx,ecx				; j
	xor	r10,r10				; carry
.mul:
	mov	rax,[r12+rcx*8]
	mul	r9				; rdx:rax = a[j]*bi
	add	rax,[rsp+rcx*8]
	adc	rdx,0
	add	rax,r10
	adc	rdx,0
	mov	[rsp+rcx*8],rax
	mov	r10,rdx
	inc	ecx
	cmp	ecx,ebp
	jb	.mul
	add	[rsp+rbp*8],r10			; t[n] += carry
	mov	r11d,0
	adc	r11d,0				; t[n+1] = carry out
	mov	[rsp+rbp*8+8],r11
	; m = t[0]*n0inv mod 2^64
	mov	rax,[rsp]
	imul	rax,r15				; m
	mov	rsi,rax				; keep m in rsi
	; t[0] += m*mod[0] (low discarded, carry kept)
	mul	qword [r14]			; m*mod[0]
	add	rax,[rsp]
	adc	rdx,0
	mov	r10,rdx				; carry
	mov	ecx,1				; j from 1
.reduce:
	mov	rax,rsi
	mul	qword [r14+rcx*8]		; m*mod[j]
	add	rax,[rsp+rcx*8]
	adc	rdx,0
	add	rax,r10
	adc	rdx,0
	mov	[rsp+rcx*8-8],rax		; t[j-1] = ...
	mov	r10,rdx
	inc	ecx
	cmp	ecx,ebp
	jb	.reduce
	; t[n-1] = t[n] + carry; propagate to t[n]
	mov	rax,[rsp+rbp*8]
	add	rax,r10
	mov	[rsp+rbp*8-8],rax
	mov	eax,0
	adc	eax,0
	add	eax,[rsp+rbp*8+8]		; t[n] = t[n+1] + carryout
	mov	[rsp+rbp*8],rax
	inc	r8d
	cmp	r8d,ebp
	jb	.outer
	; final: if t >= mod (counting the extra top limb t[n]) then t -= mod.
	; a trial subtract into out; `loop` and `lea` keep CF across iterations.
	mov	r11,[rsp+rbp*8]			; t[n]
	mov	rcx,rbp				; limb count
	xor	esi,esi				; index
	clc
.trysub:
	mov	rax,[rsp+rsi*8]
	sbb	rax,[r14+rsi*8]
	mov	[rbx+rsi*8],rax			; out = t - mod (tentative)
	lea	rsi,[rsi+1]
	loop	.trysub				; preserves CF
	sbb	r11,0				; borrow through t[n]
	jnc	.done				; t >= mod: keep out = t - mod
	xor	ecx,ecx				; t < mod: copy t into out
.copy:
	mov	rax,[rsp+rcx*8]
	mov	[rbx+rcx*8],rax
	inc	ecx
	cmp	ecx,ebp
	jb	.copy
.done:
	lea	eax,[rbp+2]
	lea	rax,[rax*8+16]
	and	rax,-16
	add	rsp,rax
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = mod, edx = n (limbs): out = R^2 mod mod, R = 2^(64n).
; Starts at 1 and doubles modulo mod 128n times. Scratch (n limbs) on the
; stack holds the trial subtract.
bn_rr:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi				; out
	mov	r13,rsi				; mod
	mov	r14d,edx			; n
	mov	eax,r14d
	shl	eax,3
	add	eax,16
	and	eax,-16
	mov	r15d,eax			; frame size
	sub	rsp,rax
	mov	rcx,r14				; out = 1
	xor	eax,eax
	mov	rdi,r12
	rep	stosq
	mov	qword [r12],1
	mov	ebx,r14d			; count = 128n (reuse ebx high? use a push)
	shl	ebx,7
.loop:
	mov	rcx,r14				; out += out (double), CF = overflow
	xor	esi,esi
	clc
.dbl:
	mov	rax,[r12+rsi*8]
	adc	rax,rax
	mov	[r12+rsi*8],rax
	lea	rsi,[rsi+1]
	loop	.dbl
	setc	r8b				; overflow out of the top
	mov	rcx,r14				; scratch = out - mod, borrow in r9b
	xor	esi,esi
	clc
.sub:
	mov	rax,[r12+rsi*8]
	sbb	rax,[r13+rsi*8]
	mov	[rsp+rsi*8],rax
	lea	rsi,[rsi+1]
	loop	.sub
	setc	r9b				; borrow (out < mod)
	test	r8b,r8b
	jnz	.take				; overflowed R: must reduce
	test	r9b,r9b
	jnz	.next				; out < mod: keep out
.take:
	mov	rcx,r14				; out = scratch (out - mod)
	xor	esi,esi
.cp:
	mov	rax,[rsp+rsi*8]
	mov	[r12+rsi*8],rax
	lea	rsi,[rsi+1]
	loop	.cp
.next:
	dec	ebx
	jnz	.loop
	add	rsp,r15
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, rsi = base, rdx = exp (big-endian bytes), ecx = exp length,
; r8 = mod, r9d = n (limbs): out = base^exp mod mod. base < mod.
; Frame (offsets from rsp): rr(n) | base_mont(n) | result(n) | tmp(n) at
; 0,8n,16n,24n; then slots out,mod,exp,explen,n0inv at 32n+{0,8,16,24,32}.
; Loop state stays in r12-r15 (bn_mont_mul preserves them).
bn_modexp:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r15d,r9d			; n
	mov	r12,rsi				; base (until base_mont is formed)
	lea	eax,[r15*8]
	shl	eax,2				; 32n
	add	eax,48
	and	eax,-16
	mov	ebp,eax				; frame size
	sub	rsp,rbp
	lea	r11,[r15*8]
	shl	r11,2				; 32n = slots base
	mov	[rsp+r11],rdi			; out
	mov	[rsp+r11+8],r8			; mod
	mov	[rsp+r11+16],rdx		; exp
	mov	[rsp+r11+24],ecx		; explen
	mov	rdi,r8				; n0inv
	call	bn_n0inv
	lea	r11,[r15*8]
	shl	r11,2
	mov	[rsp+r11+32],rax
	lea	rax,[r15*2]			; rbx = result buffer (offset 16n), kept across calls
	lea	rbx,[rsp+rax*8]
	mov	rdi,rsp				; rr = R^2 mod mod
	mov	rsi,[rsp+r11+8]
	mov	edx,r15d
	call	bn_rr
	lea	r11,[r15*8]
	shl	r11,2
	lea	rdi,[rsp+r15*8]			; base_mont = base * rr
	mov	rsi,r12
	mov	rdx,rsp
	mov	rcx,[rsp+r11+8]
	mov	r8,[rsp+r11+32]
	mov	r9d,r15d
	call	bn_mont_mul
	mov	rdi,rbx		; result = 1
	mov	rcx,r15
	xor	eax,eax
	push	rdi
	rep	stosq
	pop	rdi
	mov	qword [rdi],1
	lea	r11,[r15*8]
	shl	r11,2
	mov	rsi,rdi				; result = 1 * rr = R mod mod
	mov	rdx,rsp
	mov	rcx,[rsp+r11+8]
	mov	r8,[rsp+r11+32]
	mov	r9d,r15d
	mov	rdi,rbx
	call	bn_mont_mul
	xor	r12d,r12d			; byte index
.byte:
	lea	r11,[r15*8]
	shl	r11,2
	cmp	r12d,[rsp+r11+24]		; explen
	jae	.doneexp
	mov	rsi,[rsp+r11+16]		; exp ptr
	movzx	r13d,byte [rsi+r12]		; exp byte
	mov	r14d,8
.bit:
	lea	rax,[r15+r15*2]			; 3n -> tmp
	lea	rdi,[rsp+rax*8]
	mov	rsi,rbx		; result
	mov	rdx,rsi
	lea	r11,[r15*8]
	shl	r11,2
	mov	rcx,[rsp+r11+8]
	mov	r8,[rsp+r11+32]
	mov	r9d,r15d
	call	bn_mont_mul			; tmp = result^2
	lea	rax,[r15+r15*2]
	lea	rsi,[rsp+rax*8]
	mov	rdi,rbx
	mov	rcx,r15
	rep	movsq				; result = tmp
	test	r13b,0x80
	jz	.nomul
	lea	rax,[r15+r15*2]
	lea	rdi,[rsp+rax*8]			; tmp = result * base_mont
	mov	rsi,rbx
	lea	rdx,[rsp+r15*8]
	lea	r11,[r15*8]
	shl	r11,2
	mov	rcx,[rsp+r11+8]
	mov	r8,[rsp+r11+32]
	mov	r9d,r15d
	call	bn_mont_mul
	lea	rax,[r15+r15*2]
	lea	rsi,[rsp+rax*8]
	mov	rdi,rbx
	mov	rcx,r15
	rep	movsq
.nomul:
	shl	r13b,1
	dec	r14d
	jnz	.bit
	inc	r12d
	jmp	.byte
.doneexp:
	lea	rax,[r15+r15*2]			; tmp = 1
	lea	rdi,[rsp+rax*8]
	mov	rcx,r15
	xor	eax,eax
	push	rdi
	rep	stosq
	pop	rdi
	mov	qword [rdi],1
	lea	r11,[r15*8]
	shl	r11,2
	mov	rdi,[rsp+r11]			; out = result * 1 (leave Montgomery)
	mov	rsi,rbx
	lea	rax,[r15+r15*2]
	lea	rdx,[rsp+rax*8]
	mov	rcx,[rsp+r11+8]
	mov	r8,[rsp+r11+32]
	mov	r9d,r15d
	call	bn_mont_mul
	add	rsp,rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

rodata
	; the SHA-256 DigestInfo prefix for PKCS#1 v1.5 (RFC 8017 9.2)
	rsa_sha256_di	db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
	RSA_DI_LEN	:= $ - rsa_sha256_di
end rodata

; big-endian bytes -> little-endian limbs. rdi = limbs out, rsi = bytes,
; edx = byte length (a multiple of 8). Fills edx/8 limbs.
bn_from_be:
	mov	ecx,edx				; byte length
	xor	r8d,r8d				; limb index
.l:
	mov	rax,[rsi+rcx-8]			; the next 8 bytes (toward the LSB end)
	bswap	rax
	mov	[rdi+r8*8],rax
	inc	r8d
	sub	ecx,8
	jnz	.l
	ret

; little-endian limbs -> big-endian bytes. rdi = bytes out, rsi = limbs,
; edx = byte length (a multiple of 8).
bn_to_be:
	mov	ecx,edx
	xor	r8d,r8d
.l:
	mov	rax,[rsi+r8*8]
	bswap	rax
	mov	[rdi+rcx-8],rax
	inc	r8d
	sub	ecx,8
	jnz	.l
	ret

; rdi = modulus n (big-endian, nbytes), esi = nbytes (multiple of 8),
; rdx = signature (big-endian, nbytes), ecx = public exponent e (a small
; integer), r8 = message hash (32 bytes, SHA-256): eax = 1 when the PKCS#1
; v1.5 signature verifies, else 0. For verifying RSA certificate chains.
rsa_pkcs1_verify:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi				; n be
	mov	r13d,esi			; nbytes
	mov	r14,rdx				; sig be
	mov	r15,r8				; hash
	mov	ebp,ecx				; e
	; frame: n_le | sig_le | m_le | em_be (nbytes each) + exp(8)
	mov	eax,r13d
	shl	eax,2				; 4*nbytes
	add	eax,32
	and	eax,-16
	mov	ebx,eax
	sub	rsp,rax
	; convert n and sig to little-endian limbs
	mov	rdi,rsp				; n_le at 0
	mov	rsi,r12
	mov	edx,r13d
	call	bn_from_be
	lea	rdi,[rsp+r13]			; sig_le at nbytes
	mov	rsi,r14
	mov	edx,r13d
	call	bn_from_be
	; exp (big-endian minimal) at [rsp+4*nbytes]
	lea	r8,[rsp+r13*4]
	mov	rax,rbp
	bswap	rax				; e big-endian in a qword
	mov	[r8],rax
	; find the first non-zero byte of the 8-byte big-endian e
	xor	ecx,ecx
.elen:
	cmp	byte [r8+rcx],0
	jne	.egot
	inc	ecx
	cmp	ecx,8
	jb	.elen
.egot:
	lea	rdx,[r8+rcx]			; exp bytes start
	mov	eax,8
	sub	eax,ecx				; exp length
	; m_le = sig^e mod n  (m_le at [rsp+2*nbytes])
	push	rax
	push	rdx
	lea	rdi,[rsp+16+r13*2]		; m_le
	lea	rsi,[rsp+16+r13]		; sig_le
	mov	rdx,[rsp]			; exp ptr
	mov	ecx,[rsp+8]			; exp len
	mov	r8,rsp
	add	r8,16				; n_le
	mov	r9d,r13d
	shr	r9d,3				; nlimbs
	call	bn_modexp
	add	rsp,16
	; m_be = m_le converted back, at [rsp+3*nbytes]
	lea	rdi,[rsp+r13*2]
	add	rdi,r13				; 3*nbytes (em_be)
	lea	rsi,[rsp+r13*2]			; m_le
	mov	edx,r13d
	call	bn_to_be
	; check EM = 00 01 FF..FF 00 | DigestInfo | hash
	lea	rbx,[rsp+r13*2]
	add	rbx,r13				; em_be
	cmp	byte [rbx],0x00
	jne	.no
	cmp	byte [rbx+1],0x01
	jne	.no
	; DigestInfo starts at nbytes - (RSA_DI_LEN + 32)
	mov	ecx,r13d
	sub	ecx,RSA_DI_LEN + 32		; offset of DigestInfo
	; the separator byte just before it must be 0x00
	cmp	byte [rbx+rcx-1],0x00
	jne	.no
	; bytes [2, ecx-1) must all be 0xFF (and at least 8 of them)
	mov	edx,ecx
	sub	edx,1				; end of padding (exclusive)
	mov	eax,edx
	sub	eax,2
	cmp	eax,8
	jb	.no
	mov	esi,2
.pad:
	cmp	esi,edx
	jae	.padok
	cmp	byte [rbx+rsi],0xFF
	jne	.no
	inc	esi
	jmp	.pad
.padok:
	; addresses first (ct_equal clobbers rcx)
	lea	r12,[rbx+rcx]			; DigestInfo prefix
	lea	rbp,[rbx+rcx+RSA_DI_LEN]		; the hash
	mov	rdi,r12
	lea	rsi,[rsa_sha256_di]
	mov	edx,RSA_DI_LEN
	call	ct_equal
	test	eax,eax
	jz	.no
	mov	rdi,rbp
	mov	rsi,r15
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.no
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	mov	r9d,eax				; keep the verdict across the stack restore
	mov	eax,r13d				; frame = 4*nbytes + 32, aligned
	shl	eax,2
	add	eax,32
	and	eax,-16
	add	rsp,rax
	mov	eax,r9d
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
