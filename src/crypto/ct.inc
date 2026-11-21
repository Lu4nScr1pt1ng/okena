; Constant-time and hygiene helpers for secrets.

; rdi = a, rsi = b, edx = length. eax = 1 when equal. The running time
; depends only on the length, never on where the first difference is.
ct_equal:
	cmp	edx,16
	je	.sixteen
	xor	eax,eax
	xor	ecx,ecx
	test	edx,edx
	jz	.done
.byte:
	mov	r8b,[rdi+rcx]
	xor	r8b,[rsi+rcx]
	or	al,r8b
	inc	ecx
	cmp	ecx,edx
	jb	.byte
.done:
	; eax = (al == 0) without a branch.
	movzx	eax,al
	sub	eax,1
	shr	eax,31
	ret
.sixteen:
	; an AEAD tag (every QUIC packet, every TLS record opened): two qwords,
	; the differences ORed, no branch on them
	mov	rax,[rdi]
	xor	rax,[rsi]
	mov	rcx,[rdi+8]
	xor	rcx,[rsi+8]
	or	rax,rcx
	sete	al
	movzx	eax,al
	ret

; rdi = buffer, ecx = length. Wipes secrets from memory; in assembly there
; is no optimizer that could drop the stores. 16 bytes a store (rep stosb
; costs more to start than these small frames take to clear); the last
; store overlaps when the length is not a multiple. Uses xmm15 (no other
; code does). eax = 0; rdi and rcx clobbered, as by rep stosb.
secure_zero:
	xor	eax,eax
	cmp	ecx,16
	jb	.bytes
	push	rdx
	pxor	xmm15,xmm15
	lea	rdx,[rdi+rcx-16]		; the last 16
.block:
	movdqu	[rdi],xmm15
	add	rdi,16
	cmp	rdi,rdx
	jb	.block
	movdqu	[rdx],xmm15
	pop	rdx
	ret
.bytes:
	rep	stosb
	ret

; Which crypto paths this CPU takes (once, before the workers start).
crypto_init:
	push	rbx
	mov	eax,7
	xor	ecx,ecx
	cpuid
	mov	eax,ebx
	shr	eax,19				; ADX (adcx, adox), with BMI2 (mulx) beside it
	and	eax,1
	mov	edx,ebx
	shr	edx,8
	and	eax,edx
	and	al,1
	mov	[g_cpu_adx],al
	shr	ebx,29				; SHA extensions
	and	bl,1
	mov	[g_cpu_shani],bl
	and	ecx,(1 shl 9) or (1 shl 10)	; VAES and VPCLMULQDQ, on ymm
	cmp	ecx,(1 shl 9) or (1 shl 10)
	sete	[g_cpu_vaes]
	pop	rbx
	ret
