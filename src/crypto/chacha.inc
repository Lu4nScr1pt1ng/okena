; ChaCha20-Poly1305 (RFC 8439), for TLS_CHACHA20_POLY1305_SHA256: the
; AEAD of clients without AES in hardware (they list it first).
;
; ChaCha20 on AVX2, eight blocks at a time while 512 bytes are left: one
; ymm per state word, its eight dwords the eight blocks, so a quarter
; round is plain lane-wise arithmetic. Sixteen words and two temporaries
; do not fit sixteen registers: the third row (words 8..11) takes turns,
; two in registers and two on the stack. The key stream comes out by a
; 4x4 dword transpose and a 128-bit lane swap. Below 512 bytes, two
; blocks at a time: the state's four rows in four ymm, block n in the low
; 128-bit lane and block n + 1 in the high one.
;
; Poly1305 on long messages four blocks at a time on AVX2, radix 2^26:
; four lanes each carry h for every fourth block and are multiplied by
; r^4; the last four by r^4, r^3, r^2, r, summed into one. Short messages
; and what is left over go through the scalar code, radix 2^64 with mulx:
; h in three limbs (the top one a few bits), r clamped, 2^130 = 5 folded
; in as s1 = r1 + r1 / 4. Nothing branches on or indexes by secret data.
;
;   cp_init(rdi ctx, rsi key[32])
;   cp_seal(rdi ctx, rsi iv[12], rdx aad, ecx aad length, r8 buffer,
;           r9 length): encrypts the buffer in place, the 16-byte tag
;           right after it
;   cp_open(same): eax = 1 and the buffer decrypted when the tag after it
;           is right; eax = 0 and the buffer untouched otherwise (the tag
;           is checked before anything is decrypted)
;   chacha20_xor(rdi key[32], rsi nonce[12], edx counter, rcx buffer,
;           r8 length): the buffer XORed with the key stream

CP_KEY		:= 0
CP_SIZE		:= 32

rodata
	align 32
	chacha_sigma	db 'expand 32-byte k', 'expand 32-byte k'
	chacha_rot16	db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
			db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
	chacha_rot8	db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
			db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
	chacha_inc2	dd 0,0,0,0, 1,0,0,0		; the high lane's block: counter + 1
	chacha_add2	dd 2,0,0,0, 2,0,0,0
	chacha_lanes8	dd 0,1,2,3,4,5,6,7		; word 12 of the eight blocks
	chacha_eight	dd 8,8,8,8,8,8,8,8
	pv_mask26	dq 0x3FFFFFF
	pv_hibit	dq 1 shl 24			; 2^128 in the top limb
end rodata

; one ChaCha quarter round on the rows a, b, c, d (ymm0..ymm3), every
; column at once; ymm4 scratch, ymm14 = rot16, ymm15 = rot8
macro cc_quarter
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufb	ymm3,ymm3,ymm14
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vpslld	ymm4,ymm1,12
	vpsrld	ymm1,ymm1,20
	vpor	ymm1,ymm1,ymm4
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufb	ymm3,ymm3,ymm15
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vpslld	ymm4,ymm1,7
	vpsrld	ymm1,ymm1,25
	vpor	ymm1,ymm1,ymm4
end macro

; ymm8..ymm11 = the initial rows of two blocks: their key stream, 128
; bytes, in ymm0..ymm3 (block n then block n + 1). Clobbers ymm4, ecx.
cc_two_blocks:
	vmovdqa	ymm0,ymm8
	vmovdqa	ymm1,ymm9
	vmovdqa	ymm2,ymm10
	vmovdqa	ymm3,ymm11
	mov	ecx,10
.double:
	cc_quarter				; columns
	vpshufd	ymm1,ymm1,0x39
	vpshufd	ymm2,ymm2,0x4E
	vpshufd	ymm3,ymm3,0x93
	cc_quarter				; diagonals
	vpshufd	ymm1,ymm1,0x93
	vpshufd	ymm2,ymm2,0x4E
	vpshufd	ymm3,ymm3,0x39
	dec	ecx
	jnz	.double
	vpaddd	ymm0,ymm0,ymm8
	vpaddd	ymm1,ymm1,ymm9
	vpaddd	ymm2,ymm2,ymm10
	vpaddd	ymm3,ymm3,ymm11
	vperm2i128 ymm4,ymm0,ymm1,0x20		; block n: rows 0, 1
	vperm2i128 ymm5,ymm2,ymm3,0x20		; rows 2, 3
	vperm2i128 ymm6,ymm0,ymm1,0x31		; block n + 1
	vperm2i128 ymm7,ymm2,ymm3,0x31
	vmovdqa	ymm0,ymm4
	vmovdqa	ymm1,ymm5
	vmovdqa	ymm2,ymm6
	vmovdqa	ymm3,ymm7
	ret

; two quarter rounds side by side, eight blocks each; ymm14, ymm15 scratch
macro cc_qr2 a1,b1,c1,d1, a2,b2,c2,d2
	vpaddd	a1,a1,b1
	vpaddd	a2,a2,b2
	vpxor	d1,d1,a1
	vpxor	d2,d2,a2
	vpshufb	d1,d1,yword [chacha_rot16]
	vpshufb	d2,d2,yword [chacha_rot16]
	vpaddd	c1,c1,d1
	vpaddd	c2,c2,d2
	vpxor	b1,b1,c1
	vpxor	b2,b2,c2
	vpslld	ymm14,b1,12
	vpslld	ymm15,b2,12
	vpsrld	b1,b1,20
	vpsrld	b2,b2,20
	vpor	b1,b1,ymm14
	vpor	b2,b2,ymm15
	vpaddd	a1,a1,b1
	vpaddd	a2,a2,b2
	vpxor	d1,d1,a1
	vpxor	d2,d2,a2
	vpshufb	d1,d1,yword [chacha_rot8]
	vpshufb	d2,d2,yword [chacha_rot8]
	vpaddd	c1,c1,d1
	vpaddd	c2,c2,d2
	vpxor	b1,b1,c1
	vpxor	b2,b2,c2
	vpslld	ymm14,b1,7
	vpslld	ymm15,b2,7
	vpsrld	b1,b1,25
	vpsrld	b2,b2,25
	vpor	b1,b1,ymm14
	vpor	b2,b2,ymm15
end macro

; four ymm of one word each (eight blocks) -> per 128-bit lane, four words
; of one block: a = blocks 0 | 4, b = 1 | 5, c = 2 | 6, d = 3 | 7
macro cc_t4 a,b,c,d, t0,t1,t2,t3
	vpunpckldq t0,a,b
	vpunpckhdq t1,a,b
	vpunpckldq t2,c,d
	vpunpckhdq t3,c,d
	vpunpcklqdq a,t0,t2
	vpunpckhqdq b,t0,t2
	vpunpcklqdq c,t1,t3
	vpunpckhqdq d,t1,t3
end macro

; the 32-byte halves of blocks n and n + 4 (lo, hi: words 0-3 | 4-7 or
; 8-11 | 12-15 of both), XORed into the buffer at rsi + off
macro cc_out lo,hi, off, t
	vperm2i128 t,lo,hi,0x20
	vpxor	t,t,[rsi+off]
	vmovdqu	[rsi+off],t
	vperm2i128 t,lo,hi,0x31
	vpxor	t,t,[rsi+off+256]
	vmovdqu	[rsi+off+256],t
end macro

CC_TAIL		:= 0				; 128: the last key stream, bytewise
CC_INIT		:= 128				; 16 x 32: the eight blocks' input words
CC_C		:= CC_INIT + 512		; 4 x 32: words 8..11 while they take turns
CC_X		:= CC_C + 128			; 4 x 32: words 12..15 at the end
CC_MISC		:= CC_X + 128			; the round count; cp_xmac's state, length, mode
CC_FRAME	:= CC_MISC + 32

; [rsp] = the counter edx | the nonce at r9, for the two-block code
macro cc_counter
	mov	[rsp],edx
	mov	eax,[r9]
	mov	[rsp+4],eax
	mov	rax,[r9+4]
	mov	[rsp+8],rax
end macro

; CC_INIT from the key at rdi, the nonce at r9, the counter edx. Clobbers
; eax, ymm0..3.
macro cc8_setup
	vpbroadcastd ymm0,dword [chacha_sigma]
	vpbroadcastd ymm1,dword [chacha_sigma+4]
	vpbroadcastd ymm2,dword [chacha_sigma+8]
	vpbroadcastd ymm3,dword [chacha_sigma+12]
	vmovdqa	[rsp+CC_INIT],ymm0
	vmovdqa	[rsp+CC_INIT+32],ymm1
	vmovdqa	[rsp+CC_INIT+64],ymm2
	vmovdqa	[rsp+CC_INIT+96],ymm3
	xor	eax,eax
local key
key:
	vpbroadcastd ymm0,dword [rdi+rax]	; the key, words 4..11
	vmovdqa	[rsp+CC_INIT+128+rax*8],ymm0
	add	eax,4
	cmp	eax,32
	jb	key
	vmovd	xmm0,edx
	vpbroadcastd ymm0,xmm0
	vpaddd	ymm0,ymm0,yword [chacha_lanes8]
	vmovdqa	[rsp+CC_INIT+12*32],ymm0
	vpbroadcastd ymm0,dword [r9]
	vpbroadcastd ymm1,dword [r9+4]
	vpbroadcastd ymm2,dword [r9+8]
	vmovdqa	[rsp+CC_INIT+13*32],ymm0
	vmovdqa	[rsp+CC_INIT+14*32],ymm1
	vmovdqa	[rsp+CC_INIT+15*32],ymm2
end macro

; eight blocks of key stream XORed into the 512 bytes at rsi; the counter
; moved on by eight. With mac = 1, Poly1305 takes the 32 blocks at rdi
; meanwhile (h in r8..r10, r in r11..r13, rdi moved past them): the scalar
; multiplier runs on the integer side while ChaCha keeps the vector side
; busy. The 32 are read before any byte at rsi is written. Clobbers rax,
; rbx, rcx, rdx, r14, r15 with mac = 1, nothing else outside the ymm.
macro cc8_block mac
	vmovdqa	ymm10,[rsp+CC_INIT+10*32]
	vmovdqa	ymm11,[rsp+CC_INIT+11*32]
	vmovdqa	[rsp+CC_C+64],ymm10
	vmovdqa	[rsp+CC_C+96],ymm11
	vmovdqa	ymm0,[rsp+CC_INIT]
	vmovdqa	ymm1,[rsp+CC_INIT+32]
	vmovdqa	ymm2,[rsp+CC_INIT+64]
	vmovdqa	ymm3,[rsp+CC_INIT+96]
	vmovdqa	ymm4,[rsp+CC_INIT+128]
	vmovdqa	ymm5,[rsp+CC_INIT+160]
	vmovdqa	ymm6,[rsp+CC_INIT+192]
	vmovdqa	ymm7,[rsp+CC_INIT+224]
	vmovdqa	ymm8,[rsp+CC_INIT+256]
	vmovdqa	ymm9,[rsp+CC_INIT+288]
	vmovdqa	ymm10,[rsp+CC_INIT+384]
	vmovdqa	ymm11,[rsp+CC_INIT+416]
	vmovdqa	ymm12,[rsp+CC_INIT+448]
	vmovdqa	ymm13,[rsp+CC_INIT+480]
	mov	dword [rsp+CC_MISC],10
local dround
dround:						; ymm0-7 words 0-7, ymm10-13 words 12-15
	cc_qr2	ymm0,ymm4,ymm8,ymm10, ymm1,ymm5,ymm9,ymm11	; columns 0, 1 (words 8, 9 in)
	if mac
		py_block
	end if
	vmovdqa	[rsp+CC_C],ymm8
	vmovdqa	[rsp+CC_C+32],ymm9
	vmovdqa	ymm8,[rsp+CC_C+64]
	vmovdqa	ymm9,[rsp+CC_C+96]
	cc_qr2	ymm2,ymm6,ymm8,ymm12, ymm3,ymm7,ymm9,ymm13	; columns 2, 3 (words 10, 11 in)
	if mac
		py_block
	end if
	cc_qr2	ymm0,ymm5,ymm8,ymm13, ymm1,ymm6,ymm9,ymm10	; diagonals 0-5-10-15, 1-6-11-12
	if mac
		py_block
	end if
	vmovdqa	[rsp+CC_C+64],ymm8
	vmovdqa	[rsp+CC_C+96],ymm9
	vmovdqa	ymm8,[rsp+CC_C]
	vmovdqa	ymm9,[rsp+CC_C+32]
	cc_qr2	ymm2,ymm7,ymm8,ymm11, ymm3,ymm4,ymm9,ymm12	; diagonals 2-7-8-13, 3-4-9-14
	dec	dword [rsp+CC_MISC]
	jnz	dround
	vmovdqa	[rsp+CC_C],ymm8			; words 8..15 wait on the stack
	vmovdqa	[rsp+CC_C+32],ymm9
	vmovdqa	[rsp+CC_X],ymm10
	vmovdqa	[rsp+CC_X+32],ymm11
	vmovdqa	[rsp+CC_X+64],ymm12
	vmovdqa	[rsp+CC_X+96],ymm13
	if mac
		py_block			; 30 in the rounds, the last two here
	end if
	vpaddd	ymm0,ymm0,[rsp+CC_INIT]		; words 0..7: the first halves
	vpaddd	ymm1,ymm1,[rsp+CC_INIT+32]
	vpaddd	ymm2,ymm2,[rsp+CC_INIT+64]
	vpaddd	ymm3,ymm3,[rsp+CC_INIT+96]
	vpaddd	ymm4,ymm4,[rsp+CC_INIT+128]
	vpaddd	ymm5,ymm5,[rsp+CC_INIT+160]
	vpaddd	ymm6,ymm6,[rsp+CC_INIT+192]
	vpaddd	ymm7,ymm7,[rsp+CC_INIT+224]
	if mac
		py_block
	end if
	cc_t4	ymm0,ymm1,ymm2,ymm3, ymm8,ymm9,ymm10,ymm11
	cc_t4	ymm4,ymm5,ymm6,ymm7, ymm8,ymm9,ymm10,ymm11
	cc_out	ymm0,ymm4, 0, ymm8
	cc_out	ymm1,ymm5, 64, ymm9
	cc_out	ymm2,ymm6, 128, ymm10
	cc_out	ymm3,ymm7, 192, ymm11
	vmovdqa	ymm0,[rsp+CC_C]			; words 8..15: the second halves
	vmovdqa	ymm1,[rsp+CC_C+32]
	vmovdqa	ymm2,[rsp+CC_C+64]
	vmovdqa	ymm3,[rsp+CC_C+96]
	vmovdqa	ymm4,[rsp+CC_X]
	vmovdqa	ymm5,[rsp+CC_X+32]
	vmovdqa	ymm6,[rsp+CC_X+64]
	vmovdqa	ymm7,[rsp+CC_X+96]
	vpaddd	ymm0,ymm0,[rsp+CC_INIT+256]
	vpaddd	ymm1,ymm1,[rsp+CC_INIT+288]
	vpaddd	ymm2,ymm2,[rsp+CC_INIT+320]
	vpaddd	ymm3,ymm3,[rsp+CC_INIT+352]
	vpaddd	ymm4,ymm4,[rsp+CC_INIT+384]
	vpaddd	ymm5,ymm5,[rsp+CC_INIT+416]
	vpaddd	ymm6,ymm6,[rsp+CC_INIT+448]
	vpaddd	ymm7,ymm7,[rsp+CC_INIT+480]
	cc_t4	ymm0,ymm1,ymm2,ymm3, ymm8,ymm9,ymm10,ymm11
	cc_t4	ymm4,ymm5,ymm6,ymm7, ymm8,ymm9,ymm10,ymm11
	cc_out	ymm0,ymm4, 32, ymm8
	cc_out	ymm1,ymm5, 96, ymm9
	cc_out	ymm2,ymm6, 160, ymm10
	cc_out	ymm3,ymm7, 224, ymm11
	vmovdqa	ymm0,[rsp+CC_INIT+12*32]	; the next eight blocks
	vpaddd	ymm0,ymm0,yword [chacha_eight]
	vmovdqa	[rsp+CC_INIT+12*32],ymm0
	add	dword [rsp],8
end macro

; the key stream and the key off the stack: the first `bytes` of the frame
; of chacha20_xor or cp_xmac
macro cc_wipe bytes
	vpxor	ymm0,ymm0,ymm0
	xor	eax,eax
local more
more:
	vmovdqa	[rsp+rax],ymm0
	add	eax,32
	cmp	eax,bytes
	jb	more
end macro

chacha20_xor:
	push	rbp
	mov	rbp,rsp
	sub	rsp,CC_FRAME
	and	rsp,-32
	mov	r9,rsi				; the nonce
	mov	rsi,rcx				; the buffer
	mov	rcx,r8				; what is left
	cc_counter
	mov	r10d,CC_INIT			; what to wipe: the tail only
	cmp	rcx,512
	jb	.short
	mov	r10d,CC_FRAME			; all of it
	cc8_setup
.eight:
	cc8_block 0
	add	rsi,512
	sub	rcx,512
	cmp	rcx,512
	jae	.eight
.short:
	mov	rdx,rcx
	vmovdqa	ymm8,yword [chacha_sigma]
	vbroadcasti128 ymm9,[rdi]
	vbroadcasti128 ymm10,[rdi+16]
	vbroadcasti128 ymm11,[rsp]
	vpaddd	ymm11,ymm11,yword [chacha_inc2]
	vmovdqa	ymm14,yword [chacha_rot16]
	vmovdqa	ymm15,yword [chacha_rot8]
.two:
	test	rdx,rdx
	jz	.done
	call	cc_two_blocks
	vpaddd	ymm11,ymm11,yword [chacha_add2]
	cmp	rdx,128
	jb	.tail
	vpxor	ymm0,ymm0,[rsi]
	vpxor	ymm1,ymm1,[rsi+32]
	vpxor	ymm2,ymm2,[rsi+64]
	vpxor	ymm3,ymm3,[rsi+96]
	vmovdqu	[rsi],ymm0
	vmovdqu	[rsi+32],ymm1
	vmovdqu	[rsi+64],ymm2
	vmovdqu	[rsi+96],ymm3
	add	rsi,128
	sub	rdx,128
	jmp	.two
.tail:
	vmovdqa	[rsp],ymm0
	vmovdqa	[rsp+32],ymm1
	vmovdqa	[rsp+64],ymm2
	vmovdqa	[rsp+96],ymm3
	xor	ecx,ecx
@@:
	mov	al,[rsp+rcx]
	xor	[rsi+rcx],al
	inc	ecx
	cmp	rcx,rdx
	jb	@b
.done:
	cc_wipe r10d
	mov	rsp,rbp
	pop	rbp
	vzeroupper
	ret

; ---------------------------------------------------------------- Poly1305

PY_H0		:= 0
PY_H1		:= 8
PY_H2		:= 16
PY_R0		:= 24
PY_R1		:= 32
PY_S1		:= 40
PY_S		:= 48				; 16 bytes
PY_BUF		:= 64				; a padded block (16)
PY_SIZE		:= 80

; h (r8, r9, r10) = h * r mod 2^130 - 5, partly reduced (h2 at most 4);
; r11 = r0, r12 = r1, r13 = s1. Clobbers rax, rbx, rcx, rdx, r14, r15.
macro py_mul
	mov	rdx,r8				; 2^130 folded back as 5
	mulx	rbx,rax,r11			; h0 r0
	mulx	r15,r14,r12			; h0 r1
	mov	rdx,r9
	mulx	rdx,rcx,r13			; h1 s1
	add	rax,rcx
	adc	rbx,rdx
	mov	rdx,r9
	mulx	rdx,rcx,r11			; h1 r0
	add	r14,rcx
	adc	r15,rdx
	mov	rcx,r10
	imul	rcx,r13				; h2 s1 (h2 is a few bits)
	add	r14,rcx
	adc	r15,0
	imul	r10,r11				; h2 r0
	mov	r8,rax				; h0
	add	r14,rbx
	adc	r15,0
	mov	r9,r14				; h1
	add	r10,r15				; h2
	py_fold
end macro

; h2 above 2 bits comes back times 5 (2^130 = 5)
macro py_fold
	mov	rax,r10
	and	rax,-4
	mov	rcx,r10
	shr	rcx,2
	and	r10,3
	add	rax,rcx
	add	r8,rax
	adc	r9,0
	adc	r10,0
end macro

; rdi = state, rsi = key[32] (r | s)
poly_init:
	xor	eax,eax
	mov	[rdi+PY_H0],rax
	mov	[rdi+PY_H1],rax
	mov	[rdi+PY_H2],rax
	mov	rax,0x0FFFFFFC0FFFFFFF
	and	rax,[rsi]
	mov	[rdi+PY_R0],rax
	mov	rax,0x0FFFFFFC0FFFFFFC
	and	rax,[rsi+8]
	mov	[rdi+PY_R1],rax
	mov	rcx,rax
	shr	rcx,2
	add	rax,rcx				; s1 = 5 r1 / 4
	mov	[rdi+PY_S1],rax
	mov	rax,[rsi+16]
	mov	[rdi+PY_S],rax
	mov	rax,[rsi+24]
	mov	[rdi+PY_S+8],rax
	ret

; rdi = state, rsi = data, rdx = length: Poly1305 over the data zero-padded
; to a multiple of 16 (RFC 8439's AEAD padding), every block a full one.
poly_padded:
	cmp	rdx,256
	jb	@f
	call	poly_vec			; whole groups of 64 bytes
@@:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rdx
	mov	r8,[rdi+PY_H0]
	mov	r9,[rdi+PY_H1]
	mov	r10,[rdi+PY_H2]
	mov	r11,[rdi+PY_R0]
	mov	r12,[rdi+PY_R1]
	mov	r13,[rdi+PY_S1]
.block:
	cmp	rbp,16
	jb	.partial
	mov	rax,[rsi]
	mov	rcx,[rsi+8]
	add	rsi,16
	sub	rbp,16
.absorb:
	add	r8,rax				; h += m + 2^128
	adc	r9,rcx
	adc	r10,1
	py_mul
	jmp	.block
.partial:
	test	rbp,rbp
	jz	.done
	xor	eax,eax				; the rest, zero-padded
	mov	[rdi+PY_BUF],rax
	mov	[rdi+PY_BUF+8],rax
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	mov	[rdi+PY_BUF+rcx],al
	inc	ecx
	cmp	rcx,rbp
	jb	@b
	xor	ebp,ebp
	mov	rax,[rdi+PY_BUF]
	mov	rcx,[rdi+PY_BUF+8]
	jmp	.absorb
.done:
	mov	[rdi+PY_H0],r8
	mov	[rdi+PY_H1],r9
	mov	[rdi+PY_H2],r10
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------- Poly1305, four lanes

PV_R4		:= 0				; 9 x 32: r^4 in every lane (r0..r4, s1..s4)
PV_MIX		:= 9 * 32			; 9 x 32: lanes r^4, r^3, r^2, r
PV_ARGS		:= 18 * 32			; state, data, length
PV_FRAME	:= PV_ARGS + 32

; the five 26-bit limbs of (r8, r9, r10) and the four times five, into
; lane `lane` of PV_MIX. Clobbers rax, rcx.
macro pv_limbs lane
	mov	rax,r8
	and	eax,0x3FFFFFF
	mov	[rsp+PV_MIX+lane*8],rax
	mov	rax,r8
	shr	rax,26
	and	eax,0x3FFFFFF
	mov	[rsp+PV_MIX+32+lane*8],rax
	lea	rax,[rax+rax*4]
	mov	[rsp+PV_MIX+5*32+lane*8],rax
	mov	rax,r8
	shr	rax,52
	mov	rcx,r9
	shl	rcx,12
	or	rax,rcx
	and	eax,0x3FFFFFF
	mov	[rsp+PV_MIX+2*32+lane*8],rax
	lea	rax,[rax+rax*4]
	mov	[rsp+PV_MIX+6*32+lane*8],rax
	mov	rax,r9
	shr	rax,14
	and	eax,0x3FFFFFF
	mov	[rsp+PV_MIX+3*32+lane*8],rax
	lea	rax,[rax+rax*4]
	mov	[rsp+PV_MIX+7*32+lane*8],rax
	mov	rax,r9
	shr	rax,40
	mov	rcx,r10
	shl	rcx,24
	or	rax,rcx
	mov	[rsp+PV_MIX+4*32+lane*8],rax
	lea	rax,[rax+rax*4]
	mov	[rsp+PV_MIX+8*32+lane*8],rax
end macro

; ymm0..4 (h, four lanes) += the next four blocks at rsi, one per lane,
; then times the table at rbx; partly carried (limbs about 26 bits).
; ymm15 = 2^26 - 1, ymm14 = 2^24, in every lane.
macro pv_round
	vmovdqu	xmm10,[rsi]			; blocks 0 | 2
	vinserti128 ymm10,ymm10,[rsi+32],1
	vmovdqu	xmm11,[rsi+16]			; blocks 1 | 3
	vinserti128 ymm11,ymm11,[rsi+48],1
	vpunpcklqdq ymm12,ymm10,ymm11		; the low halves, block j in lane j
	vpunpckhqdq ymm13,ymm10,ymm11		; the high halves
	vpand	ymm10,ymm12,ymm15
	vpaddq	ymm0,ymm0,ymm10
	vpsrlq	ymm10,ymm12,26
	vpand	ymm10,ymm10,ymm15
	vpaddq	ymm1,ymm1,ymm10
	vpsrlq	ymm10,ymm12,52
	vpsllq	ymm11,ymm13,12
	vpor	ymm10,ymm10,ymm11
	vpand	ymm10,ymm10,ymm15
	vpaddq	ymm2,ymm2,ymm10
	vpsrlq	ymm10,ymm13,14
	vpand	ymm10,ymm10,ymm15
	vpaddq	ymm3,ymm3,ymm10
	vpsrlq	ymm10,ymm13,40
	vpor	ymm10,ymm10,ymm14
	vpaddq	ymm4,ymm4,ymm10
	; d_j = sum h_i r_(j-i), r_(j-i) as s_(5+j-i) = 5 r_(5+j-i) below zero
	vpmuludq ymm5,ymm0,[rbx]		; h0 r0
	vpmuludq ymm6,ymm0,[rbx+32]		; h0 r1
	vpmuludq ymm7,ymm0,[rbx+64]		; h0 r2
	vpmuludq ymm8,ymm0,[rbx+96]		; h0 r3
	vpmuludq ymm9,ymm0,[rbx+128]		; h0 r4
	vpmuludq ymm10,ymm1,[rbx+8*32]		; h1 s4
	vpmuludq ymm11,ymm1,[rbx]		; h1 r0
	vpmuludq ymm12,ymm1,[rbx+32]		; h1 r1
	vpmuludq ymm13,ymm1,[rbx+64]		; h1 r2
	vpaddq	ymm5,ymm5,ymm10
	vpaddq	ymm6,ymm6,ymm11
	vpaddq	ymm7,ymm7,ymm12
	vpaddq	ymm8,ymm8,ymm13
	vpmuludq ymm10,ymm1,[rbx+96]		; h1 r3
	vpmuludq ymm11,ymm2,[rbx+7*32]		; h2 s3
	vpmuludq ymm12,ymm2,[rbx+8*32]		; h2 s4
	vpmuludq ymm13,ymm2,[rbx]		; h2 r0
	vpaddq	ymm9,ymm9,ymm10
	vpaddq	ymm5,ymm5,ymm11
	vpaddq	ymm6,ymm6,ymm12
	vpaddq	ymm7,ymm7,ymm13
	vpmuludq ymm10,ymm2,[rbx+32]		; h2 r1
	vpmuludq ymm11,ymm2,[rbx+64]		; h2 r2
	vpmuludq ymm12,ymm3,[rbx+6*32]		; h3 s2
	vpmuludq ymm13,ymm3,[rbx+7*32]		; h3 s3
	vpaddq	ymm8,ymm8,ymm10
	vpaddq	ymm9,ymm9,ymm11
	vpaddq	ymm5,ymm5,ymm12
	vpaddq	ymm6,ymm6,ymm13
	vpmuludq ymm10,ymm3,[rbx+8*32]		; h3 s4
	vpmuludq ymm11,ymm3,[rbx]		; h3 r0
	vpmuludq ymm12,ymm3,[rbx+32]		; h3 r1
	vpmuludq ymm13,ymm4,[rbx+5*32]		; h4 s1
	vpaddq	ymm7,ymm7,ymm10
	vpaddq	ymm8,ymm8,ymm11
	vpaddq	ymm9,ymm9,ymm12
	vpaddq	ymm5,ymm5,ymm13
	vpmuludq ymm10,ymm4,[rbx+6*32]		; h4 s2
	vpmuludq ymm11,ymm4,[rbx+7*32]		; h4 s3
	vpmuludq ymm12,ymm4,[rbx+8*32]		; h4 s4
	vpmuludq ymm13,ymm4,[rbx]		; h4 r0
	vpaddq	ymm6,ymm6,ymm10
	vpaddq	ymm7,ymm7,ymm11
	vpaddq	ymm8,ymm8,ymm12
	vpaddq	ymm9,ymm9,ymm13
	; carry: 3 -> 4 and 0 -> 1, 4 -> 0 (times 5) and 1 -> 2, 2 -> 3 and
	; 0 -> 1, 3 -> 4
	vpsrlq	ymm10,ymm8,26
	vpand	ymm3,ymm8,ymm15
	vpaddq	ymm9,ymm9,ymm10
	vpsrlq	ymm11,ymm5,26
	vpand	ymm0,ymm5,ymm15
	vpaddq	ymm6,ymm6,ymm11
	vpsrlq	ymm10,ymm9,26
	vpand	ymm4,ymm9,ymm15
	vpsllq	ymm12,ymm10,2
	vpaddq	ymm10,ymm10,ymm12
	vpaddq	ymm0,ymm0,ymm10
	vpsrlq	ymm11,ymm6,26
	vpand	ymm1,ymm6,ymm15
	vpaddq	ymm2,ymm7,ymm11
	vpsrlq	ymm10,ymm2,26
	vpand	ymm2,ymm2,ymm15
	vpaddq	ymm3,ymm3,ymm10
	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm15
	vpaddq	ymm1,ymm1,ymm11
	vpsrlq	ymm10,ymm3,26
	vpand	ymm3,ymm3,ymm15
	vpaddq	ymm4,ymm4,ymm10
end macro

; the four lanes of limb y summed into reg
macro pv_hsum y, x, reg
	vextracti128 xmm10,y,1
	vpaddq	x,x,xmm10
	vpsrldq	xmm10,x,8
	vpaddq	x,x,xmm10
	vmovq	reg,x
end macro

; rdi = state, rsi = data, rdx = length (64 or more): Poly1305 over the
; whole groups of 64 bytes, h kept in the state. rsi past them, rdx what
; is left (below 64); rdi kept.
poly_vec:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rsp
	sub	rsp,PV_FRAME
	and	rsp,-32
	mov	[rsp+PV_ARGS],rdi
	mov	[rsp+PV_ARGS+8],rsi
	mov	[rsp+PV_ARGS+16],rdx
	mov	r11,[rdi+PY_R0]			; r, r^2, r^3, r^4 into the lanes
	mov	r12,[rdi+PY_R1]
	mov	r13,[rdi+PY_S1]
	mov	r8,r11
	mov	r9,r12
	xor	r10d,r10d
	pv_limbs 3
	py_mul
	pv_limbs 2
	py_mul
	pv_limbs 1
	py_mul
	pv_limbs 0
	xor	eax,eax
@@:
	vpbroadcastq ymm0,qword [rsp+PV_MIX+rax]
	vmovdqa	[rsp+PV_R4+rax],ymm0
	add	eax,32
	cmp	eax,PV_MIX
	jb	@b
	mov	rdi,[rsp+PV_ARGS]
	mov	r8,[rdi+PY_H0]			; h so far into lane 0
	mov	r9,[rdi+PY_H1]
	mov	r10,[rdi+PY_H2]
	mov	rax,r8
	and	eax,0x3FFFFFF
	vmovq	xmm0,rax
	mov	rax,r8
	shr	rax,26
	and	eax,0x3FFFFFF
	vmovq	xmm1,rax
	mov	rax,r8
	shr	rax,52
	mov	rcx,r9
	shl	rcx,12
	or	rax,rcx
	and	eax,0x3FFFFFF
	vmovq	xmm2,rax
	mov	rax,r9
	shr	rax,14
	and	eax,0x3FFFFFF
	vmovq	xmm3,rax
	mov	rax,r9
	shr	rax,40
	shl	r10,24
	or	rax,r10
	vmovq	xmm4,rax
	vpbroadcastq ymm15,qword [pv_mask26]
	vpbroadcastq ymm14,qword [pv_hibit]
	mov	rsi,[rsp+PV_ARGS+8]
	mov	rcx,[rsp+PV_ARGS+16]
	and	rcx,-64
	lea	rbx,[rsp+PV_R4]
.four:
	cmp	rcx,64
	je	.last
	pv_round
	add	rsi,64
	sub	rcx,64
	jmp	.four
.last:
	lea	rbx,[rsp+PV_MIX]		; the last four: r^4, r^3, r^2, r
	pv_round
	pv_hsum	ymm0,xmm0,r8
	pv_hsum	ymm1,xmm1,r9
	pv_hsum	ymm2,xmm2,r10
	pv_hsum	ymm3,xmm3,r11
	pv_hsum	ymm4,xmm4,r12
	mov	rax,r9				; back to radix 2^64
	shl	rax,26
	add	r8,rax
	mov	rax,r10
	shl	rax,52
	shr	r10,12
	add	r8,rax
	adc	r10,0
	mov	rax,r11
	shl	rax,14
	add	r10,rax
	mov	rax,r12
	shl	rax,40
	shr	r12,24
	add	r10,rax
	adc	r12,0
	mov	r9,r10
	mov	r10,r12
	py_fold
	mov	rdi,[rsp+PV_ARGS]
	mov	[rdi+PY_H0],r8
	mov	[rdi+PY_H1],r9
	mov	[rdi+PY_H2],r10
	mov	rsi,[rsp+PV_ARGS+8]		; past the groups
	mov	rdx,[rsp+PV_ARGS+16]
	mov	rax,rdx
	and	rax,-64
	add	rsi,rax
	and	edx,63
	vpxor	ymm0,ymm0,ymm0			; the powers of r off the stack
	xor	eax,eax
@@:
	vmovdqa	[rsp+rax],ymm0
	add	eax,32
	cmp	eax,PV_ARGS
	jb	@b
	mov	rsp,rbp
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	vzeroupper
	ret

; rdi = state, rsi = out[16]: the tag, (h mod p) + s mod 2^128.
poly_final:
	mov	r8,[rdi+PY_H0]
	mov	r9,[rdi+PY_H1]
	mov	r10,[rdi+PY_H2]
	mov	rax,r8				; g = h + 5
	add	rax,5
	mov	rcx,r9
	adc	rcx,0
	mov	rdx,r10
	adc	rdx,0
	shr	rdx,2				; g >= 2^130: h >= p, take g
	neg	rdx				; mask
	xor	rax,r8
	xor	rcx,r9
	and	rax,rdx
	and	rcx,rdx
	xor	r8,rax
	xor	r9,rcx
	add	r8,[rdi+PY_S]
	adc	r9,[rdi+PY_S+8]
	mov	[rsi],r8
	mov	[rsi+8],r9
	ret

; ------------------------------------------------------------------- AEAD
;
; Records of 512 bytes or more go through cp_xmac: ChaCha20 eight blocks at
; a time with Poly1305 over the ciphertext in the same pass. Sealing, the
; MAC trails by 512 bytes (it needs the ciphertext just written); opening,
; it reads each 512 bytes before they are decrypted. The rest, and records
; shorter than that, take chacha20_xor and poly_padded. An open with a wrong
; tag XORs the same key stream over what it decrypted: the buffer is as it
; came (QUIC tries a packet again under the next key phase).

; one Poly1305 block from rdi (h in r8..r10, r in r11..r13), rdi past it
macro py_block
	add	r8,[rdi]
	adc	r9,[rdi+8]
	adc	r10,1
	py_mul
	add	rdi,16
end macro

; rdi = Poly1305 state, rsi = key[32], rdx = nonce[12], rcx = buffer,
; r8 = length (512 or more): the whole 512-byte groups XORed with the key
; stream from counter 1 and MACed (sealing, all but the last group, at
; cp_xmac_seal; opening, all of them, at cp_xmac_open). rax = the bytes
; XORed.
cp_xmac_seal:
	mov	eax,1
	jmp	cp_xmac
cp_xmac_open:
	xor	eax,eax
cp_xmac:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rsp
	sub	rsp,CC_FRAME
	and	rsp,-32
	mov	[rsp+CC_MISC+4],eax		; sealing
	mov	[rsp+CC_MISC+8],rdi
	and	r8,-512
	mov	[rsp+CC_MISC+16],r8		; what is left to XOR
	mov	[rsp+CC_MISC+24],r8		; (the answer)
	mov	rdi,rsi
	mov	r9,rdx
	mov	rsi,rcx
	mov	edx,1
	cc_counter
	cc8_setup
	mov	rax,[rsp+CC_MISC+8]
	mov	r8,[rax+PY_H0]
	mov	r9,[rax+PY_H1]
	mov	r10,[rax+PY_H2]
	mov	r11,[rax+PY_R0]
	mov	r12,[rax+PY_R1]
	mov	r13,[rax+PY_S1]
	mov	rdi,rsi				; the MAC's place
	cmp	dword [rsp+CC_MISC+4],0
	je	.group
	cc8_block 0				; sealing: the first group ahead of the MAC
	add	rsi,512
	sub	qword [rsp+CC_MISC+16],512
.group:
	cmp	qword [rsp+CC_MISC+16],0
	je	.done
	cc8_block 1
	add	rsi,512
	sub	qword [rsp+CC_MISC+16],512
	jmp	.group
.done:
	mov	rax,[rsp+CC_MISC+8]
	mov	[rax+PY_H0],r8
	mov	[rax+PY_H1],r9
	mov	[rax+PY_H2],r10
	mov	rdx,[rsp+CC_MISC+24]
	cc_wipe CC_FRAME
	mov	rax,rdx
	mov	rsp,rbp
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	vzeroupper
	ret

CPS_POLY	:= 0
CPS_OTK		:= PY_SIZE			; the one-time Poly1305 key (64: a block)
CPS_LENS	:= CPS_OTK + 64
CPS_TAG		:= CPS_LENS + 16
CPS_ARGS	:= CPS_TAG + 16			; ctx, iv, aad, aad length, buffer, length
CPS_DONE	:= CPS_ARGS + 48		; the bytes cp_xmac XORed
CPS_SIZE	:= CPS_DONE + 16

cp_init:
	mov	rax,[rsi]
	mov	[rdi],rax
	mov	rax,[rsi+8]
	mov	[rdi+8],rax
	mov	rax,[rsi+16]
	mov	[rdi+16],rax
	mov	rax,[rsi+24]
	mov	[rdi+24],rax
	ret

; the one-time key (block 0's first 32 bytes) into Poly1305, then the aad
macro cp_start
	lea	rdi,[rsp+CPS_OTK]
	xor	eax,eax
	mov	ecx,8
	rep	stosq
	mov	[rsp+CPS_DONE],rax
	mov	rdi,[rsp+CPS_ARGS]
	mov	rsi,[rsp+CPS_ARGS+8]
	xor	edx,edx
	lea	rcx,[rsp+CPS_OTK]
	mov	r8d,64
	call	chacha20_xor
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_OTK]
	call	poly_init
	lea	rdi,[rsp+CPS_POLY]
	mov	rsi,[rsp+CPS_ARGS+16]
	mov	rdx,[rsp+CPS_ARGS+24]
	call	poly_padded
end macro

; cp_xmac over the whole groups, when there are any
macro cp_groups entry
	cmp	qword [rsp+CPS_ARGS+40],512
	jb	@f
	lea	rdi,[rsp+CPS_POLY]
	mov	rsi,[rsp+CPS_ARGS]
	mov	rdx,[rsp+CPS_ARGS+8]
	mov	rcx,[rsp+CPS_ARGS+32]
	mov	r8,[rsp+CPS_ARGS+40]
	call	entry
	mov	[rsp+CPS_DONE],rax
@@:
end macro

; chacha20_xor over the buffer from what cp_xmac did to its end
macro cp_rest
	mov	rax,[rsp+CPS_DONE]
	mov	rdi,[rsp+CPS_ARGS]
	mov	rsi,[rsp+CPS_ARGS+8]
	mov	edx,eax
	shr	edx,6
	inc	edx				; block 0 is the one-time key
	mov	rcx,[rsp+CPS_ARGS+32]
	add	rcx,rax
	mov	r8,[rsp+CPS_ARGS+40]
	sub	r8,rax
	call	chacha20_xor
end macro

; Poly1305 over the ciphertext from rax on, the lengths, the tag into
; [rsp+CPS_TAG]
macro cp_finish
	lea	rdi,[rsp+CPS_POLY]
	mov	rsi,[rsp+CPS_ARGS+32]
	add	rsi,rax
	mov	rdx,[rsp+CPS_ARGS+40]
	sub	rdx,rax
	call	poly_padded
	mov	rax,[rsp+CPS_ARGS+24]
	mov	[rsp+CPS_LENS],rax
	mov	rax,[rsp+CPS_ARGS+40]
	mov	[rsp+CPS_LENS+8],rax
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_LENS]
	mov	edx,16
	call	poly_padded
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_TAG]
	call	poly_final
end macro

macro cp_frame
	sub	rsp,CPS_SIZE + 8
	mov	[rsp+CPS_ARGS],rdi
	mov	[rsp+CPS_ARGS+8],rsi
	mov	[rsp+CPS_ARGS+16],rdx
	mov	ecx,ecx
	mov	[rsp+CPS_ARGS+24],rcx
	mov	[rsp+CPS_ARGS+32],r8
	mov	[rsp+CPS_ARGS+40],r9
end macro

; jumped to: the frame wiped (the one-time key, the Poly1305 state), then
; return eax
cp_leave:
	mov	r8d,eax
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,CPS_ARGS / 8
	rep	stosq
	mov	eax,r8d
	add	rsp,CPS_SIZE + 8
	ret

cp_seal:
	cp_frame
	cp_start
	cp_groups cp_xmac_seal
	cp_rest
	mov	rax,[rsp+CPS_DONE]		; the MAC trails cp_xmac by a group
	sub	rax,512
	jae	@f
	xor	eax,eax
@@:
	cp_finish
	mov	rdi,[rsp+CPS_ARGS+32]		; the tag after the ciphertext
	add	rdi,[rsp+CPS_ARGS+40]
	mov	rax,[rsp+CPS_TAG]
	mov	[rdi],rax
	mov	rax,[rsp+CPS_TAG+8]
	mov	[rdi+8],rax
	mov	eax,1
	jmp	cp_leave

cp_open:
	cp_frame
	cp_start
	cp_groups cp_xmac_open
	mov	rax,[rsp+CPS_DONE]
	cp_finish
	mov	rdi,[rsp+CPS_ARGS+32]		; the tag, in constant time
	add	rdi,[rsp+CPS_ARGS+40]
	mov	rax,[rsp+CPS_TAG]
	xor	rax,[rdi]
	mov	rcx,[rsp+CPS_TAG+8]
	xor	rcx,[rdi+8]
	or	rax,rcx
	jnz	.bad
	cp_rest					; right: the rest decrypted
	mov	eax,1
	jmp	cp_leave
.bad:
	mov	r8,[rsp+CPS_DONE]		; wrong: what cp_xmac decrypted goes back
	test	r8,r8
	jz	@f
	mov	rdi,[rsp+CPS_ARGS]
	mov	rsi,[rsp+CPS_ARGS+8]
	mov	edx,1
	mov	rcx,[rsp+CPS_ARGS+32]
	call	chacha20_xor
@@:
	xor	eax,eax
	jmp	cp_leave

; ------------------------------------------------- the AEAD of a TLS suite
;
; One context for either AEAD: AES-128-GCM's or AES-256-GCM's (gcm_*), or
; ChaCha20-Poly1305's (cp_*), its type after it. aead_seal and aead_open take what gcm_seal and
; gcm_open take.

AEAD_TYPE	:= GCM256_SIZE			; d: 0 AES-GCM (128 or 256), 1 ChaCha20-Poly1305
AEAD_SIZE	:= GCM256_SIZE + 16
assert CP_SIZE <= GCM_SIZE

; rdi = ctx, rsi = key (16 or 32 bytes), edx = the type
AEAD_GCM128	:= 0
AEAD_CHACHA	:= 1
AEAD_GCM256	:= 2

aead_init:
	mov	[rdi+AEAD_TYPE],edx
	cmp	edx,AEAD_CHACHA
	je	cp_init
	cmp	edx,AEAD_GCM256
	je	gcm_init256
	jmp	gcm_init

aead_seal:
	cmp	dword [rdi+AEAD_TYPE],AEAD_CHACHA
	je	cp_seal
	jmp	gcm_seal

aead_open:
	cmp	dword [rdi+AEAD_TYPE],AEAD_CHACHA
	je	cp_open
	jmp	gcm_open
