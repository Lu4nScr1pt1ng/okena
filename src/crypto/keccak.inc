; Keccak (FIPS 202): the Keccak-f[1600] permutation and the sponge on top
; of it, for SHA3-256, SHA3-512, SHAKE128 and SHAKE256 (ML-KEM's hash, XOF
; and PRF).
;
; The state is 25 lanes of 64 bits, lane (x, y) at index x + 5y, little
; endian, as the standard lays them out. One round is theta, rho and pi
; (rotations and the lane shuffle, both fixed at assembly time, so the
; whole round is straight-line code), chi (with andn) and iota. Nothing
; depends on the data but the values: constant time.
;
; Sponge: keccak_absorb takes the whole message at once (every caller has
; it in memory), pads it with the domain bits and leaves the state with
; the first output block ready; keccak_squeeze copies out whole blocks,
; permuting before each but the first, so it can be called again for more
; (SampleNTT) and never permutes for output nobody reads.

KECCAK_STATE	:= 200
SHA3_256_RATE	:= 136
SHA3_512_RATE	:= 72
SHAKE128_RATE	:= 168
SHAKE256_RATE	:= 136
KECCAK_SHA3	:= 0x06			; domain bits + the first padding bit
KECCAK_SHAKE	:= 0x1F

; the rotation of lane i (rho)
iterate <i,r>, 0,0, 1,1, 2,62, 3,28, 4,27, 5,36, 6,44, 7,6, 8,55, 9,20, \
		10,3, 11,10, 12,43, 13,25, 14,39, 15,41, 16,45, 17,15, 18,21, 19,8, \
		20,18, 21,2, 22,61, 23,56, 24,14
	KECCAK_ROT#i := r
end iterate

rodata
	align 8
	keccak_rc	dq 0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000
			dq 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009
			dq 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A
			dq 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003
			dq 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A
			dq 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
end rodata

; rdi = state: Keccak-f[1600], 24 rounds. Keeps every register but rax,
; rcx, rdx, r8..r11. Theta's D goes into rho and pi on the way (no
; read-modify-write of the state), chi works from the shuffled copy.
keccak_f1600:
	sub	rsp,200 + 40			; B (25 lanes), then D (5)
	xor	ecx,ecx				; the round
.round:
	; theta: C[x] = A[x, 0..4] combined, D[x] = C[x-1] ^ rol(C[x+1], 1)
	mov	r8,[rdi]
	mov	r9,[rdi+8]
	mov	r10,[rdi+16]
	mov	r11,[rdi+24]
	mov	rdx,[rdi+32]
	repeat 4, y:1
		xor	r8,[rdi+(5*y)*8]
		xor	r9,[rdi+(5*y+1)*8]
		xor	r10,[rdi+(5*y+2)*8]
		xor	r11,[rdi+(5*y+3)*8]
		xor	rdx,[rdi+(5*y+4)*8]
	end repeat
	rorx	rax,r9,63			; D[0] = C[4] ^ rol(C[1], 1)
	xor	rax,rdx
	mov	[rsp+200],rax
	rorx	rax,r10,63			; D[1] = C[0] ^ rol(C[2], 1)
	xor	rax,r8
	mov	[rsp+208],rax
	rorx	rax,r11,63			; D[2] = C[1] ^ rol(C[3], 1)
	xor	rax,r9
	mov	[rsp+216],rax
	rorx	rax,rdx,63			; D[3] = C[2] ^ rol(C[4], 1)
	xor	rax,r10
	mov	[rsp+224],rax
	rorx	rax,r8,63			; D[4] = C[3] ^ rol(C[0], 1)
	xor	rax,r11
	mov	[rsp+232],rax
	; rho and pi, with theta's D: B[y, 2x + 3y] = rol(A[x, y] ^ D[x], r[x, y])
	repeat 25, i:0
		mov	rax,[rdi+i*8]
		xor	rax,[rsp+200+(i mod 5)*8]
		if KECCAK_ROT#i <> 0
			rorx	rax,rax,64-KECCAK_ROT#i
		end if
		mov	[rsp+((i / 5) + 5*((2*(i mod 5) + 3*(i / 5)) mod 5))*8],rax
	end repeat
	; chi: A[x, y] = B[x, y] ^ (~B[x+1, y] & B[x+2, y]), a row in registers
	repeat 5, y:0
		mov	r8,[rsp+(5*y)*8]
		mov	r9,[rsp+(5*y+1)*8]
		mov	r10,[rsp+(5*y+2)*8]
		mov	r11,[rsp+(5*y+3)*8]
		mov	rdx,[rsp+(5*y+4)*8]
		andn	rax,r9,r10
		xor	rax,r8
		mov	[rdi+(5*y)*8],rax
		andn	rax,r10,r11
		xor	rax,r9
		mov	[rdi+(5*y+1)*8],rax
		andn	rax,r11,rdx
		xor	rax,r10
		mov	[rdi+(5*y+2)*8],rax
		andn	rax,rdx,r8
		xor	rax,r11
		mov	[rdi+(5*y+3)*8],rax
		andn	rax,r8,r9
		xor	rax,rdx
		mov	[rdi+(5*y+4)*8],rax
	end repeat
	; iota
	lea	rax,[keccak_rc]
	mov	rax,[rax+rcx*8]
	xor	[rdi],rax
	inc	ecx
	cmp	ecx,24
	jb	.round
	add	rsp,200 + 40
	ret

; rdi = state, rsi = message, rdx = its length, ecx = rate (bytes, a
; multiple of 8), r8d = domain byte: the state zeroed, the message
; absorbed and padded. The state then holds the first output block.
; Keeps rdi.
keccak_absorb:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13,rdx
	mov	ebx,ecx
	mov	r14d,r8d
	push	rdi
	xor	eax,eax
	mov	ecx,KECCAK_STATE / 8
	rep	stosq
	pop	rdi
.block:
	cmp	r13,rbx
	jb	.last
	xor	ecx,ecx
@@:
	mov	rax,[r12+rcx]
	xor	[rdi+rcx],rax
	add	ecx,8
	cmp	ecx,ebx
	jb	@b
	add	r12,rbx
	sub	r13,rbx
	call	keccak_f1600
	jmp	.block
.last:
	xor	ecx,ecx
@@:
	cmp	rcx,r13
	jae	@f
	mov	al,[r12+rcx]
	xor	[rdi+rcx],al
	inc	ecx
	jmp	@b
@@:
	xor	[rdi+r13],r14b			; the domain bits, then pad10*1
	xor	byte [rdi+rbx-1],0x80
	call	keccak_f1600
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = state (as keccak_absorb left it, or a previous squeeze), rsi =
; out, edx = whole blocks, ecx = rate, r8d = 1 when the state's block was
; given out already (a later call), 0 right after keccak_absorb: edx blocks
; of output, a permutation before each new one only (none wasted after the
; last). Keeps rdi.
keccak_squeeze:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13d,edx
	mov	ebx,ecx
	mov	r14d,r8d
.block:
	test	r13d,r13d
	jz	.done
	test	r14d,r14d
	jz	@f
	call	keccak_f1600
@@:
	mov	r14d,1
	xor	ecx,ecx
@@:
	mov	rax,[rdi+rcx]
	mov	[r12+rcx],rax
	add	ecx,8
	cmp	ecx,ebx
	jb	@b
	add	r12,rbx
	dec	r13d
	jmp	.block
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out (32), rsi = message, rdx = its length. Uses 200 bytes of stack.
sha3_256:
	mov	ecx,SHA3_256_RATE
	mov	r9d,32
	jmp	sha3_fixed

; rdi = out (64), rsi = message, rdx = its length.
sha3_512:
	mov	ecx,SHA3_512_RATE
	mov	r9d,64

; ecx = rate, r9d = output bytes (<= rate)
sha3_fixed:
	push	rdi
	push	r9
	sub	rsp,KECCAK_STATE + 8
	lea	rdi,[rsp]
	mov	r8d,KECCAK_SHA3
	call	keccak_absorb
	mov	rsi,rsp
	mov	ecx,[rsp+KECCAK_STATE + 8]	; the output length
	mov	rdi,[rsp+KECCAK_STATE + 16]
	rep	movsb
	mov	rdi,rsp				; the state held what was hashed
	xor	eax,eax
	mov	ecx,KECCAK_STATE / 8
	rep	stosq
	add	rsp,KECCAK_STATE + 8
	pop	r9
	pop	rdi
	ret

; rdi = out, esi = output length, rdx = message, rcx = its length,
; r8d = rate (SHAKE128_RATE or SHAKE256_RATE): SHAKE, any output length.
shake:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,KECCAK_STATE + SHAKE128_RATE
	mov	r12,rdi
	mov	r13d,esi
	mov	ebx,r8d
	lea	rdi,[rsp]
	mov	rsi,rdx
	mov	rdx,rcx
	mov	ecx,ebx
	mov	r8d,KECCAK_SHAKE
	call	keccak_absorb
	xor	r14d,r14d			; the first block is the state's own
.more:
	test	r13d,r13d
	jz	.done
	lea	rsi,[rsp+KECCAK_STATE]
	mov	edx,1
	mov	ecx,ebx
	mov	r8d,r14d
	call	keccak_squeeze
	mov	r14d,1
	mov	ecx,r13d
	cmp	ecx,ebx
	jbe	@f
	mov	ecx,ebx
@@:
	sub	r13d,ecx
	lea	rsi,[rsp+KECCAK_STATE]
	push	rdi
	mov	rdi,r12
	rep	movsb
	mov	r12,rdi
	pop	rdi
	jmp	.more
.done:
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,(KECCAK_STATE + SHAKE128_RATE) / 8
	rep	stosq
	add	rsp,KECCAK_STATE + SHAKE128_RATE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- four-way
;
; Four Keccak states side by side on AVX2: lane i of the four at
; [state + 32 i] (one ymm), 800 bytes. One permutation of the four costs
; about 1.25 of a single one (AVX2 has no 64-bit rotate: a rotation is
; two shifts and an or), so independent sponges of one block of input
; (ML-KEM's matrix entries and PRF calls) go four at a time.

KECCAK_X4	:= 800

; v = rol(v, n). Uses t.
macro kx4_rol v, t, n
	vpsllq	t,v,n
	vpsrlq	v,v,64-n
	vpor	v,v,t
end macro

; rdi = the four states: Keccak-f[1600] on each. Keeps every general
; register but rax, rcx; ymm0..ymm11 are scratch.
keccak_f1600_x4:
	push	rbp
	mov	rbp,rsp
	sub	rsp,KECCAK_X4
	and	rsp,-32
	xor	ecx,ecx
.round:
	; theta
	repeat 5, x:0
		vmovdqu	ymm#x,[rdi+x*32]
		repeat 4, y:1
			vpxor	ymm#x,ymm#x,[rdi+(x+5*y)*32]
		end repeat
	end repeat
	; D[x] = C[x-1] ^ rol(C[x+1], 1), in ymm5..ymm9
	irp <d,cm,cp>, 5,4,1, 6,0,2, 7,1,3, 8,2,4, 9,3,0
		vpsrlq	ymm10,ymm#cp,63
		vpaddq	ymm#d,ymm#cp,ymm#cp
		vpor	ymm#d,ymm#d,ymm10
		vpxor	ymm#d,ymm#d,ymm#cm
	end irp
	; rho and pi, with D
	repeat 25, i:0
		vmovdqu	ymm10,[rdi+i*32]
		if i mod 5 = 0
			vpxor	ymm10,ymm10,ymm5
		else if i mod 5 = 1
			vpxor	ymm10,ymm10,ymm6
		else if i mod 5 = 2
			vpxor	ymm10,ymm10,ymm7
		else if i mod 5 = 3
			vpxor	ymm10,ymm10,ymm8
		else
			vpxor	ymm10,ymm10,ymm9
		end if
		if KECCAK_ROT#i <> 0
			kx4_rol	ymm10, ymm11, KECCAK_ROT#i
		end if
		vmovdqa	[rsp+((i / 5) + 5*((2*(i mod 5) + 3*(i / 5)) mod 5))*32],ymm10
	end repeat
	; chi
	repeat 5, y:0
		repeat 5, x:0
			vmovdqa	ymm#x,[rsp+(x+5*y)*32]
		end repeat
		irp <x,x1,x2>, 0,1,2, 1,2,3, 2,3,4, 3,4,0, 4,0,1
			vpandn	ymm10,ymm#x1,ymm#x2
			vpxor	ymm10,ymm10,ymm#x
			vmovdqu	[rdi+(x+5*y)*32],ymm10
		end irp
	end repeat
	; iota
	lea	rax,[keccak_rc]
	vpbroadcastq ymm10,[rax+rcx*8]
	vpxor	ymm10,ymm10,[rdi]
	vmovdqu	[rdi],ymm10
	inc	ecx
	cmp	ecx,24
	jb	.round
	mov	rsp,rbp
	pop	rbp
	vzeroupper
	ret

; rdi = the four states, rsi = a 32-byte prefix common to the four, rdx =
; four qwords: each one's lane 4 (its own last input bytes with the SHAKE
; domain bits right after them), ecx = rate: four one-block absorptions,
; padded and permuted, the first output blocks ready. Keeps rdi.
keccak_x4_init:
	push	rdi
	push	rcx
	xor	eax,eax
	mov	ecx,KECCAK_X4 / 8
	rep	stosq
	pop	rcx
	pop	rdi
	repeat 4, i:0
		vpbroadcastq ymm0,[rsi+i*8]
		vmovdqu	[rdi+i*32],ymm0
	end repeat
	vmovdqu	ymm0,[rdx]
	vmovdqu	[rdi+4*32],ymm0
	shr	ecx,3				; the rate's last lane: its top byte 0x80
	dec	ecx
	shl	ecx,5
	mov	rax,0x8000000000000000
	mov	[rdi+rcx],rax
	mov	[rdi+rcx+8],rax
	mov	[rdi+rcx+16],rax
	mov	[rdi+rcx+24],rax
	vzeroupper
	jmp	keccak_f1600_x4

; rdi = the four states, esi = which (0..3), rdx = out, ecx = rate: that
; state's output block. Keeps rdi.
keccak_x4_extract:
	shr	ecx,3
	lea	rax,[rdi+rsi*8]
@@:
	mov	r8,[rax]
	mov	[rdx],r8
	add	rax,32
	add	rdx,8
	dec	ecx
	jnz	@b
	ret
