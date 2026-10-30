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
; permuting after each, so it can be called again for more (SampleNTT).

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
; rcx, rdx, r8..r11.
keccak_f1600:
	push	rbx
	sub	rsp,200 + 40			; B (25 lanes), then C (5)
	xor	ecx,ecx				; the round
.round:
	; theta: C[x] = A[x, 0..4] combined; A[x, y] ^= C[x-1] ^ rol(C[x+1], 1)
	repeat 5, x:0
		mov	rax,[rdi+x*8]
		xor	rax,[rdi+(x+5)*8]
		xor	rax,[rdi+(x+10)*8]
		xor	rax,[rdi+(x+15)*8]
		xor	rax,[rdi+(x+20)*8]
		mov	[rsp+200+x*8],rax
	end repeat
	repeat 5, x:0
		mov	rax,[rsp+200+((x+1) mod 5)*8]
		rol	rax,1
		xor	rax,[rsp+200+((x+4) mod 5)*8]
		repeat 5, y:0
			xor	[rdi+(x+5*y)*8],rax
		end repeat
	end repeat
	; rho and pi: B[y, 2x + 3y] = rol(A[x, y], r[x, y])
	repeat 25, i:0
		mov	rax,[rdi+i*8]
		if KECCAK_ROT#i <> 0
			rol	rax,KECCAK_ROT#i
		end if
		mov	[rsp+((i / 5) + 5*((2*(i mod 5) + 3*(i / 5)) mod 5))*8],rax
	end repeat
	; chi: A[x, y] = B[x, y] ^ (~B[x+1, y] & B[x+2, y])
	repeat 5, y:0
		repeat 5, x:0
			mov	rax,[rsp+(((x+1) mod 5) + 5*y)*8]
			andn	rax,rax,[rsp+(((x+2) mod 5) + 5*y)*8]
			xor	rax,[rsp+(x + 5*y)*8]
			mov	[rdi+(x + 5*y)*8],rax
		end repeat
	end repeat
	; iota
	lea	rax,[keccak_rc]
	mov	rax,[rax+rcx*8]
	xor	[rdi],rax
	inc	ecx
	cmp	ecx,24
	jb	.round
	add	rsp,200 + 40
	pop	rbx
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
; out, edx = whole blocks, ecx = rate: edx blocks of output, the state
; permuted after each so the next call goes on. Keeps rdi.
keccak_squeeze:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	mov	ebx,ecx
.block:
	test	r13d,r13d
	jz	.done
	xor	ecx,ecx
@@:
	mov	rax,[rdi+rcx]
	mov	[r12+rcx],rax
	add	ecx,8
	cmp	ecx,ebx
	jb	@b
	add	r12,rbx
	dec	r13d
	call	keccak_f1600
	jmp	.block
.done:
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
.more:
	test	r13d,r13d
	jz	.done
	lea	rsi,[rsp+KECCAK_STATE]
	mov	edx,1
	mov	ecx,ebx
	call	keccak_squeeze
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
