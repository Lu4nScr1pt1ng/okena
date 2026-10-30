; ML-KEM-768 (FIPS 203): encapsulation, what a TLS server needs
; for X25519MLKEM768. The client sends an encapsulation key (1184 bytes);
; the server checks it, encapsulates to it and answers the ciphertext
; (1088 bytes); both sides then hold the same 32-byte secret.
;
; Polynomials are 256 coefficients modulo q = 3329, one dword each, kept
; in [0, q). Products are reduced by Barrett (x < 2^26: one multiply, one
; shift and a conditional subtraction by cmov), so nothing that depends
; on a secret (the message, the noise, their transforms) takes a branch
; or indexes a table. Rejection sampling of the matrix and the key's
; modulus check branch on public data only.
;
; The constants were proven over every input their callers can pass
; (tests/kat/mlkem_ref.py derives them): Barrett's M = floor(2^32 / q)
; leaves x - q * floor(x M / 2^32) in [0, 2q) for x < 2^26, and the
; rounding divisions of Compress are multiply-shifts exact for the
; numerators they see.
;
;   mlkem768_encaps(rdi ct (1088), rsi shared secret (32), rdx ek (1184),
;                   rcx m (32, random))
;       eax = 1, or 0 when ek fails the modulus check (nothing written).
;   mlkem768_keygen(rdi ek (1184), rsi dk (2400), rdx d | z (64, random))
;       the key pair (FIPS 203 algorithm 16); for okena's own client side.
;   mlkem768_decaps(rdi shared secret (32), rsi dk (2400), rdx ct (1088))
;       algorithm 18: decrypt, encrypt again and compare in constant time;
;       a ciphertext that does not match yields the implicit-rejection
;       secret J(z | c) instead, never an error.

MLKEM_Q		:= 3329
MLKEM_EK	:= 1184
MLKEM_CT	:= 1088
MLKEM_SS	:= 32
MLKEM_DK	:= 2400

; the encapsulation's workspace, on the stack
MK_Y		:= 0			; NTT(y), three polynomials
MK_ACC		:= 3 * 1024		; an accumulator
MK_TMP		:= MK_ACC + 1024	; a matrix entry, a key polynomial, noise
MK_KEC		:= MK_TMP + 1024	; Keccak state (SampleNTT)
MK_XOF		:= MK_KEC + KECCAK_STATE	; one SHAKE128 block
MK_PRF		:= MK_XOF + SHAKE128_RATE	; 128 bytes of PRF output
MK_IN		:= MK_PRF + 128		; m | H(ek), then the seeds
MK_KR		:= MK_IN + 64		; K | r
MK_EK		:= MK_KR + 64		; q: ek
MK_CT		:= MK_EK + 8		; q: ct
MK_M		:= MK_CT + 8		; q: m
MK_SS		:= MK_M + 8		; q: the shared secret's destination
MK_DK		:= MK_SS + 8		; q: dk (decapsulation)
MK_M2		:= MK_DK + 8		; m' (decapsulation)
MK_KBAR		:= MK_M2 + 32		; J(z | c)
MK_CT2		:= MK_KBAR + 32		; c' (1088), then z | c for J (1120)
MK_SIZE		:= (MK_CT2 + 32 + MLKEM_CT + 15) and not 15

rodata
	align 2
	; 17^bitrev7(i) mod q
	mlkem_zetas	dw 1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746
			dw 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821
			dw 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915
			dw 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910
			dw 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050
			dw 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641
			dw 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594
			dw 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
	; 17^(2 bitrev7(i) + 1) mod q, for the base-case products
	mlkem_gammas	dw 17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229
			dw 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279
			dw 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642
			dw 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688
			dw 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684
			dw 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735
			dw 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443
			dw 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175
end rodata

; r (a dword register) = r mod q, for r < 2^26. Uses edx.
macro mk_red r
	mov	edx,r
	imul	rdx,rdx,1290167
	shr	rdx,32
	imul	edx,edx,MLKEM_Q
	sub	r,edx
	mov	edx,r
	sub	edx,MLKEM_Q
	cmp	r,MLKEM_Q
	cmovae	r,edx
end macro

; r = r - q when r >= q (r < 2q). Uses t.
macro mk_csub r, t
	mov	t,r
	sub	t,MLKEM_Q
	cmp	r,MLKEM_Q
	cmovae	r,t
end macro

; rdi = polynomial: the NTT in place (FIPS 203 algorithm 9).
mlkem_ntt:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	r14,[mlkem_zetas]
	mov	r8d,1				; the zeta index
	mov	r9d,128				; len
.layer:
	xor	r10d,r10d			; start
.group:
	movzx	r11d,word [r14+r8*2]
	inc	r8d
	mov	r12d,r10d			; j
	lea	r13d,[r10+r9]			; start + len
.bfly:
	lea	ecx,[r12+r9]
	mov	eax,[rdi+rcx*4]
	imul	eax,r11d
	mk_red	eax				; t = zeta * f[j + len]
	mov	ebx,[rdi+r12*4]
	lea	edx,[rbx+MLKEM_Q]
	sub	edx,eax
	mk_csub	edx,esi
	mov	[rdi+rcx*4],edx			; f[j] - t
	add	ebx,eax
	mk_csub	ebx,esi
	mov	[rdi+r12*4],ebx			; f[j] + t
	inc	r12d
	cmp	r12d,r13d
	jb	.bfly
	lea	r10d,[r10+r9*2]
	cmp	r10d,256
	jb	.group
	shr	r9d,1
	cmp	r9d,2
	jae	.layer
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = polynomial: the inverse NTT in place, times 128^-1 (algorithm 10).
mlkem_invntt:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	r14,[mlkem_zetas]
	mov	r8d,127
	mov	r9d,2
.layer:
	xor	r10d,r10d
.group:
	movzx	r11d,word [r14+r8*2]
	dec	r8d
	mov	r12d,r10d
	lea	r13d,[r10+r9]
.bfly:
	lea	ecx,[r12+r9]
	mov	ebx,[rdi+r12*4]			; t = f[j]
	mov	eax,[rdi+rcx*4]			; f[j + len]
	lea	esi,[rax+rbx]
	mk_csub	esi,edx
	mov	[rdi+r12*4],esi			; t + f[j + len]
	add	eax,MLKEM_Q
	sub	eax,ebx
	imul	eax,r11d
	mk_red	eax
	mov	[rdi+rcx*4],eax			; zeta * (f[j + len] - t)
	inc	r12d
	cmp	r12d,r13d
	jb	.bfly
	lea	r10d,[r10+r9*2]
	cmp	r10d,256
	jb	.group
	shl	r9d,1
	cmp	r9d,128
	jbe	.layer
	xor	ecx,ecx
.scale:
	mov	eax,[rdi+rcx*4]
	imul	eax,3303			; 128^-1 mod q
	mk_red	eax
	mov	[rdi+rcx*4],eax
	inc	ecx
	cmp	ecx,256
	jb	.scale
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = acc, rsi = a, rdx = b (NTT domain): acc += a * b (algorithms 11
; and 12, the 128 degree-one products).
mlkem_basemul_acc:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdx
	lea	r14,[mlkem_gammas]
	xor	r13d,r13d			; i
.pair:
	mov	r8d,[rsi+r13*8]			; a0
	mov	r9d,[rsi+r13*8+4]		; a1
	mov	r10d,[r12+r13*8]		; b0
	mov	r11d,[r12+r13*8+4]		; b1
	mov	eax,r9d
	imul	eax,r11d
	mk_red	eax				; a1 b1
	movzx	ecx,word [r14+r13*2]
	imul	eax,ecx				; a1 b1 gamma
	mov	ebx,r8d
	imul	ebx,r10d
	add	eax,ebx				; + a0 b0
	add	eax,[rdi+r13*8]
	mk_red	eax
	mov	[rdi+r13*8],eax
	mov	eax,r8d
	imul	eax,r11d
	mov	ebx,r9d
	imul	ebx,r10d
	add	eax,ebx				; a0 b1 + a1 b0
	add	eax,[rdi+r13*8+4]
	mk_red	eax
	mov	[rdi+r13*8+4],eax
	inc	r13d
	cmp	r13d,128
	jb	.pair
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = acc, rsi = b: acc += b.
mlkem_add:
	xor	ecx,ecx
@@:
	mov	eax,[rdi+rcx*4]
	add	eax,[rsi+rcx*4]
	mk_csub	eax,edx
	mov	[rdi+rcx*4],eax
	inc	ecx
	cmp	ecx,256
	jb	@b
	ret

; rdi = polynomial, rsi = 128 bytes: SamplePolyCBD with eta = 2 (algorithm
; 8). Each nibble is two pairs of bits: (b0 + b1) - (b2 + b3).
mlkem_cbd2:
	push	rbx
	xor	r8d,r8d				; the word
.word:
	mov	eax,[rsi+r8*4]
	mov	edx,eax
	shr	edx,1
	and	eax,0x55555555
	and	edx,0x55555555
	add	eax,edx				; 2-bit sums
	xor	ecx,ecx
.nib:
	mov	ebx,eax
	and	ebx,3
	mov	edx,eax
	shr	edx,2
	and	edx,3
	sub	ebx,edx
	add	ebx,MLKEM_Q			; in [q - 2, q + 2]
	mk_csub	ebx,edx
	lea	edx,[r8*8+rcx]
	mov	[rdi+rdx*4],ebx
	shr	eax,4
	inc	ecx
	cmp	ecx,8
	jb	.nib
	inc	r8d
	cmp	r8d,32
	jb	.word
	pop	rbx
	ret

; rdi = polynomial, rsi = 384 bytes: ByteDecode12. eax = 1, or 0 when a
; coefficient is not below q (the modulus check). No branch on the values:
; it decodes the secret key too.
mlkem_decode12:
	push	rbx
	xor	ecx,ecx				; coefficient pair
	xor	r8d,r8d				; any out of range
.pair:
	movzx	eax,word [rsi]
	movzx	edx,byte [rsi+2]
	shl	edx,16
	or	eax,edx				; 24 bits
	mov	edx,eax
	and	eax,0xFFF
	shr	edx,12
	cmp	eax,MLKEM_Q
	setae	bl
	or	r8b,bl
	cmp	edx,MLKEM_Q
	setae	bl
	or	r8b,bl
	mov	[rdi+rcx*8],eax
	mov	[rdi+rcx*8+4],edx
	add	rsi,3
	inc	ecx
	cmp	ecx,128
	jb	.pair
	xor	eax,eax
	test	r8b,r8b
	sete	al
	pop	rbx
	ret

; rdi = out (384), rsi = polynomial (coefficients below q): ByteEncode12.
mlkem_encode12:
	xor	ecx,ecx
.pair:
	mov	eax,[rsi+rcx*8]
	mov	edx,[rsi+rcx*8+4]
	shl	edx,12
	or	eax,edx
	mov	[rdi],ax
	shr	eax,16
	mov	[rdi+2],al
	add	rdi,3
	inc	ecx
	cmp	ecx,128
	jb	.pair
	ret

; rdi = polynomial, rsi = 320 bytes: Decompress10(ByteDecode10).
mlkem_decompress10:
	xor	ecx,ecx
.four:
	mov	r8d,[rsi]
	movzx	eax,byte [rsi+4]
	shl	rax,32
	or	r8,rax				; 40 bits
	repeat 4, k:0
		mov	rax,r8
		if k > 0
			shr	rax,k*10
		end if
		and	eax,1023
		imul	eax,MLKEM_Q
		add	eax,512
		shr	eax,10
		mov	[rdi+rcx*4+k*4],eax
	end repeat
	add	rsi,5
	add	ecx,4
	cmp	ecx,256
	jb	.four
	ret

; rdi = polynomial, rsi = 128 bytes: Decompress4(ByteDecode4).
mlkem_decompress4:
	xor	ecx,ecx
.two:
	movzx	eax,byte [rsi]
	mov	edx,eax
	and	eax,15
	shr	edx,4
	imul	eax,MLKEM_Q
	add	eax,8
	shr	eax,4
	imul	edx,MLKEM_Q
	add	edx,8
	shr	edx,4
	mov	[rdi+rcx*4],eax
	mov	[rdi+rcx*4+4],edx
	inc	rsi
	add	ecx,2
	cmp	ecx,256
	jb	.two
	ret

; rdi = out (32), rsi = polynomial: ByteEncode1(Compress1), the message.
; Secret data: a multiply-shift, no branch.
mlkem_compress1:
	xor	ecx,ecx
.byte:
	xor	r8d,r8d
	repeat 8, k:0
		mov	eax,[rsi+rcx*4+k*4]
		shl	eax,2
		add	eax,MLKEM_Q
		imul	eax,315
		shr	eax,21
		and	eax,1
		if k > 0
			shl	eax,k
		end if
		or	r8d,eax
	end repeat
	mov	[rdi],r8b
	inc	rdi
	add	ecx,8
	cmp	ecx,256
	jb	.byte
	ret

; rdi = out (320), rsi = polynomial: ByteEncode10(Compress10).
mlkem_compress10:
	xor	ecx,ecx
.four:
	xor	r8d,r8d				; 40 bits
	repeat 4, k:0
		mov	eax,[rsi+rcx*4+k*4]
		shl	eax,11
		add	eax,MLKEM_Q
		imul	rax,rax,2580335
		shr	rax,34
		and	eax,1023
		if k > 0
			shl	rax,k*10
		end if
		or	r8,rax
	end repeat
	mov	[rdi],r8d
	shr	r8,32
	mov	[rdi+4],r8b
	add	rdi,5
	add	ecx,4
	cmp	ecx,256
	jb	.four
	ret

; rdi = out (128), rsi = polynomial: ByteEncode4(Compress4).
mlkem_compress4:
	xor	ecx,ecx
.two:
	mov	eax,[rsi+rcx*4]
	shl	eax,5
	add	eax,MLKEM_Q
	imul	eax,20159
	shr	eax,27
	and	eax,15
	mov	edx,[rsi+rcx*4+4]
	shl	edx,5
	add	edx,MLKEM_Q
	imul	edx,20159
	shr	edx,27
	and	edx,15
	shl	edx,4
	or	eax,edx
	mov	[rdi],al
	inc	rdi
	add	ecx,2
	cmp	ecx,256
	jb	.two
	ret

; rdi = polynomial, rsi = 34-byte seed (rho | i | j), rdx = workspace:
; SampleNTT (algorithm 7), from SHAKE128 one block (56 triples) at a time.
mlkem_sample_ntt:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13,rdx
	lea	rdi,[r13+MK_KEC]
	mov	edx,34
	mov	ecx,SHAKE128_RATE
	mov	r8d,KECCAK_SHAKE
	call	keccak_absorb
	xor	ebx,ebx				; coefficients so far
	xor	r8d,r8d				; the first block: the state's own
.block:
	lea	rdi,[r13+MK_KEC]
	lea	rsi,[r13+MK_XOF]
	mov	edx,1
	mov	ecx,SHAKE128_RATE
	call	keccak_squeeze
	mov	r8d,1
	lea	rsi,[r13+MK_XOF]
	lea	r14,[rsi+SHAKE128_RATE]
.triple:
	movzx	eax,word [rsi]
	movzx	edx,byte [rsi+2]
	shl	edx,16
	or	eax,edx
	add	rsi,3
	mov	edx,eax
	and	eax,0xFFF			; d1
	shr	edx,12				; d2
	cmp	eax,MLKEM_Q
	jae	@f
	mov	[r12+rbx*4],eax
	inc	ebx
	cmp	ebx,256
	jae	.done
@@:
	cmp	edx,MLKEM_Q
	jae	@f
	mov	[r12+rbx*4],edx
	inc	ebx
	cmp	ebx,256
	jae	.done
@@:
	cmp	rsi,r14
	jb	.triple
	jmp	.block
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbp = workspace, edx = N: PRF_2(r, N) -> MK_PRF (128 bytes), then the
; noise polynomial into MK_TMP.
mlkem_noise:
	lea	rsi,[rbp+MK_KR+32]		; r
	lea	rdi,[rbp+MK_IN]
	mov	rax,[rsi]
	mov	[rdi],rax
	mov	rax,[rsi+8]
	mov	[rdi+8],rax
	mov	rax,[rsi+16]
	mov	[rdi+16],rax
	mov	rax,[rsi+24]
	mov	[rdi+24],rax
	mov	[rdi+32],dl
	lea	rdi,[rbp+MK_PRF]
	mov	esi,128
	lea	rdx,[rbp+MK_IN]
	mov	ecx,33
	mov	r8d,SHAKE256_RATE
	call	shake
	lea	rdi,[rbp+MK_TMP]
	lea	rsi,[rbp+MK_PRF]
	jmp	mlkem_cbd2

; rbp = workspace, rdi = polynomial: zeroed.
mlkem_zero:
	xor	eax,eax
	mov	ecx,256
	rep	stosd
	ret

mlkem768_encaps:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MK_SIZE
	mov	rbp,rsp
	mov	[rbp+MK_CT],rdi
	mov	[rbp+MK_SS],rsi
	mov	[rbp+MK_EK],rdx
	mov	[rbp+MK_M],rcx
	; the modulus check: every coefficient of t below q
	xor	r12d,r12d
.check:
	lea	rdi,[rbp+MK_TMP]
	imul	rsi,r12,384
	add	rsi,[rbp+MK_EK]
	call	mlkem_decode12
	test	eax,eax
	jz	mlkem_leave
	inc	r12d
	cmp	r12d,3
	jb	.check
	; (K, r) = G(m | H(ek))
	mov	rsi,[rbp+MK_M]
	lea	rdi,[rbp+MK_IN]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbp+MK_IN+32]
	mov	rsi,[rbp+MK_EK]
	mov	edx,MLKEM_EK
	call	sha3_256
	lea	rdi,[rbp+MK_KR]
	lea	rsi,[rbp+MK_IN]
	mov	edx,64
	call	sha3_512
	call	mlkem_encrypt
	; the shared secret is K
	mov	rdi,[rbp+MK_SS]
	lea	rsi,[rbp+MK_KR]
	mov	ecx,32
	rep	movsb
	mov	eax,1
	jmp	mlkem_leave

; rbp = workspace with MK_EK, MK_M, MK_CT and r (MK_KR + 32): K-PKE.Encrypt
; (algorithm 14), the ciphertext to MK_CT.
mlkem_encrypt:
	push	r12
	push	r13
	; y = NTT(CBD(PRF(r, i))), i = 0..2
	xor	r12d,r12d
.y:
	mov	edx,r12d
	call	mlkem_noise
	imul	rdi,r12,1024
	add	rdi,rbp				; MK_Y = 0
	lea	rsi,[rbp+MK_TMP]
	mov	ecx,256
	push	rdi
	rep	movsd
	pop	rdi
	call	mlkem_ntt
	inc	r12d
	cmp	r12d,3
	jb	.y
	; u[i] = NTT^-1(sum_j A[j][i] y[j]) + e1[i], A[j][i] = SampleNTT(rho | i | j)
	xor	r12d,r12d			; i
.u:
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_zero
	xor	r13d,r13d			; j
.uj:
	mov	rsi,[rbp+MK_EK]			; rho, then i, j
	add	rsi,3 * 384
	lea	rdi,[rbp+MK_IN]
	mov	ecx,32
	rep	movsb
	mov	[rdi],r12b
	mov	[rdi+1],r13b
	lea	rdi,[rbp+MK_TMP]
	lea	rsi,[rbp+MK_IN]
	mov	rdx,rbp
	call	mlkem_sample_ntt
	lea	rdi,[rbp+MK_ACC]
	lea	rsi,[rbp+MK_TMP]
	imul	rdx,r13,1024
	add	rdx,rbp
	call	mlkem_basemul_acc
	inc	r13d
	cmp	r13d,3
	jb	.uj
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_invntt
	lea	edx,[r12+3]			; e1[i] = CBD(PRF(r, 3 + i))
	call	mlkem_noise
	lea	rdi,[rbp+MK_ACC]
	lea	rsi,[rbp+MK_TMP]
	call	mlkem_add
	imul	rdi,r12,320
	add	rdi,[rbp+MK_CT]
	lea	rsi,[rbp+MK_ACC]
	call	mlkem_compress10
	inc	r12d
	cmp	r12d,3
	jb	.u
	; v = NTT^-1(sum_j t[j] y[j]) + e2 + Decompress1(m)
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_zero
	xor	r13d,r13d
.vj:
	lea	rdi,[rbp+MK_TMP]
	imul	rsi,r13,384
	add	rsi,[rbp+MK_EK]
	call	mlkem_decode12
	lea	rdi,[rbp+MK_ACC]
	lea	rsi,[rbp+MK_TMP]
	imul	rdx,r13,1024
	add	rdx,rbp
	call	mlkem_basemul_acc
	inc	r13d
	cmp	r13d,3
	jb	.vj
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_invntt
	mov	edx,6				; e2 = CBD(PRF(r, 6))
	call	mlkem_noise
	lea	rdi,[rbp+MK_ACC]
	lea	rsi,[rbp+MK_TMP]
	call	mlkem_add
	mov	rsi,[rbp+MK_M]			; + round(q/2) for each set bit of m
	xor	ecx,ecx
.mu:
	mov	eax,ecx
	shr	eax,3
	movzx	eax,byte [rsi+rax]
	mov	edx,ecx
	and	edx,7
	xchg	ecx,edx
	shr	eax,cl
	xchg	ecx,edx
	and	eax,1
	neg	eax
	and	eax,1665
	add	eax,[rbp+MK_ACC+rcx*4]
	mk_csub	eax,edx
	mov	[rbp+MK_ACC+rcx*4],eax
	inc	ecx
	cmp	ecx,256
	jb	.mu
	mov	rdi,[rbp+MK_CT]
	add	rdi,3 * 320
	lea	rsi,[rbp+MK_ACC]
	call	mlkem_compress4
	pop	r13
	pop	r12
	ret

; the end of every entry point: eax = the result, the workspace wiped
mlkem_leave:
	mov	r12d,eax
	mov	rdi,rbp				; wipe: y, the noise, m, K, r, m', J
	xor	eax,eax
	mov	ecx,MK_SIZE / 8
	rep	stosq
	mov	eax,r12d
	add	rsp,MK_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; the prologue of every entry point: rbp = a fresh workspace
macro mlkem_enter
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MK_SIZE
	mov	rbp,rsp
end macro

mlkem768_keygen:
	mlkem_enter
	mov	[rbp+MK_CT],rdi			; ek
	mov	[rbp+MK_DK],rsi
	mov	[rbp+MK_M],rdx			; d | z
	; (rho, sigma) = G(d | k)
	mov	rsi,rdx
	lea	rdi,[rbp+MK_IN]
	mov	ecx,32
	rep	movsb
	mov	byte [rdi],3
	lea	rdi,[rbp+MK_KR]
	lea	rsi,[rbp+MK_IN]
	mov	edx,33
	call	sha3_512
	; s = NTT(CBD(PRF(sigma, i))) into MK_Y (sigma is at MK_KR + 32, where
	; mlkem_noise takes its seed)
	xor	r12d,r12d
.s:
	mov	edx,r12d
	call	mlkem_noise
	imul	rdi,r12,1024
	add	rdi,rbp
	lea	rsi,[rbp+MK_TMP]
	mov	ecx,256
	push	rdi
	rep	movsd
	pop	rdi
	call	mlkem_ntt
	inc	r12d
	cmp	r12d,3
	jb	.s
	; t[i] = sum_j A[i][j] s[j] + NTT(e[i]), A[i][j] = SampleNTT(rho | j | i)
	xor	r12d,r12d
.t:
	lea	edx,[r12+3]
	call	mlkem_noise
	lea	rdi,[rbp+MK_TMP]
	call	mlkem_ntt
	lea	rsi,[rbp+MK_TMP]
	lea	rdi,[rbp+MK_ACC]
	mov	ecx,256
	rep	movsd
	xor	r13d,r13d
.tj:
	lea	rsi,[rbp+MK_KR]			; rho, then j, i
	lea	rdi,[rbp+MK_IN]
	mov	ecx,32
	rep	movsb
	mov	[rdi],r13b
	mov	[rdi+1],r12b
	lea	rdi,[rbp+MK_TMP]
	lea	rsi,[rbp+MK_IN]
	mov	rdx,rbp
	call	mlkem_sample_ntt
	lea	rdi,[rbp+MK_ACC]
	lea	rsi,[rbp+MK_TMP]
	imul	rdx,r13,1024
	add	rdx,rbp
	call	mlkem_basemul_acc
	inc	r13d
	cmp	r13d,3
	jb	.tj
	imul	rdi,r12,384
	add	rdi,[rbp+MK_CT]
	lea	rsi,[rbp+MK_ACC]
	call	mlkem_encode12
	inc	r12d
	cmp	r12d,3
	jb	.t
	mov	rdi,[rbp+MK_CT]			; ek = t | rho
	add	rdi,3 * 384
	lea	rsi,[rbp+MK_KR]
	mov	ecx,32
	rep	movsb
	; dk = s | ek | H(ek) | z
	xor	r12d,r12d
.dks:
	imul	rdi,r12,384
	add	rdi,[rbp+MK_DK]
	imul	rsi,r12,1024
	add	rsi,rbp
	call	mlkem_encode12
	inc	r12d
	cmp	r12d,3
	jb	.dks
	mov	rdi,[rbp+MK_DK]
	add	rdi,3 * 384
	mov	rsi,[rbp+MK_CT]
	mov	ecx,MLKEM_EK
	rep	movsb
	mov	rdi,[rbp+MK_DK]
	add	rdi,3 * 384 + MLKEM_EK
	mov	rsi,[rbp+MK_CT]
	mov	edx,MLKEM_EK
	call	sha3_256
	mov	rdi,[rbp+MK_DK]
	add	rdi,3 * 384 + MLKEM_EK + 32
	mov	rsi,[rbp+MK_M]
	add	rsi,32
	mov	ecx,32
	rep	movsb
	mov	eax,1
	jmp	mlkem_leave

mlkem768_decaps:
	mlkem_enter
	mov	[rbp+MK_SS],rdi
	mov	[rbp+MK_DK],rsi
	mov	[rbp+MK_CT],rdx			; c, for now
	; K-PKE.Decrypt (algorithm 15): w = v - NTT^-1(sum s[i] NTT(u[i]))
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_zero
	xor	r12d,r12d
.u:
	lea	rdi,[rbp+MK_TMP]
	imul	rsi,r12,320
	add	rsi,[rbp+MK_CT]
	call	mlkem_decompress10
	lea	rdi,[rbp+MK_TMP]
	call	mlkem_ntt
	mov	rdi,rbp				; s[i] into MK_Y
	imul	rsi,r12,384
	add	rsi,[rbp+MK_DK]
	call	mlkem_decode12
	lea	rdi,[rbp+MK_ACC]
	mov	rsi,rbp
	lea	rdx,[rbp+MK_TMP]
	call	mlkem_basemul_acc
	inc	r12d
	cmp	r12d,3
	jb	.u
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_invntt
	lea	rdi,[rbp+MK_TMP]		; v
	mov	rsi,[rbp+MK_CT]
	add	rsi,3 * 320
	call	mlkem_decompress4
	xor	ecx,ecx
.w:
	mov	eax,[rbp+MK_TMP+rcx*4]		; v - that, mod q
	add	eax,MLKEM_Q
	sub	eax,[rbp+MK_ACC+rcx*4]
	mk_csub	eax,edx
	mov	[rbp+MK_ACC+rcx*4],eax
	inc	ecx
	cmp	ecx,256
	jb	.w
	lea	rdi,[rbp+MK_M2]
	lea	rsi,[rbp+MK_ACC]
	call	mlkem_compress1
	; (K', r') = G(m' | h)
	lea	rsi,[rbp+MK_M2]
	lea	rdi,[rbp+MK_IN]
	mov	ecx,32
	rep	movsb
	mov	rsi,[rbp+MK_DK]
	add	rsi,3 * 384 + MLKEM_EK
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbp+MK_KR]
	lea	rsi,[rbp+MK_IN]
	mov	edx,64
	call	sha3_512
	; K-bar = J(z | c) = SHAKE256(z | c, 32)
	mov	rsi,[rbp+MK_DK]
	add	rsi,3 * 384 + MLKEM_EK + 32
	lea	rdi,[rbp+MK_CT2]
	mov	ecx,32
	rep	movsb
	mov	rsi,[rbp+MK_CT]
	mov	ecx,MLKEM_CT
	rep	movsb
	lea	rdi,[rbp+MK_KBAR]
	mov	esi,32
	lea	rdx,[rbp+MK_CT2]
	mov	ecx,32 + MLKEM_CT
	mov	r8d,SHAKE256_RATE
	call	shake
	; c' = K-PKE.Encrypt(ek, m', r')
	mov	r14,[rbp+MK_CT]			; c
	lea	rax,[rbp+MK_CT2]
	mov	[rbp+MK_CT],rax
	lea	rax,[rbp+MK_M2]
	mov	[rbp+MK_M],rax
	mov	rax,[rbp+MK_DK]
	add	rax,3 * 384
	mov	[rbp+MK_EK],rax
	call	mlkem_encrypt
	; c == c'? in constant time; then K' or K-bar by mask
	xor	eax,eax
	xor	ecx,ecx
.cmp:
	mov	rdx,[r14+rcx]
	xor	rdx,[rbp+MK_CT2+rcx]
	or	rax,rdx
	add	ecx,8
	cmp	ecx,MLKEM_CT
	jb	.cmp
	neg	rax				; CF = 1 when they differ
	sbb	rax,rax				; -1 differ, 0 same
	mov	rdi,[rbp+MK_SS]
	xor	ecx,ecx
.sel:
	mov	rdx,[rbp+MK_KR+rcx]		; K'
	mov	r8,[rbp+MK_KBAR+rcx]
	xor	r8,rdx
	and	r8,rax
	xor	rdx,r8				; K' ^ ((K' ^ K-bar) & mask)
	mov	[rdi+rcx],rdx
	add	ecx,8
	cmp	ecx,32
	jb	.sel
	mov	eax,1
	jmp	mlkem_leave
