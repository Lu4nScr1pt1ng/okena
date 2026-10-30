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
MK_A		:= MK_CT2 + 32 + MLKEM_CT	; a row of the matrix (three polynomials)
MK_E		:= MK_A + 3 * 1024		; noise: e1[0..2] and e2, or e[0..2]
MK_X4		:= MK_E + 4 * 1024		; four Keccak states (KECCAK_X4)
MK_L4		:= MK_X4 + KECCAK_X4		; their lanes 4 (4 x 8)
MK_CNT		:= MK_L4 + 32			; SampleNTT: coefficients so far (3 x 4)
MK_SIZE		:= (MK_CNT + 16 + 31) and not 31


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

; The polynomial arithmetic on AVX2, eight coefficients a ymm (dwords, as
; the rest of the file keeps them). ymm15 = q and ymm14 = 5039 everywhere:
; Barrett on 32 bits, q~ = ((x >> 8) * 5039) >> 16, leaves x - q~ q in
; [0, 2.49q) for x < 2^25 (checked over every such x), and a conditional
; subtraction is an unsigned min with x - q (which wraps when x < q).

rodata
	align 32
	; the zetas as dwords (vpbroadcastd)
	mlkem_zetas32	dd 1, 1729, 2580, 3289, 2642, 630, 1897, 848
			dd 1062, 1919, 193, 797, 2786, 3260, 569, 1746
			dd 296, 2447, 1339, 1476, 3046, 56, 2240, 1333
			dd 1426, 2094, 535, 2882, 2393, 2879, 1974, 821
			dd 289, 331, 3253, 1756, 1197, 2304, 2277, 2055
			dd 650, 1977, 2513, 632, 2865, 33, 1320, 1915
			dd 2319, 1435, 807, 452, 1438, 2868, 1534, 2402
			dd 2647, 2617, 1481, 648, 2474, 3110, 1227, 910
			dd 17, 2761, 583, 2649, 1637, 723, 2288, 1100
			dd 1409, 2662, 3281, 233, 756, 2156, 3015, 3050
			dd 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687
			dd 939, 2308, 2437, 2388, 733, 2337, 268, 641
			dd 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645
			dd 1063, 319, 2773, 757, 2099, 561, 2466, 2594
			dd 2804, 1092, 403, 1026, 1143, 2150, 2775, 886
			dd 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
	; NTT, len 4: two groups a vector, [z(2t) x4 | z(2t+1) x4]
	mlkem_ntt4	dd 289, 289, 289, 289, 331, 331, 331, 331
			dd 3253, 3253, 3253, 3253, 1756, 1756, 1756, 1756
			dd 1197, 1197, 1197, 1197, 2304, 2304, 2304, 2304
			dd 2277, 2277, 2277, 2277, 2055, 2055, 2055, 2055
			dd 650, 650, 650, 650, 1977, 1977, 1977, 1977
			dd 2513, 2513, 2513, 2513, 632, 632, 632, 632
			dd 2865, 2865, 2865, 2865, 33, 33, 33, 33
			dd 1320, 1320, 1320, 1320, 1915, 1915, 1915, 1915
			dd 2319, 2319, 2319, 2319, 1435, 1435, 1435, 1435
			dd 807, 807, 807, 807, 452, 452, 452, 452
			dd 1438, 1438, 1438, 1438, 2868, 2868, 2868, 2868
			dd 1534, 1534, 1534, 1534, 2402, 2402, 2402, 2402
			dd 2647, 2647, 2647, 2647, 2617, 2617, 2617, 2617
			dd 1481, 1481, 1481, 1481, 648, 648, 648, 648
			dd 2474, 2474, 2474, 2474, 3110, 3110, 3110, 3110
			dd 1227, 1227, 1227, 1227, 910, 910, 910, 910
	; NTT, len 2: four groups, laid out as vpunpck[lh]qdq leaves them
	mlkem_ntt2	dd 17, 17, 583, 583, 2761, 2761, 2649, 2649
			dd 1637, 1637, 2288, 2288, 723, 723, 1100, 1100
			dd 1409, 1409, 3281, 3281, 2662, 2662, 233, 233
			dd 756, 756, 3015, 3015, 2156, 2156, 3050, 3050
			dd 1703, 1703, 2789, 2789, 1651, 1651, 1789, 1789
			dd 1847, 1847, 1461, 1461, 952, 952, 2687, 2687
			dd 939, 939, 2437, 2437, 2308, 2308, 2388, 2388
			dd 733, 733, 268, 268, 2337, 2337, 641, 641
			dd 1584, 1584, 2037, 2037, 2298, 2298, 3220, 3220
			dd 375, 375, 2090, 2090, 2549, 2549, 1645, 1645
			dd 1063, 1063, 2773, 2773, 319, 319, 757, 757
			dd 2099, 2099, 2466, 2466, 561, 561, 2594, 2594
			dd 2804, 2804, 403, 403, 1092, 1092, 1026, 1026
			dd 1143, 1143, 2775, 2775, 2150, 2150, 886, 886
			dd 1722, 1722, 1874, 1874, 1212, 1212, 1029, 1029
			dd 2110, 2110, 885, 885, 2935, 2935, 2154, 2154
	; inverse NTT, len 2
	mlkem_intt2	dd 2154, 2154, 2935, 2935, 885, 885, 2110, 2110
			dd 1029, 1029, 1212, 1212, 1874, 1874, 1722, 1722
			dd 886, 886, 2150, 2150, 2775, 2775, 1143, 1143
			dd 1026, 1026, 1092, 1092, 403, 403, 2804, 2804
			dd 2594, 2594, 561, 561, 2466, 2466, 2099, 2099
			dd 757, 757, 319, 319, 2773, 2773, 1063, 1063
			dd 1645, 1645, 2549, 2549, 2090, 2090, 375, 375
			dd 3220, 3220, 2298, 2298, 2037, 2037, 1584, 1584
			dd 641, 641, 2337, 2337, 268, 268, 733, 733
			dd 2388, 2388, 2308, 2308, 2437, 2437, 939, 939
			dd 2687, 2687, 952, 952, 1461, 1461, 1847, 1847
			dd 1789, 1789, 1651, 1651, 2789, 2789, 1703, 1703
			dd 3050, 3050, 2156, 2156, 3015, 3015, 756, 756
			dd 233, 233, 2662, 2662, 3281, 3281, 1409, 1409
			dd 1100, 1100, 723, 723, 2288, 2288, 1637, 1637
			dd 2649, 2649, 2761, 2761, 583, 583, 17, 17
	; inverse NTT, len 4
	mlkem_intt4	dd 910, 910, 910, 910, 1227, 1227, 1227, 1227
			dd 3110, 3110, 3110, 3110, 2474, 2474, 2474, 2474
			dd 648, 648, 648, 648, 1481, 1481, 1481, 1481
			dd 2617, 2617, 2617, 2617, 2647, 2647, 2647, 2647
			dd 2402, 2402, 2402, 2402, 1534, 1534, 1534, 1534
			dd 2868, 2868, 2868, 2868, 1438, 1438, 1438, 1438
			dd 452, 452, 452, 452, 807, 807, 807, 807
			dd 1435, 1435, 1435, 1435, 2319, 2319, 2319, 2319
			dd 1915, 1915, 1915, 1915, 1320, 1320, 1320, 1320
			dd 33, 33, 33, 33, 2865, 2865, 2865, 2865
			dd 632, 632, 632, 632, 2513, 2513, 2513, 2513
			dd 1977, 1977, 1977, 1977, 650, 650, 650, 650
			dd 2055, 2055, 2055, 2055, 2277, 2277, 2277, 2277
			dd 2304, 2304, 2304, 2304, 1197, 1197, 1197, 1197
			dd 1756, 1756, 1756, 1756, 3253, 3253, 3253, 3253
			dd 331, 331, 331, 331, 289, 289, 289, 289
	; base-case gammas, eight pairs a block in vshufps order
	mlkem_gammas8	dd 17, 3312, 583, 2746, 2761, 568, 2649, 680
			dd 1637, 1692, 2288, 1041, 723, 2606, 1100, 2229
			dd 1409, 1920, 3281, 48, 2662, 667, 233, 3096
			dd 756, 2573, 3015, 314, 2156, 1173, 3050, 279
			dd 1703, 1626, 2789, 540, 1651, 1678, 1789, 1540
			dd 1847, 1482, 1461, 1868, 952, 2377, 2687, 642
			dd 939, 2390, 2437, 892, 2308, 1021, 2388, 941
			dd 733, 2596, 268, 3061, 2337, 992, 641, 2688
			dd 1584, 1745, 2037, 1292, 2298, 1031, 3220, 109
			dd 375, 2954, 2090, 1239, 2549, 780, 1645, 1684
			dd 1063, 2266, 2773, 556, 319, 3010, 757, 2572
			dd 2099, 1230, 2466, 863, 561, 2768, 2594, 735
			dd 2804, 525, 403, 2926, 1092, 2237, 1026, 2303
			dd 1143, 2186, 2775, 554, 2150, 1179, 886, 2443
			dd 1722, 1607, 1874, 1455, 1212, 2117, 1029, 2300
			dd 2110, 1219, 885, 2444, 2935, 394, 2154, 1175
end rodata

; ymm15 = q, ymm14 = 5039
macro mk_vinit
	mov	eax,MLKEM_Q
	vmovd	xmm15,eax
	vpbroadcastd ymm15,xmm15
	mov	eax,5039
	vmovd	xmm14,eax
	vpbroadcastd ymm14,xmm14
end macro

; r = r - q when r >= q (r < 2q). Uses t.
macro mk_vcsub r, t
	vpsubd	t,r,ymm15
	vpminud	r,r,t
end macro

; r = r mod q, for r < 2^25 (two subtractions; one when r < 2^24). Uses t.
macro mk_vred r, t, once:0
	vpsrld	t,r,8
	vpmulld	t,t,ymm14
	vpsrld	t,t,16
	vpmulld	t,t,ymm15
	vpsubd	r,r,t
	mk_vcsub r, t
	if once = 0
		mk_vcsub r, t
	end if
end macro

; a CT butterfly on (a, b) with zetas z: b = a - z b, a = a + z b
macro mk_ct a, b, z
	vpmulld	b,b,z
	mk_vred	b, ymm13, 1			; z b < q^2 < 2^24
	vpaddd	ymm12,a,ymm15
	vpsubd	ymm12,ymm12,b
	vpaddd	a,a,b
	mk_vcsub a, ymm13
	mk_vcsub ymm12, ymm13
	vmovdqa	b,ymm12
end macro

; a GS butterfly: a = a + b, b = z (b - a)
macro mk_gs a, b, z
	vpaddd	ymm12,b,ymm15
	vpsubd	ymm12,ymm12,a
	vpaddd	a,a,b
	mk_vcsub a, ymm13
	vpmulld	b,ymm12,z			; < 2q^2 < 2^25
	mk_vred	b, ymm13
end macro

; rdi = polynomial: the NTT in place (FIPS 203 algorithm 9).
mlkem_ntt:
	mk_vinit
	lea	r8,[mlkem_zetas32+4]		; zeta 1 on
	mov	r9d,128*4			; len, in bytes
.layer:
	xor	r10d,r10d			; start, in bytes
.group:
	vpbroadcastd ymm2,[r8]
	add	r8,4
	mov	r11,r10				; j
	lea	rcx,[r10+r9]			; start + len
.vec:
	lea	rax,[rdi+r11]
	vmovdqu	ymm0,[rax]
	vmovdqu	ymm1,[rax+r9]
	mk_ct	ymm0, ymm1, ymm2
	vmovdqu	[rax],ymm0
	vmovdqu	[rax+r9],ymm1
	add	r11,32
	cmp	r11,rcx
	jb	.vec
	lea	r10,[r10+r9*2]
	cmp	r10,1024
	jb	.group
	shr	r9d,1
	cmp	r9d,8*4
	jae	.layer
	; len 4: two groups a vector, their halves split by vperm2i128
	lea	r8,[mlkem_ntt4]
	xor	ecx,ecx
.l4:
	vmovdqu	ymm4,[rdi+rcx]
	vmovdqu	ymm5,[rdi+rcx+32]
	vperm2i128 ymm0,ymm4,ymm5,0x20
	vperm2i128 ymm1,ymm4,ymm5,0x31
	vmovdqa	ymm2,[r8]
	mk_ct	ymm0, ymm1, ymm2
	vperm2i128 ymm4,ymm0,ymm1,0x20
	vperm2i128 ymm5,ymm0,ymm1,0x31
	vmovdqu	[rdi+rcx],ymm4
	vmovdqu	[rdi+rcx+32],ymm5
	add	r8,32
	add	ecx,64
	cmp	ecx,1024
	jb	.l4
	; len 2: four groups, split by vpunpck[lh]qdq
	lea	r8,[mlkem_ntt2]
	xor	ecx,ecx
.l2:
	vmovdqu	ymm4,[rdi+rcx]
	vmovdqu	ymm5,[rdi+rcx+32]
	vpunpcklqdq ymm0,ymm4,ymm5
	vpunpckhqdq ymm1,ymm4,ymm5
	vmovdqa	ymm2,[r8]
	mk_ct	ymm0, ymm1, ymm2
	vpunpcklqdq ymm4,ymm0,ymm1
	vpunpckhqdq ymm5,ymm0,ymm1
	vmovdqu	[rdi+rcx],ymm4
	vmovdqu	[rdi+rcx+32],ymm5
	add	r8,32
	add	ecx,64
	cmp	ecx,1024
	jb	.l2
	vzeroupper
	ret

; rdi = polynomial: the inverse NTT in place, times 128^-1 (algorithm 10).
mlkem_invntt:
	mk_vinit
	; len 2, then len 4: the NTT's last layers, undone first
	lea	r8,[mlkem_intt2]
	xor	ecx,ecx
.l2:
	vmovdqu	ymm4,[rdi+rcx]
	vmovdqu	ymm5,[rdi+rcx+32]
	vpunpcklqdq ymm0,ymm4,ymm5
	vpunpckhqdq ymm1,ymm4,ymm5
	vmovdqa	ymm2,[r8]
	mk_gs	ymm0, ymm1, ymm2
	vpunpcklqdq ymm4,ymm0,ymm1
	vpunpckhqdq ymm5,ymm0,ymm1
	vmovdqu	[rdi+rcx],ymm4
	vmovdqu	[rdi+rcx+32],ymm5
	add	r8,32
	add	ecx,64
	cmp	ecx,1024
	jb	.l2
	lea	r8,[mlkem_intt4]
	xor	ecx,ecx
.l4:
	vmovdqu	ymm4,[rdi+rcx]
	vmovdqu	ymm5,[rdi+rcx+32]
	vperm2i128 ymm0,ymm4,ymm5,0x20
	vperm2i128 ymm1,ymm4,ymm5,0x31
	vmovdqa	ymm2,[r8]
	mk_gs	ymm0, ymm1, ymm2
	vperm2i128 ymm4,ymm0,ymm1,0x20
	vperm2i128 ymm5,ymm0,ymm1,0x31
	vmovdqu	[rdi+rcx],ymm4
	vmovdqu	[rdi+rcx+32],ymm5
	add	r8,32
	add	ecx,64
	cmp	ecx,1024
	jb	.l4
	; len 8 .. 128, zetas from 31 down
	lea	r8,[mlkem_zetas32+31*4]
	mov	r9d,8*4
.layer:
	xor	r10d,r10d
.group:
	vpbroadcastd ymm2,[r8]
	sub	r8,4
	mov	r11,r10
	lea	rcx,[r10+r9]
.vec:
	lea	rax,[rdi+r11]
	vmovdqu	ymm0,[rax]
	vmovdqu	ymm1,[rax+r9]
	mk_gs	ymm0, ymm1, ymm2
	vmovdqu	[rax],ymm0
	vmovdqu	[rax+r9],ymm1
	add	r11,32
	cmp	r11,rcx
	jb	.vec
	lea	r10,[r10+r9*2]
	cmp	r10,1024
	jb	.group
	shl	r9d,1
	cmp	r9d,128*4
	jbe	.layer
	; times 128^-1 = 3303
	mov	eax,3303
	vmovd	xmm2,eax
	vpbroadcastd ymm2,xmm2
	xor	ecx,ecx
.scale:
	vmovdqu	ymm0,[rdi+rcx]
	vpmulld	ymm0,ymm0,ymm2
	mk_vred	ymm0, ymm13, 1
	vmovdqu	[rdi+rcx],ymm0
	add	ecx,32
	cmp	ecx,1024
	jb	.scale
	vzeroupper
	ret

; rdi = acc, rsi = a, rdx = b (NTT domain): acc += a * b (algorithms 11
; and 12). Eight pairs at a time: vshufps splits the even and odd
; coefficients (pairs in the order mlkem_gammas8 follows), vunpck[lh]ps
; puts them back.
mlkem_basemul_acc:
	mk_vinit
	lea	r8,[mlkem_gammas8]
	xor	ecx,ecx
.block:
	vmovdqu	ymm0,[rsi+rcx]
	vmovdqu	ymm1,[rsi+rcx+32]
	vshufps	ymm2,ymm0,ymm1,0x88		; a0
	vshufps	ymm3,ymm0,ymm1,0xDD		; a1
	vmovdqu	ymm0,[rdx+rcx]
	vmovdqu	ymm1,[rdx+rcx+32]
	vshufps	ymm4,ymm0,ymm1,0x88		; b0
	vshufps	ymm5,ymm0,ymm1,0xDD		; b1
	vmovdqu	ymm0,[rdi+rcx]
	vmovdqu	ymm1,[rdi+rcx+32]
	vshufps	ymm6,ymm0,ymm1,0x88		; acc, even
	vshufps	ymm7,ymm0,ymm1,0xDD		; acc, odd
	; c0 = a0 b0 + (a1 b1 mod q) gamma + acc0
	vpmulld	ymm8,ymm3,ymm5
	mk_vred	ymm8, ymm13, 1
	vpmulld	ymm8,ymm8,[r8]
	vpmulld	ymm9,ymm2,ymm4
	vpaddd	ymm8,ymm8,ymm9
	vpaddd	ymm8,ymm8,ymm6
	mk_vred	ymm8, ymm13
	; c1 = a0 b1 + a1 b0 + acc1
	vpmulld	ymm9,ymm2,ymm5
	vpmulld	ymm10,ymm3,ymm4
	vpaddd	ymm9,ymm9,ymm10
	vpaddd	ymm9,ymm9,ymm7
	mk_vred	ymm9, ymm13
	vunpcklps ymm0,ymm8,ymm9
	vunpckhps ymm1,ymm8,ymm9
	vmovdqu	[rdi+rcx],ymm0
	vmovdqu	[rdi+rcx+32],ymm1
	add	r8,32
	add	ecx,64
	cmp	ecx,1024
	jb	.block
	vzeroupper
	ret

; rdi = acc, rsi = b: acc += b.
mlkem_add:
	mk_vinit
	xor	ecx,ecx
@@:
	vmovdqu	ymm0,[rdi+rcx]
	vpaddd	ymm0,ymm0,[rsi+rcx]
	mk_vcsub ymm0, ymm1
	vmovdqu	[rdi+rcx],ymm0
	add	ecx,32
	cmp	ecx,1024
	jb	@b
	vzeroupper
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

; rdi = polynomial, ebx = its coefficients so far, rsi = a SHAKE128 block
; (56 triples): SampleNTT's rejection sampling (algorithm 7) on it. ebx =
; the coefficients now (256 when done). Public data.
mlkem_parse:
	lea	r9,[rsi+SHAKE128_RATE]
.triple:
	cmp	ebx,256
	jae	.done
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
	mov	[rdi+rbx*4],eax
	inc	ebx
	cmp	ebx,256
	jae	.done
@@:
	cmp	edx,MLKEM_Q
	jae	@f
	mov	[rdi+rbx*4],edx
	inc	ebx
@@:
	cmp	rsi,r9
	jb	.triple
.done:
	ret

; rbp = workspace, rsi = rho, rdx = three words (the two bytes after rho
; for each entry), rdi = three polynomials: three matrix entries, their
; SHAKE128 sponges run side by side (the fourth lane idle).
mlkem_sample3:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	xor	ecx,ecx
@@:
	movzx	eax,word [rdx+rcx*2]
	or	eax,KECCAK_SHAKE shl 16
	mov	[rbp+MK_L4+rcx*8],rax
	mov	dword [rbp+MK_CNT+rcx*4],0
	inc	ecx
	cmp	ecx,3
	jb	@b
	mov	[rbp+MK_L4+24],rax
	lea	rdi,[rbp+MK_X4]
	lea	rdx,[rbp+MK_L4]
	mov	ecx,SHAKE128_RATE
	call	keccak_x4_init
.blocks:
	xor	r13d,r13d			; which entry
	xor	r14d,r14d			; any still short
.entry:
	mov	ebx,[rbp+MK_CNT+r13*4]
	cmp	ebx,256
	jae	.next
	lea	rdi,[rbp+MK_X4]
	mov	esi,r13d
	lea	rdx,[rbp+MK_XOF]
	mov	ecx,SHAKE128_RATE
	call	keccak_x4_extract
	imul	rdi,r13,1024
	add	rdi,r12
	lea	rsi,[rbp+MK_XOF]
	call	mlkem_parse
	mov	[rbp+MK_CNT+r13*4],ebx
	cmp	ebx,256
	adc	r14d,0
.next:
	inc	r13d
	cmp	r13d,3
	jb	.entry
	test	r14d,r14d
	jz	.done
	lea	rdi,[rbp+MK_X4]
	call	keccak_f1600_x4
	jmp	.blocks
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbp = workspace, rsi = the 32-byte seed (r or sigma), edx = the first N,
; ecx = how many (1..4), rdi = that many consecutive polynomials:
; CBD_2(PRF(seed, N)), N = edx onwards, four SHAKE256 sponges at once.
mlkem_noise4:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,ecx
	xor	ecx,ecx
@@:
	lea	eax,[rdx+rcx]
	or	eax,KECCAK_SHAKE shl 8
	mov	[rbp+MK_L4+rcx*8],rax
	inc	ecx
	cmp	ecx,4
	jb	@b
	lea	rdi,[rbp+MK_X4]
	lea	rdx,[rbp+MK_L4]
	mov	ecx,SHAKE256_RATE
	call	keccak_x4_init
	xor	ebx,ebx
.poly:
	lea	rdi,[rbp+MK_X4]
	mov	esi,ebx
	lea	rdx,[rbp+MK_XOF]
	mov	ecx,SHAKE256_RATE
	call	keccak_x4_extract
	imul	rdi,rbx,1024
	add	rdi,r12
	lea	rsi,[rbp+MK_XOF]
	call	mlkem_cbd2
	inc	ebx
	cmp	ebx,r13d
	jb	.poly
	pop	r13
	pop	r12
	pop	rbx
	ret

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
	; y = NTT(CBD(PRF(r, 0..2))); e1 = CBD(PRF(r, 3..5)), e2 = CBD(PRF(r, 6))
	mov	rdi,rbp				; MK_Y = 0
	lea	rsi,[rbp+MK_KR+32]
	xor	edx,edx
	mov	ecx,3
	call	mlkem_noise4
	lea	rdi,[rbp+MK_E]
	lea	rsi,[rbp+MK_KR+32]
	mov	edx,3
	mov	ecx,4
	call	mlkem_noise4
	xor	r12d,r12d
.y:
	imul	rdi,r12,1024
	add	rdi,rbp
	call	mlkem_ntt
	inc	r12d
	cmp	r12d,3
	jb	.y
	; u[i] = NTT^-1(sum_j A[j][i] y[j]) + e1[i], A[j][i] = SampleNTT(rho | i | j)
	xor	r12d,r12d			; i
.u:
	mov	eax,r12d			; the row's seeds: i, then j = 0, 1, 2
	mov	[rbp+MK_IN],ax
	or	eax,1 shl 8
	mov	[rbp+MK_IN+2],ax
	xor	eax,(1 shl 8) xor (2 shl 8)
	mov	[rbp+MK_IN+4],ax
	lea	rdi,[rbp+MK_A]
	mov	rsi,[rbp+MK_EK]
	add	rsi,3 * 384
	lea	rdx,[rbp+MK_IN]
	call	mlkem_sample3
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_zero
	xor	r13d,r13d			; j
.uj:
	lea	rdi,[rbp+MK_ACC]
	imul	rsi,r13,1024
	lea	rsi,[rbp+MK_A+rsi]
	imul	rdx,r13,1024
	add	rdx,rbp
	call	mlkem_basemul_acc
	inc	r13d
	cmp	r13d,3
	jb	.uj
	lea	rdi,[rbp+MK_ACC]
	call	mlkem_invntt
	lea	rdi,[rbp+MK_ACC]		; + e1[i]
	imul	rsi,r12,1024
	lea	rsi,[rbp+MK_E+rsi]
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
	lea	rdi,[rbp+MK_ACC]		; + e2
	lea	rsi,[rbp+MK_E+3*1024]
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
	; s = NTT(CBD(PRF(sigma, 0..2))) into MK_Y; e = NTT(CBD(PRF(sigma, 3..5)))
	mov	rdi,rbp
	lea	rsi,[rbp+MK_KR+32]
	xor	edx,edx
	mov	ecx,3
	call	mlkem_noise4
	lea	rdi,[rbp+MK_E]
	lea	rsi,[rbp+MK_KR+32]
	mov	edx,3
	mov	ecx,3
	call	mlkem_noise4
	xor	r12d,r12d
.s:
	imul	rdi,r12,1024
	add	rdi,rbp
	call	mlkem_ntt
	imul	rdi,r12,1024
	lea	rdi,[rbp+MK_E+rdi]
	call	mlkem_ntt
	inc	r12d
	cmp	r12d,3
	jb	.s
	; t[i] = sum_j A[i][j] s[j] + e[i], A[i][j] = SampleNTT(rho | j | i)
	xor	r12d,r12d
.t:
	mov	eax,r12d			; the row's seeds: j = 0, 1, 2, then i
	shl	eax,8
	mov	[rbp+MK_IN],ax
	or	eax,1
	mov	[rbp+MK_IN+2],ax
	xor	eax,1 xor 2
	mov	[rbp+MK_IN+4],ax
	lea	rdi,[rbp+MK_A]
	lea	rsi,[rbp+MK_KR]
	lea	rdx,[rbp+MK_IN]
	call	mlkem_sample3
	xor	r13d,r13d
.tj:
	imul	rdi,r12,1024
	lea	rdi,[rbp+MK_E+rdi]		; e[i] accumulates t[i]
	imul	rsi,r13,1024
	lea	rsi,[rbp+MK_A+rsi]
	imul	rdx,r13,1024
	add	rdx,rbp
	call	mlkem_basemul_acc
	inc	r13d
	cmp	r13d,3
	jb	.tj
	imul	rdi,r12,384
	add	rdi,[rbp+MK_CT]
	imul	rsi,r12,1024
	lea	rsi,[rbp+MK_E+rsi]
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
