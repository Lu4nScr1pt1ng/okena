; `compress zstd`: Zstandard (RFC 8878) as the answer goes out, on compress.inc's
; context: its window, its hash of three bytes, its LZ77 (one candidate a place,
; a match as long as the piece allows).
;
; The frame says a 64 KiB window and no size (it is not known); each piece is one
; block of its own, so that what went out decodes at once (a stream of events is
; not held back), and the end an empty last block. A block's literals are
; Huffman-coded in four streams (codes of at most 11 bits, their weights written
; directly, which holds for literals up to 128: text; others go raw, as do a
; few, and one byte repeated is RLE). Its sequences use the predefined FSE
; distributions: no tables to describe, and every offset given (no repeat
; offsets). A block that would not be smaller than its bytes goes raw.

ZF_LOG		:= 0				; d: an FSE table's accuracy
ZF_STATE	:= 8				; w each: the states (up to 512); ZF_LOG 0: RLE, no bits
ZF_TT		:= ZF_STATE + 1024		; per symbol: d deltaFindState, d deltaNbBits
ZF_SIZE		:= ZF_TT + 64 * 8
Z_REP0		:= 48				; d: the repeat offsets (compress.inc's context)
Z_REP1		:= 52
Z_REP2		:= 56
ZS_NEAR3	:= 1024				; a match of 3 bytes no farther than this
ZS_OWN_MIN	:= 64				; sequences a block has for tables of its own

bss
	align 8
	g_zs_fll	rb ZF_SIZE		; the predefined tables, made once
	g_zs_fml	rb ZF_SIZE
	g_zs_fof	rb ZF_SIZE
	g_zs_tll	rb ZF_SIZE		; a block's own
	g_zs_tml	rb ZF_SIZE
	g_zs_tof	rb ZF_SIZE
	g_zs_pll	dq ?			; the ones its sequences use
	g_zs_pml	dq ?
	g_zs_pof	dq ?
	g_zs_mp		dq ?			; where its modes go
	g_zs_hll	rd 36			; its codes' counts (cleared together)
	g_zs_hml	rd 53
	g_zs_hof	rd 32
	g_zs_norm	rw 64
	g_zs_total	dd ?			; what zs_normalize scales from
	g_zs_tw		rb ZF_SIZE		; the Huffman weights' FSE table
	g_zs_w		rb 256			; the weights
	g_zs_hw		rd 16			; their counts
	g_zs_s1		dd ?			; its two states
	g_zs_s2		dd ?
	g_zs_ready	dd ?
	g_zs_nlit	dd ?
	g_zs_maxs	dd ?			; the largest literal + 1
	g_zs_maxb	dd ?			; the longest code
	g_zs_sll	dd ?			; the three states
	g_zs_sml	dd ?
	g_zs_sof	dd ?
	g_zs_c		rd 8			; a sequence's codes: ll c, bits, extra; ml c, bits, extra; of bits, extra
	g_zs_rsave	rd 4			; the history before the block
	g_zs_bh		dq ?			; where the block's header goes
	g_zs_lh		dq ?			; the literals' header
	g_zs_jt		dq ?			; their jump table
	g_zs_code	rw 256
	g_zs_cum	rw 64
	g_zs_tsym	rb 512
	g_zs_lit	rb H_UP_CAP + 16
end bss

rodata
	align 4
	zs_ll_base	dd 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	          	dd 16,18,20,22,24,28,32,40,48,64,128,256,512,1024,2048,4096
	          	dd 8192,16384,32768,65536
	zs_ml_base	dd 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
	          	dd 19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34
	          	dd 35,37,39,41,43,47,51,59,67,83,99,131,259,515,1027,2051
	          	dd 4099,8195,16387,32771,65539
	zs_ll_bits	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	          	db 1,1,1,1,2,2,3,3,4,6,7,8,9,10,11,12
	          	db 13,14,15,16
	zs_ml_bits	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	          	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	          	db 1,1,1,1,2,2,3,3,4,4,5,7,8,9,10,11
	          	db 12,13,14,15,16
	zs_ll_c	db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	       	db 16,16,17,17,18,18,19,19,20,20,20,20,21,21,21,21
	       	db 22,22,22,22,22,22,22,22,23,23,23,23,23,23,23,23
	       	db 24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24
	zs_ml_c	db 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	       	db 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	       	db 32,32,33,33,34,34,35,35,36,36,36,36,37,37,37,37
	       	db 38,38,38,38,38,38,38,38,39,39,39,39,39,39,39,39
	       	db 40,40,40,40,40,40,40,40,40,40,40,40,40,40,40,40
	       	db 41,41,41,41,41,41,41,41,41,41,41,41,41,41,41,41
	       	db 42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42
	       	db 42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42
	; the predefined distributions (RFC 8878 3.1.1.3.2.2)
	zs_ll_norm	dw 4,3,2,2,2,2,2,2,2,2,2,2,2,1,1,1
	          	dw 2,2,2,2,2,2,2,2,2,3,2,1,1,1,1,1
	          	dw -1,-1,-1,-1
	zs_ml_norm	dw 1,4,3,2,2,2,2,2,2,1,1,1,1,1,1,1
	          	dw 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
	          	dw 1,1,1,1,1,1,1,1,1,1,1,1,1,1,-1,-1
	          	dw -1,-1,-1,-1,-1
	zs_of_norm	dw 1,1,1,1,1,1,2,2,2,1,1,1,1,1,1,1
	          	dw 1,1,1,1,1,1,1,1,-1,-1,-1,-1,-1
end rodata

; The predefined FSE tables, once (zip_init)
zs_tables:
	cmp	dword [g_zs_ready],0
	jne	.out
	mov	dword [g_zs_ready],1
	lea	rsi,[zs_ll_norm]
	mov	ecx,36
	mov	edx,6
	lea	rdi,[g_zs_fll]
	call	zs_fse_build
	lea	rsi,[zs_ml_norm]
	mov	ecx,53
	mov	edx,6
	lea	rdi,[g_zs_fml]
	call	zs_fse_build
	lea	rsi,[zs_of_norm]
	mov	ecx,29
	mov	edx,5
	lea	rdi,[g_zs_fof]
	call	zs_fse_build
.out:
	ret

; rsi = normalized counts (signed words, -1 a "less than 1"), ecx = how many,
; edx = the accuracy, rdi = a table: its states and each symbol's transform, as
; zstd's FSE_buildCTable makes them (the spread is the format's).
zs_fse_build:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rsi
	mov	r13d,ecx
	mov	r14,rdi
	mov	[r14+ZF_LOG],edx
	mov	ebp,1
	mov	ecx,edx
	shl	ebp,cl				; the table's size
	lea	r15d,[rbp-1]			; the high threshold
	; where each symbol's states begin; "less than 1"s at the top
	xor	eax,eax
	xor	ecx,ecx
.cum:
	mov	[g_zs_cum+rcx*2],ax
	movsx	edx,word [r12+rcx*2]
	cmp	edx,-1
	jne	@f
	mov	[g_zs_tsym+r15],cl
	dec	r15d
	mov	edx,1
@@:
	add	eax,edx
	inc	ecx
	cmp	ecx,r13d
	jb	.cum
	; the spread
	mov	ebx,ebp
	shr	ebx,1
	mov	eax,ebp
	shr	eax,3
	add	ebx,eax
	add	ebx,3				; the step
	lea	r8d,[rbp-1]			; the mask
	xor	eax,eax				; the position
	xor	ecx,ecx
.sym:
	cmp	ecx,r13d
	jae	.spread
	movsx	edx,word [r12+rcx*2]
.occ:
	test	edx,edx
	jle	.sym_next
	mov	[g_zs_tsym+rax],cl
.adv:
	add	eax,ebx
	and	eax,r8d
	cmp	eax,r15d
	ja	.adv
	dec	edx
	jmp	.occ
.sym_next:
	inc	ecx
	jmp	.sym
.spread:
	xor	ecx,ecx
.st:
	movzx	eax,byte [g_zs_tsym+rcx]
	movzx	edx,word [g_zs_cum+rax*2]
	inc	word [g_zs_cum+rax*2]
	lea	r8d,[rbp+rcx]
	mov	[r14+ZF_STATE+rdx*2],r8w
	inc	ecx
	cmp	ecx,ebp
	jb	.st
	; each symbol's transform
	xor	r9d,r9d				; the total
	xor	ecx,ecx
.tt:
	cmp	ecx,r13d
	jae	.done
	movsx	edx,word [r12+rcx*2]
	test	edx,edx
	jz	.tt_next
	cmp	edx,1
	jg	.many
	mov	eax,[r14+ZF_LOG]		; -1, 1
	shl	eax,16
	sub	eax,ebp
	mov	[r14+ZF_TT+rcx*8+4],eax
	lea	eax,[r9-1]
	mov	[r14+ZF_TT+rcx*8],eax
	inc	r9d
	jmp	.tt_next
.many:
	lea	eax,[rdx-1]
	bsr	eax,eax
	mov	r8d,[r14+ZF_LOG]
	sub	r8d,eax				; the most bits out
	mov	eax,edx
	push	rcx
	mov	ecx,r8d
	shl	eax,cl				; the least state + 1
	pop	rcx
	shl	r8d,16
	sub	r8d,eax
	mov	[r14+ZF_TT+rcx*8+4],r8d
	mov	eax,r9d
	sub	eax,edx
	mov	[r14+ZF_TT+rcx*8],eax
	add	r9d,edx
.tt_next:
	inc	ecx
	jmp	.tt
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; zip_feed, a zstd context: r12, rbp as there, r8/r9d = the piece. Ends in
; zip_feed's .frame (its pushes).
zs_feed:
	call	zs_block
	jmp	zip_feed.frame

; r12 = context, rbp = out: the frame's header, if it has not gone (magic; no
; size, no checksum, one segment not; a window of 64 KiB)
zs_head:
	cmp	dword [r12+Z_HEAD],0
	jne	.out
	mov	dword [r12+Z_HEAD],1
	mov	dword [rbp],0xFD2FB528
	mov	word [rbp+4],0x3000
	add	rbp,6
	mov	dword [r12+Z_REP0],1		; the repeat offsets' start (RFC 8878 3.1.2.5)
	mov	dword [r12+Z_REP1],4
	mov	dword [r12+Z_REP2],8
.out:
	ret

; r12 = a zstd context, rbp = out, r8/r9d = a piece (H_UP_CAP at most): its
; block, out. rbx, r13, r14 and rax-r11 are free.
zs_block:
	call	zs_head
	test	r9d,r9d
	jz	.empty
	mov	[g_br_mlen],r9d
	call	z_window
	mov	eax,[r12+Z_POS]
	mov	[g_br_start],eax
	lea	rdi,[g_br_hl]
	mov	ecx,256
	xor	eax,eax
	rep	stosd
	mov	dword [g_br_ncmd],0
	mov	dword [g_br_ins],0
	mov	dword [g_zs_nlit],0
	mov	rax,[r12+Z_REP0]		; (the history as it was: a raw block keeps it)
	mov	qword [g_zs_rsave],rax
	mov	eax,[r12+Z_REP2]
	mov	[g_zs_rsave+8],eax
	mov	ebx,[r12+Z_POS]
	mov	r13d,[r12+Z_END]
.next:
	cmp	ebx,r13d
	jae	.lz_done
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,3
	jb	.literal
	; the repeat offset that costs nothing (rep 1; after no literals, rep 2)
	mov	esi,[r12+Z_REP0]
	cmp	dword [g_br_ins],0
	jne	@f
	mov	esi,[r12+Z_REP1]
@@:
	xor	r14d,r14d			; its length
	cmp	esi,ebx
	ja	@f
	push	rsi
	call	zs_mlen
	pop	rsi
	mov	r14d,eax
@@:
	mov	r10d,esi			; (its distance)
	; the hash's candidate
	mov	eax,[r12+Z_WIN+rbx]
	and	eax,0xFFFFFF
	imul	eax,eax,0x9E3779B1
	shr	eax,32 - Z_HBITS
	mov	ecx,[r12+Z_HASH+rax*4]
	mov	edx,[r12+Z_ABS]
	lea	edx,[rdx+1]
	mov	[r12+Z_HASH+rax*4],edx
	xor	r11d,r11d			; its length
	test	ecx,ecx
	jz	.chosen
	sub	edx,ecx				; how far back
	jz	.chosen
	cmp	edx,32768
	ja	.chosen
	cmp	edx,ebx
	ja	.chosen
	mov	esi,edx
	call	zs_mlen
	mov	r11d,eax
	; worth it: 4 bytes, or 3 near enough that the offset costs less than they would
	cmp	eax,4
	jae	.chosen
	cmp	edx,ZS_NEAR3
	jbe	.chosen
	xor	r11d,r11d
.chosen:
	; the repeat when it is as long, or nearly
	cmp	r14d,3
	jb	.hash
	lea	eax,[r14+1]
	cmp	eax,r11d
	jb	.hash
	mov	ecx,r14d
	mov	edx,r10d
	jmp	.match
.hash:
	cmp	r11d,3
	jb	.literal
	mov	ecx,r11d
.match:
	; a sequence: the literals before it, this match; edx = its distance:
	; its offset value, the history after it
	push	rcx
	call	zs_offval			; eax = the value
	pop	rcx
	mov	esi,[g_br_ncmd]
	mov	r8d,ecx
	shl	r8d,16
	or	r8d,[g_br_ins]
	mov	dword [g_br_cmd+rsi*8],r8d
	mov	dword [g_br_cmd+rsi*8+4],eax
	inc	dword [g_br_ncmd]
	mov	dword [g_br_ins],0
	; the places it covers go in the hash, while there are three bytes
	mov	r9d,ecx
	add	[r12+Z_ABS],ecx
	inc	ebx
	dec	r9d
	mov	edx,[r12+Z_ABS]
	sub	edx,r9d
.cover:
	test	r9d,r9d
	jz	.next
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,3
	jb	.skip
	mov	eax,[r12+Z_WIN+rbx]
	and	eax,0xFFFFFF
	imul	eax,eax,0x9E3779B1
	shr	eax,32 - Z_HBITS
	lea	ecx,[rdx+1]
	mov	[r12+Z_HASH+rax*4],ecx
.skip:
	inc	ebx
	inc	edx
	dec	r9d
	jmp	.cover
.literal:
	movzx	eax,byte [r12+Z_WIN+rbx]
	inc	dword [g_br_hl+rax*4]
	mov	ecx,[g_zs_nlit]
	mov	[g_zs_lit+rcx],al
	inc	dword [g_zs_nlit]
	inc	dword [g_br_ins]
	inc	ebx
	inc	dword [r12+Z_ABS]
	jmp	.next
.lz_done:
	mov	[r12+Z_POS],ebx
	xor	r10d,r10d			; (the bits: each stream its own)
	xor	r11d,r11d
	mov	[g_zs_bh],rbp
	add	rbp,3
	call	zs_literals
	call	zs_sequences
	mov	rax,rbp
	sub	rax,[g_zs_bh]
	sub	eax,3
	cmp	eax,[g_br_mlen]
	jae	.raw
	shl	eax,3
	or	eax,2 shl 1			; a compressed block, not the last
	jmp	.header
.raw:
	mov	rax,qword [g_zs_rsave]		; (the decoder's history stays as it was)
	mov	[r12+Z_REP0],rax
	mov	eax,[g_zs_rsave+8]
	mov	[r12+Z_REP2],eax
	mov	rbp,[g_zs_bh]			; no smaller: the bytes themselves
	add	rbp,3
	mov	eax,[g_br_start]
	lea	rsi,[r12+Z_WIN+rax]
	mov	rdi,rbp
	mov	ecx,[g_br_mlen]
	add	rbp,rcx
	rep	movsb
	mov	eax,[g_br_mlen]
	shl	eax,3
.header:
	mov	rdi,[g_zs_bh]
	mov	[rdi],ax
	shr	eax,16
	mov	[rdi+2],al
.empty:
	ret

; esi = a distance (no farther than ebx): eax = how long the bytes at ebx
; match those esi before them, to the end of the window's bytes (r13d).
; Keeps all but rax, rcx, rsi.
zs_mlen:
	push	rdx
	push	rdi
	mov	ecx,r13d
	sub	ecx,ebx				; the most
	lea	rdi,[r12+Z_WIN+rbx]
	neg	rsi
	add	rsi,rdi
	xor	eax,eax
.q:
	lea	edx,[rax+8]			; 8 at a time while there are 8
	cmp	edx,ecx
	ja	.b
	mov	rdx,[rsi+rax]
	xor	rdx,[rdi+rax]
	jnz	.diff
	add	eax,8
	jmp	.q
.diff:
	bsf	rdx,rdx
	shr	edx,3
	add	eax,edx
	pop	rdi
	pop	rdx
	ret
.b:
	cmp	eax,ecx
	jae	.out
	mov	dl,[rsi+rax]
	cmp	dl,[rdi+rax]
	jne	.out
	inc	eax
	jmp	.b
.out:
	pop	rdi
	pop	rdx
	ret

; edx = a match's distance, g_br_ins the literals before it: eax = its offset
; value (a repeat's code, or the distance + 3), the history (Z_REP*) after it
zs_offval:
	mov	r8d,[r12+Z_REP0]
	mov	r9d,[r12+Z_REP1]
	mov	ecx,[r12+Z_REP2]
	cmp	dword [g_br_ins],0
	je	.no_lit
	mov	eax,1
	cmp	edx,r8d
	je	.out				; (rep 1: as it was)
	mov	eax,2
	cmp	edx,r9d
	je	.second
	mov	eax,3
	cmp	edx,ecx
	je	.third
	jmp	.new
.no_lit:					; (no literals: 1 is rep 2, 2 rep 3)
	mov	eax,1
	cmp	edx,r9d
	je	.second
	mov	eax,2
	cmp	edx,ecx
	je	.third
.new:
	lea	eax,[rdx+3]
	mov	[r12+Z_REP2],r9d
	mov	[r12+Z_REP1],r8d
	mov	[r12+Z_REP0],edx
	ret
.second:
	mov	[r12+Z_REP1],r8d
	mov	[r12+Z_REP0],edx
	ret
.third:
	mov	[r12+Z_REP2],r9d
	mov	[r12+Z_REP1],r8d
	mov	[r12+Z_REP0],edx
.out:
	ret

; rbp = out: the block's literals section (g_zs_lit, g_br_hl)
zs_literals:
	mov	ecx,[g_zs_nlit]
	test	ecx,ecx
	jnz	@f
	mov	byte [rbp],0			; raw, none
	inc	rbp
	ret
@@:
	xor	edx,edx				; how many differ
	xor	r8d,r8d				; the largest + 1
	xor	eax,eax
.scan:
	cmp	dword [g_br_hl+rax*4],0
	je	@f
	inc	edx
	lea	r8d,[rax+1]
@@:
	inc	eax
	cmp	eax,256
	jb	.scan
	cmp	edx,1
	je	.rle
	cmp	ecx,32
	jb	.raw
	mov	[g_zs_maxs],r8d
	mov	[g_zs_lh],rbp
	call	zs_huff
	jnc	.out
	mov	rbp,[g_zs_lh]
.raw:
	mov	ecx,[g_zs_nlit]
	mov	eax,ecx
	shl	eax,4
	or	eax,3 shl 2			; raw, its size in 20 bits
	mov	[rbp],ax
	shr	eax,16
	mov	[rbp+2],al
	add	rbp,3
	lea	rsi,[g_zs_lit]
	mov	rdi,rbp
	add	rbp,rcx
	rep	movsb
.out:
	ret
.rle:
	mov	eax,ecx
	shl	eax,4
	or	eax,1 or (3 shl 2)		; RLE, its size in 20 bits
	mov	[rbp],ax
	shr	eax,16
	mov	[rbp+2],al
	mov	al,[g_zs_lit]
	mov	[rbp+3],al
	add	rbp,4
	ret

; g_zs_lh = rbp = out: the literals, Huffman-coded in four streams. CF when
; that is no smaller than they are (nothing kept).
zs_huff:
	lea	rsi,[g_br_hl]
	mov	ecx,[g_zs_maxs]
	mov	edx,11
	lea	rdi,[g_br_len]
	call	br_huff
	xor	eax,eax				; the longest
	xor	ecx,ecx
@@:
	movzx	edx,byte [g_br_len+rcx]
	cmp	edx,eax
	cmova	eax,edx
	inc	ecx
	cmp	ecx,[g_zs_maxs]
	jb	@b
	mov	[g_zs_maxb],eax
	add	rbp,5				; (the header: below)
	; the weights, a byte each: one for each but the largest
	mov	ecx,[g_zs_maxs]
	dec	ecx
	xor	esi,esi
@@:
	mov	edx,esi
	call	.weight
	mov	[g_zs_w+rsi],al
	inc	esi
	cmp	esi,ecx
	jb	@b
	cmp	ecx,128
	ja	.fse
	; written directly: a header of 127 + how many, two a byte
	lea	eax,[rcx+127]
	mov	[rbp],al
	inc	rbp
	xor	esi,esi
.w:
	cmp	esi,ecx
	jae	.codes
	movzx	eax,byte [g_zs_w+rsi]
	shl	eax,4
	lea	edx,[rsi+1]
	cmp	edx,ecx
	jae	@f
	or	al,[g_zs_w+rdx]
@@:
	mov	[rbp],al
	inc	rbp
	add	esi,2
	jmp	.w
.fse:
	call	zs_weights_fse
	jc	.no
.codes:
	call	zs_canon
	mov	[g_zs_jt],rbp
	add	rbp,6
	; four streams of a quarter each (the last what is left)
	mov	ebx,[g_zs_nlit]
	add	ebx,3
	shr	ebx,2				; a segment
	xor	r13d,r13d			; which stream
.stream:
	mov	esi,r13d
	imul	esi,ebx
	lea	edi,[rsi+rbx]
	cmp	r13d,3
	jne	@f
	mov	edi,[g_zs_nlit]
@@:
	mov	r9,rbp
	call	zs_stream
	cmp	r13d,3
	je	@f
	mov	rax,rbp
	sub	rax,r9
	mov	rcx,[g_zs_jt]
	mov	[rcx+r13*2],ax
@@:
	inc	r13d
	cmp	r13d,4
	jb	.stream
	; the header: compressed, four streams, sizes of 18 bits
	mov	rax,rbp
	sub	rax,[g_zs_lh]
	sub	rax,5
	cmp	eax,[g_zs_nlit]
	jae	.no
	shl	rax,22
	mov	ecx,[g_zs_nlit]
	shl	ecx,4
	or	rax,rcx
	or	rax,2 or (3 shl 2)
	mov	rcx,[g_zs_lh]
	mov	[rcx],eax
	shr	rax,32
	mov	[rcx+4],al
	clc
	ret
.no:
	stc
	ret
; edx = a symbol: eax = its weight (0 none; the longest code 1)
.weight:
	movzx	eax,byte [g_br_len+rdx]
	test	eax,eax
	jz	@f
	neg	eax
	add	eax,[g_zs_maxb]
	inc	eax
@@:
	ret

; g_zs_w = ecx weights (more than 128): their FSE-compressed form at rbp
; (RFC 8878 4.2.1.2: its size in a byte, a table, two states). CF when it
; cannot be (one weight only, or 128 bytes or more), rbp as it was.
zs_weights_fse:
	push	rbx
	push	r13
	mov	r13d,ecx			; how many
	mov	[g_zs_total],ecx
	lea	rdi,[g_zs_hw]
	mov	ecx,16
	xor	eax,eax
	rep	stosd
	xor	ecx,ecx
@@:
	movzx	eax,byte [g_zs_w+rcx]
	inc	dword [g_zs_hw+rax*4]
	inc	ecx
	cmp	ecx,r13d
	jb	@b
	xor	ecx,ecx				; how many differ, the largest
	xor	edx,edx
	xor	eax,eax
@@:
	cmp	dword [g_zs_hw+rax*4],0
	je	.nx
	inc	ecx
	mov	edx,eax
.nx:
	inc	eax
	cmp	eax,16
	jb	@b
	cmp	ecx,2
	jb	.fail
	; the accuracy: zstd's FSE_optimalTableLog(6, how many, the largest), 5 or 6
	mov	ebx,6
	lea	eax,[r13-1]
	bsr	eax,eax
	sub	eax,2
	cmp	eax,ebx
	jge	@f
	mov	ebx,eax
@@:
	bsr	eax,r13d
	inc	eax
	bsr	ecx,edx
	add	ecx,2
	cmp	ecx,eax
	cmovb	eax,ecx
	cmp	eax,ebx
	jle	@f
	mov	ebx,eax
@@:
	cmp	ebx,5
	jge	@f
	mov	ebx,5
@@:
	cmp	ebx,6
	jle	@f
	mov	ebx,6
@@:
	push	rbp				; (to go back to)
	push	rdx
	inc	rbp				; (its size: below)
	lea	rsi,[g_zs_hw]
	lea	ecx,[rdx+1]
	mov	edx,ebx
	call	zs_normalize
	pop	rcx
	inc	ecx
	push	rcx
	lea	rsi,[g_zs_norm]
	mov	edx,ebx
	call	zs_ncount
	pop	rcx
	lea	rsi,[g_zs_norm]
	mov	edx,ebx
	lea	rdi,[g_zs_tw]
	call	zs_fse_build
	; two states, interleaved, from the last weight back (FSE_compress_usingCTable)
	lea	rsi,[g_zs_tw]
	mov	ebx,r13d			; ip
	test	ebx,1
	jz	.even
	movzx	eax,byte [g_zs_w+rbx-1]
	call	zs_fse_init
	mov	[g_zs_s1],eax
	movzx	eax,byte [g_zs_w+rbx-2]
	call	zs_fse_init
	mov	[g_zs_s2],eax
	movzx	eax,byte [g_zs_w+rbx-3]
	lea	rdi,[g_zs_s1]
	call	zs_fse_enc
	sub	ebx,3
	jmp	.pairs
.even:
	movzx	eax,byte [g_zs_w+rbx-1]
	call	zs_fse_init
	mov	[g_zs_s2],eax
	movzx	eax,byte [g_zs_w+rbx-2]
	call	zs_fse_init
	mov	[g_zs_s1],eax
	sub	ebx,2
.pairs:
	test	ebx,ebx
	jz	.flush
	movzx	eax,byte [g_zs_w+rbx-1]
	lea	rdi,[g_zs_s2]
	call	zs_fse_enc
	movzx	eax,byte [g_zs_w+rbx-2]
	lea	rdi,[g_zs_s1]
	call	zs_fse_enc
	sub	ebx,2
	jmp	.pairs
.flush:
	mov	eax,[g_zs_s2]
	call	zs_fse_flush
	lea	rsi,[g_zs_tw]
	mov	eax,[g_zs_s1]
	call	zs_fse_flush
	call	zs_close
	mov	rax,rbp				; its size, under 128
	mov	rcx,[rsp]
	sub	rax,rcx
	dec	rax
	cmp	rax,128
	jae	.too_big
	mov	[rcx],al
	add	rsp,8
	pop	r13
	pop	rbx
	clc
	ret
.too_big:
	pop	rbp
.fail:
	pop	r13
	pop	rbx
	stc
	ret

; zstd's prefix codes from the lengths (g_br_len): the longest take the
; lowest, in the order of the symbols within a length
zs_canon:
	lea	rdi,[g_bh_nc]
	mov	ecx,16
	xor	eax,eax
	rep	stosd
	xor	ecx,ecx
@@:
	movzx	eax,byte [g_br_len+rcx]
	inc	dword [g_bh_nc+rax*4]
	inc	ecx
	cmp	ecx,[g_zs_maxs]
	jb	@b
	mov	edx,[g_zs_maxb]
	mov	dword [g_bc_next+rdx*4],0
.start:
	cmp	edx,1
	jbe	.assign
	mov	eax,[g_bc_next+rdx*4]
	add	eax,[g_bh_nc+rdx*4]
	shr	eax,1
	mov	[g_bc_next+rdx*4-4],eax
	dec	edx
	jmp	.start
.assign:
	xor	ecx,ecx
.sym:
	movzx	eax,byte [g_br_len+rcx]
	test	eax,eax
	jz	@f
	mov	edx,[g_bc_next+rax*4]
	mov	[g_zs_code+rcx*2],dx
	inc	dword [g_bc_next+rax*4]
@@:
	inc	ecx
	cmp	ecx,[g_zs_maxs]
	jb	.sym
	ret

; esi, edi = literals [esi, edi): a Huffman stream of them, the last first
; (it is read from its end). Keeps rbx, r9, r12, r13, r15.
zs_stream:
	push	rbx
	mov	ebx,edi
.lit:
	cmp	ebx,esi
	jbe	.done
	dec	ebx
	movzx	edx,byte [g_zs_lit+rbx]
	movzx	ecx,byte [g_br_len+rdx]
	movzx	eax,word [g_zs_code+rdx*2]
	call	z_put
	jmp	.lit
.done:
	pop	rbx
; the stream's end: a 1, then to a whole byte
zs_close:
	mov	eax,1
	mov	ecx,1
	call	z_put
	test	r11d,r11d			; (all out already: the 1 ends a word)
	jz	.closed
.byte:
	mov	[rbp],r10b
	inc	rbp
	shr	r10,8
	sub	r11d,8
	jg	.byte
.closed:
	xor	r10d,r10d
	xor	r11d,r11d
	ret

; rbp = out: the block's sequences (g_br_cmd), the predefined distributions
zs_sequences:
	mov	ecx,[g_br_ncmd]
	test	ecx,ecx
	jnz	@f
	mov	byte [rbp],0
	inc	rbp
	ret
@@:
	cmp	ecx,128
	jae	.two
	mov	[rbp],cl
	inc	rbp
	jmp	.modes
.two:
	cmp	ecx,0x7F00
	jae	.three
	mov	eax,ecx
	shr	eax,8
	add	eax,128
	mov	[rbp],al
	mov	[rbp+1],cl
	add	rbp,2
	jmp	.modes
.three:
	mov	byte [rbp],255
	lea	eax,[rcx-0x7F00]
	mov	[rbp+1],ax
	add	rbp,3
.modes:
	push	rbx
	push	r13
	mov	[g_zs_mp],rbp
	inc	rbp
	; each alphabet's codes counted: its tables chosen, described
	lea	rdi,[g_zs_hll]
	mov	ecx,36 + 53 + 32
	xor	eax,eax
	rep	stosd
	xor	r13d,r13d
.count:
	call	zs_codes
	mov	eax,[g_zs_c]
	inc	dword [g_zs_hll+rax*4]
	mov	eax,[g_zs_c+12]
	inc	dword [g_zs_hml+rax*4]
	mov	eax,[g_zs_c+24]
	inc	dword [g_zs_hof+rax*4]
	inc	r13d
	cmp	r13d,[g_br_ncmd]
	jb	.count
	lea	rsi,[g_zs_hll]
	mov	ecx,36
	mov	edx,9
	lea	rdi,[g_zs_tll]
	lea	r8,[g_zs_fll]
	call	zs_choose
	mov	[g_zs_pll],rdx
	shl	eax,6
	mov	rcx,[g_zs_mp]
	mov	[rcx],al
	lea	rsi,[g_zs_hof]
	mov	ecx,32
	mov	edx,8
	lea	rdi,[g_zs_tof]
	lea	r8,[g_zs_fof]
	call	zs_choose
	mov	[g_zs_pof],rdx
	shl	eax,4
	mov	rcx,[g_zs_mp]
	or	[rcx],al
	lea	rsi,[g_zs_hml]
	mov	ecx,53
	mov	edx,9
	lea	rdi,[g_zs_tml]
	lea	r8,[g_zs_fml]
	call	zs_choose
	mov	[g_zs_pml],rdx
	shl	eax,2
	mov	rcx,[g_zs_mp]
	or	[rcx],al
	mov	r13d,[g_br_ncmd]
	dec	r13d
	call	zs_codes			; the last: the states start with it
	mov	eax,[g_zs_c+12]
	mov	rsi,[g_zs_pml]
	call	zs_fse_init
	mov	[g_zs_sml],eax
	mov	eax,[g_zs_c+24]
	mov	rsi,[g_zs_pof]
	call	zs_fse_init
	mov	[g_zs_sof],eax
	mov	eax,[g_zs_c]
	mov	rsi,[g_zs_pll]
	call	zs_fse_init
	mov	[g_zs_sll],eax
	call	zs_extras
.seq:
	test	r13d,r13d
	jz	.flush
	dec	r13d
	call	zs_codes
	mov	eax,[g_zs_c+24]
	mov	rsi,[g_zs_pof]
	lea	rdi,[g_zs_sof]
	call	zs_fse_enc
	mov	eax,[g_zs_c+12]
	mov	rsi,[g_zs_pml]
	lea	rdi,[g_zs_sml]
	call	zs_fse_enc
	mov	eax,[g_zs_c]
	mov	rsi,[g_zs_pll]
	lea	rdi,[g_zs_sll]
	call	zs_fse_enc
	call	zs_extras
	jmp	.seq
.flush:
	mov	eax,[g_zs_sml]
	mov	rsi,[g_zs_pml]
	call	zs_fse_flush
	mov	eax,[g_zs_sof]
	mov	rsi,[g_zs_pof]
	call	zs_fse_flush
	mov	eax,[g_zs_sll]
	mov	rsi,[g_zs_pll]
	call	zs_fse_flush
	call	zs_close
	pop	r13
	pop	rbx
	ret

; r13d = a sequence: g_zs_c = its codes, their extra bits and values
zs_codes:
	mov	rdx,[g_br_cmd+r13*8]
	movzx	eax,dx				; the literals before it
	cmp	eax,64
	jae	@f
	movzx	ecx,byte [zs_ll_c+rax]
	jmp	.ll
@@:
	bsr	ecx,eax
	add	ecx,19
.ll:
	mov	[g_zs_c],ecx
	movzx	r8d,byte [zs_ll_bits+rcx]
	mov	[g_zs_c+4],r8d
	sub	eax,[zs_ll_base+rcx*4]
	mov	[g_zs_c+8],eax
	mov	eax,edx				; the match
	shr	eax,16
	sub	eax,3
	cmp	eax,128
	jae	@f
	movzx	ecx,byte [zs_ml_c+rax]
	jmp	.ml
@@:
	bsr	ecx,eax
	add	ecx,36
.ml:
	mov	[g_zs_c+12],ecx
	movzx	r8d,byte [zs_ml_bits+rcx]
	mov	[g_zs_c+16],r8d
	add	eax,3
	sub	eax,[zs_ml_base+rcx*4]
	mov	[g_zs_c+20],eax
	shr	rdx,32				; the offset value
	bsr	ecx,edx
	mov	[g_zs_c+24],ecx
	mov	eax,1
	shl	eax,cl
	sub	edx,eax
	mov	[g_zs_c+28],edx
	ret

; a sequence's extra bits (g_zs_c): the literals', the match's, the offset's
zs_extras:
	mov	eax,[g_zs_c+8]
	mov	ecx,[g_zs_c+4]
	call	z_put
	mov	eax,[g_zs_c+20]
	mov	ecx,[g_zs_c+16]
	call	z_put
	mov	eax,[g_zs_c+28]
	mov	ecx,[g_zs_c+24]
	jmp	z_put

; eax = a state, rsi = its table: its last bits out
zs_fse_flush:
	mov	ecx,[rsi+ZF_LOG]
	mov	edx,1
	shl	edx,cl
	dec	edx
	and	eax,edx
	jmp	z_put

; eax = a symbol, rsi = its FSE table: eax = the state that starts with it
zs_fse_init:
	cmp	dword [rsi+ZF_LOG],0
	je	.rle
	mov	ecx,[rsi+ZF_TT+rax*8+4]		; deltaNbBits
	movsxd	rdx,dword [rsi+ZF_TT+rax*8]	; deltaFindState
	lea	r8d,[rcx+0x8000]
	shr	r8d,16
	mov	eax,r8d
	shl	eax,16
	sub	eax,ecx
	mov	ecx,r8d
	shr	eax,cl
	add	rax,rdx
	movzx	eax,word [rsi+ZF_STATE+rax*2]
	ret
.rle:
	xor	eax,eax
	ret

; eax = a symbol, rsi = its FSE table, rdi = the state: its bits out, the next state
zs_fse_enc:
	cmp	dword [rsi+ZF_LOG],0
	je	.rle
	mov	ecx,[rsi+ZF_TT+rax*8+4]
	movsxd	rdx,dword [rsi+ZF_TT+rax*8]
	mov	r8d,[rdi]
	lea	r9d,[r8+rcx]
	shr	r9d,16				; how many bits
	mov	ecx,r9d
	mov	eax,1
	shl	eax,cl
	dec	eax
	and	eax,r8d
	call	z_put
	mov	ecx,r9d
	shr	r8d,cl
	add	r8,rdx
	movzx	eax,word [rsi+ZF_STATE+r8*2]
	mov	[rdi],eax
.rle:
	ret

; rsi = an alphabet's counts in this block (dwords), ecx = its size, edx = the
; most accuracy its own table may have, rdi = room for that table, r8 = the
; predefined one: eax = its mode (0 predefined, 1 RLE, 2 its own, described at
; rbp), rdx = the table its codes go by
zs_choose:
	push	rbx
	push	r13
	xor	r9d,r9d				; how many differ
	xor	r10d,r10d			; the largest
	xor	eax,eax
.scan:
	cmp	dword [rsi+rax*4],0
	je	@f
	inc	r9d
	mov	r10d,eax
@@:
	inc	eax
	cmp	eax,ecx
	jb	.scan
	cmp	r9d,1
	je	.rle
	mov	r13d,[g_br_ncmd]
	mov	[g_zs_total],r13d
	cmp	r13d,ZS_OWN_MIN
	jb	.predefined
	; its accuracy (zstd's FSE_optimalTableLog)
	mov	ebx,edx				; the most
	lea	eax,[r13-1]
	bsr	eax,eax
	sub	eax,2				; what the count supports
	cmp	eax,ebx
	jge	@f
	mov	ebx,eax
@@:
	bsr	eax,r13d
	inc	eax
	bsr	ecx,r10d
	add	ecx,2
	cmp	ecx,eax
	cmovb	eax,ecx				; the least
	cmp	eax,ebx
	jle	@f
	mov	ebx,eax
@@:
	cmp	ebx,5
	jge	@f
	mov	ebx,5
@@:
	cmp	ebx,edx
	jle	@f
	mov	ebx,edx
@@:
	push	rdi
	lea	r13d,[r10+1]			; the symbols, to the largest
	mov	ecx,r13d
	mov	edx,ebx
	call	zs_normalize
	lea	rsi,[g_zs_norm]
	mov	ecx,r13d
	mov	edx,ebx
	call	zs_ncount			; (r10, r11: 0 after)
	lea	rsi,[g_zs_norm]
	mov	ecx,r13d
	mov	edx,ebx
	mov	rdi,[rsp]
	call	zs_fse_build
	pop	rdx
	mov	eax,2
	jmp	.out
.rle:
	mov	[rbp],r10b
	inc	rbp
	mov	dword [rdi+ZF_LOG],0
	mov	rdx,rdi
	mov	eax,1
	jmp	.out
.predefined:
	mov	rdx,r8
	xor	eax,eax
.out:
	xor	r10d,r10d			; (the bits: the sequences' stream starts empty)
	xor	r11d,r11d
	pop	r13
	pop	rbx
	ret

; rsi = counts (dwords), ecx = how many, edx = the accuracy, g_br_ncmd their
; sum: g_zs_norm = them scaled to 1 shl edx, each that is there 1 at least.
; Keeps rbx, rbp, rdi, r10-r15.
zs_normalize:
	push	r10
	push	r11
	push	r12
	mov	r12d,ecx
	mov	r11d,1
	push	rcx
	mov	ecx,edx
	shl	r11d,cl				; the scale
	pop	rcx
	xor	r10d,r10d			; the sum
	xor	r8d,r8d				; the most counted
	xor	r9d,r9d
	xor	ecx,ecx
.s:
	mov	eax,[rsi+rcx*4]
	test	eax,eax
	jz	.zero
	cmp	eax,r9d
	jbe	@f
	mov	r9d,eax
	mov	r8d,ecx
@@:
	imul	rax,r11
	xor	edx,edx
	push	rcx
	mov	ecx,[g_zs_total]
	div	rcx
	pop	rcx
	test	eax,eax
	jnz	.zero
	inc	eax
.zero:
	mov	[g_zs_norm+rcx*2],ax
	add	r10d,eax
	inc	ecx
	cmp	ecx,r12d
	jb	.s
	mov	eax,r11d
	sub	eax,r10d			; what is left over (or past)
	jl	.over
	add	[g_zs_norm+r8*2],ax
	jmp	.out
.over:						; past: from the largest, one at a time
	xor	ecx,ecx
	xor	edx,edx				; the largest's
	xor	r9d,r9d
.find:
	movzx	r10d,word [g_zs_norm+rcx*2]
	cmp	r10d,r9d
	jbe	@f
	mov	r9d,r10d
	mov	edx,ecx
@@:
	inc	ecx
	cmp	ecx,r12d
	jb	.find
	dec	word [g_zs_norm+rdx*2]
	inc	eax
	jl	.over
.out:
	pop	r12
	pop	r11
	pop	r10
	ret

; rsi = normalized counts (words), ecx = how many, edx = the accuracy: their
; description (RFC 8878 4.1.1) at rbp, to a whole byte. Uses r10, r11, r14 (0 after).
zs_ncount:
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r12,rsi
	mov	r13d,ecx
	mov	ebx,edx
	xor	r10d,r10d
	xor	r11d,r11d
	lea	eax,[rdx-5]
	mov	ecx,4
	call	z_put
	mov	r8d,1
	mov	ecx,ebx
	shl	r8d,cl				; the threshold
	lea	r9d,[r8+1]			; what remains
	inc	ebx				; the bits
	xor	edi,edi				; the symbol
	xor	r15d,r15d			; the last was 0
.sym:
	cmp	edi,r13d
	jae	.end
	cmp	r9d,1
	jbe	.end
	test	r15d,r15d
	jz	.count
	mov	esi,edi				; a run of zeros: how many more, 2 bits at a time
@@:
	cmp	edi,r13d
	jae	.end
	cmp	word [r12+rdi*2],0
	jne	@f
	inc	edi
	jmp	@b
@@:
	lea	eax,[rsi+3]
	cmp	edi,eax
	jb	@f
	mov	esi,eax
	mov	eax,3
	mov	ecx,2
	call	z_put
	jmp	@b
@@:
	mov	eax,edi
	sub	eax,esi
	mov	ecx,2
	call	z_put
.count:
	movsx	eax,word [r12+rdi*2]
	inc	edi
	lea	edx,[r8*2-1]
	sub	edx,r9d				; max
	mov	ecx,eax
	test	ecx,ecx
	jns	@f
	neg	ecx
@@:
	sub	r9d,ecx
	inc	eax
	cmp	eax,r8d
	jb	@f
	add	eax,edx
@@:
	mov	ecx,ebx
	cmp	eax,edx
	jae	@f
	dec	ecx
@@:
	xor	r15d,r15d
	cmp	eax,1
	sete	r15b
	call	z_put
.shrink:
	cmp	r9d,r8d
	jae	.sym
	dec	ebx
	shr	r8d,1
	jmp	.shrink
.end:
	test	r11d,r11d			; to a whole byte
	jz	.out
@@:
	mov	[rbp],r10b
	inc	rbp
	shr	r10,8
	sub	r11d,8
	jg	@b
.out:
	xor	r10d,r10d
	xor	r11d,r11d
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12 = context, rbp = out: the end (the header, if nothing went; an empty last block)
zs_finish:
	call	zs_head
	mov	byte [rbp],1
	mov	word [rbp+1],0
	add	rbp,3
	ret
