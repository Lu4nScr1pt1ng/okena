; `compress br`: Brotli (RFC 7932) as the answer goes out, on compress.inc's context:
; its window, its hash of three bytes, its LZ77 (one candidate a place).
;
; Each piece is a meta-block of its own, with prefix codes made for it (Huffman
; from what the piece holds, at most 15 bits; described in the complex form, runs
; of zeros as code 17, or in the simple form for four symbols or fewer). An empty
; metadata block after it brings the stream to a whole byte, so that what went
; out decodes at once (a stream of events is not held back). A piece its codes
; would make larger goes as an uncompressed meta-block. The window is 64 KiB
; (WBITS 16), the distances at most 32 KiB, as the matcher finds them.
;
; One literal tree, one insert-and-copy tree, one distance tree a meta-block: no
; block switches, no context modeling; NPOSTFIX and NDIRECT 0, every distance
; given (no use of the last ones).

Z_KIND		:= 44				; d: 0 gzip, 1 br (compress.inc's context)
BR_CMDS		:= H_UP_CAP / 3 + 16		; commands a piece (each copy covers 3 bytes)
assert H_UP_CAP < 65536				; (an insert, a meta-block's MLEN: 16 bits)
assert H_UP_CAP * 10 / 8 + 4096 <= Z_OUTCAP - Z_FRAME - 64

bss
	align 8
	g_br_cmd	rq BR_CMDS		; insert | copy << 16 | distance << 32 (0: none)
	g_br_ncmd	dd ?
	g_br_ins	dd ?			; the literals since the last copy
	g_br_start	dd ?			; the piece's place in the window
	g_br_mlen	dd ?
	g_br_rw		dq ?			; where the meta-block starts (to go back to)
	g_br_rwb	dq ?
	g_br_rwn	dd ?
	g_z_kind	dd ?			; zip_request to zip_head: which one
	; the histograms, one after the other (cleared together)
	g_br_hl		rd 256
	g_br_hc		rd 704
	g_br_hd		rd 64
	; the codes, as z_put_code wants them: code reversed | bits << 16
	g_br_lit	rd 256
	g_br_cmdc	rd 704
	g_br_dist	rd 64
	g_br_clc	rd 18
	g_br_clh	rd 18			; the code lengths' own histogram
	g_br_len	rb 704			; an alphabet's code lengths
	g_br_cll	rb 32			; the code lengths' code lengths
	g_br_seq	rw 1024			; the lengths, as written: symbol | extra << 8
	g_br_nseq	dd ?
	g_bp_sym	rd 4			; the simple form: its symbols
	g_bh_k		rd 704			; Huffman: counts, sorted, then depths
	g_bh_s		rw 704			; and their symbols
	g_bh_nc		rd 34			; how many codes of each length
	g_bc_next	rd 16
end bss

rodata
	align 4
	br_ins_base	dd 0,1,2,3,4,5,6,8,10,14,18,26,34,50,66,98,130,194,322,578,1090,2114,6210,22594
	br_cp_base	dd 2,3,4,5,6,7,8,9,10,12,14,18,22,30,38,54,70,102,134,198,326,582,1094,2118
	br_ins_ext	db 0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,12,14,24
	br_cp_ext	db 0,0,0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,24
	align 2
	br_cell		dw 128,192,384, 256,320,512, 448,576,640	; insert code / 8, copy code / 8
	br_clorder	db 1,2,3,4,0,5,17,6,16,7,8,9,10,11,12,13,14,15
	br_clval	db 0,7,3,2,1,15			; a code length's code length, as written
	br_clbits	db 2,4,3,2,2,4
end rodata

; zip_feed, a br context: r12, rbp as there, r8/r9d = the piece. Ends in zip_feed's
; .frame (its pushes).
br_feed:
	test	r9d,r9d
	jz	zip_feed.frame
	mov	[g_br_mlen],r9d
	mov	eax,[r12+Z_POS]
	call	z_window
	mov	eax,[r12+Z_POS]
	mov	[g_br_start],eax
	lea	rdi,[g_br_hl]
	mov	ecx,256 + 704 + 64
	xor	eax,eax
	rep	stosd
	mov	dword [g_br_ncmd],0
	mov	dword [g_br_ins],0
	mov	ebx,[r12+Z_POS]
	mov	r13d,[r12+Z_END]
.next:
	cmp	ebx,r13d
	jae	.lz_done
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,3
	jb	.literal
	mov	eax,[r12+Z_WIN+rbx]
	and	eax,0xFFFFFF
	imul	eax,eax,0x9E3779B1
	shr	eax,32 - Z_HBITS
	mov	ecx,[r12+Z_HASH+rax*4]
	mov	edx,[r12+Z_ABS]
	lea	edx,[rdx+1]
	mov	[r12+Z_HASH+rax*4],edx
	test	ecx,ecx
	jz	.literal
	sub	edx,ecx				; how far back
	jz	.literal
	cmp	edx,32768
	ja	.literal
	cmp	edx,ebx
	ja	.literal
	mov	esi,ebx
	sub	esi,edx
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,258
	jbe	@f
	mov	eax,258
@@:
	xor	ecx,ecx
	lea	r8,[r12+Z_WIN+rsi]
	lea	r9,[r12+Z_WIN+rbx]
.same:
	cmp	ecx,eax
	jae	.measured
	mov	sil,[r8+rcx]
	cmp	sil,[r9+rcx]
	jne	.measured
	inc	ecx
	jmp	.same
.measured:
	cmp	ecx,3
	jb	.literal
	; a command: what was inserted, this copy
	mov	esi,[g_br_ncmd]
	mov	eax,ecx
	shl	eax,16
	or	eax,[g_br_ins]
	mov	dword [g_br_cmd+rsi*8],eax
	mov	dword [g_br_cmd+rsi*8+4],edx
	inc	dword [g_br_ncmd]
	push	rcx
	push	rdx
	mov	edx,ecx
	mov	eax,[g_br_ins]
	call	br_cmdsym
	inc	dword [g_br_hc+rax*4]
	pop	rdx
	push	rdx
	call	br_dcode
	inc	dword [g_br_hd+rax*4]
	pop	rdx
	pop	rcx
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
	inc	dword [g_br_ins]
	inc	ebx
	inc	dword [r12+Z_ABS]
	jmp	.next
.lz_done:
	mov	[r12+Z_POS],ebx
	mov	eax,[g_br_ins]
	test	eax,eax
	jz	@f
	mov	esi,[g_br_ncmd]			; the literals at the end: a command whose
	mov	ecx,eax				; copy is never reached (MLEN ends it)
	or	ecx,2 shl 16
	mov	dword [g_br_cmd+rsi*8],ecx
	mov	dword [g_br_cmd+rsi*8+4],0
	inc	dword [g_br_ncmd]
	xor	edx,edx
	call	br_cmdsym
	inc	dword [g_br_hc+rax*4]
@@:
	; the stream's header, once: WBITS 16
	mov	r10,[r12+Z_BITS]
	mov	r11d,[r12+Z_NBITS]
	cmp	dword [r12+Z_HEAD],0
	jne	@f
	mov	dword [r12+Z_HEAD],1
	xor	eax,eax
	mov	ecx,1
	call	z_put
@@:
	mov	[g_br_rw],rbp
	mov	[g_br_rwb],r10
	mov	[g_br_rwn],r11d
	; ISLAST 0, MNIBBLES 4, MLEN - 1, ISUNCOMPRESSED 0
	mov	eax,[g_br_mlen]
	dec	eax
	shl	eax,3
	mov	ecx,20
	call	z_put
	; one block type each, NPOSTFIX 0, NDIRECT 0, its context mode, one tree each
	xor	eax,eax
	mov	ecx,13
	call	z_put
	lea	rsi,[g_br_hl]
	mov	ecx,256
	mov	edx,8
	lea	rdi,[g_br_lit]
	call	br_prefix
	lea	rsi,[g_br_hc]
	mov	ecx,704
	mov	edx,10
	lea	rdi,[g_br_cmdc]
	call	br_prefix
	lea	rsi,[g_br_hd]
	mov	ecx,64
	mov	edx,6
	lea	rdi,[g_br_dist]
	call	br_prefix
	; the commands
	mov	ebx,[g_br_start]		; the place of the next literal
	xor	r13d,r13d
.cmd:
	cmp	r13d,[g_br_ncmd]
	jae	.cmds_done
	mov	r8,[g_br_cmd+r13*8]
	inc	r13d
	movzx	eax,r8w				; the insert
	mov	edx,r8d
	shr	edx,16				; the copy
	call	br_cmdsym			; eax = symbol, ecx = insert code, edx = copy code
	push	rdx
	push	rcx
	mov	eax,[g_br_cmdc+rax*4]
	call	z_put_code
	pop	rcx
	movzx	r9d,r8w
	movzx	eax,byte [br_ins_ext+rcx]
	test	eax,eax
	jz	@f
	mov	edx,r9d
	sub	edx,[br_ins_base+rcx*4]
	mov	ecx,eax
	mov	eax,edx
	call	z_put
@@:
	pop	rdx
	movzx	eax,byte [br_cp_ext+rdx]
	test	eax,eax
	jz	@f
	mov	ecx,r8d
	shr	ecx,16
	sub	ecx,[br_cp_base+rdx*4]
	xchg	eax,ecx
	call	z_put
@@:
	; the literals
	test	r9d,r9d
	jz	.distance
	movzx	eax,byte [r12+Z_WIN+rbx]
	mov	eax,[g_br_lit+rax*4]
	call	z_put_code
	inc	ebx
	dec	r9d
	jmp	@b
.distance:
	mov	rdx,r8
	shr	rdx,32
	jz	.cmd				; (the literals at the end)
	mov	eax,r8d
	shr	eax,16
	add	ebx,eax
	call	br_dcode			; eax = its code, ecx = bits, edx = extra
	push	rcx
	push	rdx
	mov	eax,[g_br_dist+rax*4]
	call	z_put_code
	pop	rax
	pop	rcx
	test	ecx,ecx
	jz	.cmd
	call	z_put
	jmp	.cmd
.cmds_done:
	; an empty metadata block: ISLAST 0, MNIBBLES 0 (11), reserved 0, MSKIPBYTES 0;
	; then to a whole byte
	mov	eax,6
	mov	ecx,6
	call	z_put
	call	br_align
	; larger than the bytes themselves: those, uncompressed
	mov	rax,rbp
	sub	rax,[g_br_rw]
	mov	ecx,[g_br_mlen]
	add	ecx,8
	cmp	rax,rcx
	jbe	.done
	mov	rbp,[g_br_rw]
	mov	r10,[g_br_rwb]
	mov	r11d,[g_br_rwn]
	mov	eax,[g_br_mlen]			; ISLAST 0, MNIBBLES 4, MLEN - 1, ISUNCOMPRESSED 1
	dec	eax
	shl	eax,3
	or	eax,1 shl 19
	mov	ecx,20
	call	z_put
	call	br_align
	mov	eax,[g_br_start]
	lea	rsi,[r12+Z_WIN+rax]
	mov	rdi,rbp
	mov	ecx,[g_br_mlen]
	add	rbp,rcx
	rep	movsb
.done:
	mov	[r12+Z_BITS],r10
	mov	[r12+Z_NBITS],r11d
	jmp	zip_feed.frame

; zip_finish, a br context: r12, rbp: the last meta-block (ISLAST, ISLASTEMPTY), the
; header before it if nothing went yet
br_finish:
	mov	r10,[r12+Z_BITS]
	mov	r11d,[r12+Z_NBITS]
	cmp	dword [r12+Z_HEAD],0
	jne	@f
	mov	dword [r12+Z_HEAD],1
	xor	eax,eax
	mov	ecx,1
	call	z_put
@@:
	mov	eax,3
	mov	ecx,2
	call	z_put
	call	br_align
	ret

; r10/r11d/rbp: zeros to a whole byte, then the bytes out
br_align:
	mov	ecx,r11d
	neg	ecx
	and	ecx,7
	jz	.bytes
	xor	eax,eax
	call	z_put
.bytes:
	test	r11d,r11d
	jz	.out
	mov	[rbp],r10b
	inc	rbp
	shr	r10,8
	sub	r11d,8
	jmp	.bytes
.out:
	ret

; eax = insert, edx = copy: eax = the insert-and-copy symbol, ecx = the insert's
; code, edx = the copy's. Keeps r8-r11.
br_cmdsym:
	xor	ecx,ecx
@@:
	cmp	ecx,23
	jae	@f
	cmp	eax,[br_ins_base+rcx*4+4]
	jb	@f
	inc	ecx
	jmp	@b
@@:
	xor	esi,esi
@@:
	cmp	esi,23
	jae	@f
	cmp	edx,[br_cp_base+rsi*4+4]
	jb	@f
	inc	esi
	jmp	@b
@@:
	mov	edx,esi
	mov	eax,ecx
	shr	eax,3
	imul	eax,eax,3
	shr	esi,3
	add	eax,esi
	movzx	eax,word [br_cell+rax*2]
	mov	esi,ecx
	and	esi,7
	lea	eax,[rax+rsi*8]
	mov	esi,edx
	and	esi,7
	add	eax,esi
	ret

; edx = a distance (1 or more): eax = its code (16 + ...), ecx = its extra bits,
; edx = them. Keeps r8-r11.
br_dcode:
	lea	eax,[rdx+3]
	bsr	ecx,eax
	dec	ecx				; n: (2 + b) << n <= d + 3 < (4 << n)
	mov	esi,eax
	shr	esi,cl
	and	esi,1				; b
	lea	edi,[rsi+2]
	shl	edi,cl
	mov	edx,eax
	sub	edx,edi
	lea	eax,[rcx*2+14]
	add	eax,esi
	ret

; rsi = a histogram, ecx = its alphabet's size, edx = the bits a symbol takes in the
; simple form, rdi = its code table: the prefix code, written (r10, r11d, rbp), and
; its table. Keeps rbx, rbp, r10-r13, r15.
br_prefix:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	mov	rbx,rdi
	push	rdx
	lea	rdi,[g_br_len]
	mov	ecx,704
	xor	eax,eax
	rep	stosb
	pop	rdx
	; the symbols used: four at most, the simple form
	xor	r8d,r8d				; how many
	xor	ecx,ecx
.count:
	cmp	ecx,r13d
	jae	.counted
	cmp	dword [r12+rcx*4],0
	je	@f
	cmp	r8d,4
	jae	.complex
	mov	[g_bp_sym+r8*4],ecx
	inc	r8d
@@:
	inc	ecx
	jmp	.count
.counted:
	test	r8d,r8d
	jnz	@f
	mov	dword [g_bp_sym],0		; none: one, never used
	inc	r8d
@@:
	cmp	r8d,3
	jne	.simple
	; three: the most frequent first (one bit), the others two
	mov	eax,[g_bp_sym]
	mov	ecx,[g_bp_sym+4]
	mov	esi,[g_bp_sym+8]
	mov	edi,[r12+rax*4]
	cmp	edi,[r12+rcx*4]
	jae	@f
	xchg	eax,ecx
	mov	edi,[r12+rax*4]
@@:
	cmp	edi,[r12+rsi*4]
	jae	@f
	xchg	eax,esi
@@:
	mov	[g_bp_sym],eax
	mov	[g_bp_sym+4],ecx
	mov	[g_bp_sym+8],esi
.simple:
	push	rdx
	lea	eax,[r8-1]			; HSKIP 1, NSYM - 1
	shl	eax,2
	or	eax,1
	mov	ecx,4
	call	z_put
	pop	rdx
	xor	r9d,r9d
@@:
	mov	eax,[g_bp_sym+r9*4]
	mov	ecx,edx
	push	rdx
	call	z_put
	pop	rdx
	inc	r9d
	cmp	r9d,r8d
	jb	@b
	; their lengths
	mov	eax,[g_bp_sym]
	mov	ecx,[g_bp_sym+4]
	mov	esi,[g_bp_sym+8]
	mov	edi,[g_bp_sym+12]
	cmp	r8d,2
	jb	.lengths			; one: no bits at all
	ja	@f
	mov	byte [g_br_len+rax],1
	mov	byte [g_br_len+rcx],1
	jmp	.lengths
@@:
	cmp	r8d,3
	ja	@f
	mov	byte [g_br_len+rax],1
	mov	byte [g_br_len+rcx],2
	mov	byte [g_br_len+rsi],2
	jmp	.lengths
@@:
	mov	byte [g_br_len+rax],2
	mov	byte [g_br_len+rcx],2
	mov	byte [g_br_len+rsi],2
	mov	byte [g_br_len+rdi],2
	push	rax
	xor	eax,eax				; (tree-select 0: 2, 2, 2, 2)
	mov	ecx,1
	call	z_put
	pop	rax
.lengths:
	lea	rsi,[g_br_len]
	mov	ecx,r13d
	mov	rdi,rbx
	call	br_canon
	pop	r13
	pop	r12
	pop	rbx
	ret
.complex:
	mov	rsi,r12
	mov	ecx,r13d
	mov	edx,15
	lea	rdi,[g_br_len]
	call	br_huff
	; the lengths as written: runs of zeros as 17s; their histogram
	lea	rdi,[g_br_clh]
	mov	ecx,18
	xor	eax,eax
	rep	stosd
	mov	dword [g_br_nseq],0
	mov	ecx,r13d			; the last one used
@@:
	dec	ecx
	cmp	byte [g_br_len+rcx],0
	je	@b
	lea	r9d,[rcx+1]			; the end
	xor	ecx,ecx
.seq:
	cmp	ecx,r9d
	jae	.seq_done
	movzx	eax,byte [g_br_len+rcx]
	test	eax,eax
	jz	.zeros
	xor	edx,edx
	call	.emit
	inc	ecx
	jmp	.seq
.zeros:
	mov	esi,ecx				; how many
@@:
	inc	esi
	cmp	byte [g_br_len+rsi],0
	je	@b
	mov	edx,esi
	sub	edx,ecx
	mov	ecx,esi
	cmp	edx,11
	jne	@f
	xor	eax,eax
	push	rdx
	xor	edx,edx
	call	.emit
	pop	rdx
	dec	edx
@@:
	cmp	edx,3
	jae	.reps
.single:
	test	edx,edx
	jz	.seq
	xor	eax,eax
	push	rdx
	xor	edx,edx
	call	.emit
	pop	rdx
	dec	edx
	jmp	.single
.reps:
	sub	edx,3
	mov	r8d,[g_br_nseq]			; (written backwards, then turned)
@@:
	mov	eax,17
	push	rdx
	and	edx,7
	call	.emit
	pop	rdx
	shr	edx,3
	jz	@f
	dec	edx
	jmp	@b
@@:
	mov	esi,[g_br_nseq]
	dec	esi
.turn:
	cmp	r8d,esi
	jae	.seq
	mov	ax,[g_br_seq+r8*2]
	mov	dx,[g_br_seq+rsi*2]
	mov	[g_br_seq+r8*2],dx
	mov	[g_br_seq+rsi*2],ax
	inc	r8d
	dec	esi
	jmp	.turn
.seq_done:
	; the code lengths' code: five bits at most
	lea	rsi,[g_br_clh]
	mov	ecx,18
	mov	edx,5
	lea	rdi,[g_br_cll]
	call	br_huff
	push	rax
	lea	rsi,[g_br_cll]
	mov	ecx,18
	lea	rdi,[g_br_clc]
	call	br_canon
	pop	rax
	cmp	eax,1
	jne	@f
	xor	ecx,ecx				; only one: it takes no bits
.one:
	cmp	byte [g_br_cll+rcx],0
	jne	.the_one
	inc	ecx
	jmp	.one
.the_one:
	mov	dword [g_br_clc+rcx*4],0
@@:
	xor	eax,eax				; HSKIP 0
	mov	ecx,2
	call	z_put
	mov	r9d,32				; the room left
	xor	r8d,r8d
.cl:
	cmp	r8d,18
	jae	.cl_done
	movzx	eax,byte [br_clorder+r8]
	movzx	edx,byte [g_br_cll+rax]
	movzx	eax,byte [br_clval+rdx]
	movzx	ecx,byte [br_clbits+rdx]
	call	z_put
	inc	r8d
	test	edx,edx
	jz	.cl
	mov	eax,32
	mov	ecx,edx
	shr	eax,cl
	sub	r9d,eax
	jg	.cl
.cl_done:
	xor	r8d,r8d
.put:
	cmp	r8d,[g_br_nseq]
	jae	.lengths
	movzx	edx,word [g_br_seq+r8*2]
	movzx	eax,dl
	mov	eax,[g_br_clc+rax*4]
	call	z_put_code
	cmp	dl,17
	jne	@f
	movzx	eax,dh
	mov	ecx,3
	call	z_put
@@:
	inc	r8d
	jmp	.put
; eax = a code length symbol, edx = its extra: into the sequence, counted
.emit:
	inc	dword [g_br_clh+rax*4]
	shl	edx,8
	or	eax,edx
	mov	edx,[g_br_nseq]
	mov	[g_br_seq+rdx*2],ax
	inc	dword [g_br_nseq]
	ret

; rsi = counts, ecx = how many symbols, edx = the longest a code may be, rdi = their
; lengths (bytes): Huffman, limited (one symbol: length 1). eax = symbols used.
; Keeps rbx, rbp, r10-r15.
br_huff:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r15
	mov	r12,rsi
	mov	r13d,ecx
	mov	ebp,edx
	mov	r15,rdi
	xor	eax,eax
	push	rcx
	rep	stosb
	pop	rcx
	; the used ones, sorted by count (insertion: a few hundred at most)
	xor	r9d,r9d				; m
	xor	ecx,ecx
.collect:
	cmp	ecx,r13d
	jae	.sorted
	mov	eax,[r12+rcx*4]
	test	eax,eax
	jz	.c_next
	mov	edx,r9d
@@:
	test	edx,edx
	jz	@f
	cmp	[g_bh_k+rdx*4-4],eax
	jbe	@f
	mov	esi,[g_bh_k+rdx*4-4]
	mov	[g_bh_k+rdx*4],esi
	mov	si,[g_bh_s+rdx*2-2]
	mov	[g_bh_s+rdx*2],si
	dec	edx
	jmp	@b
@@:
	mov	[g_bh_k+rdx*4],eax
	mov	[g_bh_s+rdx*2],cx
	inc	r9d
.c_next:
	inc	ecx
	jmp	.collect
.sorted:
	mov	eax,r9d
	cmp	r9d,1
	ja	.mk
	jb	.out
	movzx	ecx,word [g_bh_s]
	mov	byte [r15+rcx],1
	jmp	.out
.mk:
	; Moffat and Katajainen, in place: the depths
	lea	r8,[g_bh_k]
	mov	eax,[r8+4]
	add	[r8],eax
	xor	esi,esi				; root
	mov	edi,2				; leaf
	mov	edx,1				; next
.mk1:
	lea	eax,[r9-1]
	cmp	edx,eax
	jae	.mk1_done
	cmp	edi,r9d
	jae	.r1
	mov	eax,[r8+rsi*4]
	cmp	eax,[r8+rdi*4]
	jb	.r1
	mov	eax,[r8+rdi*4]
	mov	[r8+rdx*4],eax
	inc	edi
	jmp	.s2
.r1:
	mov	eax,[r8+rsi*4]
	mov	[r8+rdx*4],eax
	mov	[r8+rsi*4],edx
	inc	esi
.s2:
	cmp	edi,r9d
	jae	.r2
	cmp	esi,edx
	jae	.l2
	mov	eax,[r8+rsi*4]
	cmp	eax,[r8+rdi*4]
	jb	.r2
.l2:
	mov	eax,[r8+rdi*4]
	add	[r8+rdx*4],eax
	inc	edi
	jmp	.n1
.r2:
	mov	eax,[r8+rsi*4]
	add	[r8+rdx*4],eax
	mov	[r8+rsi*4],edx
	inc	esi
.n1:
	inc	edx
	jmp	.mk1
.mk1_done:
	lea	eax,[r9-2]
	mov	dword [r8+rax*4],0
	lea	edx,[r9-3]
.mk2:
	test	edx,edx
	js	.mk2_done
	mov	eax,[r8+rdx*4]
	mov	eax,[r8+rax*4]
	inc	eax
	mov	[r8+rdx*4],eax
	dec	edx
	jmp	.mk2
.mk2_done:
	mov	esi,1				; available
	xor	edi,edi				; used
	xor	ecx,ecx				; depth
	lea	ebx,[r9-2]			; root
	lea	edx,[r9-1]			; next
.mk3:
	test	esi,esi
	jz	.mk3_done
.mk3a:
	test	ebx,ebx
	js	.mk3b
	cmp	[r8+rbx*4],ecx
	jne	.mk3b
	inc	edi
	dec	ebx
	jmp	.mk3a
.mk3b:
	cmp	esi,edi
	jbe	.mk3c
	mov	[r8+rdx*4],ecx
	dec	edx
	dec	esi
	jmp	.mk3b
.mk3c:
	lea	esi,[rdi*2]
	inc	ecx
	xor	edi,edi
	jmp	.mk3
.mk3_done:
	; how many of each length, then none longer than allowed
	lea	rdi,[g_bh_nc]
	mov	ecx,34
	xor	eax,eax
	rep	stosd
	xor	ecx,ecx
@@:
	mov	eax,[r8+rcx*4]
	cmp	eax,32
	jbe	.len_ok
	mov	eax,32
.len_ok:
	inc	dword [g_bh_nc+rax*4]
	inc	ecx
	cmp	ecx,r9d
	jb	@b
	lea	ecx,[rbp+1]
@@:
	cmp	ecx,32
	ja	@f
	mov	eax,[g_bh_nc+rcx*4]
	add	[g_bh_nc+rbp*4],eax
	inc	ecx
	jmp	@b
@@:
	xor	edx,edx				; the total, in 2^-max units
	mov	ecx,1
@@:
	mov	eax,[g_bh_nc+rcx*4]
	push	rcx
	neg	ecx
	add	ecx,ebp
	shl	eax,cl
	pop	rcx
	add	edx,eax
	inc	ecx
	cmp	ecx,ebp
	jbe	@b
	mov	eax,1
	mov	ecx,ebp
	shl	eax,cl				; what it must be
.fix:
	cmp	edx,eax
	je	.fixed
	dec	dword [g_bh_nc+rbp*4]
	lea	ecx,[rbp-1]
@@:
	test	ecx,ecx
	jz	@f
	cmp	dword [g_bh_nc+rcx*4],0
	jne	.longer
	dec	ecx
	jmp	@b
.longer:
	dec	dword [g_bh_nc+rcx*4]
	add	dword [g_bh_nc+rcx*4+4],2
@@:
	dec	edx
	jmp	.fix
.fixed:
	; the most frequent the shortest
	mov	edx,r9d
	mov	ecx,1
.assign:
	cmp	ecx,ebp
	ja	.assigned
	mov	esi,[g_bh_nc+rcx*4]
@@:
	test	esi,esi
	jz	@f
	dec	edx
	movzx	eax,word [g_bh_s+rdx*2]
	mov	[r15+rax],cl
	dec	esi
	jmp	@b
@@:
	inc	ecx
	jmp	.assign
.assigned:
	mov	eax,r9d
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rsi = code lengths (bytes), ecx = how many, rdi = the table: canonical codes,
; reversed, | length << 16 (0: none, or no bits). Keeps rbx, rbp, r8-r15.
br_canon:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	mov	rbx,rdi
	lea	rdi,[g_bh_nc]
	mov	ecx,16
	xor	eax,eax
	rep	stosd
	xor	ecx,ecx
@@:
	movzx	eax,byte [r12+rcx]
	inc	dword [g_bh_nc+rax*4]
	inc	ecx
	cmp	ecx,r13d
	jb	@b
	mov	dword [g_bh_nc],0
	xor	eax,eax				; the code
	mov	ecx,1
@@:
	add	eax,[g_bh_nc+rcx*4-4]
	add	eax,eax
	mov	[g_bc_next+rcx*4],eax
	inc	ecx
	cmp	ecx,16
	jb	@b
	xor	ecx,ecx
.sym:
	cmp	ecx,r13d
	jae	.out
	movzx	esi,byte [r12+rcx]
	xor	eax,eax
	test	esi,esi
	jz	.put
	mov	edi,[g_bc_next+rsi*4]
	inc	dword [g_bc_next+rsi*4]
	push	rcx
	push	rsi
	call	z_rev
	pop	rsi
	pop	rcx
	shl	esi,16
	or	eax,esi
.put:
	mov	[rbx+rcx*4],eax
	inc	ecx
	jmp	.sym
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
