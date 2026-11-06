; `compress gzip min=1KiB` on a listener or a route (`compress off` undoes it there):
; gzip as the answer goes out, in pieces, its length unknown until it ends.
;
; DEFLATE (RFC 1951) with one fixed-code block: LZ77 over a 32 KiB window, a single
; candidate for each place from a hash of three bytes, so it costs little and is
; about what gzip -1 gets with worse luck. What it reads goes through the window, so
; a match reaches back across pieces.
;
; Only 200s of text the client said it takes; not what is encoded already, nor
; `Cache-Control: no-transform`, nor a HEAD, nor HTTP/1.0, which has no chunks. With
; no context free the answer simply goes as it is. The cache keeps what the backend
; sent: each client gets what it takes.
;
; A context is big, so there are Z_N per worker, reserved only when used. An answer
; holds one from its head to its end.

SF_ZIP		:= 67108864			; S_FLAGS: it goes out compressed

Z_N		:= 64
Z_WINCAP	:= 1 shl 17
Z_HBITS		:= 14
Z_NEXT		:= 0				; d: free list
Z_POS		:= 4				; d: in the window: what comes next
Z_END		:= 8				; d: what is there
Z_ABS		:= 12				; d: Z_POS counted from the start of it all
Z_NBITS		:= 16				; d
Z_CRC		:= 20				; d
Z_ISIZE		:= 24				; d
Z_DONE		:= 28				; d
Z_BITS		:= 32				; q
Z_HEAD		:= 40				; d: its gzip header went out
Z_HASH		:= 64				; d each: the place + 1
Z_WIN		:= Z_HASH + (4 shl Z_HBITS)
Z_OUT		:= Z_WIN + Z_WINCAP
Z_OUTCAP	:= 32768
Z_SIZE		:= Z_OUT + Z_OUTCAP
assert (H_UP_CAP * 9 / 8) + 256 <= Z_OUTCAP
assert 32768 + H_UP_CAP < Z_WINCAP
Z_FRAME		:= 16				; the room before OUT's bytes for a chunk's line

bss
	align 8
	g_z_base	dq ?
	g_z_free	dd ?
	g_zh		dd ?			; the head being written is of such an answer
	g_plan_zip	dd ?
	g_z_lit		rd 288			; code | bits << 16, as the writer wants them
	g_z_dist	rb 32
	g_z_lcode	rw 259			; a length's symbol, its extra bits in the top byte
	g_z_crc		rd 256
end bss

rodata
	z_lbase		dw 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
	z_lext		db 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
	z_dbase		dw 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
	z_dext		db 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
	z_head		db 0x1F,0x8B,8,0,0,0,0,0,0,0xFF
end rodata

; edi = a code, esi = how many bits: eax = it reversed
z_rev:
	xor	eax,eax
@@:
	add	eax,eax
	mov	edx,edi
	and	edx,1
	or	eax,edx
	shr	edi,1
	dec	esi
	jnz	@b
	ret

; a worker, at its start
zip_init:
	cmp	dword [g_plan_zip],0
	je	.none
	push	rbx
	push	r12
	xor	edi,edi
	mov	esi,Z_N * Z_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	js	.out
	mov	[g_z_base],rax
	; the free list
	mov	rdi,rax
	mov	ecx,Z_N - 1
	xor	eax,eax
.link:
	inc	eax
	mov	[rdi+Z_NEXT],eax
	add	rdi,Z_SIZE
	dec	ecx
	jnz	.link
	mov	dword [rdi+Z_NEXT],NIL
	mov	dword [g_z_free],0
	; the literal and length codes
	xor	ebx,ebx
.lit:
	cmp	ebx,288
	jae	.dist
	cmp	ebx,144
	jae	@f
	lea	edi,[rbx+0x30]
	mov	esi,8
	jmp	.code
@@:
	cmp	ebx,256
	jae	@f
	lea	edi,[rbx+0x190-144]
	mov	esi,9
	jmp	.code
@@:
	cmp	ebx,280
	jae	@f
	lea	edi,[rbx-256]
	mov	esi,7
	jmp	.code
@@:
	lea	edi,[rbx+0xC0-280]
	mov	esi,8
.code:
	mov	r12d,esi
	call	z_rev
	shl	r12d,16
	or	eax,r12d
	mov	[g_z_lit+rbx*4],eax
	inc	ebx
	jmp	.lit
.dist:
	xor	ebx,ebx
@@:
	mov	edi,ebx
	mov	esi,5
	call	z_rev
	mov	[g_z_dist+rbx],al
	inc	ebx
	cmp	ebx,32
	jb	@b
	; a length's symbol
	xor	ebx,ebx				; which symbol
	mov	ecx,3
.len:
	cmp	ecx,258
	ja	.crc
.sym:
	lea	eax,[rbx+1]
	cmp	eax,29
	jae	.this
	movzx	eax,word [z_lbase+rax*2]
	cmp	ecx,eax
	jb	.this
	inc	ebx
	jmp	.sym
.this:
	cmp	ecx,258
	jne	@f
	mov	ebx,28
@@:
	movzx	eax,byte [z_lext+rbx]
	shl	eax,8
	or	eax,ebx
	mov	[g_z_lcode+rcx*2],ax
	inc	ecx
	jmp	.len
.crc:
	xor	ecx,ecx
.c:
	mov	eax,ecx
	mov	edx,8
@@:
	shr	eax,1
	jnc	.even
	xor	eax,0xEDB88320
.even:
	dec	edx
	jnz	@b
	mov	[g_z_crc+rcx*4],eax
	inc	ecx
	cmp	ecx,256
	jb	.c
.out:
	pop	r12
	pop	rbx
.none:
	ret

; g_hm = the request, r15: whether this answer may be compressed, for when its head
; comes. rax, rcx, rdx, rsi, rdi, r8-r11 are free. Keeps rbx, r12-r15.
zip_request:
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_ZOK],0
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	edx,[g_acts+rax+RA_ZMIN]
	test	edx,edx
	jz	.none
	test	dword [r15+H_FLAGS],HX_HTTP10 or HX_HEAD or HX_UPGRADE
	jnz	.none
	push	rdx
	lea	rdi,[fs_precompressed.ae]
	mov	esi,15
	call	limit_find
	pop	rdx
	test	ecx,ecx
	jz	.none
	push	rdx
	mov	eax,FE_GZ
	call	fs_accepts
	pop	rdx
	test	eax,eax
	jz	.none
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_ZOK],edx
.none:
	ret

; g_hm = an answer's head, ebx, r15: g_zh, and a context, if it is to be compressed
zip_head:
	mov	dword [g_zh],0
	mov	rax,[r15+H_BUF]
	mov	edx,[rax+HB_ZOK]
	test	edx,edx
	jz	.none
	mov	dword [rax+HB_ZOK],0
	test	dword [r15+H_FLAGS],HX_MIRROR
	jnz	.none
	cmp	dword [g_hm+HM_STATUS],200
	jne	.none
	cmp	dword [g_z_free],NIL
	je	.none
	mov	eax,[r15+H_RBODY]
	cmp	eax,BK_NONE
	je	.none
	cmp	eax,BK_LENGTH
	jne	@f
	cmp	[r15+H_RREMAIN],rdx
	jb	.none
@@:
	; a type worth it
	lea	rdi,[.ct]
	mov	esi,12
	call	limit_find
	test	ecx,ecx
	jz	.none
	lea	r8,[.types]
.type:
	movzx	eax,byte [r8]
	test	eax,eax
	jz	.none
	cmp	ecx,eax
	jb	.other
	push	rsi
	push	rcx
	push	r8
	mov	rdi,rsi
	lea	rsi,[r8+1]
	mov	edx,eax
	call	mem_eq_nocase
	pop	r8
	pop	rcx
	pop	rsi
	test	eax,eax
	jnz	.typed
	movzx	eax,byte [r8]
.other:
	lea	r8,[r8+rax+1]
	jmp	.type
.typed:
	lea	rdi,[.ce]
	mov	esi,16
	call	limit_find
	test	ecx,ecx
	jnz	.none
	; every Cache-Control there is
	xor	r8d,r8d
.cc:
	cmp	r8d,[g_hm+HM_NHDR]
	jae	.yes
	imul	rdi,r8,HF_SIZE
	lea	rdi,[g_hm+HM_HDRS+rdi]
	inc	r8d
	push	r8
	push	rdi
	lea	rsi,[.n_cc]
	call	hf_is
	pop	rdi
	pop	r8
	jnz	.cc
	mov	rsi,[rdi+HF_VALUE]
	mov	ecx,[rdi+HF_VLEN]
.scan:
	cmp	ecx,12
	jb	.cc
	push	rsi
	push	rcx
	push	r8
	mov	rdi,rsi
	lea	rsi,[.nt]
	mov	edx,12
	call	mem_eq_nocase
	pop	r8
	pop	rcx
	pop	rsi
	test	eax,eax
	jnz	.none
	inc	rsi
	dec	ecx
	jmp	.scan
.yes:
	; a context
	mov	eax,[g_z_free]
	mov	ecx,eax
	imul	rax,rax,Z_SIZE
	add	rax,[g_z_base]
	mov	edx,[rax+Z_NEXT]
	mov	[g_z_free],edx
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_ZC],ecx
	; (its hash has entries of who had it: they are checked against the bytes, and
	; only places in this window are looked at: Z_ABS starts past them)
	mov	dword [rax+Z_POS],0
	mov	dword [rax+Z_END],0
	mov	dword [rax+Z_NBITS],3
	mov	qword [rax+Z_BITS],2		; a block, not the last, of fixed codes
	mov	dword [rax+Z_CRC],-1
	mov	dword [rax+Z_ISIZE],0
	mov	dword [rax+Z_DONE],0
	mov	dword [rax+Z_HEAD],0
	mov	dword [rax+Z_ABS],0
	lea	rdi,[rax+Z_HASH]
	mov	ecx,1 shl Z_HBITS
	xor	eax,eax
	rep	stosd
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_ZIP
	mov	dword [g_zh],1
	call	h_chunkout
.none:
	ret
.ct	db 'content-type'
.ce	db 'content-encoding'
cstring .n_cc, 'cache-control',0
.nt	db 'no-transform'
.types	db 5,'text/'
	db 16,'application/json'
	db 22,'application/javascript'
	db 15,'application/xml'
	db 22,'application/xhtml+xml'
	db 13,'image/svg+xml'
	db 25,'application/manifest+json'
	db 19,'application/ld+json'
	db 0

; r8 = bytes, r9d = how many: rdi = what goes out, esi = how much, 0 nothing yet.
; ebx, r15. Keeps rbx, r12-r15.
zip_feed:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_ZC]
	imul	rax,rax,Z_SIZE
	add	rax,[g_z_base]
	mov	r12,rax				; the context
	lea	rbp,[r12+Z_OUT+Z_FRAME]		; the cursor out
	call	zip_gz_head
	test	r9d,r9d
	jz	.frame
	; crc, size
	add	[r12+Z_ISIZE],r9d
	mov	eax,[r12+Z_CRC]
	mov	rsi,r8
	mov	ecx,r9d
.crc:
	movzx	edx,byte [rsi]
	xor	dl,al
	shr	eax,8
	xor	eax,[g_z_crc+rdx*4]
	inc	rsi
	dec	ecx
	jnz	.crc
	mov	[r12+Z_CRC],eax
	; into the window, sliding it when it would not fit
	mov	eax,[r12+Z_END]
	lea	ecx,[rax+r9]
	cmp	ecx,Z_WINCAP
	jbe	.fits
	lea	rsi,[r12+Z_WIN]
	mov	ecx,eax
	sub	ecx,32768
	lea	rsi,[rsi+rcx]
	lea	rdi,[r12+Z_WIN]
	mov	eax,32768
	sub	[r12+Z_POS],ecx
	mov	ecx,eax
	rep	movsb
	mov	dword [r12+Z_END],32768
	mov	eax,32768
.fits:
	lea	rdi,[r12+Z_WIN+rax]
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	add	[r12+Z_END],r9d
	; rbx = the place, r13 = the end, r14 = what is on r10/r11: the bits
	mov	ebx,[r12+Z_POS]
	mov	r13d,[r12+Z_END]
	mov	r10,[r12+Z_BITS]
	mov	r11d,[r12+Z_NBITS]
.next:
	cmp	ebx,r13d
	jae	.fed
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,3
	jb	.literal
	; the hash of three bytes
	mov	eax,[r12+Z_WIN+rbx]
	and	eax,0xFFFFFF
	imul	eax,eax,0x9E3779B1
	shr	eax,32 - Z_HBITS
	mov	ecx,[r12+Z_HASH+rax*4]		; the place + 1 it was seen at
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
	ja	.literal			; (not in the window)
	; how long
	mov	esi,ebx
	sub	esi,edx
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,258
	jbe	@f
	mov	eax,258
@@:
	xor	ecx,ecx				; the length
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
	; the length: symbol and extra bits
	mov	r9d,ecx				; the length, for after
	movzx	eax,word [g_z_lcode+rcx*2]
	movzx	esi,al				; the symbol, 0..28
	mov	r8d,eax
	shr	r8d,8				; extra bits
	push	rdx
	mov	eax,[g_z_lit+257*4+rsi*4]
	call	z_put_code
	test	r8d,r8d
	jz	@f
	movzx	eax,word [z_lbase+rsi*2]
	mov	ecx,r9d
	sub	ecx,eax
	mov	eax,ecx
	mov	ecx,r8d
	call	z_put
@@:
	pop	rdx
	; the distance
	xor	esi,esi
@@:
	cmp	esi,29
	jae	@f
	movzx	eax,word [z_dbase+rsi*2+2]
	cmp	edx,eax
	jb	@f
	inc	esi
	jmp	@b
@@:
	movzx	eax,byte [g_z_dist+rsi]
	mov	ecx,5
	call	z_put
	movzx	ecx,byte [z_dext+rsi]
	test	ecx,ecx
	jz	@f
	movzx	eax,word [z_dbase+rsi*2]
	sub	edx,eax
	mov	eax,edx
	call	z_put
@@:
	; the places it covers go in the hash, while there are three bytes
	mov	ecx,r9d
	add	[r12+Z_ABS],ecx
	inc	ebx
	dec	r9d
	mov	edx,[r12+Z_ABS]
	sub	edx,r9d				; (the second place + 1)
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
	mov	eax,[g_z_lit+rax*4]
	call	z_put_code
	inc	ebx
	inc	dword [r12+Z_ABS]
	jmp	.next
.fed:
	mov	[r12+Z_POS],ebx
	mov	[r12+Z_BITS],r10
	mov	[r12+Z_NBITS],r11d
.frame:
	call	zip_frame
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; eax = code | bits << 16: out. Keeps rcx-rdx, rsi, r8, r9.
z_put_code:
	push	rcx
	mov	ecx,eax
	shr	ecx,16
	and	eax,0xFFFF
	call	z_put
	pop	rcx
	ret

; eax = bits, ecx = how many (under 32): r10, r11d = what waits, rbp = out
z_put:
	mov	r14d,eax			; (zero upper half)
	mov	eax,ecx
	mov	ecx,r11d
	shl	r14,cl
	or	r10,r14
	add	r11d,eax
.flush:
	cmp	r11d,32
	jb	.out
	mov	[rbp],r10d
	add	rbp,4
	shr	r10,32
	sub	r11d,32
.out:
	ret

; rbp = what comes after what was written, from Z_OUT + Z_FRAME: rdi, esi to send
zip_frame:
	lea	rdi,[r12+Z_OUT+Z_FRAME]
	mov	rsi,rbp
	sub	rsi,rdi
	test	esi,esi
	jz	.out
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jz	.out
	; its size, in hex, right before; CRLF after
	mov	word [rbp],0x0A0D
	add	rbp,2
	mov	eax,esi
	mov	word [rdi-2],0x0A0D
	sub	rdi,3
.hex:
	mov	ecx,eax
	and	ecx,15
	movzx	ecx,byte [fs_validators.digits+rcx]
	mov	[rdi],cl
	dec	rdi
	shr	eax,4
	jnz	.hex
	inc	rdi
	mov	rsi,rbp
	sub	rsi,rdi
.out:
	ret

; r12 = context, rbp = out: the gzip header, if it has not gone
zip_gz_head:
	cmp	dword [r12+Z_HEAD],0
	jne	.out
	mov	dword [r12+Z_HEAD],1
	mov	rax,qword [z_head]
	mov	[rbp],rax
	mov	ax,word [z_head+8]
	mov	[rbp+8],ax
	add	rbp,10
.out:
	ret

; ebx, r15: the end of the body: rdi, esi = what goes out, the last of it. Keeps
; rbx, r12-r15.
zip_finish:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_ZC]
	imul	rax,rax,Z_SIZE
	add	rax,[g_z_base]
	mov	r12,rax
	mov	dword [r12+Z_DONE],1
	lea	rbp,[r12+Z_OUT+Z_FRAME]
	call	zip_gz_head
	mov	r10,[r12+Z_BITS]
	mov	r11d,[r12+Z_NBITS]
	mov	eax,[g_z_lit+256*4]		; the end of the block
	call	z_put_code
	mov	eax,3				; another, the last, empty
	mov	ecx,3
	call	z_put
	mov	eax,[g_z_lit+256*4]
	call	z_put_code
	; to a whole byte
	mov	ecx,r11d
	neg	ecx
	and	ecx,7
	xor	eax,eax
	test	ecx,ecx
	jz	@f
	call	z_put
@@:
	; (what is left is whole bytes)
.byte:
	test	r11d,r11d
	jz	.bytes
	mov	[rbp],r10b
	inc	rbp
	shr	r10,8
	sub	r11d,8
	jmp	.byte
.bytes:
	mov	eax,[r12+Z_CRC]
	not	eax
	mov	[rbp],eax
	mov	eax,[r12+Z_ISIZE]
	mov	[rbp+4],eax
	add	rbp,8
	call	zip_frame
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jz	.out
	lea	rax,[rdi+rsi]
	mov	dword [rax],0x0D0A0D30		; 0 CR LF CR
	mov	byte [rax+4],10			; LF
	add	esi,5
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; the context goes back: ebx, r15
zip_done:
	push	rax
	call	session_ptr
	and	dword [rax+S_FLAGS],not SF_ZIP
	pop	rax
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_ZC]
	imul	rax,rcx,Z_SIZE
	add	rax,[g_z_base]
	mov	edx,[g_z_free]
	mov	[rax+Z_NEXT],edx
	mov	[g_z_free],ecx
	ret

; rbx = a route's node, r12 = it, r13 = the action: `compress`, its own or the
; listener's. Keeps rbx, r12, r13.
compile_compress:
	push	r14
	mov	r14,r12
.up:
	test	r14,r14
	jz	.out
	mov	rdi,r14
	mov	ecx,DIR_COMPRESS
	call	find_child
	test	rax,rax
	jnz	.found
	mov	r14,[r14+N_PARENT]
	jmp	.up
.found:
	mov	r14,rax
	mov	rax,[r14+N_ARGS]
	mov	rcx,[rax+A_VAL]
	cmp	dword [rax+A_VLEN],3
	jne	.gzip
	cmp	word [rcx],'of'
	je	.out
.gzip:
	mov	eax,[rax+A_VLEN]
	cmp	eax,4
	jne	plan_bad_compress
	cmp	dword [rcx],'gzip'
	jne	plan_bad_compress
	cmp	dword [r14+N_ARGC],1
	jne	.args
.size:
	mov	dword [r13+RA_ZMIN],256
	mov	rdi,r14
	lea	rsi,[.k_min]
	call	node_option
	test	rax,rax
	jz	.on
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_size
	test	rax,rax
	jnz	@f
	mov	eax,1				; (0: all of them)
@@:
	mov	[r13+RA_ZMIN],eax
.on:
	inc	dword [g_plan_zip]
.out:
	pop	r14
	ret
.args:
	; (min= is one of the arguments too: a second word is what is not known)
	mov	eax,[r14+N_ARGC]
	mov	rcx,[r14+N_ARGS]
.a:
	add	rcx,A_SIZE
	dec	eax
	jz	.size
	cmp	dword [rcx+A_KIND],ARG_KV
	jne	plan_bad_compress
	jmp	.a
cstring .k_min, 'min',0

plan_bad_compress:
	call	log_begin
	out_lit 'compress takes gzip or off, and min=SIZE: zstd is not here yet'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
