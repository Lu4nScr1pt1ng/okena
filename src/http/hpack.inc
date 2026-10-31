; HPACK (RFC 7541): the header compression of HTTP/2.
;
;   hpack_init(rdi ctx, esi limit): a decoder context (HPD_BYTES) whose
;       dynamic table may grow to `limit` bytes (what okena advertises as
;       SETTINGS_HEADER_TABLE_SIZE; at most HPACK_TABLE_MAX).
;   hpack_decode(rdi ctx, rsi block, edx length, rcx out): decodes one
;       header block into out (HO_*): eax = 0, HPE_COMPRESSION (the peer
;       broke the format: a connection error) or HPE_TOO_BIG (more fields
;       or bytes than out holds: the request is refused, 431).
;   hpack_encode(rdi dst, rsi name, edx name length, rcx value, r8d value
;       length): appends one field; rax = dst after it. Stateless (no
;       dynamic table): an indexed field when the static table has the
;       pair, else a literal without indexing, its name indexed when the
;       static table has it; strings Huffman-coded when that is shorter.
;       Names are written as given (lower case is the caller's).
;
; Every decoded string is copied into out's buffer, names from the tables
; included, so what a field points at stays valid while the table changes
; under the rest of the block. That buffer's size is the bound on what a
; block may expand to: a few bytes that index a large entry many times (an
; HPACK bomb) end in HPE_TOO_BIG, not in memory.

; (the tables, hpack_tables.inc, are included next to this file)

HPACK_TABLE_MAX	:= 4096
HPD_ENTRIES_MAX	:= HPACK_TABLE_MAX / 32		; an entry counts 32 bytes more than its strings

; decoder context
HPD_LIMIT	:= 0				; d: the most a size update may ask
HPD_MAX		:= 4				; d: the table's maximum now
HPD_SIZE		:= 8				; d: its size (strings + 32 an entry)
HPD_COUNT	:= 12				; d: entries
HPD_DLEN		:= 16				; d: bytes of HPD_DATA in use
HPD_ENT		:= 32				; entries, oldest first: offset, name length, value length (d each)
HPD_ESIZE	:= 12
HPD_DATA		:= HPD_ENT + HPD_ENTRIES_MAX * HPD_ESIZE	; their strings, name then value, oldest first
HPD_BYTES	:= HPD_DATA + HPACK_TABLE_MAX

; where a block is decoded to
HPO_FIELDS	:= 0				; q: HP_* entries
HPO_FMAX		:= 8				; d: how many fit
HPO_COUNT	:= 12				; d: how many were decoded
HPO_BUF		:= 16				; q: the strings
HPO_BCAP		:= 24				; d
HPO_BLEN		:= 28				; d: bytes used
HPO_SIZE		:= 32

; a decoded field
HP_NAME		:= 0				; q
HP_VALUE	:= 8				; q
HP_NLEN		:= 16				; d
HP_VLEN		:= 20				; d
HP_FLAGS	:= 24				; d: HPF_*
HP_SIZE		:= 32
HPF_NEVER	:= 1				; never indexed: a proxy keeps it so (RFC 7541 6.2.3)

HPE_COMPRESSION	:= 1
HPE_TOO_BIG	:= 2

; rdi = ctx, esi = limit
hpack_init:
	mov	eax,HPACK_TABLE_MAX
	cmp	esi,eax
	cmova	esi,eax
	mov	[rdi+HPD_LIMIT],esi
	mov	[rdi+HPD_MAX],esi
	xor	eax,eax
	mov	[rdi+HPD_SIZE],eax
	mov	[rdi+HPD_COUNT],eax
	mov	[rdi+HPD_DLEN],eax
	ret

; ----------------------------------------------------------------- decode

; Registers through hpack_decode and its local helpers: rbx = ctx, r12 =
; the next byte, r13 = the block's end, r14 = out, r15d = 1 while no field
; has been decoded yet (size updates allowed).
hpack_decode:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,40				; [rsp]: name ptr, +8 name len, +16 value ptr, +24 value len, +32 flags
	mov	rbx,rdi
	mov	r12,rsi
	lea	r13,[rsi+rdx]
	mov	r14,rcx
	mov	dword [r14+HPO_COUNT],0
	mov	dword [r14+HPO_BLEN],0
	mov	r15d,1
.next:
	cmp	r12,r13
	jae	.ok
	movzx	eax,byte [r12]
	test	al,0x80
	jnz	.indexed
	test	al,0x40
	jnz	.incremental
	test	al,0x20
	jnz	.size_update
	; literal without indexing (0000) or never indexed (0001)
	and	eax,0x10
	shr	eax,4
	mov	[rsp+32],eax
	mov	ecx,4
	call	.int
	jc	.bad
	call	.name
	jc	.err
	call	.str
	jc	.err
	mov	[rsp+16],rax
	mov	[rsp+24],rdx
	call	.emit
	jc	.err
	jmp	.next
.indexed:
	mov	ecx,7
	call	.int
	jc	.bad
	test	eax,eax
	jz	.bad				; index 0 does not exist
	mov	esi,eax
	call	.entry				; rax/rdx name, r8/r9 value
	jc	.bad
	mov	[rsp+16],r8
	mov	[rsp+24],r9
	mov	rcx,rax
	mov	r8,rdx
	call	.copy
	jc	.err
	mov	[rsp],rax
	mov	[rsp+8],rdx
	mov	rcx,[rsp+16]
	mov	r8,[rsp+24]
	call	.copy
	jc	.err
	mov	[rsp+16],rax
	mov	[rsp+24],rdx
	mov	dword [rsp+32],0
	call	.emit
	jc	.err
	jmp	.next
.incremental:
	mov	ecx,6
	call	.int
	jc	.bad
	call	.name
	jc	.err
	call	.str
	jc	.err
	mov	[rsp+16],rax
	mov	[rsp+24],rdx
	mov	dword [rsp+32],0
	call	.emit
	jc	.err
	mov	rdi,rbx				; and into the table
	mov	rsi,[rsp]
	mov	edx,[rsp+8]
	mov	rcx,[rsp+16]
	mov	r8d,[rsp+24]
	call	hd_insert
	jmp	.next
.size_update:
	test	r15d,r15d			; only before the block's first field
	jz	.bad
	mov	ecx,5
	call	.int
	jc	.bad
	cmp	eax,[rbx+HPD_LIMIT]
	ja	.bad
	mov	[rbx+HPD_MAX],eax
	mov	rdi,rbx
	xor	esi,esi
	call	hd_evict
	jmp	.next
.ok:
	xor	eax,eax
	jmp	.out
.bad:
	mov	eax,HPE_COMPRESSION
	jmp	.out
.err:
	; eax holds the error from the helper
.out:
	add	rsp,40
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ecx = prefix bits: an integer at r12 (RFC 7541 5.1), r12 advanced.
; eax = value, CF when truncated or beyond 2^28.
.int:
	cmp	r12,r13
	jae	.int_bad
	mov	edx,1
	shl	edx,cl
	dec	edx				; the prefix mask
	movzx	eax,byte [r12]
	inc	r12
	and	eax,edx
	cmp	eax,edx
	jb	.int_ok
	xor	ecx,ecx				; shift
.int_more:
	cmp	r12,r13
	jae	.int_bad
	movzx	r8d,byte [r12]
	inc	r12
	mov	r9d,r8d
	and	r9d,127
	shl	r9d,cl
	add	eax,r9d
	add	ecx,7
	test	r8d,128
	jz	.int_end
	cmp	ecx,21
	jbe	.int_more
.int_bad:
	stc
	ret
.int_end:
	cmp	eax,1 shl 28
	jae	.int_bad
.int_ok:
	clc
	ret

; eax = the index of a field's name (0: the name is a string that follows):
; the name, copied to out, at [rsp+8+0] and [rsp+8+8] (the caller's frame).
; CF and eax = the error.
.name:
	test	eax,eax
	jz	.name_str
	mov	esi,eax
	call	.entry
	jc	.name_bad
	mov	rcx,rax
	mov	r8,rdx
	call	.copy
	jc	.name_ret
	mov	[rsp+8],rax
	mov	[rsp+16],rdx
	clc
	ret
.name_str:
	call	.str
	jc	.name_ret
	mov	[rsp+8],rax
	mov	[rsp+16],rdx
	clc
.name_ret:
	ret
.name_bad:
	mov	eax,HPE_COMPRESSION
	stc
	ret

; a string at r12 (H bit, 7-bit length, bytes), decoded into out:
; rax = where, rdx = its length. CF and eax = the error.
.str:
	cmp	r12,r13
	jae	.str_bad
	movzx	ebp,byte [r12]
	and	ebp,0x80			; Huffman?
	mov	ecx,7
	call	.int
	jc	.str_bad
	mov	rcx,r13
	sub	rcx,r12
	cmp	rax,rcx
	ja	.str_bad			; longer than what is left of the block
	mov	rsi,r12
	add	r12,rax
	test	ebp,ebp
	jnz	.str_huff
	mov	rcx,rsi
	mov	r8,rax
	jmp	.copy
.str_huff:
	mov	ecx,eax
	mov	rdi,[r14+HPO_BUF]
	mov	eax,[r14+HPO_BLEN]
	add	rdi,rax
	push	rdi
	mov	r8,[r14+HPO_BUF]
	mov	eax,[r14+HPO_BCAP]
	add	r8,rax
	call	huff_decode
	pop	rdx
	jc	.str_ret			; eax = the error
	mov	rcx,rax				; the end
	sub	rcx,[r14+HPO_BUF]
	mov	[r14+HPO_BLEN],ecx
	sub	rax,rdx
	xchg	rax,rdx				; rax = start, rdx = length
	clc
	ret
.str_bad:
	mov	eax,HPE_COMPRESSION
	stc
.str_ret:
	ret

; rcx = bytes, r8 = length: copied to out. rax = where, rdx = length,
; CF and eax = HPE_TOO_BIG when out is full.
.copy:
	mov	eax,[r14+HPO_BLEN]
	lea	rdx,[rax+r8]
	cmp	edx,[r14+HPO_BCAP]
	ja	.copy_full
	mov	[r14+HPO_BLEN],edx
	mov	rdi,[r14+HPO_BUF]
	add	rdi,rax
	push	rdi
	mov	rsi,rcx
	mov	rcx,r8
	rep	movsb
	pop	rax
	mov	rdx,r8
	clc
	ret
.copy_full:
	mov	eax,HPE_TOO_BIG
	stc
	ret

; esi = index (1..): rax/rdx = name and length, r8/r9 = value and length,
; from the static table (1..61) or the dynamic one (62.., newest first).
; CF when there is no such entry.
.entry:
	cmp	esi,61
	ja	.dynamic
	lea	r10,[hp_static-8]
	lea	r10,[r10+rsi*8]
	lea	r11,[hp_pool]
	movzx	eax,word [r10]
	add	rax,r11
	movzx	edx,word [r10+2]
	movzx	r8d,word [r10+4]
	add	r8,r11
	movzx	r9d,word [r10+6]
	clc
	ret
.dynamic:
	sub	esi,62				; 0 = the newest
	cmp	esi,[rbx+HPD_COUNT]
	jae	.entry_bad
	mov	eax,[rbx+HPD_COUNT]
	sub	eax,esi
	dec	eax				; its position, oldest first
	imul	eax,eax,HPD_ESIZE
	lea	r10,[rbx+HPD_ENT+rax]
	mov	eax,[r10]
	lea	rax,[rbx+HPD_DATA+rax]
	mov	edx,[r10+4]
	lea	r8,[rax+rdx]
	mov	r9d,[r10+8]
	clc
	ret
.entry_bad:
	stc
	ret

; the field in the caller's frame ([rsp+8..]) to out's list
.emit:
	mov	eax,[r14+HPO_COUNT]
	cmp	eax,[r14+HPO_FMAX]
	jae	.emit_full
	inc	dword [r14+HPO_COUNT]
	imul	eax,eax,HP_SIZE
	add	rax,[r14+HPO_FIELDS]
	mov	rcx,[rsp+8]
	mov	[rax+HP_NAME],rcx
	mov	rcx,[rsp+16]
	mov	[rax+HP_NLEN],ecx
	mov	rcx,[rsp+24]
	mov	[rax+HP_VALUE],rcx
	mov	rcx,[rsp+32]
	mov	[rax+HP_VLEN],ecx
	mov	ecx,[rsp+40]
	mov	[rax+HP_FLAGS],ecx
	xor	r15d,r15d			; size updates are over for this block
	clc
	ret
.emit_full:
	mov	eax,HPE_TOO_BIG
	stc
	ret

; rdi = ctx, esi = bytes about to be added: the oldest entries go until the
; table holds them within its maximum.
hd_evict:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12d,esi
.again:
	mov	eax,[rbx+HPD_SIZE]
	add	eax,r12d
	cmp	eax,[rbx+HPD_MAX]
	jbe	.done
	cmp	dword [rbx+HPD_COUNT],0
	je	.done
	; the oldest: its bytes and its entry leave the front
	mov	eax,[rbx+HPD_ENT+4]
	add	eax,[rbx+HPD_ENT+8]		; its strings
	mov	ecx,[rbx+HPD_DLEN]
	sub	ecx,eax
	mov	[rbx+HPD_DLEN],ecx
	lea	rdi,[rbx+HPD_DATA]
	lea	rsi,[rdi+rax]
	push	rax
	rep	movsb
	pop	rax
	lea	edx,[rax+32]
	sub	[rbx+HPD_SIZE],edx
	dec	dword [rbx+HPD_COUNT]
	mov	ecx,[rbx+HPD_COUNT]
	imul	ecx,ecx,HPD_ESIZE
	lea	rdi,[rbx+HPD_ENT]
	lea	rsi,[rdi+HPD_ESIZE]
	rep	movsb
	mov	ecx,[rbx+HPD_COUNT]		; offsets move down by what left
	lea	rdi,[rbx+HPD_ENT]
@@:
	test	ecx,ecx
	jz	.again
	sub	[rdi],eax
	add	rdi,HPD_ESIZE
	dec	ecx
	jmp	@b
.done:
	pop	r12
	pop	rbx
	ret

; rdi = ctx, rsi = name, edx = its length, rcx = value, r8d = its length:
; a new newest entry (RFC 7541 4.4: one larger than the maximum empties
; the table and is not kept).
hd_insert:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,edx
	mov	r14,rcx
	mov	r15d,r8d
	lea	esi,[r13+r15+32]
	mov	rdi,rbx
	call	hd_evict
	lea	eax,[r13+r15+32]
	add	eax,[rbx+HPD_SIZE]
	cmp	eax,[rbx+HPD_MAX]
	ja	.out				; too large even for an empty table
	mov	[rbx+HPD_SIZE],eax
	mov	eax,[rbx+HPD_COUNT]
	inc	dword [rbx+HPD_COUNT]
	imul	eax,eax,HPD_ESIZE
	lea	rdx,[rbx+HPD_ENT+rax]
	mov	eax,[rbx+HPD_DLEN]
	mov	[rdx],eax
	mov	[rdx+4],r13d
	mov	[rdx+8],r15d
	lea	rdi,[rbx+HPD_DATA+rax]
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	lea	rax,[rbx+HPD_DATA]
	sub	rdi,rax
	mov	[rbx+HPD_DLEN],edi
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = Huffman-coded bytes, ecx = their length, rdi = where to, r8 = the
; end of the room: rax = the end of what was written. CF with eax =
; HPE_COMPRESSION (an invalid code, EOS, or padding that is longer than 7
; bits or not all ones) or HPE_TOO_BIG (no room). Canonical decoding, a
; bit at a time: the code so far against the first code of its length.
huff_decode:
	push	rbx
	push	r12
	lea	r12,[rsi+rcx]			; the input's end
	xor	r9d,r9d				; the code so far
	xor	r10d,r10d			; its length
.byte:
	cmp	rsi,r12
	jae	.end
	movzx	ebx,byte [rsi]
	inc	rsi
	mov	r11d,8
.bit:
	add	r9d,r9d
	shl	bl,1
	adc	r9d,0
	inc	r10d
	cmp	r10d,30
	ja	.bad
	lea	rax,[hp_hcount]
	movzx	ecx,word [rax+r10*2]
	test	ecx,ecx
	jz	.nextbit
	lea	rax,[hp_hfirst]
	mov	edx,r9d
	sub	edx,[rax+r10*4]
	cmp	edx,ecx
	jae	.nextbit			; (below the first code: wraps, also above)
	lea	rax,[hp_hstart]
	movzx	ecx,word [rax+r10*2]
	add	edx,ecx
	lea	rax,[hp_hsyms]
	movzx	eax,word [rax+rdx*2]
	cmp	eax,256
	je	.bad				; EOS inside the string
	cmp	rdi,r8
	jae	.full
	mov	[rdi],al
	inc	rdi
	xor	r9d,r9d
	xor	r10d,r10d
.nextbit:
	dec	r11d
	jnz	.bit
	jmp	.byte
.end:
	cmp	r10d,7				; padding: at most 7 bits, all ones
	ja	.bad
	mov	ecx,r10d
	mov	eax,1
	shl	eax,cl
	dec	eax
	cmp	r9d,eax
	jne	.bad
	mov	rax,rdi
	clc
	jmp	.out
.full:
	mov	eax,HPE_TOO_BIG
	stc
	jmp	.out
.bad:
	mov	eax,HPE_COMPRESSION
	stc
.out:
	pop	r12
	pop	rbx
	ret

; ----------------------------------------------------------------- encode

; rdi = dst, rax = value, cl = prefix bits, dl = the first byte's high bits:
; an integer (RFC 7541 5.1). rdi advanced. Clobbers rax, rdx, r10.
hp_put_int:
	mov	r10d,1
	shl	r10d,cl
	dec	r10d				; the prefix mask
	cmp	rax,r10
	jae	.long
	or	al,dl
	mov	[rdi],al
	inc	rdi
	ret
.long:
	or	dl,r10b
	mov	[rdi],dl
	inc	rdi
	sub	rax,r10
@@:
	cmp	rax,128
	jb	@f
	mov	edx,eax
	or	dl,128
	mov	[rdi],dl
	inc	rdi
	shr	rax,7
	jmp	@b
@@:
	mov	[rdi],al
	inc	rdi
	ret

; rsi = bytes, ecx = length: rax = their Huffman length in bytes
huff_len:
	xor	eax,eax
	lea	r9,[hp_hlen]
@@:
	test	ecx,ecx
	jz	@f
	movzx	edx,byte [rsi]
	movzx	edx,byte [r9+rdx]
	add	rax,rdx
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	add	rax,7
	shr	rax,3
	ret

; rdi = dst, rsi = bytes, ecx = length: a string literal, Huffman-coded
; when that is shorter. rdi advanced.
hp_put_str:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	call	huff_len
	mov	rbx,rax
	cmp	rbx,r13
	jb	.huff
	mov	rax,r13				; raw
	mov	cl,7
	xor	edx,edx
	call	hp_put_int
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
	jmp	.out
.huff:
	mov	rax,rbx
	mov	cl,7
	mov	dl,0x80
	call	hp_put_int
	xor	r8d,r8d				; bit accumulator
	xor	r9d,r9d				; bits in it
	lea	r10,[hp_hcode]
	lea	r11,[hp_hlen]
.sym:
	test	r13d,r13d
	jz	.flush
	movzx	eax,byte [r12]
	inc	r12
	dec	r13d
	movzx	ecx,byte [r11+rax]
	mov	eax,[r10+rax*4]
	shl	r8,cl
	or	r8,rax
	add	r9d,ecx
.drain:
	cmp	r9d,8
	jb	.sym
	sub	r9d,8
	mov	rax,r8
	mov	ecx,r9d
	shr	rax,cl
	mov	[rdi],al
	inc	rdi
	jmp	.drain
.flush:
	test	r9d,r9d
	jz	.out
	mov	ecx,8				; pad with ones (the EOS prefix)
	sub	ecx,r9d
	shl	r8,cl
	mov	eax,1
	shl	eax,cl
	dec	eax
	or	r8,rax
	mov	[rdi],r8b
	inc	rdi
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = dst, rsi = name, edx = name length, rcx = value, r8d = value
; length: one field (see the top). rax = dst after it.
hpack_encode:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,edx
	mov	r14,rcx
	mov	r15d,r8d
	xor	ebp,ebp				; a static index with this name, 0 = none
	mov	r9d,1
.search:
	cmp	r9d,61
	ja	.searched
	lea	r10,[hp_static-8]
	lea	r10,[r10+r9*8]
	movzx	eax,word [r10+2]
	cmp	eax,r13d
	jne	.skip
	lea	rsi,[hp_pool]
	movzx	eax,word [r10]
	add	rsi,rax
	mov	rdi,r12
	mov	edx,r13d
	push	r9
	push	r10
	call	mem_eq
	pop	r10
	pop	r9
	test	eax,eax
	jz	.skip
	test	ebp,ebp
	jnz	@f
	mov	ebp,r9d				; the first with this name
@@:
	movzx	eax,word [r10+6]		; and its value too?
	cmp	eax,r15d
	jne	.skip
	lea	rsi,[hp_pool]
	movzx	eax,word [r10+4]
	add	rsi,rax
	mov	rdi,r14
	mov	edx,r15d
	push	r9
	call	mem_eq
	pop	r9
	test	eax,eax
	jnz	.indexed
.skip:
	inc	r9d
	jmp	.search
.indexed:
	mov	rdi,rbx
	mov	eax,r9d
	mov	cl,7
	mov	dl,0x80
	call	hp_put_int
	jmp	.out
.searched:
	; literal without indexing: 0000, the name indexed (4-bit) or a string
	mov	rdi,rbx
	mov	eax,ebp
	mov	cl,4
	xor	edx,edx
	call	hp_put_int
	test	ebp,ebp
	jnz	@f
	mov	rsi,r12
	mov	ecx,r13d
	call	hp_put_str
@@:
	mov	rsi,r14
	mov	ecx,r15d
	call	hp_put_str
.out:
	mov	rax,rdi
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
