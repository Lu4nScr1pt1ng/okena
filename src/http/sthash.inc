; The static tables of HPACK (RFC 7541 Appendix A) and QPACK (RFC 9204
; Appendix A) looked up by hash: a field our answers carry is found with a
; probe and a compare or two, where the entries whose names were as long
; were each compared (content-type alone has eleven in QPACK's).
;
; Both tables have the same entries: name offset (w), name length (w),
; value offset (w), value length (w), into their pool. A table's
; descriptor (SD_*) names them and the lookup tables made from them the
; first time (per worker): by name (the first entry with it) and by name and
; value, ST_SLOTS each, open addressing, an entry's number + 1 (0 empty).

SD_ENT		:= 0				; q: entry 0
SD_POOL		:= 8				; q
SD_N		:= 16				; d: entries
SD_IDX0		:= 20				; d: entry 0's index (HPACK 1, QPACK 0)
SD_NAME		:= 24				; q: ST_SLOTS words
SD_PAIR		:= 32				; q: ST_SLOTS words
SD_NID		:= 40				; q: per entry, the first entry with its name (b)
SD_OK		:= 48				; q: a dword, 1 once made
ST_SLOTS	:= 256

; rsi = bytes, edx = their length: eax = a hash of them (CRC32C of the
; first and last eight bytes, or four, or the bytes, and the length).
; Keeps all but rax, rcx, flags.
st_hash:
	mov	eax,edx
	cmp	edx,8
	jb	.lt8
	crc32	rax,qword [rsi]
	crc32	rax,qword [rsi+rdx-8]
	ret
.lt8:
	cmp	edx,4
	jb	.lt4
	crc32	eax,dword [rsi]
	crc32	eax,dword [rsi+rdx-4]
	ret
.lt4:
	test	edx,edx
	jz	.out
	crc32	eax,byte [rsi]
	crc32	eax,byte [rsi+rdx-1]
	mov	ecx,edx
	shr	ecx,1
	crc32	eax,byte [rsi+rcx]
.out:
	ret

; r11 = a descriptor: its lookup tables made. Keeps rbx, rbp, r11-r15.
st_init:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	xor	ebx,ebx				; the entry
.entry:
	cmp	ebx,[r11+SD_N]
	jae	.made
	mov	r12,[r11+SD_ENT]
	lea	r12,[r12+rbx*8]			; its entry
	mov	r13,[r11+SD_POOL]
	; by name: the first with it
	movzx	esi,word [r12]
	add	rsi,r13
	movzx	edx,word [r12+2]
	call	st_hash
	mov	r14d,eax			; the name's hash
	mov	r15,[r11+SD_NAME]
	mov	r8d,eax
.name_probe:
	and	r8d,ST_SLOTS - 1
	movzx	r9d,word [r15+r8*2]
	test	r9d,r9d
	jz	.name_new
	dec	r9d				; an entry there: the same name?
	mov	r10,[r11+SD_ENT]
	lea	r10,[r10+r9*8]
	movzx	edx,word [r12+2]
	cmp	dx,[r10+2]
	jne	.name_next
	movzx	esi,word [r12]
	add	rsi,r13
	movzx	edi,word [r10]
	add	rdi,r13
	push	r8
	push	r9
	call	mem_eq
	pop	r9
	pop	r8
	test	eax,eax
	jz	.name_next
	mov	rax,[r11+SD_NID]		; its group's first
	mov	al,[rax+r9]
	mov	rcx,[r11+SD_NID]
	mov	[rcx+rbx],al
	jmp	.pair
.name_next:
	inc	r8d
	jmp	.name_probe
.name_new:
	lea	eax,[rbx+1]
	mov	[r15+r8*2],ax
	mov	rax,[r11+SD_NID]
	mov	[rax+rbx],bl
.pair:
	; by name and value
	movzx	esi,word [r12+4]
	add	rsi,r13
	movzx	edx,word [r12+6]
	call	st_hash
	crc32	r14d,eax
	mov	r15,[r11+SD_PAIR]
.pair_probe:
	and	r14d,ST_SLOTS - 1
	cmp	word [r15+r14*2],0
	je	.pair_new
	inc	r14d
	jmp	.pair_probe
.pair_new:
	lea	eax,[rbx+1]
	mov	[r15+r14*2],ax
	inc	ebx
	jmp	.entry
.made:
	mov	rax,[r11+SD_OK]
	mov	dword [rax],1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r11 = a descriptor, r12 = a name (lower case), r13d = its length, r14 =
; a value, r15d = its length: eax = the index of the entry with both, -1
; none; edx = the index of the first with the name, -1 none. Keeps rbx,
; rbp, r11-r15.
st_find:
	mov	rax,[r11+SD_OK]
	cmp	dword [rax],0
	jne	@f
	call	st_init
@@:
	push	rbx
	push	rbp
	mov	rsi,r12
	mov	edx,r13d
	call	st_hash
	mov	ebp,eax				; the name's hash
	mov	r8d,eax
.name_probe:
	and	r8d,ST_SLOTS - 1
	mov	r9,[r11+SD_NAME]
	movzx	r9d,word [r9+r8*2]
	test	r9d,r9d
	jz	.none
	dec	r9d
	mov	r10,[r11+SD_ENT]
	lea	r10,[r10+r9*8]
	movzx	edx,word [r10+2]
	cmp	edx,r13d
	jne	.name_next
	movzx	esi,word [r10]
	add	rsi,[r11+SD_POOL]
	mov	rdi,r12
	push	r8
	push	r9
	call	mem_eq
	pop	r9
	pop	r8
	test	eax,eax
	jnz	.named
.name_next:
	inc	r8d
	jmp	.name_probe
.named:
	mov	ebx,r9d				; the name's first entry
	mov	rsi,r14
	mov	edx,r15d
	call	st_hash
	crc32	ebp,eax
.pair_probe:
	and	ebp,ST_SLOTS - 1
	mov	r9,[r11+SD_PAIR]
	movzx	r9d,word [r9+rbp*2]
	test	r9d,r9d
	jz	.name_only
	dec	r9d
	mov	rax,[r11+SD_NID]
	cmp	[rax+r9],bl
	jne	.pair_next
	mov	r10,[r11+SD_ENT]
	lea	r10,[r10+r9*8]
	movzx	edx,word [r10+6]
	cmp	edx,r15d
	jne	.pair_next
	movzx	esi,word [r10+4]
	add	rsi,[r11+SD_POOL]
	mov	rdi,r14
	push	r9
	call	mem_eq
	pop	r9
	test	eax,eax
	jnz	.both
.pair_next:
	inc	ebp
	jmp	.pair_probe
.both:
	lea	eax,[r9+0]
	add	eax,[r11+SD_IDX0]
	lea	edx,[rbx+0]
	add	edx,[r11+SD_IDX0]
	pop	rbp
	pop	rbx
	ret
.name_only:
	mov	eax,-1
	mov	edx,ebx
	add	edx,[r11+SD_IDX0]
	pop	rbp
	pop	rbx
	ret
.none:
	mov	eax,-1
	mov	edx,-1
	pop	rbp
	pop	rbx
	ret
