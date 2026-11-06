; `geoip FILE` in the `okena` block: a MaxMind .mmdb country database, for
; `match client.country=BR,PT` and `allow country:BR` / `deny country:RU`.
;
; The file is a binary tree over the address bits, then a data section of typed values.
; It is read at load into memory that workers share by forking, and it is walked for
; requests: every read is checked against the file's end and decoding nests no deeper
; than GEO_DEPTH, so that a corrupt file gives no country, and nothing worse.

GEO_DEPTH	:= 8
GT_POINTER	:= 1
GT_STRING	:= 2
GT_MAP		:= 7
GT_ARRAY	:= 11
GT_BOOL		:= 14

bss
	align 8
	g_geo_base	dq ?			; the file, 0 none
	g_geo_end	dq ?
	g_geo_data	dq ?			; its data section
	g_geo_dbase	dq ?			; what a pointer counts from
	g_geo_tree	dq ?			; the tree's bytes
	g_geo_nodes	dd ?
	g_geo_rec	dd ?			; bits in a record
	g_geo_ver	dd ?			; 4 or 6
	g_geo_v4	dd ?			; the node where IPv4 starts in an IPv6 tree
end bss

; rsi = a value: eax = its type, rcx = its size (a pointer: where it points), rsi = its
; payload (a pointer: what follows it). CF: past the end. Keeps r8-r15, rbx.
geo_head:
	cmp	rsi,[g_geo_end]
	jae	.bad
	movzx	edx,byte [rsi]
	inc	rsi
	mov	eax,edx
	shr	eax,5
	jnz	.base
	; extended: the type is in the next byte
	cmp	rsi,[g_geo_end]
	jae	.bad
	movzx	eax,byte [rsi]
	inc	rsi
	add	eax,7
.base:
	cmp	eax,GT_POINTER
	je	.pointer
	mov	ecx,edx
	and	ecx,31
	cmp	ecx,29
	jb	.sized
	lea	rdi,[rsi+3]
	cmp	rdi,[g_geo_end]
	ja	.bad
	cmp	ecx,29
	jne	@f
	movzx	ecx,byte [rsi]
	add	ecx,29
	inc	rsi
	jmp	.sized
@@:
	cmp	ecx,30
	jne	@f
	movzx	ecx,word [rsi]
	xchg	cl,ch
	add	ecx,285
	add	rsi,2
	jmp	.sized
@@:
	mov	ecx,[rsi-1]			; (three bytes after the control byte)
	bswap	ecx
	and	ecx,0xFFFFFF
	add	ecx,65821
	add	rsi,3
.sized:
	clc
	ret
.pointer:
	mov	ecx,edx
	shr	ecx,3
	and	ecx,3
	and	edx,7
	lea	rdi,[rsi+rcx+1]
	cmp	rdi,[g_geo_end]
	ja	.bad
	cmp	ecx,1
	ja	.p2
	je	.p1
	movzx	ecx,byte [rsi]
	shl	edx,8
	or	ecx,edx
	jmp	.p_end
.p1:
	movzx	ecx,word [rsi]
	xchg	cl,ch
	shl	edx,16
	or	ecx,edx
	add	ecx,2048
	jmp	.p_end
.p2:
	cmp	ecx,3
	je	.p3
	mov	ecx,[rsi-1]
	bswap	ecx
	and	ecx,0xFFFFFF
	shl	edx,24
	or	ecx,edx
	add	ecx,526336
	jmp	.p_end
.p3:
	mov	ecx,[rsi]
	bswap	ecx
.p_end:
	mov	rsi,rdi
	clc
	ret
.bad:
	stc
	ret

; rsi = a value, a pointer or not: eax, rcx, rsi of what it is
geo_value:
	call	geo_head
	jc	.out
	cmp	eax,GT_POINTER
	jne	.ok
	mov	eax,ecx
	mov	rsi,[g_geo_dbase]
	add	rsi,rax
	call	geo_head
	jc	.out
	cmp	eax,GT_POINTER			; (it may not point to a pointer)
	je	.bad
.ok:
	clc
.out:
	ret
.bad:
	stc
	ret

; rsi = a value, edi = how deep: rsi = what follows it. CF: not to be read.
geo_skip:
	cmp	edi,GEO_DEPTH
	ja	.bad
	call	geo_head_keep
	jc	.bad
	cmp	eax,GT_POINTER
	je	.done
	cmp	eax,GT_BOOL
	je	.done
	cmp	eax,GT_MAP
	je	.map
	cmp	eax,GT_ARRAY
	je	.items
	add	rsi,rcx				; the size is in bytes
	cmp	rsi,[g_geo_end]
	ja	.bad
.done:
	clc
	ret
.map:
	add	rcx,rcx
.items:
	test	rcx,rcx
	jz	.done
	push	rcx
	push	rdi
	inc	edi
	call	geo_skip
	pop	rdi
	pop	rcx
	jc	.bad
	dec	rcx
	jmp	.items
.bad:
	stc
	ret
geo_head_keep:
	push	rdi
	call	geo_head
	pop	rdi
	ret

; rsi = a map, r8 = a key, r9d = its length: rsi = its value. CF: not in it.
geo_get:
	push	rbx
	push	r12
	call	geo_value
	jc	.out
	cmp	eax,GT_MAP
	jne	.no
	mov	ebx,ecx				; pairs
.pair:
	test	ebx,ebx
	jz	.no
	dec	ebx
	; the key; if it is a pointer, the cursor stays here
	call	geo_head
	jc	.out
	mov	r12,rsi
	cmp	eax,GT_POINTER
	jne	.direct
	mov	eax,ecx
	mov	rsi,[g_geo_dbase]
	add	rsi,rax
	call	geo_head
	jc	.out
	jmp	.key
.direct:
	mov	edx,ecx
	add	r12,rdx				; past it
.key:
	cmp	eax,GT_STRING
	jne	.no
	cmp	ecx,r9d
	jne	.other
	lea	rax,[rsi+rcx]
	cmp	rax,[g_geo_end]
	ja	.no
	mov	rdi,r8
	repe	cmpsb
	jne	.other
	mov	rsi,r12
	clc
	jmp	.out
.other:
	mov	rsi,r12
	xor	edi,edi
	call	geo_skip
	jnc	.pair
	jmp	.out
.no:
	stc
.out:
	pop	r12
	pop	rbx
	ret

; eax = a node, ecx = 0 or 1: eax = that record. CF past the end.
geo_record:
	mov	r8d,[g_geo_rec]
	mov	r9d,r8d
	shr	r9d,2				; bytes for two: rec * 2 / 8
	mov	r10,rax
	imul	r10,r9
	add	r10,[g_geo_base]
	lea	r11,[r10+r9]
	cmp	r11,[g_geo_end]
	ja	.bad
	cmp	r8d,28
	je	.r28
	cmp	r8d,32
	je	.r32
	; 24: three bytes each
	lea	r9d,[rcx+rcx*2]
	movzx	eax,byte [r10+r9]
	shl	eax,16
	movzx	edx,byte [r10+r9+1]
	shl	edx,8
	or	eax,edx
	movzx	edx,byte [r10+r9+2]
	or	eax,edx
	clc
	ret
.r28:
	movzx	edx,byte [r10+3]
	test	ecx,ecx
	jnz	.right
	shr	edx,4
	mov	eax,[r10]			; (from the node on: it may be the file's start)
	bswap	eax
	shr	eax,8
	jmp	.mid
.right:
	and	edx,15
	mov	eax,[r10+3]
	bswap	eax
	and	eax,0xFFFFFF
.mid:
	shl	edx,24
	or	eax,edx
	clc
	ret
.r32:
	mov	eax,[r10+rcx*4]
	bswap	eax
	clc
	ret
.bad:
	stc
	ret

; rsi = the address, edx = 4 or 6: eax = its country as two bytes, 0 none.
; Keeps rbx, r12-r15.
geo_country:
	cmp	qword [g_geo_base],0
	je	.none
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13d,32
	cmp	edx,6
	jne	@f
	mov	r13d,128
	cmp	dword [g_geo_ver],4
	je	.not
@@:
	xor	eax,eax
	cmp	edx,4
	jne	@f
	mov	eax,[g_geo_v4]
@@:
	xor	r14d,r14d			; the bit
.bit:
	cmp	r14d,r13d
	jae	.not
	mov	ecx,r14d
	shr	ecx,3
	movzx	edx,byte [r12+rcx]
	mov	ecx,r14d
	and	ecx,7
	neg	ecx
	add	ecx,7
	shr	edx,cl
	and	edx,1
	mov	ecx,edx
	call	geo_record
	jc	.not
	inc	r14d
	cmp	eax,[g_geo_nodes]
	jb	.bit
	je	.not
	; the data
	sub	eax,[g_geo_nodes]
	sub	eax,16
	jc	.not
	mov	rsi,[g_geo_data]
	mov	rcx,rsi
	mov	[g_geo_dbase],rcx
	add	rsi,rax
	lea	r8,[.n_country]
	mov	r9d,7
	call	geo_get
	jc	.not
	lea	r8,[.n_iso]
	mov	r9d,8
	call	geo_get
	jc	.not
	call	geo_value
	jc	.not
	cmp	eax,GT_STRING
	jne	.not
	cmp	ecx,2
	jne	.not
	lea	rax,[rsi+2]
	cmp	rax,[g_geo_end]
	ja	.not
	movzx	eax,word [rsi]
	jmp	.out
.not:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
.none:
	xor	eax,eax
	ret
.n_country db 'country'
.n_iso	db 'iso_code'

; rdi = `geoip`'s node: the file, read and looked over
compile_geoip:
	push	rbx
	push	r12
	push	r13
	mov	rax,[rdi+N_ARGS]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_geoip
	mov	rsi,[rax+A_VAL]
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_geoip
	mov	edx,edx
	cmp	rdx,1024
	jb	plan_bad_geoip
	mov	[g_geo_base],rax
	lea	rcx,[rax+rdx]
	mov	[g_geo_end],rcx
	; the metadata: after the last marker, in the last 128 KiB
	lea	rbx,[rcx-14]
	lea	r12,[rax]
	cmp	rdx,131072
	jbe	.search
	lea	r12,[rcx-131072]
.search:
	cmp	rbx,r12
	jb	plan_bad_geoip
	lea	rsi,[.marker]
	mov	rdi,rbx
	mov	ecx,14
	repe	cmpsb
	je	.found
	dec	rbx
	jmp	.search
.found:
	add	rbx,14
	mov	[g_geo_dbase],rbx
	mov	rsi,rbx
	lea	r8,[.k_nodes]
	mov	r9d,10
	call	.number
	mov	[g_geo_nodes],eax
	mov	rsi,rbx
	lea	r8,[.k_rec]
	mov	r9d,11
	call	.number
	cmp	eax,24
	je	@f
	cmp	eax,28
	je	@f
	cmp	eax,32
	jne	plan_bad_geoip
@@:
	mov	[g_geo_rec],eax
	mov	rsi,rbx
	lea	r8,[.k_ver]
	mov	r9d,10
	call	.number
	cmp	eax,4
	je	@f
	cmp	eax,6
	jne	plan_bad_geoip
@@:
	mov	[g_geo_ver],eax
	; the tree must fit before the data
	mov	eax,[g_geo_rec]
	shr	eax,2
	mov	ecx,[g_geo_nodes]
	imul	rax,rcx
	test	rax,rax
	jz	plan_bad_geoip
	mov	[g_geo_tree],rax
	add	rax,16
	add	rax,[g_geo_base]
	mov	[g_geo_data],rax
	cmp	rax,[g_geo_end]
	jae	plan_bad_geoip
	; where IPv4 starts: 96 zero bits down
	mov	dword [g_geo_v4],0
	cmp	dword [g_geo_ver],6
	jne	.done
	xor	r13d,r13d
	xor	eax,eax
.down:
	cmp	r13d,96
	jae	.v4
	xor	ecx,ecx
	call	geo_record
	jc	plan_bad_geoip
	inc	r13d
	cmp	eax,[g_geo_nodes]
	jb	.down
	; (a tree with nothing for IPv4: a node past them all, that finds nothing)
	mov	eax,[g_geo_nodes]
	dec	eax
.v4:
	mov	[g_geo_v4],eax
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi = the metadata map, r8/r9d a key: eax = its number. A uint up to 32 bits.
.number:
	call	geo_get
	jc	plan_bad_geoip
	call	geo_value
	jc	plan_bad_geoip
	cmp	eax,5
	je	@f
	cmp	eax,6
	jne	plan_bad_geoip
@@:
	cmp	ecx,4
	ja	plan_bad_geoip
	xor	eax,eax
.byte:
	test	ecx,ecx
	jz	.number_end
	shl	eax,8
	mov	al,[rsi]
	inc	rsi
	dec	ecx
	jmp	.byte
.number_end:
	ret
.marker	db 0xAB,0xCD,0xEF,'MaxMind.com'
.k_nodes db 'node_count'
.k_rec	db 'record_size'
.k_ver	db 'ip_version'

plan_bad_geoip:
	call	log_begin
	out_lit 'geoip needs a .mmdb file okena can read: up to 64 MiB, records of 24, 28 or 32 bits'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
