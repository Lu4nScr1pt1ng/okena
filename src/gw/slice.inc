; `cache 1d slice=4MiB`: a large object (video, a download) kept as slices, each a
; cache entry of its own (key: the object's, and the slice's number), fetched from
; the backend with a Range of that slice. What is kept is what was asked for: a
; client that wants the end of a 4 GB file costs the backend those slices, not 4 GB.
;
; A client never reads the backend on a sliced route. Its answer is put together
; from the cache, slice by slice: the head from its first slice (the object's size
; is in its Content-Range), then each slice's bytes in turn. A slice that is not
; there is fetched by a copy of the request (like a stale entry's refetch) that asks
; for that slice and fills it whole; meanwhile the client's read waits, looking again
; every millisecond. While one slice goes out, the next one is asked for. A backend
; that does not answer a Range with 206 (or answers 200 for an object larger than a
; slice) is not sliced: the copy fills nothing, and the request goes to the backend
; as it came.
;
; Its state, per session, in g_slices (touched only when used).

SC_BASE		:= 0				; 32: the object's key
SC_K		:= 32				; d: the slice being sent
SC_FETCH	:= 36				; d: the last one asked for, + 1
SC_TOTAL	:= 40				; q: the object's size
SC_END		:= 48				; q: the byte after the last one the client wants, -1 all
SC_A		:= 56				; q: the first one it wants
SC_S		:= 64				; d: slice size
SC_POOL		:= 68				; d
SC_HEAD		:= 72				; d: the request head's length (for a copy)
SC_TRIES	:= 76				; d
SC_RBUF		:= 80				; q: a read that waits for its slice: where
SC_RROOM	:= 88				; d: and its room
SC_RK		:= 92				; d: the client asked for a range (206)
SC_PRE		:= 96				; d: the next slice asked for already
SC_REASK	:= 100				; d: times a slice was asked for again (its fetch went)
SL_REASK	:= 3
SC_SIZE		:= 128
FD_SLICE	:= 0x08000000			; FD_SESS: a read that waits for its slice
SL_WAIT_US	:= 1000
SL_TRIES	:= 30000			; 30 s, then the client is cut
SF_SLICE	:= 1 shl 31			; S_FLAGS: its answer is put together from slices
SL_RECENT	:= 64				; slices asked for lately, in a worker
SL_RECENT_US	:= 2000000			; (a copy starts on the loop's next turn: until its
						; fill is there, others would ask again)

bss
	align 8
	g_slices	dq ?
	g_plan_slices	dd ?			; any route slices
	align 8
	g_sl_key:	rb 40
	g_sl_recent	rq 2 * SL_RECENT	; (a key's first 8 bytes, µs) each
	g_sl_rnext	dd ?
end bss

; a worker, at its start
slice_init:
	cmp	dword [g_plan_slices],0
	je	.none
	xor	edi,edi
	mov	esi,[g_sessions]
	imul	rsi,rsi,SC_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	js	.none
	mov	[g_slices],rax
.none:
	ret

; ebx = session: rax = its slice state
macro sl_ctx
	mov	eax,ebx
	imul	rax,rax,SC_SIZE
	add	rax,[g_slices]
end macro

; rsi = an object's key, eax = a slice's number: g_ck = the slice's key. Keeps
; rbx, r12-r15.
sl_key:
	lea	rdi,[g_sl_key]
	mov	ecx,32
	rep	movsb
	mov	[g_sl_key+32],rax
	lea	rsi,[g_sl_key]
	mov	edx,40
	lea	rdi,[g_ck]
	jmp	sha256

; cache_check, a sliced route (r12), g_ck = the object's key, g_c_rk its Range: the
; key becomes the first slice's, and the session's answer is to be put together.
; CF: no state to keep it in (not sliced). Keeps rbx, r12-r15.
slice_prepare:
	cmp	qword [g_slices],0
	je	.no
	sl_ctx
	mov	r8,rax
	lea	rdi,[r8+SC_BASE]
	lea	rsi,[g_ck]
	mov	ecx,32
	rep	movsb
	mov	eax,[r12+CA_SLICE]
	mov	[r8+SC_S],eax
	mov	eax,[g_c_pool]
	mov	[r8+SC_POOL],eax
	mov	eax,[r15+H_INOFF]
	mov	[r8+SC_HEAD],eax
	xor	eax,eax
	mov	[r8+SC_FETCH],eax
	mov	[r8+SC_TRIES],eax
	mov	[r8+SC_PRE],eax
	mov	[r8+SC_RK],eax
	mov	[r8+SC_REASK],eax
	mov	qword [r8+SC_A],0
	mov	qword [r8+SC_END],-1
	mov	eax,[g_c_rk]
	mov	dword [g_c_rk],0		; (slice_fix answers it)
	cmp	eax,1
	je	.ab
	cmp	eax,2
	jne	.first				; (none, or the last n: all of it)
	mov	rax,[g_c_ra]
	mov	[r8+SC_A],rax
	mov	dword [r8+SC_RK],1
	jmp	.first
.ab:
	mov	rax,[g_c_ra]
	mov	[r8+SC_A],rax
	mov	rax,[g_c_rb]
	inc	rax
	mov	[r8+SC_END],rax
	mov	dword [r8+SC_RK],1
.first:
	mov	rax,[r8+SC_A]
	xor	edx,edx
	mov	ecx,[r8+SC_S]
	div	rcx
	mov	[r8+SC_K],eax
	lea	rsi,[r8+SC_BASE]
	call	sl_key
	mov	rdi,[r15+H_BUF]			; what a wait looks for
	lea	rdi,[rdi+HB_CK]
	lea	rsi,[g_ck]
	mov	ecx,32
	rep	movsb
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_SLICE
	clc
	ret
.no:
	stc
	ret

; eax = a slice's number: a copy of the request asks the backend for it, and fills
; it (ebx, r15, the session's slice state). CF: no copy now. Keeps rbx, r12-r15.
slice_fetch:
	push	r12
	mov	r12d,eax
	; asked for a moment ago (by any request of this worker): that copy fills it
	call	qs_clock
	mov	rdx,qword [g_ck]
	xor	ecx,ecx
.recent:
	cmp	[g_sl_recent+rcx*8],rdx
	jne	@f
	mov	rax,[g_qnow]
	sub	rax,[g_sl_recent+rcx*8+8]
	cmp	rax,SL_RECENT_US
	jb	.asked
@@:
	add	ecx,2
	cmp	ecx,2 * SL_RECENT
	jb	.recent
	cmp	dword [g_mir_n],MIR_MAX
	jae	.no
	cmp	dword [g_fd_n],FD_MAX
	jae	.no
	sl_ctx
	mov	edi,[rax+SC_POOL]
	cmp	edi,[g_plan_pools]
	jae	.no
	mov	r9d,[rax+SC_HEAD]
	mov	r10d,r9d
	mov	esi,SF_CREF
	xor	edx,edx
	call	mirror_new
	cmp	eax,NIL
	je	.no
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	lea	ecx,[r12+1]
	mov	[rax+HB_SPLIT],ecx		; (the copy: which slice it asks for)
	mov	eax,[g_sl_rnext]		; remembered
	inc	dword [g_sl_rnext]
	and	eax,SL_RECENT - 1
	shl	eax,1
	mov	rdx,qword [g_ck]
	mov	[g_sl_recent+rax*8],rdx
	mov	rdx,[g_qnow]
	mov	[g_sl_recent+rax*8+8],rdx
.asked:
	sl_ctx
	lea	ecx,[r12+1]
	mov	[rax+SC_FETCH],ecx
	clc
	pop	r12
	ret
.no:
	stc
	pop	r12
	ret

; cache_serve, cd_serve: rdi = past the head of the first slice in HB_UP (r15), eax =
; the slice's length: the client's head, of the whole object or the range it asked
; for, and g_c_skip, g_c_take for this slice. Keeps rbx, r12-r15.
slice_fix:
	push	rax
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_SLICE
	pop	rax
	jz	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r13d,eax			; the slice's length
	mov	r14,rdi				; the head's end
	sl_ctx
	mov	r12,rax
	mov	eax,[r12+SC_K]
	mov	ecx,[r12+SC_S]
	imul	rax,rcx
	mov	rbx,rax				; where the slice begins
	mov	r10,[r15+H_BUF]
	add	r10,HB_UP
	mov	r8,-1				; the object's size, from Content-Range
	; the fields, past the status line and before the last (the cache's Content-Length)
	mov	rsi,r10
@@:
	cmp	rsi,r14
	jae	.bad
	cmp	byte [rsi],10
	je	@f
	inc	rsi
	jmp	@b
@@:
	inc	rsi
	lea	rdx,[r14-3]
@@:
	cmp	rdx,rsi
	jb	.bad
	cmp	byte [rdx],10
	je	@f
	dec	rdx
	jmp	@b
@@:
	inc	rdx
	lea	rdi,[g_rng_tmp]
.line:
	cmp	rsi,rdx
	jae	.copied
	mov	rcx,rsi
@@:
	cmp	byte [rcx],10
	je	@f
	inc	rcx
	jmp	@b
@@:
	inc	rcx				; past its line feed
	call	.is_cr
	jne	.copy
	call	.parse_cr
	jc	.bad
	mov	rsi,rcx
	jmp	.line
.copy:
	push	rcx
	sub	rcx,rsi
	rep	movsb
	pop	rsi
	jmp	.line
.copied:
	mov	r11,rdi
	lea	rax,[g_rng_tmp]
	sub	r11,rax				; the fields' length
	; its size: Content-Range's, or (a first slice that is the whole) its own
	cmp	r8,-1
	jne	@f
	test	rbx,rbx
	jnz	.bad
	mov	r8d,r13d
@@:
	mov	[r12+SC_TOTAL],r8
	mov	rax,[r12+SC_END]
	cmp	rax,r8
	jbe	@f
	mov	rax,r8
@@:
	mov	[r12+SC_END],rax
	mov	rcx,[r12+SC_A]
	cmp	rcx,rax
	jae	.unsatisfiable
	; this slice: from the first byte wanted, to its end or the last wanted
	mov	rdx,rcx
	sub	rdx,rbx
	mov	[g_c_skip],rdx
	mov	r9d,r13d
	sub	r9,rdx				; what it has from there
	mov	rdx,rax
	sub	rdx,rcx				; what is wanted from there
	cmp	r9,rdx
	jbe	@f
	mov	r9,rdx
@@:
	mov	[g_c_take],r9
	; the head
	mov	rdi,r10
	lea	rsi,[.s200]
	cmp	dword [r12+SC_RK],0
	je	@f
	lea	rsi,[.s206]
@@:
	call	.put
	lea	rsi,[g_rng_tmp]
	mov	rcx,r11
	rep	movsb
	cmp	dword [r12+SC_RK],0
	je	@f
	memit_x 'Content-Range: bytes '
	mov	rax,[r12+SC_A]
	call	fmt_u64
	mov	byte [rdi],'-'
	inc	rdi
	mov	rax,[r12+SC_END]
	dec	rax
	call	fmt_u64
	mov	byte [rdi],'/'
	inc	rdi
	mov	rax,[r12+SC_TOTAL]
	call	fmt_u64
	memit_x 13,10
@@:
	memit_x 'Content-Length: '
	mov	rax,[r12+SC_END]
	sub	rax,[r12+SC_A]
	call	fmt_u64
	memit_x 13,10
	jmp	.out
.unsatisfiable:
	mov	rdi,r10
	lea	rsi,[.s416]
	call	.put
	memit_x 'Content-Range: bytes */'
	mov	rax,[r12+SC_TOTAL]
	call	fmt_u64
	memit_x 13,10,'Content-Length: 0',13,10
	jmp	.nothing
.bad:
	; a slice that is not what it should be: nothing more of this object
	mov	rdi,r10
	lea	rsi,[.s502]
	call	.put
	memit_x 'Content-Length: 0',13,10
.nothing:
	mov	qword [g_c_skip],0
	mov	qword [g_c_take],0
	mov	qword [r12+SC_END],0
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
; rsi = NUL-ended: at rdi
.put:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	.put
@@:
	ret
; ZF: the line at rsi is Content-Range (in any case)
.is_cr:
	push	rcx
	push	rsi
	push	rdi
	lea	rdi,[.n_cr]
	mov	ecx,14
@@:
	mov	al,[rsi]
	or	al,0x20
	cmp	al,[rdi]
	jne	@f
	inc	rsi
	inc	rdi
	dec	ecx
	jnz	@b
@@:
	pop	rdi
	pop	rsi
	pop	rcx
	ret
; the Content-Range line at rsi (rcx past it): r8 = the size; CF unless it begins
; where this slice does (rbx)
.parse_cr:
	push	rcx
	push	rdx
	push	rdi
	mov	rdi,rcx				; the end
	add	rsi,14
	call	.spaces
	add	rsi,6				; "bytes "
	call	.num
	jc	.parsed_bad
	cmp	rax,rbx
	jne	.parsed_bad
	cmp	rsi,rdi
	jae	.parsed_bad
	cmp	byte [rsi],'-'
	jne	.parsed_bad
	inc	rsi
	call	.num
	jc	.parsed_bad
	cmp	byte [rsi],'/'
	jne	.parsed_bad
	inc	rsi
	call	.num
	jc	.parsed_bad
	mov	r8,rax
	pop	rdi
	pop	rdx
	pop	rcx
	clc
	ret
.parsed_bad:
	pop	rdi
	pop	rdx
	pop	rcx
	stc
	ret
.spaces:
	cmp	byte [rsi],' '
	jne	@f
	inc	rsi
	jmp	.spaces
@@:
	ret
; digits at rsi (rdi the end): rax. CF: none
.num:
	xor	eax,eax
	xor	r9d,r9d
@@:
	cmp	rsi,rdi
	jae	@f
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	@f
	imul	rax,rax,10
	add	rax,rdx
	inc	r9d
	inc	rsi
	jmp	@b
@@:
	cmp	r9d,1				; CF when none
	ret
.n_cr	db 'content-range:'
.s200	db 'HTTP/1.1 200 OK',13,10,0
.s206	db 'HTTP/1.1 206 Partial Content',13,10,0
.s416	db 'HTTP/1.1 416 Range Not Satisfiable',13,10,0
.s502	db 'HTTP/1.1 502 Bad Gateway',13,10,0

; ---------------------------------------------------- the next slices

; cache_recv of a sliced answer whose slice is spent (rdi = buffer, esi = room):
; the next slice, from memory or disk, or a wait for it
slice_next:
	push	rdi
	push	rsi
	call	cache_unpin			; (the slice it leaves)
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_CE],NIL
	pop	rsi
	pop	rdi
	sl_ctx
	inc	dword [rax+SC_K]
	mov	dword [rax+SC_TRIES],0
	mov	dword [rax+SC_PRE],0
	mov	dword [rax+SC_REASK],0
	mov	[rax+SC_RBUF],rdi
	mov	[rax+SC_RROOM],esi
	; falls through

; ebx, r15: the slice SC_K, if it is there; else it is asked for, and looked for again
slice_try:
	push	r12
	push	r13
	sl_ctx
	mov	r12,rax
	mov	eax,[r12+SC_K]
	mov	ecx,[r12+SC_S]
	imul	rax,rcx
	mov	r13,rax				; where it begins
	cmp	r13,[r12+SC_END]
	jae	.fail				; (nothing more is wanted: never asked)
	lea	rsi,[r12+SC_BASE]
	mov	eax,[r12+SC_K]
	call	sl_key
	call	qs_clock
	call	ce_find
	mov	eax,[g_cf_r]
	cmp	eax,NIL
	je	.disk
	call	pm_purged
	jc	.disk
	mov	eax,[g_cf_r]
	ce_ptr
	mov	rcx,[g_qnow]
	cmp	rcx,[rax+CE_STALE]
	jae	.disk
	; its length: a whole slice, or the object's last
	mov	ecx,[rax+CE_BLEN]
	call	.fits
	jc	.fail
	inc	dword [rax+CE_PIN]
	mov	rdx,[r15+H_BUF]
	mov	ecx,[g_cf_r]
	mov	[rdx+HB_CE],ecx
	mov	ecx,[rax+CE_BODY]
	mov	[rdx+HB_CPOSB],ecx
	mov	dword [rdx+HB_CPOS],0
	mov	[rdx+HB_CLEFT],r9d
	jmp	.go
.disk:
	call	cd_lookup
	test	eax,eax
	jz	.missing
	cmp	eax,3
	jne	@f
	mov	edi,[g_cd_sidx]
	call	cd_unpin
	jmp	.missing
@@:
	mov	ecx,[g_cd_buf+RH_BLEN]
	call	.fits
	jnc	@f
	mov	edi,[g_cd_sidx]
	call	cd_unpin
	jmp	.fail
@@:
	mov	rdx,[r15+H_BUF]
	mov	ecx,[g_cd_sidx]
	or	ecx,CD_MARK
	mov	[rdx+HB_CE],ecx
	mov	rcx,[g_cd_spos]
	mov	[rdx+HB_CPOSB],rcx
	mov	[rdx+HB_CLEFT],r9d
	inc	qword [g_st_cd_hits]
.go:
	mov	rdi,[r12+SC_RBUF]
	mov	esi,[r12+SC_RROOM]
	pop	r13
	pop	r12
	jmp	cache_recv
.missing:
	; asked for already? a fill that went: the backend would not slice it
	mov	eax,[r12+SC_K]
	inc	eax
	cmp	[r12+SC_FETCH],eax
	je	@f
	cmp	dword [g_cf_f],NIL
	jne	.wait				; (a fetch of another request's)
	mov	eax,[r12+SC_K]
	call	slice_fetch
	jc	.fail
	jmp	.wait
@@:
	cmp	dword [g_cf_f],NIL
	jne	.wait
	cmp	dword [g_cf_p],NIL
	jne	.fail				; refused
	; its fetch went with nothing (a backend that could not be reached): again,
	; a few times
	cmp	dword [r12+SC_TRIES],50
	jb	.wait				; (its copy may not have begun yet)
	cmp	dword [r12+SC_REASK],SL_REASK
	jae	.fail
	inc	dword [r12+SC_REASK]
	mov	dword [r12+SC_TRIES],0
	mov	dword [r12+SC_FETCH],0
	mov	eax,[r12+SC_K]
	call	slice_fetch
	jc	.fail
.wait:
	inc	dword [r12+SC_TRIES]
	cmp	dword [r12+SC_TRIES],SL_TRIES
	ja	.fail
	cmp	dword [g_fd_n],FD_MAX
	jae	.fail
	call	qs_clock
	mov	rax,[g_qnow]
	add	rax,SL_WAIT_US
	mov	ecx,[g_fd_n]
	inc	dword [g_fd_n]
	shl	rcx,4
	mov	[g_fd+rcx+FD_AT],rax
	mov	edx,ebx
	or	edx,FD_SLICE
	mov	[g_fd+rcx+FD_SESS],edx
	mov	rdx,[g_fd_next]
	test	rdx,rdx
	jz	@f
	cmp	rax,rdx
	jae	.armed
@@:
	mov	[g_fd_next],rax
.armed:
	push	rcx
	call	session_ptr
	pop	rcx
	mov	eax,[rax+S_GEN]
	mov	[g_fd+rcx+FD_GEN],eax
	pop	r13
	pop	r12
	ret
.fail:
	pop	r13
	pop	r12
	mov	rax,-1				; the client is cut: its length says so
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue
; ecx = a slice's length (r13 its start, r12 the state): CF unless a whole slice or
; the object's last; r9d = what of it is wanted
.fits:
	mov	r9,r13
	add	r9,rcx
	cmp	r9,[r12+SC_TOTAL]
	ja	.no_fit
	cmp	ecx,[r12+SC_S]
	je	@f
	cmp	r9,[r12+SC_TOTAL]
	jne	.no_fit
@@:
	mov	r9,[r12+SC_END]
	sub	r9,r13
	cmp	r9,rcx
	jbe	@f
	mov	r9d,ecx
@@:
	clc
	ret
.no_fit:
	stc
	ret

; fault_flush: a read that waits for its slice (ebx, r15)
slice_poll:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_SLICE
	jz	.none
	jmp	slice_try
.none:
	ret

; the first read of a sliced answer: the next slice is asked for now, if it is
; wanted and not there (ebx, r15). Keeps all.
slice_ahead:
	push	rax
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	sl_ctx
	mov	r12,rax
	cmp	dword [r12+SC_PRE],0
	jne	.out
	mov	dword [r12+SC_PRE],1
	mov	eax,[r12+SC_K]
	inc	eax
	mov	ecx,[r12+SC_S]
	imul	rcx,rax
	cmp	rcx,[r12+SC_END]
	jae	.out
	lea	rsi,[r12+SC_BASE]
	push	rax
	call	sl_key
	call	ce_find
	pop	rax
	cmp	dword [g_cf_r],NIL
	jne	.out
	cmp	dword [g_cf_f],NIL
	jne	.out
	push	rax
	call	cd_lookup
	mov	ecx,eax
	pop	rax
	test	ecx,ecx
	jz	.fetch
	push	rax
	push	rcx
	mov	edi,[g_cd_sidx]
	call	cd_unpin
	pop	rcx
	pop	rax
	cmp	ecx,3
	jne	.out
.fetch:
	inc	eax
	cmp	[r12+SC_FETCH],eax
	je	.out
	dec	eax
	call	slice_fetch
.out:
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
	ret

; ------------------------------------------------- the copy that fetches one

; r15 = a record: rax = its session (in the request writer, ebx counts fields)
macro sl_sess_of_r15
	mov	rax,r15
	sub	rax,[g_http_base]
	shr	rax,H_SHIFT
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
end macro

; http_write_request_head: r15's copy asks for slice HB_SPLIT - 1 (rdi = output):
; its Range. Keeps rbx, r12-r15.
slice_range_emit:
	sl_sess_of_r15
	test	dword [rax+S_FLAGS],SF_CREF
	jz	.none
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_SPLIT]
	test	ecx,ecx
	jz	.none
	dec	ecx
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CACHE]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,CA_SIZE
	mov	edx,[g_caches+rax+CA_SLICE]
	test	edx,edx
	jz	.none
	imul	rcx,rdx				; its first byte
	push	rdx
	push	rcx
	memit_x 'Range: bytes='
	mov	rax,[rsp]
	call	fmt_u64
	mov	byte [rdi],'-'
	inc	rdi
	pop	rax
	pop	rdx
	lea	rax,[rax+rdx-1]
	call	fmt_u64
	memit_x 13,10
.none:
	ret

; http_write_request_head: r14 = a field of the request; ZF when a slice's copy
; leaves it out (the client's Range, and what would make it conditional)
slice_drops:
	sl_sess_of_r15
	test	dword [rax+S_FLAGS],SF_CREF
	jz	.keep
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_SPLIT],0
	je	.keep
	mov	rdi,[r14+HF_NAME]
	mov	esi,[r14+HF_NLEN]
	lea	rdx,[.names]
	call	name_in
	jz	.keep
	xor	eax,eax				; ZF
	ret
.keep:
	or	eax,1				; (ZF clear)
	ret
.names	db 5,'range',8,'if-range',13,'if-none-match',17,'if-modified-since',8,'if-match',19,'if-unmodified-since',0

; cache_refetch, a slice's copy (HB_SPLIT): its key is the slice's
slice_copy_key:
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_SPLIT]
	test	eax,eax
	jz	.none
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_CREF
	jz	.none
	cmp	dword [r12+CA_SLICE],0
	je	.none
	sub	rsp,32
	mov	rdi,rsp
	lea	rsi,[g_ck]
	mov	ecx,32
	rep	movsb
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_SPLIT]
	dec	eax
	mov	rsi,rsp
	call	sl_key
	add	rsp,32
	; its fill begins: no more "asked for a moment ago" for it (that is the fill now)
	mov	rdx,qword [g_ck]
	xor	ecx,ecx
@@:
	cmp	[g_sl_recent+rcx*8],rdx
	jne	.other
	mov	qword [g_sl_recent+rcx*8],0
.other:
	add	ecx,2
	cmp	ecx,2 * SL_RECENT
	jb	@b
.none:
	ret

; cache_head, filling for a slice's copy (r12 = the entry, g_hm the answer): CF
; unless it is the slice: 206 from where the slice begins, or 200 for an object no
; larger than a slice, asked as the first one
slice_answer_ok:
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_SPLIT]
	dec	ecx				; the slice
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CACHE]
	dec	eax
	imul	rax,rax,CA_SIZE
	mov	r8d,[g_caches+rax+CA_SLICE]
	mov	[r12+CE_MAX],r8d		; (a slice is kept up to its size)
	mov	eax,[g_hm+HM_STATUS]
	cmp	eax,200
	jne	.partial
	test	ecx,ecx
	jnz	.no
	clc
	ret
.partial:
	cmp	eax,206
	jne	.no
	imul	rcx,r8				; where it must begin
	push	rcx
	lea	rdi,[.cr]
	mov	esi,13
	call	limit_find
	pop	r10
	test	ecx,ecx
	jz	.no
	lea	rdi,[rsi+rcx]
	cmp	ecx,6
	jb	.no
	add	rsi,6				; "bytes "
	call	slice_fix.num			; (r9: its count of digits)
	jc	.no
	cmp	rax,r10
	jne	.no
	clc
	ret
.no:
	stc
	ret
.cr	db 'content-range'
