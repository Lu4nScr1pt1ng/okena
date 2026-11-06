; `redirects FILE code=301` on a route: thousands of old paths in a file, one lookup
; each. Lines are `/old /new` or `/old https://else/ 302`; # begins a comment. The
; path is the normalized one, exact, with no query, and the client's query goes along.
; What is not in the file goes on through the route.
;
; `hold 10s` on a route: when no backend can be connected to, the request waits for
; one, for that long, instead of a 502: a pool that is restarting. Nothing has reached
; a backend when a connection fails, so any request can wait, a POST with its body too.
; A held request tries every HOLD_POLL, ejected servers included (server_pick's last
; pass), so a backend that is back is found at once. Past that time, the 502.

MAX_RMAPS	:= 64
RM_TAB		:= 0				; q
RM_MASK		:= 8				; d
RM_CODE		:= 12				; d
RM_SIZE		:= 16
RE_PATH		:= 0				; q
RE_TGT		:= 8				; q
RE_PLEN		:= 16				; d
RE_TLEN		:= 20				; d
RE_CODE		:= 24				; d
RE_SIZE		:= 32

HOLD_POLL	:= 100000			; µs
FD_HOLD		:= 0x10000000			; FD_SESS: a held request tries again

bss
	align 8
	g_rmaps:	rb RM_SIZE * MAX_RMAPS
	g_plan_rmaps	dd ?
	g_rm_act:	rb RA_SIZE		; what http_redirect reads, for one answer
end bss

; rsi = bytes, ecx = how many: eax = their hash. Keeps r12-r15, rbx.
rm_hash:
	mov	eax,0x811C9DC5
	test	ecx,ecx
	jz	.out
.b:
	movzx	edx,byte [rsi]
	xor	eax,edx
	imul	eax,eax,16777619
	inc	rsi
	dec	ecx
	jnz	.b
.out:
	ret

; eax = the map + 1, g_npath: rax = its entry, 0 none. Keeps rbx, rdx?, r12-r15.
rm_lookup:
	push	r12
	dec	eax
	shl	rax,4
	lea	r12,[g_rmaps+rax]
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	call	rm_hash
	mov	r8d,eax
.probe:
	and	r8d,[r12+RM_MASK]
	imul	rax,r8,RE_SIZE
	add	rax,[r12+RM_TAB]
	cmp	qword [rax+RE_PATH],0
	je	.none
	mov	ecx,[rax+RE_PLEN]
	cmp	ecx,[g_npath_len]
	jne	.next
	mov	rdi,[rax+RE_PATH]
	lea	rsi,[g_npath]
	repe	cmpsb
	je	.found
.next:
	inc	r8d
	jmp	.probe
.none:
	xor	eax,eax
.found:
	mov	r8,rax
	pop	r12
	ret

; rdx = the action's offset, g_npath: CF when the map has this path, rdx then the
; offset of a one-time action for http_redirect. Keeps rax? no; rcx, r12-r15, rbx.
rm_check:
	push	rcx
	push	rdx
	mov	eax,[g_acts+rdx+RA_RMAP]
	call	rm_lookup
	pop	rdx
	pop	rcx
	test	r8,r8
	jz	.no
	mov	eax,[r8+RE_CODE]
	mov	[g_rm_act+RA_CODE],eax
	mov	rax,[r8+RE_TGT]
	mov	[g_rm_act+RA_TGT],rax
	mov	eax,[r8+RE_TLEN]
	mov	[g_rm_act+RA_TLEN],eax
	lea	rdx,[g_rm_act]
	lea	rax,[g_acts]
	sub	rdx,rax
	stc
	ret
.no:
	clc
	ret

; r12 = a route's node, r13 = the action: `redirects`
compile_rmap:
	push	rbx
	push	r14
	push	r15
	push	rbp
	mov	rdi,r12
	mov	ecx,DIR_REDIRECTS
	call	find_child
	test	rax,rax
	jz	.out
	mov	rbx,rax
	mov	eax,[g_plan_rmaps]
	cmp	eax,MAX_RMAPS
	jae	plan_bad_rmap
	inc	dword [g_plan_rmaps]
	lea	ecx,[rax+1]
	mov	[r13+RA_RMAP],ecx
	shl	rax,4
	lea	rbp,[g_rmaps+rax]
	mov	dword [rbp+RM_CODE],301
	mov	rdi,rbx
	lea	rsi,[.k_code]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	edi,eax
	call	.is_code
	jnz	plan_bad_rmap
	mov	[rbp+RM_CODE],eax
@@:
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_rmap
	mov	rsi,[rax+A_VAL]
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_rmap
	mov	r14,rax				; the text
	mov	edx,edx
	lea	r15,[rax+rdx]			; its end
	; how many lines: the table has room for twice that
	mov	rsi,r14
	mov	ecx,2
.count:
	cmp	rsi,r15
	jae	.counted
	cmp	byte [rsi],10
	jne	@f
	inc	ecx
@@:
	inc	rsi
	jmp	.count
.counted:
	cmp	ecx,1 shl 22
	ja	plan_bad_rmap
	add	ecx,ecx
	bsr	ecx,ecx
	inc	ecx
	mov	eax,1
	shl	eax,cl
	lea	ecx,[rax-1]
	mov	[rbp+RM_MASK],ecx
	imul	rsi,rax,RE_SIZE
	push	rsi
	lea	rdi,[g_ar_text]
	call	arena_alloc
	pop	rcx
	mov	[rbp+RM_TAB],rax
	mov	rdi,rax
	xor	eax,eax
	rep	stosb
	; each line
	mov	rsi,r14
.line:
	cmp	rsi,r15
	jae	.out
	call	.blanks
	cmp	rsi,r15
	jae	.out
	mov	al,[rsi]
	cmp	al,10
	je	.eol
	cmp	al,'#'
	je	.comment
	cmp	al,'/'
	jne	plan_bad_rmap
	mov	r8,rsi				; the path
	call	.word
	mov	r9,rcx
	test	r9,r9
	jz	plan_bad_rmap
	call	.blanks
	mov	r10,rsi				; the target
	call	.word
	mov	r11,rcx
	test	r11,r11
	jz	plan_bad_rmap
	mov	edi,[rbp+RM_CODE]
	call	.blanks
	cmp	rsi,r15
	jae	.put
	mov	al,[rsi]
	cmp	al,10
	je	.put
	cmp	al,'#'
	je	.put
	; a code of its own
	push	r8
	push	r9
	push	r10
	push	r11
	mov	rdx,rsi
	call	.word
	push	rsi
	mov	rdi,rdx
	mov	esi,ecx
	call	parse_decimal
	pop	rsi
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	mov	edi,eax
	call	.is_code
	jnz	plan_bad_rmap
.put:
	; `{*}` means something to http_redirect, and nothing here
	mov	rax,r10
	mov	rcx,r11
.brace:
	cmp	byte [rax],'{'
	je	plan_bad_rmap
	inc	rax
	dec	rcx
	jnz	.brace
	push	rsi
	push	rdi
	mov	rsi,r8
	mov	ecx,r9d
	call	rm_hash
	pop	rdi
	pop	rsi
	mov	edx,eax
.slot:
	and	edx,[rbp+RM_MASK]
	imul	rax,rdx,RE_SIZE
	add	rax,[rbp+RM_TAB]
	cmp	qword [rax+RE_PATH],0
	je	.free
	; the same path twice is a mistake in the file
	cmp	[rax+RE_PLEN],r9d
	jne	.taken
	push	rsi
	push	rdi
	mov	rdi,[rax+RE_PATH]
	mov	rsi,r8
	mov	ecx,r9d
	repe	cmpsb
	pop	rdi
	pop	rsi
	je	plan_bad_rmap
.taken:
	inc	edx
	jmp	.slot
.free:
	mov	[rax+RE_PATH],r8
	mov	[rax+RE_TGT],r10
	mov	[rax+RE_PLEN],r9d
	mov	[rax+RE_TLEN],r11d
	mov	[rax+RE_CODE],edi
.comment:
	cmp	rsi,r15
	jae	.out
	cmp	byte [rsi],10
	je	.eol
	inc	rsi
	jmp	.comment
.eol:
	inc	rsi
	jmp	.line
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	rbx
	ret
.blanks:
	cmp	rsi,r15
	jae	.blanks_end
	cmp	byte [rsi],' '
	je	@f
	cmp	byte [rsi],9
	je	@f
	cmp	byte [rsi],13
	jne	.blanks_end
@@:
	inc	rsi
	jmp	.blanks
.blanks_end:
	ret
; rsi at a word: rsi past it, rcx = its length
.word:
	mov	rcx,rsi
.w:
	cmp	rsi,r15
	jae	.w_end
	mov	al,[rsi]
	cmp	al,' '
	jbe	.w_end
	inc	rsi
	jmp	.w
.w_end:
	neg	rcx
	add	rcx,rsi
	ret
; edi = a code: eax = it, ZF when it is one a redirect may be
.is_code:
	mov	eax,edi
	cmp	eax,301
	je	.yes
	cmp	eax,302
	je	.yes
	cmp	eax,303
	je	.yes
	cmp	eax,307
	je	.yes
	cmp	eax,308
.yes:
	ret
cstring .k_code, 'code',0

plan_bad_rmap:
	call	log_begin
	out_lit 'redirects: a file of `/path target [code]` lines, each path once, no {*}; code= is 301, 302, 303, 307 or 308; at most 64 files'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ebx: no backend could be connected to. CF: it waits, and will try again.
hold_wait:
	h_rec
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	rcx,[g_acts+rax+RA_HOLD]
	test	rcx,rcx
	jz	.no
	test	dword [r15+H_FLAGS],HX_STARTED or HX_MIRROR
	jnz	.no
	cmp	dword [g_fd_n],FD_MAX
	jae	.no
	push	rcx
	call	qs_clock
	pop	rcx
	mov	rdx,[r15+H_BUF]
	mov	rax,[rdx+HB_HOLD]
	test	rax,rax
	jnz	@f
	mov	rax,[g_qnow]
	add	rax,rcx
	mov	[rdx+HB_HOLD],rax
@@:
	cmp	rax,[g_qnow]
	jbe	.no
	call	h_upclose			; (as http_retry_fresh: what the try left)
	h_rec
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	mov	eax,HOLD_POLL
	call	fault_hold
	or	dword [g_fd+rcx+FD_SESS],FD_HOLD
	stc
	ret
.no:
	clc
	ret

; its time: ebx, r15
hold_again:
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.none
	call	session_ptr
	mov	dword [rax+S_TRIES],0
	and	dword [r15+H_FLAGS],not (HX_NOPOOL or HX_AVOID)
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect
.none:
	ret

; r12 = a route's node, r13 = the action: `hold`
compile_hold:
	mov	rdi,r12
	mov	ecx,DIR_HOLD
	call	find_child
	test	rax,rax
	jz	.none
	mov	rdi,rax
	call	node_duration
	mov	[r13+RA_HOLD],rax
.none:
	ret
