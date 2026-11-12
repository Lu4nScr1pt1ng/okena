; Error pages of one's own: `errors 502 503 504 file=/srv/down.html`, on an
; http listener or a route (the route's first, then its listener's), for the
; errors okena answers itself, and with `backend` for those a backend sent
; too (its body is dropped, its status kept). A code is a status (502) or a
; class (5xx). The file is read when the configuration is, at most 16 KiB;
; its type is its extension's (.html, .json, .txt; else HTML). In it,
; {status}, {reason} and {request_id} become this answer's.

EP_LO		:= 0			; d: the statuses it answers
EP_HI		:= 4			; d
EP_OFF		:= 8			; d: in g_ep_store
EP_LEN		:= 12			; d
EP_TYPE		:= 16			; d: 0 HTML, 1 JSON, 2 text
EP_BACKEND	:= 20			; d: a backend's errors too
EP_SIZE		:= 24
MAX_EPS		:= 16384
EP_STORE	:= 16 shl 20
EP_PAGE_MAX	:= 16 shl 10

bss
	align 8
	g_plan_eps	dd ?
	g_ep_used	dd ?
	g_eps		rb MAX_EPS * EP_SIZE
	g_ep_store	rb EP_STORE
end bss

cstring str_key_file, 'file',0
cstring str_ep_backend, 'backend',0

; rdi = a listener's or a route's node: its `errors` lines into g_eps. eax =
; the first, edx = how many (0: none)
compile_errors:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,[g_plan_eps]		; the first
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.done
	lea	rcx,[dir_table + D_SIZE*DIR_ERRORS]
	cmp	[rbx+N_DEF],rcx
	jne	.next
	; the page
	mov	rdi,rbx
	lea	rsi,[str_key_file]
	call	node_option
	test	rax,rax
	jz	.no_file
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	call	ep_read				; r14d, r9d, r15d
	; a backend's errors too?
	xor	r10d,r10d
	mov	rdx,[rbx+N_ARGS]
	mov	r11d,[rbx+N_ARGC]
.flag:
	test	r11d,r11d
	jz	.codes
	cmp	dword [rdx+A_KIND],ARG_KV
	je	@f
	mov	rdi,[rdx+A_VAL]
	mov	esi,[rdx+A_VLEN]
	push	rdx
	push	r9
	push	r10
	push	r11
	lea	rdx,[str_ep_backend]
	call	mem_eq_cstr
	pop	r11
	pop	r10
	pop	r9
	pop	rdx
	test	eax,eax
	jz	@f
	mov	r10d,1
@@:
	add	rdx,A_SIZE
	dec	r11d
	jmp	.flag
.codes:
	; an entry per code
	mov	rdx,[rbx+N_ARGS]
	mov	r11d,[rbx+N_ARGC]
.code:
	test	r11d,r11d
	jz	.next
	cmp	dword [rdx+A_KIND],ARG_KV
	je	.code_next
	mov	rdi,[rdx+A_VAL]
	mov	esi,[rdx+A_VLEN]
	cmp	esi,3
	jne	.maybe_word
	; "backend" is no code: skipped
	movzx	eax,byte [rdi]
	sub	eax,'0'
	cmp	eax,4
	jb	.maybe_word
	cmp	eax,5
	ja	.maybe_word
	imul	r8d,eax,100
	cmp	word [rdi+1],'xx'
	jne	@f
	lea	ecx,[r8+99]
	jmp	.add
@@:
	movzx	eax,byte [rdi+1]
	sub	eax,'0'
	cmp	eax,9
	ja	.bad_code
	imul	eax,eax,10
	add	r8d,eax
	movzx	eax,byte [rdi+2]
	sub	eax,'0'
	cmp	eax,9
	ja	.bad_code
	add	r8d,eax
	mov	ecx,r8d
.add:
	mov	eax,[g_plan_eps]
	cmp	eax,MAX_EPS
	jae	.too_many
	inc	dword [g_plan_eps]
	imul	rax,rax,EP_SIZE
	lea	rax,[g_eps+rax]
	mov	[rax+EP_LO],r8d
	mov	[rax+EP_HI],ecx
	mov	[rax+EP_OFF],r14d
	mov	[rax+EP_LEN],r9d
	mov	[rax+EP_TYPE],r15d
	mov	[rax+EP_BACKEND],r10d
	jmp	.code_next
.maybe_word:
	push	rdx
	push	r9
	push	r10
	push	r11
	lea	rdx,[str_ep_backend]
	call	mem_eq_cstr
	pop	r11
	pop	r10
	pop	r9
	pop	rdx
	test	eax,eax
	jz	.bad_code
.code_next:
	add	rdx,A_SIZE
	dec	r11d
	jmp	.code
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.done:
	mov	eax,r13d
	mov	edx,[g_plan_eps]
	sub	edx,r13d
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad_code:
	call	log_begin
	out_lit 'errors takes statuses from 400 to 599 or classes (4xx, 5xx), `backend`, and file=PAGE'
	jmp	.fail
.no_file:
	call	log_begin
	out_lit 'errors: file= names a page that can be read'
	jmp	.fail
.too_big:
	call	log_begin
	out_lit 'errors: a page is at most 16 KiB (and all of them 1 MiB)'
	jmp	.fail
.too_many:
	call	log_begin
	out_lit 'errors: at most 256 codes with pages'
.fail:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rsi/ecx = a page's path: it, read into g_ep_store. r14d = its place, r9d =
; its length, r15d = its type. Refuses the configuration when it cannot.
ep_read:
	cmp	ecx,4096
	jae	compile_errors.no_file
	lea	rdi,[g_trust_path]
	push	rsi
	push	rcx
	rep	movsb
	mov	byte [rdi],0
	pop	rcx
	pop	rsi
	; its type, by its extension
	xor	r15d,r15d
	cmp	ecx,5
	jb	.read
	mov	eax,[rsi+rcx-5]
	or	eax,0x20202000
	cmp	eax,'.jso'
	jne	@f
	cmp	byte [rsi+rcx-1],'n'
	jne	@f
	mov	r15d,1
	jmp	.read
@@:
	mov	eax,[rsi+rcx-4]
	or	eax,0x20202000
	cmp	eax,'.txt'
	jne	.read
	mov	r15d,2
.read:
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	compile_errors.no_file
	cmp	rdx,EP_PAGE_MAX
	ja	compile_errors.too_big
	mov	ecx,[g_ep_used]
	lea	r8,[rcx+rdx]
	cmp	r8,EP_STORE
	ja	compile_errors.too_big
	mov	r14d,ecx
	mov	[g_ep_used],r8d
	mov	rsi,rax
	lea	rdi,[g_ep_store+rcx]
	mov	r9,rdx
	mov	rcx,rdx
	rep	movsb
	ret

; rsi/ecx = a page's path: eax = a new entry of no status range for it
errpage_load:
	push	r14
	push	r15
	call	ep_read
	mov	eax,[g_plan_eps]
	cmp	eax,MAX_EPS
	jae	compile_errors.too_many
	inc	dword [g_plan_eps]
	imul	rdx,rax,EP_SIZE
	lea	rdx,[g_eps+rdx]
	mov	dword [rdx+EP_LO],0
	mov	dword [rdx+EP_HI],0
	mov	[rdx+EP_OFF],r14d
	mov	[rdx+EP_LEN],r9d
	mov	[rdx+EP_TYPE],r15d
	mov	dword [rdx+EP_BACKEND],0
	pop	r15
	pop	r14
	ret

; ------------------------------------------------------------------ serving

; ebx = session, r15 = record, eax = a status, ecx = 1 when a backend sent
; it: rsi = its page entry (the route's first, then the listener's), or 0.
; Keeps rax, rbx, rdi, r12-r15.
errpage_find:
	mov	rsi,[g_ep_force]		; (maintenance: its page, once)
	test	rsi,rsi
	jz	@f
	mov	qword [g_ep_force],0
	ret
@@:
	push	rdi
	push	rax
	mov	r9d,ecx
	mov	edx,[r15+H_ACT]
	test	edx,edx
	jz	.listener
	dec	edx
	imul	rdx,rdx,RA_SIZE
	mov	r8d,[g_acts+rdx+RA_EFIRST]
	mov	ecx,[g_acts+rdx+RA_ECOUNT]
	call	.look
	jnz	.out
.listener:
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	r8d,[g_listeners+rax+LS_EFIRST]
	mov	ecx,[g_listeners+rax+LS_ECOUNT]
	call	.look
.out:
	pop	rax
	pop	rdi
	ret
; r8d/ecx = entries, [rsp+16] = the status, r9d = from a backend: rsi = the
; one, ZF clear; or rsi = 0, ZF
.look:
	mov	eax,[rsp+8]
	xor	esi,esi
.e:
	test	ecx,ecx
	jz	.none
	imul	rdi,r8,EP_SIZE
	lea	rdi,[g_eps+rdi]
	inc	r8d
	dec	ecx
	cmp	eax,[rdi+EP_LO]
	jb	.e
	cmp	eax,[rdi+EP_HI]
	ja	.e
	test	r9d,r9d
	jz	.it
	cmp	dword [rdi+EP_BACKEND],0
	je	.e
.it:
	mov	rsi,rdi
	test	rsi,rsi				; (ZF clear)
	ret
.none:
	xor	esi,esi
	test	esi,esi
	ret

rodata
	ep_types	db 'text/html; charset=utf-8',0,'application/json',0,'text/plain; charset=utf-8',0
end rodata

; ebx = session, r15 = record, eax = status, rsi = its page: the answer,
; written and sent (as http_error, which comes here: the connection closes
; after it). With [g_ep_retry] seconds, a Retry-After.
http_error_page:
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,eax
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 '
	mov	eax,r13d
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,r13d
	call	http_reason
	call	fmt_cstr
	memit_x 13,10,'Content-Type: '
	lea	rsi,[ep_types]
	mov	eax,[r12+EP_TYPE]
	call	st_word
	call	fmt_cstr
	memit_x 13,10,'Cache-Control: no-store',13,10,'Connection: close',13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	call	cors_emit
	mov	eax,[g_ep_retry]
	test	eax,eax
	jz	@f
	push	rax
	memit_x 'Retry-After: '
	pop	rax
	call	fmt_u64
	memit_x 13,10
	mov	dword [g_ep_retry],0
@@:
	memit_x 'Content-Length: '
	xor	ecx,ecx				; measure, then write
	call	.body
	mov	rax,rdx
	call	fmt_u64
	memit_x 13,10,13,10
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	@f				; (a HEAD: the head alone)
	mov	ecx,1
	call	.body
@@:
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_OUT]
	sub	rdi,rax
	mov	esi,edi
	mov	ecx,SIDE_CLIENT
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	pop	r13
	pop	r12
	jmp	h_send
; ecx = 0 to measure (rdx = its length), 1 to write it at rdi
.body:
	push	rbx
	push	r14
	mov	r14d,ecx
	mov	eax,[r12+EP_OFF]
	lea	rsi,[g_ep_store+rax]
	mov	ebx,[r12+EP_LEN]
	xor	edx,edx
.ch:
	test	ebx,ebx
	jz	.end
	cmp	byte [rsi],'{'
	jne	.plain
	; {status} {reason} {request_id}
	cmp	ebx,8
	jb	.plain
	cmp	dword [rsi],'{sta'
	jne	@f
	cmp	dword [rsi+4],'tus}'
	jne	@f
	add	rsi,8
	sub	ebx,8
	push	rsi
	push	rdx
	lea	rsi,[g_ep_tmp]
	push	rdi
	mov	rdi,rsi
	mov	eax,r13d
	call	fmt_u64
	mov	rcx,rdi
	pop	rdi
	lea	rsi,[g_ep_tmp]
	sub	rcx,rsi
	pop	rdx
	call	.put
	pop	rsi
	jmp	.ch
@@:
	cmp	dword [rsi],'{rea'
	jne	@f
	cmp	dword [rsi+4],'son}'
	jne	@f
	add	rsi,8
	sub	ebx,8
	push	rsi
	mov	eax,r13d
	push	rdx
	call	http_reason
	pop	rdx
	xor	ecx,ecx
.rlen:
	cmp	byte [rsi+rcx],0
	je	.rput
	inc	ecx
	jmp	.rlen
.rput:
	call	.put
	pop	rsi
	jmp	.ch
@@:
	cmp	ebx,12
	jb	.plain
	cmp	dword [rsi],'{req'
	jne	.plain
	cmp	dword [rsi+4],'uest'
	jne	.plain
	cmp	dword [rsi+8],'_id}'
	jne	.plain
	add	rsi,12
	sub	ebx,12
	push	rsi
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	call	.put
	pop	rsi
	jmp	.ch
.plain:
	test	r14d,r14d
	jz	@f
	mov	al,[rsi]
	mov	[rdi],al
	inc	rdi
@@:
	inc	rsi
	inc	edx
	dec	ebx
	jmp	.ch
.end:
	pop	r14
	pop	rbx
	ret
; rsi/ecx = text: counted, and written when writing
.put:
	add	edx,ecx
	test	r14d,r14d
	jz	@f
	rep	movsb
@@:
	ret

bss
	g_ep_tmp	rb 24
	g_ep_retry	dd ?		; seconds for a Retry-After (maintenance), 0 none
	align 8
	g_ep_force	dq ?		; a page that comes first (maintenance), 0 none
end bss
