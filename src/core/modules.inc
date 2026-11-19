; Handler modules: code assembled into okena itself, as nginx's modules are
; compiled into nginx, for answers no configuration can give.
;
;   make MODULES="/path/a.inc /path/b.inc"
;
; A module is a file of this same assembly, included after everything else
; (so it may call any of okena's functions). It declares what it offers:
;
;   okena_handler 'name', function      ; a route's `handler name [ARG]`
;   okena_init function                 ; run by the supervisor before the
;                                       ; workers start, and on each reload
;
; An init function reads what it needs (files, the environment) into the
; module's own memory, which the workers inherit; it returns CF to stop okena
; (it says why first). A handler is called in a worker for each request of
; its routes, over HTTP/1.1, HTTP/2 or HTTP/3, with:
;
;   rdi = where its body goes, esi = room there (MOD_OUT_CAP)
;   rdx = the request's body, ecx = its length (Content-Length or chunked,
;         decoded; HTTP/1.1 only: an HTTP/2 or HTTP/3 request's body is not
;         read and ecx is 0)
;   r8  = the route's ARG, r9d = its length (0 when it has none)
;   g_hm = the parsed request: HM_METHOD/HM_MLEN, HM_TARGET/HM_TLEN/HM_PLEN
;         (the path before any '?'), its fields (limit_find finds one)
;
; and returns eax = the status (100..599), edx = its body's length, rsi = its
; Content-Type (a NUL-ended string, 0 for text/plain). It keeps rbx, rbp and
; r12-r15, and must not block: it runs in the event loop.

MOD_OUT_CAP	:= H_OUT_CAP - 1024		; (the head's room in OUT)
HS_MBODY	:= 56				; H_STATE: the request's body read for a handler

MOD_HEAD = 0
MOD_IHEAD = 0

; okena_handler 'name', function
macro okena_handler name*, fn*
	local e
	rodata
		align 8
		e:	dq MOD_HEAD, fn
			db name, 0
	end rodata
	MOD_HEAD = e
end macro

; okena_init function
macro okena_init fn*
	local e
	rodata
		align 8
		e:	dq MOD_IHEAD, fn
	end rodata
	MOD_IHEAD = e
end macro

MH_NEXT		:= 0
MH_FN		:= 8
MH_NAME		:= 16

bss
	align 8
	g_mod_act	dq ?			; the route's action, this request
	g_mod_bptr	dq ?
	g_mod_blen	dd ?
	g_mod_used	dd ?			; the body's bytes as they came (framing too)
	g_mod_body	rb H_IN_CAP		; a chunked body, undone
	g_mod_out	rb MOD_OUT_CAP + 64
end bss

; ------------------------------------------------------------ compiling

; r12 = a route node, r13 = its action: `handler NAME [ARG]` into RA_MOD and
; RA_MARG. Keeps rbx, r12-r15.
mod_compile:
	mov	rdi,r12
	mov	ecx,DIR_HANDLER
	call	find_child
	test	rax,rax
	jz	.out
	push	rbx
	mov	rbx,rax
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	mod_find			; rax = its function, 0 none
	test	rax,rax
	jz	plan_bad_handler
	mov	[r13+RA_MOD],rax
	mov	qword [r13+RA_MARG],0
	mov	dword [r13+RA_MALEN],0
	cmp	dword [rbx+N_ARGC],2
	jb	@f
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_SIZE+A_VAL]
	mov	[r13+RA_MARG],rcx
	mov	ecx,[rax+A_SIZE+A_VLEN]
	mov	[r13+RA_MALEN],ecx
@@:
	pop	rbx
.out:
	ret

; rdi/esi = a handler's name: rax = its function, 0 when no module has it.
; Keeps rbx, r12-r15.
mod_find:
	mov	r8,[mod_handlers]
.next:
	test	r8,r8
	jz	.none
	lea	rdx,[r8+MH_NAME]
	push	rdi
	push	rsi
	push	r8
	call	mem_eq_cstr
	pop	r8
	pop	rsi
	pop	rdi
	test	eax,eax
	jnz	.found
	mov	r8,[r8+MH_NEXT]
	jmp	.next
.found:
	mov	rax,[r8+MH_FN]
	ret
.none:
	xor	eax,eax
	ret

plan_bad_handler:
	call	log_begin
	out_lit 'handler: no module of this okena has a handler by that name ('
	mov	r8,[mod_handlers]
	test	r8,r8
	jnz	.list
	out_lit 'it was built with none: make MODULES=FILE.inc'
	jmp	.listed
.list:
	out_lit 'it has: '
.name:
	push	r8
	lea	rsi,[r8+MH_NAME]
	call	out_cstr
	pop	r8
	mov	r8,[r8+MH_NEXT]
	test	r8,r8
	jz	.listed
	out_lit ', '
	jmp	.name
.listed:
	out_lit ')'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------ the supervisor

; at the start, before the workers: each module's init. Exits when one fails.
mod_init_all:
	call	mod_inits_run
	jc	.failed
	ret
.failed:
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; a reload, before the new workers: each module's init again. One that fails
; is said; the workers go on with what it read last.
mod_init_reload:
	call	mod_inits_run
	jnc	.out
	call	log_begin
	out_lit 'reload: a module could not read its data again; its last stays'
	call	log_end
.out:
	ret

; CF when one failed (it said why)
mod_inits_run:
	push	rbx
	mov	rbx,[mod_inits]
.next:
	test	rbx,rbx
	jz	.done
	call	qword [rbx+MH_FN]
	jc	.out
	mov	rbx,[rbx+MH_NEXT]
	jmp	.next
.done:
	clc
.out:
	pop	rbx
	ret

; ------------------------------------------------------------ the workers

; http_request, a route with `handler`: ebx, r15, rdx = its action's offset in
; g_acts. The body read first (HTTP/1.1), then the handler, then its answer.
mod_request:
	mov	[g_mod_act],rdx
	lea	rax,[g_mod_body]
	mov	[g_mod_bptr],rax
	xor	eax,eax
	mov	[g_mod_blen],eax
	mov	[g_mod_used],eax
	cmp	dword [r15+H_BODY],BK_NONE
	je	.call
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S
	jnz	.call				; (a stream's body: not read here)
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_INOFF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	ecx,[r15+H_INLEN]
	sub	ecx,eax				; what came after the head
	cmp	dword [r15+H_BODY],BK_LENGTH
	jne	.chunked
	mov	rax,[g_hm+HM_LENGTH]
	cmp	rax,rcx
	ja	.more
	mov	[g_mod_bptr],rsi
	mov	[g_mod_blen],eax
	mov	[g_mod_used],eax
	jmp	.call
.chunked:
	call	mod_unchunk			; CF: not all in yet; eax < 0: not chunked as it must be
	jc	.more
	test	eax,eax
	js	.bad
.call:
	mov	rax,[g_mod_act]
	lea	rax,[g_acts+rax]
	mov	r8,[rax+RA_MARG]
	mov	r9d,[rax+RA_MALEN]
	mov	rdx,[g_mod_bptr]
	mov	ecx,[g_mod_blen]
	lea	rdi,[g_mod_out]
	mov	esi,MOD_OUT_CAP
	push	rbx
	push	r15
	call	qword [rax+RA_MOD]
	pop	r15
	pop	rbx
	cmp	edx,MOD_OUT_CAP
	ja	.broken
	cmp	eax,100
	jb	.broken
	cmp	eax,599
	ja	.broken
	; the body is used up: what follows it is the next request
	mov	ecx,[g_mod_used]
	add	[r15+H_INOFF],ecx
	mov	dword [r15+H_BODY],BK_NONE
	or	dword [r15+H_FLAGS],HX_NOBODY
	jmp	mod_answer
.broken:
	mov	edi,500				; a handler that said nothing that makes sense
	jmp	http_error
.bad:
	mov	edi,400
	jmp	http_error
.more:
	; the rest of the body, into the request's buffer after what came
	mov	eax,[r15+H_INLEN]
	cmp	eax,H_IN_CAP
	jae	.too_large
	cmp	dword [r15+H_BODY],BK_LENGTH
	jne	.read
	mov	rax,[g_hm+HM_LENGTH]
	mov	ecx,[r15+H_INOFF]
	add	rax,rcx
	cmp	rax,H_IN_CAP
	ja	.too_large
.read:
	mov	dword [r15+H_STATE],HS_MBODY
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	h_rec
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	mov	eax,[r15+H_INLEN]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rax]
	mov	ecx,SIDE_CLIENT
	jmp	h_recv
.too_large:
	or	dword [r15+H_FLAGS],HX_CLOSE
	mov	edi,413
	jmp	http_error

; http_recv_plain, HS_MBODY: rax more bytes of the body. Through the request
; again: its handler finds the body in, or waits for more.
mod_body_in:
	test	rax,rax
	jle	.gone
	add	[r15+H_INLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	or	dword [r15+H_FLAGS],HX_FAULTED	; (a request back, not a new one)
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.gone:
	mov	edi,ebx
	jmp	session_close

; rsi/ecx = a chunked body as it came: g_mod_body, g_mod_blen its data,
; g_mod_used the bytes it took, eax = 0. CF: its last chunk (and trailer) is
; not in yet. eax = -1: it is not a chunked body. Keeps rbx, r12-r15.
mod_unchunk:
	lea	r8,[rsi+rcx]			; the end
	mov	r9,rsi				; its start
	lea	rdi,[g_mod_body]
.chunk:
	; the size, in hex, then an extension perhaps, then CRLF
	xor	eax,eax
	xor	edx,edx				; digits
.hex:
	cmp	rsi,r8
	jae	.more
	movzx	ecx,byte [rsi]
	lea	r10d,[rcx-'0']
	cmp	r10d,9
	jbe	.digit
	mov	r10d,ecx
	or	r10d,0x20
	sub	r10d,'a'
	cmp	r10d,5
	ja	.size_end
	add	r10d,10
.digit:
	cmp	edx,7
	jae	.bad				; (no chunk of 256 MiB)
	shl	eax,4
	or	eax,r10d
	inc	edx
	inc	rsi
	jmp	.hex
.size_end:
	test	edx,edx
	jz	.bad
.ext:
	cmp	rsi,r8
	jae	.more
	cmp	byte [rsi],13
	je	.crlf
	cmp	byte [rsi],10
	je	.bad
	inc	rsi				; (an extension: skipped)
	jmp	.ext
.crlf:
	lea	rcx,[rsi+2]
	cmp	rcx,r8
	ja	.more
	cmp	byte [rsi+1],10
	jne	.bad
	add	rsi,2
	test	eax,eax
	jz	.trailer
	; its data, then CRLF
	lea	rcx,[rsi+rax+2]
	cmp	rcx,r8
	ja	.more
	lea	rcx,[rdi+rax]
	lea	rdx,[g_mod_body+H_IN_CAP]
	cmp	rcx,rdx
	ja	.bad
	mov	ecx,eax
	rep	movsb
	cmp	word [rsi],0x0A0D
	jne	.bad
	add	rsi,2
	jmp	.chunk
.trailer:
	; lines up to an empty one
	cmp	rsi,r8
	jae	.more
	cmp	byte [rsi],13
	jne	.field
	lea	rcx,[rsi+2]
	cmp	rcx,r8
	ja	.more
	cmp	byte [rsi+1],10
	jne	.bad
	add	rsi,2
	lea	rax,[g_mod_body]
	sub	rdi,rax
	mov	[g_mod_blen],edi
	sub	rsi,r9
	mov	[g_mod_used],esi
	xor	eax,eax
	clc
	ret
.field:
	cmp	rsi,r8
	jae	.more
	lodsb
	cmp	al,10
	jne	.field
	jmp	.trailer
.more:
	stc
	ret
.bad:
	mov	eax,-1
	clc
	ret

; the handler's answer: eax = status, edx = body length (in g_mod_out), rsi =
; its Content-Type or 0. ebx, r15.
mod_answer:
	push	r12
	push	r13
	mov	r12d,edx
	mov	r13,rsi
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	mov	[r15+H_STATUS],eax
	push	rax
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	edi,[rsp]
	mov	esi,5
	call	http_count
	pop	rax
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	call	status_line
	memit_x 'Content-Type: '
	test	r13,r13
	jz	.plain
	mov	rsi,r13
	call	fmt_cstr
	jmp	.typed
.plain:
	memit_x 'text/plain'
.typed:
	memit_x 13,10,'Content-Length: '
	mov	eax,r12d
	call	fmt_u64
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	mov	edx,HS_SELF_SEND
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	@f				; (HEAD: its length, no body)
	lea	rsi,[g_mod_out]
	mov	ecx,r12d
	rep	movsb
@@:
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	[r15+H_STATE],edx
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	pop	r13
	pop	r12
	jmp	h_send
