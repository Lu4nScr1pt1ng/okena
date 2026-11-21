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
;         decoded, or an HTTP/2 or HTTP/3 stream's DATA; up to MOD_BODY_MAX)
;   r8  = the route's ARG, r9d = its length (0 when it has none)
;   r10d = 1 when the request comes back after the handler held it, else 0
;   g_hm = the parsed request: HM_METHOD/HM_MLEN, HM_TARGET/HM_TLEN/HM_PLEN
;         (the path before any '?'), its fields (limit_find finds one)
;
; and returns eax = the status (100..599), edx = its body's length, rsi = its
; Content-Type (a NUL-ended string, 0 for text/plain), rcx = 0 when the body
; is where rdi pointed, or where it is (the request's own body, the module's
; memory: it must stay as it is until the answer is out). Or eax = 0 and edx =
; microseconds: the request is held that long, not answered, and the handler
; called again (r10d = 1) - a timer, not a wait (a request with a body cannot
; be held). Lines of its own for the answer's head ("Name: value" and CRLF
; each, MOD_XH_MAX bytes at most) go in g_mod_xh/g_mod_xhlen, cleared before
; each call; lines for trailers, the same way, in g_mod_tr/g_mod_trlen (sent
; after the body over HTTP/2, as gRPC's grpc-status must be; MOD_TR_MAX at
; most; not over HTTP/1.1 or HTTP/3, where the answer has none). It keeps rbx, rbp and r12-r15, and must not block: it runs in
; the event loop.

MOD_HEAD_ROOM	:= 1024				; OUT: room for the head, then the body
MOD_OUT_CAP	:= H_OUT_CAP - MOD_HEAD_ROOM - 16	; (and HB_TAIL, at OUT's end)
MOD_HEAD_CAP	:= 8192				; a head as written, before it goes in place
MOD_BODY_MAX	:= 1 shl 20			; a request body a handler gets, at most
MOD_BUFS	:= 64				; buffers for bodies past the request's own, a worker
MOD_XH_MAX	:= 2048				; a handler's own head lines, at most
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
	g_mod_out	rb MOD_OUT_CAP + 64
	align 64
	g_mod_scr	rb H_OUT_CAP			; an HTTP/2 stream's answer: head room, body
	g_mod_base	dq ?			; where this call's body goes (OUT or g_mod_scr)
	g_mod_head	rb MOD_HEAD_CAP
	g_mod_src	dd ?			; the body: 1 after the head, 2 in a buffer
	g_mod_bidx	dd ?
	g_mod_resumed	dd ?
	g_mod_xhlen	dd ?
	g_mod_xh	dq ?
	g_mod_trlen	dd ?
	g_mod_tr	dq ?
	g_mod_ck	rb CK_SIZE		; a chunked body's decoder
	g_mod_bbase	dq ?			; MOD_BUFS of MOD_BODY_MAX, 0 none
	g_mod_sess	dq ?			; per session: its buffer + 1 (d), the exchange it held (d)
	g_mod_bown	rd MOD_BUFS		; a buffer's session + 1, 0 free
	g_mod_bgen	rd MOD_BUFS		; and that session's generation
	g_mod_bfill	rd MOD_BUFS		; bytes in it
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
	mov	dword [g_plan_mods],1
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

; worker start, with handlers in the plan: the body buffers (address space;
; pages as they are touched) and the per-session words. eax = 0
mod_worker_init:
	cmp	dword [g_plan_mods],0
	je	.none
	xor	edi,edi
	mov	esi,MOD_BUFS * MOD_BODY_MAX
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none
	mov	[g_mod_bbase],rax
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,3
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_sess
	mov	[g_mod_sess],rax
	jmp	.none
.no_sess:
	mov	qword [g_mod_bbase],0
.none:
	xor	eax,eax
	ret

; ebx = session: eax = its body buffer, -1 none. Keeps all but rax, rcx.
mod_buf_of:
	mov	rax,[g_mod_sess]
	test	rax,rax
	jz	.none
	mov	ecx,ebx
	mov	eax,[rax+rcx*8]
	test	eax,eax
	jz	.none
	dec	eax
	lea	ecx,[rbx+1]
	cmp	[g_mod_bown+rax*4],ecx
	jne	.none
	push	rax
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	pop	rax
	cmp	[g_mod_bgen+rax*4],ecx
	jne	.none
	ret
.none:
	mov	eax,-1
	ret

; eax = a buffer: rax = its bytes. Keeps all but rax.
mod_buf_ptr:
	shl	rax,20				; (MOD_BODY_MAX)
	add	rax,[g_mod_bbase]
	ret

; ebx: eax = a buffer of its own (the one it has, or a free one), -1 none:
; free is no session's, a session's that is gone, or one not using it now
; (not reading a body into it, nor sending an answer from it).
; Keeps all but rax, rcx, rdx.
mod_buf_get:
	call	mod_buf_of
	test	eax,eax
	jns	.out
	cmp	qword [g_mod_bbase],0
	je	.none
	xor	ecx,ecx
.scan:
	cmp	ecx,MOD_BUFS
	jae	.none
	mov	eax,[g_mod_bown+rcx*4]
	test	eax,eax
	jz	.take
	push	rbx
	lea	ebx,[rax-1]
	call	session_ptr
	mov	edx,[rax+S_GEN]
	cmp	edx,[g_mod_bgen+rcx*4]
	jne	.stale
	mov	eax,ebx				; its record: busy with the buffer?
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	edx,[rax+H_STATE]
	pop	rbx
	cmp	edx,HS_MBODY
	je	.next
	cmp	edx,HS_SELF_TAIL
	je	.next
	cmp	edx,HS_SELF_SEND
	je	.next
	jmp	.take
.stale:
	pop	rbx
	jmp	.take
.next:
	inc	ecx
	jmp	.scan
.take:
	lea	eax,[rbx+1]
	mov	[g_mod_bown+rcx*4],eax
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[g_mod_bgen+rcx*4],eax
	mov	dword [g_mod_bfill+rcx*4],0
	mov	rax,[g_mod_sess]
	lea	edx,[rcx+1]
	push	rbx
	mov	ebx,ebx
	mov	[rax+rbx*8],edx
	pop	rbx
	mov	eax,ecx
.out:
	ret
.none:
	mov	eax,-1
	ret

; ebx: the buffer it held, free. Keeps all but rax, rcx.
mod_buf_drop:
	call	mod_buf_of
	test	eax,eax
	js	.out
	mov	dword [g_mod_bown+rax*4],0
	mov	rax,[g_mod_sess]
	mov	ecx,ebx
	mov	dword [rax+rcx*8],0
.out:
	ret

; http_request, a route with `handler`: ebx, r15, rdx = its action's offset in
; g_acts. The body read first, then the handler, then its answer.
mod_request:
	mov	[g_mod_act],rdx
	xor	eax,eax
	mov	[g_mod_blen],eax
	mov	[g_mod_used],eax
	mov	[g_mod_src],eax
	mov	[g_mod_resumed],eax
	lea	rax,[g_mod_out]
	mov	[g_mod_bptr],rax
	; back after the handler held it? (or a new request: what an earlier one
	; of the session held, given back)
	mov	rax,[g_mod_sess]
	test	rax,rax
	jz	.fresh
	mov	ecx,ebx
	lea	rcx,[rax+rcx*8]
	mov	eax,dword [r15+H_LT0]
	test	dword [r15+H_FLAGS],HX_FAULTED
	jz	.new
	cmp	[rcx+4],eax
	jne	.fresh
	mov	dword [rcx+4],0
	mov	dword [g_mod_resumed],1
	jmp	.call				; (held: it had no body)
.new:
	mov	dword [rcx+4],0
	call	mod_buf_drop
.fresh:
	cmp	dword [r15+H_BODY],BK_NONE
	je	.call
	call	mod_buf_of
	test	eax,eax
	js	.in_in
	mov	[g_mod_bidx],eax
	mov	ecx,[g_mod_bfill+rax*4]
	call	mod_buf_ptr
	mov	rsi,rax
	mov	dword [g_mod_src],2
	jmp	.have
.in_in:
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_INOFF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	ecx,[r15+H_INLEN]
	sub	ecx,eax				; what came after the head
	mov	dword [g_mod_src],1
.have:
	mov	[g_mod_bptr],rsi
	cmp	dword [r15+H_BODY],BK_LENGTH
	jne	.chunked
	mov	rax,[g_hm+HM_LENGTH]
	cmp	rax,MOD_BODY_MAX
	ja	.too_large
	cmp	rax,rcx
	ja	.more
	mov	[g_mod_blen],eax
	mov	[g_mod_used],eax
	jmp	.call
.chunked:
	push	rsi
	xor	r11d,r11d			; first only looked through
	mov	rdi,rsi
	call	mod_unchunk
	pop	rsi
	jc	.more
	test	eax,eax
	js	.bad
	mov	[g_mod_used],eax
	mov	ecx,eax
	mov	rdi,rsi				; then undone in place
	mov	r11d,1
	call	mod_unchunk
	mov	[g_mod_blen],edx
.call:
	mov	rax,[g_mod_act]
	lea	rax,[g_acts+rax]
	mov	r8,[rax+RA_MARG]
	mov	r9d,[rax+RA_MALEN]
	mov	r10d,[g_mod_resumed]
	mov	qword [g_mod_xh],0
	mov	dword [g_mod_xhlen],0
	mov	qword [g_mod_tr],0
	mov	dword [g_mod_trlen],0
	mov	rdx,[g_mod_bptr]
	mov	ecx,[g_mod_blen]
	mov	rdi,[r15+H_BUF]			; the body where it is sent from: in OUT,
	add	rdi,HB_OUT + MOD_HEAD_ROOM	; after the head's room (no copy after)
	push	rax				; an HTTP/2 stream: in the worker's g_mod_scr
	push	rdi				; instead, written and taken while in the
	call	session_ptr			; cache (each stream's own buffer is a cold
	test	dword [rax+S_FLAGS],SF_H2S	; one; what its connection cannot take at
	pop	rdi				; once moves there after)
	pop	rax
	jz	@f
	lea	rdi,[g_mod_scr+MOD_HEAD_ROOM]
@@:
	mov	[g_mod_base],rdi
	mov	esi,MOD_OUT_CAP
	push	rbx
	push	r15
	call	qword [rax+RA_MOD]
	pop	r15
	pop	rbx
	test	eax,eax
	jz	.hold
	cmp	eax,100
	jb	.broken
	cmp	eax,599
	ja	.broken
	test	rcx,rcx
	jnz	@f
	cmp	edx,MOD_OUT_CAP
	ja	.broken
@@:
	push	rax
	push	rcx
	push	rdx
	push	rsi
	call	mod_used_up
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
	jmp	mod_answer
.hold:
	cmp	dword [r15+H_BODY],BK_NONE	; (a body would be read again)
	jne	.broken
	cmp	dword [g_fd_n],FD_MAX
	jae	.busy
	mov	rax,[g_mod_sess]
	test	rax,rax
	jz	.broken
	mov	ecx,ebx
	mov	esi,dword [r15+H_LT0]
	mov	[rax+rcx*8+4],esi
	mov	eax,edx
	call	fault_hold
	ret
.busy:
	mov	edi,503
	jmp	http_error
.broken:
	mov	edi,500				; a handler that said nothing that makes sense
	jmp	http_error
.bad:
	mov	edi,400
	jmp	http_error
.more:
	cmp	dword [g_mod_src],2
	je	.more_buf
	; after the head, while it fits; else into a body buffer
	cmp	dword [r15+H_BODY],BK_LENGTH
	jne	@f
	mov	rax,[g_hm+HM_LENGTH]
	mov	ecx,[r15+H_INOFF]
	add	rax,rcx
	cmp	rax,H_IN_CAP
	ja	.move
	jmp	.read_in
@@:
	cmp	dword [r15+H_INLEN],H_IN_CAP
	jae	.move
.read_in:
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	mov	eax,[r15+H_INLEN]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rax]
	jmp	.read
.move:
	call	mod_buf_get
	test	eax,eax
	js	.busy				; (none free now)
	mov	[g_mod_bidx],eax
	push	rax
	call	mod_buf_ptr
	mov	rdi,rax
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_INOFF]
	lea	rsi,[rsi+HB_IN+rax]
	mov	ecx,[r15+H_INLEN]
	sub	ecx,eax
	pop	rax
	mov	[g_mod_bfill+rax*4],ecx
	rep	movsb
	mov	eax,[r15+H_INOFF]
	mov	[r15+H_INLEN],eax
.more_buf:
	mov	eax,[g_mod_bidx]
	mov	esi,MOD_BODY_MAX
	sub	esi,[g_mod_bfill+rax*4]
	jz	.too_large
	mov	ecx,[g_mod_bfill+rax*4]
	call	mod_buf_ptr
	lea	rdi,[rax+rcx]
.read:
	push	rdi
	push	rsi
	mov	dword [r15+H_STATE],HS_MBODY
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	pop	rsi
	pop	rdi
	h_rec
	mov	ecx,SIDE_CLIENT
	jmp	h_recv
.too_large:
	or	dword [r15+H_FLAGS],HX_CLOSE
	mov	edi,413
	jmp	http_error

; mod_request, answered: the body's bytes are used up, and what came after them
; (a pipelined request) is the next request's. Keeps rbx, r12-r15.
mod_used_up:
	cmp	dword [r15+H_BODY],BK_NONE
	je	.done
	cmp	dword [g_mod_src],2
	je	.buf
	mov	ecx,[g_mod_used]
	add	[r15+H_INOFF],ecx
	jmp	.done
.buf:
	; from the buffer back after the head: what followed the body
	mov	eax,[g_mod_bidx]
	mov	ecx,[g_mod_bfill+rax*4]
	sub	ecx,[g_mod_used]
	jbe	.done
	mov	edx,[r15+H_INOFF]
	lea	r8d,[rdx+rcx]
	cmp	r8d,H_IN_CAP
	ja	.too_much
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rdx]
	mov	[r15+H_INLEN],r8d
	push	rcx
	call	mod_buf_ptr
	mov	esi,[g_mod_used]
	add	rsi,rax
	pop	rcx
	rep	movsb
	jmp	.done
.too_much:
	or	dword [r15+H_FLAGS],HX_CLOSE	; (more pipelined than fits: one at a time)
.done:
	mov	dword [r15+H_BODY],BK_NONE
	or	dword [r15+H_FLAGS],HX_NOBODY
	ret

; http_recv_plain, HS_MBODY: rax more bytes of the body (after the head, or in
; the session's buffer). Through the request again: its handler finds the
; body in, or waits for more.
mod_body_in:
	test	rax,rax
	jle	.gone
	push	rax
	call	mod_buf_of
	pop	rcx
	test	eax,eax
	js	.in_in
	add	[g_mod_bfill+rax*4],ecx
	jmp	@f
.in_in:
	add	[r15+H_INLEN],ecx
@@:
	mov	edi,ebx
	call	idle_touch
	h_rec
	or	dword [r15+H_FLAGS],HX_FAULTED	; (a request back, not a new one)
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.gone:
	mov	edi,ebx
	jmp	session_close

; rsi/ecx = a chunked body as it came, r11d = 0 to look through it, 1 to undo
; it into rdi (which may be rsi: it only moves bytes back). eax = the bytes it
; took, edx = its data's length. CF: its last chunk (and trailer) is not in
; yet. eax = -1: not a chunked body. Keeps rbx, r12-r15.
mod_unchunk:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbp,rsi				; its start
	mov	r12,rsi				; where the decoder stands
	mov	r13d,ecx			; bytes left
	mov	r14,rdi				; where data goes (copying)
	mov	r15d,r11d
	xor	ebx,ebx				; data so far
	xor	eax,eax
	mov	qword [g_mod_ck],rax
	mov	qword [g_mod_ck+8],rax
	mov	qword [g_mod_ck+16],rax
	mov	qword [g_mod_ck+24],rax		; (CK_TBUF 0: trailers dropped)
.step:
	lea	rdi,[g_mod_ck]			; chunk.inc's decoder, as the proxy's:
	mov	rsi,r12				; CRLF only, tokens in extensions
	mov	edx,r13d
	call	chunk_step
	add	r12,rcx
	sub	r13d,ecx
	cmp	eax,CK_DATAOUT
	jne	.not_data
	add	ebx,r9d
	cmp	ebx,MOD_BODY_MAX
	ja	.bad
	test	r15d,r15d
	jz	.step
	mov	rdi,r14				; (never past where it is read)
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	r14,rdi
	jmp	.step
.not_data:
	cmp	eax,CK_END
	je	.end
	cmp	eax,CK_MORE
	jne	.bad
	stc
	jmp	.out
.bad:
	mov	eax,-1
	clc
	jmp	.out
.end:
	mov	rax,r12
	sub	rax,rbp
	mov	edx,ebx
	clc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; the handler's answer: eax = status, edx = body length, rsi = its
; Content-Type or 0, rcx = where its body is (0: g_mod_out). ebx, r15.
; mod_answer: the handler's trailers, on an HTTP/2 stream, where its
; response's trailers go (HB_TRAIL, CK_TLEN: h2_trailers_out sends them)
MOD_TR_MAX	:= CK_TRAIL_MAX - 256		; (HB_TRAIL's end holds a request's validators)
mod_trailers:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S
	jz	.out
	mov	ecx,[g_mod_trlen]
	cmp	ecx,MOD_TR_MAX
	jbe	@f
	xor	ecx,ecx
@@:
	mov	[r15+H_RCK+CK_TLEN],ecx
	test	ecx,ecx
	jz	.out
	push	rsi
	mov	rsi,[g_mod_tr]
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TRAIL
	rep	movsb
	pop	rsi
.out:
	ret

mod_answer:
	push	r12
	push	r13
	push	r14
	mov	r12d,edx
	mov	r13,rsi
	mov	r14,rcx
	test	r14,r14
	jnz	@f
	mov	r14,[g_mod_base]
@@:
	push	rax
	call	mod_trailers
	pop	rax
	; a route that compresses: the answer goes through the response path, as a
	; file's does (fs_head_ready), its body compressed when the client takes it
	mov	rcx,[g_mod_act]
	cmp	dword [g_acts+rcx+RA_ZMIN],0
	je	.direct
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.direct
	cmp	r12d,H_UP_CAP - 512
	ja	.direct
	push	rax
	call	zip_request			; (what the client takes, for its head)
	pop	rax
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	call	status_line
	call	.fields
	memit_x 13,10
	mov	rsi,r14
	mov	ecx,r12d
	rep	movsb
	pop	r14
	pop	r13
	pop	r12
	jmp	fs_head_ready
.direct:
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	mov	[r15+H_STATUS],eax
	push	rax
	cmp	dword [r15+H_RIDLEN],0		; an id, for what reads it: the access
	jne	@f				; log, a trace, an addon (the answer
	call	session_ptr			; itself carries none)
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_ALOG],0
	jne	.rid
	cmp	dword [g_listeners+rax+LS_TRACE],0
	jne	.rid
	cmp	qword [g_ad_side],0
	je	@f
.rid:
	call	rid_new
@@:
	mov	edi,[rsp]
	mov	esi,5
	call	http_count
	pop	rax
	; the head, written aside, then put where it goes
	lea	rdi,[g_mod_head]
	call	status_line
	call	.fields
	mov	rax,[g_mod_act]			; the route's response set and add, CORS
	mov	esi,[g_acts+rax+RA_PFIRST]
	mov	edx,[g_acts+rax+RA_PCOUNT]
	push	r13
	lea	r13,[g_mod_head+MOD_HEAD_CAP-512]
	call	hdrop_emit
	pop	r13
	call	cors_emit
	memit_x 13,10
	mov	rcx,rdi
	lea	rsi,[g_mod_head]
	sub	rcx,rsi				; the head's length
	lea	rdx,[g_mod_scr+MOD_HEAD_ROOM]
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	@f
	cmp	r14,rdx
	je	.scratch
@@:
	mov	rax,[r15+H_BUF]
	lea	rdx,[rax+HB_OUT+MOD_HEAD_ROOM]
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.at_start			; (HEAD: its length, no body)
	cmp	r14,rdx
	jne	.at_start
	cmp	ecx,MOD_HEAD_ROOM
	ja	.aside
	; the body where the handler wrote it, in OUT: the head just before it,
	; and both go as they are
	mov	rdi,rdx
	sub	rdi,rcx
	push	rdi
	lea	r8,[rcx+r12]			; head and body
	call	copy_small			; (a few dozen bytes: no rep movsb start-up)
	pop	rdi
	mov	esi,r8d
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	pop	r14
	pop	r13
	pop	r12
	jmp	h_send
.scratch:
	; an HTTP/2 stream's, in g_mod_scr: the head before it, the stream takes
	; what its connection can; the rest moves to the stream's OUT
	cmp	ecx,MOD_HEAD_ROOM
	ja	.aside
	mov	rdi,rdx
	sub	rdi,rcx
	push	rdi
	lea	r8,[rcx+r12]
	call	copy_small
	pop	rdi
	mov	esi,r8d
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	pop	r14
	pop	r13
	pop	r12
	call	h_send
	h_rec
	mov	ecx,[r15+H_H2PL]		; all taken: done with it
	test	ecx,ecx
	jz	.scr_done
	mov	rsi,[r15+H_H2PP]
	lea	rax,[g_mod_scr]
	cmp	rsi,rax
	jb	.scr_done
	add	rax,H_OUT_CAP
	cmp	rsi,rax
	jae	.scr_done
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	[r15+H_H2PP],rdi
	rep	movsb
.scr_done:
	ret
.aside:
	; (a head past its room: the body out of its way first)
	push	rcx
	lea	rdi,[g_mod_out]
	mov	rsi,r14
	mov	ecx,r12d
	rep	movsb
	lea	r14,[g_mod_out]
	pop	rcx
.at_start:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	lea	rsi,[g_mod_head]
	rep	movsb
	mov	edx,HS_SELF_SEND
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.send				; (HEAD: its length, no body)
	; the body after the head when it fits there, else sent after it
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_TAIL]
	sub	rax,rdi
	cmp	r12,rax
	ja	.tail
	mov	rsi,r14
	mov	ecx,r12d
	rep	movsb
	jmp	.send
.tail:
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_TAIL],r14
	mov	[rax+HB_TAIL+8],r12d
	mov	dword [rax+HB_TAIL+12],HS_SELF_SEND
	mov	edx,HS_SELF_TAIL
.send:
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	[r15+H_STATE],edx
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	pop	r14
	pop	r13
	pop	r12
	jmp	h_send
; its fields, at rdi, and the empty line
.fields:
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
	mov	ecx,[g_mod_xhlen]		; the handler's own lines
	test	ecx,ecx
	jz	@f
	cmp	ecx,MOD_XH_MAX
	ja	@f
	mov	rsi,[g_mod_xh]
	rep	movsb
@@:
	ret
