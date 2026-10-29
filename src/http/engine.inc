; The four HTTP primitives (src/http/proxy.inc) on both engines.

; ---------------------------------------------------------------- io_uring

; ebx = session, ecx = side, rdi = buffer, esi = room.
h_recv:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_recv
	push	rdi
	push	rsi
	push	rcx
	mov	edi,OP_H_RECV_C
	test	ecx,ecx
	jz	@f
	mov	edi,OP_H_RECV_U
@@:
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	pop	rcx
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],esi
	jmp	h_sqe_fd

; ebx = session, ecx = side, rdi = bytes, esi = length.
h_send:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_send
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_SPTR],rdi
	mov	[rax+H_SLEN],esi
	mov	[rax+H_SSIDE],ecx

; post (the rest of) the session's pending send
h_send_more:
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	ecx,[r8+H_SSIDE]
	push	r8
	push	rcx
	mov	edi,OP_H_SEND_C
	test	ecx,ecx
	jz	@f
	mov	edi,OP_H_SEND_U
@@:
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	pop	r8
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	rsi,[r8+H_SPTR]
	mov	[rax+SQE_ADDR],rsi
	mov	esi,[r8+H_SLEN]
	mov	[rax+SQE_LEN],esi
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL

; rax = SQE, rdx = session, ecx = side: the descriptor and its flags.
h_sqe_fd:
	test	ecx,ecx
	jnz	.upstream
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe rdx
	ret
.upstream:
	mov	ecx,[g_sessions]
	add	ecx,ebx
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	ret

; ebx = session: connect to a server of its pool.
h_connect:
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_connect
	mov	edi,ebx
	jmp	session_connect

; ebx = session: close its upstream connection (nothing in flight on it).
; Keeps rbx.
h_upclose:
	push	r12
	call	session_ptr
	mov	r12,rax
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	call	session_uncount
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[g_sessions]
	add	ecx,ebx
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	jmp	.done
.epoll:
	mov	edi,[r12+S_UPFD]
	mov	eax,SYS_close
	syscall
.done:
	pop	r12
	ret

; completions: ebx = session, r12d = generation, r14 = res
on_h_recv_c:
	xor	ecx,ecx
	jmp	on_h_recv
on_h_recv_u:
	mov	ecx,SIDE_UP
on_h_recv:
	push	rcx
	call	sess_complete
	pop	rcx
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	mov	rax,r14
	jmp	http_recv_done
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

on_h_send_c:
on_h_send_u:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	ecx,[r8+H_SSIDE]
	test	r14,r14
	jle	.failed
	add	[r8+H_SPTR],r14
	sub	[r8+H_SLEN],r14d
	jnz	h_send_more			; partly sent: the rest
	xor	eax,eax
	jmp	http_send_done
.failed:
	mov	rax,-1
	jmp	http_send_done
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; ------------------------------------------------------------------ epoll
;
; An operation is tried at once; when the socket is not ready it waits
; for the event. A result available at once is queued and delivered by
; the main loop (ep_http_ready), never from inside the call, so a long
; body does not turn into deep recursion.

H_SSIDE		= 68		; d: side of the pending send
H_EPOP		= 136		; d: 0 none, 1 recv waiting, 2 send waiting
H_EPSIDE	= 140
H_EPBUF		= 144		; q: receive buffer
H_EPLEN		= 152		; d: its room
H_READY		= 156		; d: queued result's kind (1 recv, 2 send), 0 none
H_RSIDE		= 160
H_RESULT	= 168		; q
H_RNEXT		= 176		; d: ready queue link
H_RGEN		= 180		; d: generation when queued

bss
	g_hready_head	dd ?
	g_hready_tail	dd ?
end bss

; ebx = session, ecx = side: the socket.
hep_fd:
	call	session_ptr
	test	ecx,ecx
	jnz	@f
	mov	eax,[rax+S_CLIENT]
	ret
@@:
	mov	eax,[rax+S_UPFD]
	ret

hep_recv:
	h_rec
	mov	dword [r15+H_EPOP],1
	mov	[r15+H_EPSIDE],ecx
	mov	[r15+H_EPBUF],rdi
	mov	[r15+H_EPLEN],esi
	jmp	hep_try_recv

; Try the waiting receive of session ebx. Queues the result unless the
; socket has nothing yet.
hep_try_recv:
	h_rec
	mov	ecx,[r15+H_EPSIDE]
	call	hep_fd
	mov	edi,eax
	mov	rsi,[r15+H_EPBUF]
	mov	edx,[r15+H_EPLEN]
	xor	eax,eax				; SYS_read
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	hep_try_recv
	mov	dword [r15+H_EPOP],0
	mov	edx,1
	mov	ecx,[r15+H_EPSIDE]
	jmp	hep_queue
.wait:
	ret

hep_send:
	h_rec
	mov	[r15+H_SPTR],rdi
	mov	[r15+H_SLEN],esi
	mov	[r15+H_SSIDE],ecx
	mov	dword [r15+H_EPOP],2
	mov	[r15+H_EPSIDE],ecx

; Write what is pending; queue the result once all is written or on an
; error.
hep_try_send:
	h_rec
.again:
	cmp	dword [r15+H_SLEN],0
	je	.done
	mov	ecx,[r15+H_EPSIDE]
	call	hep_fd
	mov	edi,eax
	mov	rsi,[r15+H_SPTR]
	mov	edx,[r15+H_SLEN]
	mov	eax,SYS_write
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	.again
	test	rax,rax
	jle	.failed
	add	[r15+H_SPTR],rax
	sub	[r15+H_SLEN],eax
	jmp	.again
.done:
	xor	eax,eax
	jmp	.queue
.failed:
	mov	rax,-1
.queue:
	mov	dword [r15+H_EPOP],0
	mov	edx,2
	mov	ecx,[r15+H_EPSIDE]
	jmp	hep_queue
.wait:
	ret

; Queue a result: ebx = session, edx = kind, ecx = side, rax = result.
hep_queue:
	h_rec
	mov	[r15+H_READY],edx
	mov	[r15+H_RSIDE],ecx
	mov	[r15+H_RESULT],rax
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[r15+H_RGEN],eax
	mov	dword [r15+H_RNEXT],NIL
	mov	eax,[g_hready_tail]
	cmp	dword [g_hready_head],NIL
	jne	@f
	mov	[g_hready_head],ebx
	mov	[g_hready_tail],ebx
	ret
@@:
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_RNEXT],ebx
	mov	[g_hready_tail],ebx
	ret

; Main loop: deliver the queued results.
ep_http_ready:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
.next:
	mov	ebx,[g_hready_head]
	cmp	ebx,NIL
	je	.done
	h_rec
	mov	eax,[r15+H_RNEXT]
	mov	[g_hready_head],eax
	cmp	eax,NIL
	jne	@f
	mov	[g_hready_tail],eax
@@:
	mov	edx,[r15+H_READY]
	mov	dword [r15+H_READY],0
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+H_RGEN]
	jne	.next				; that session is gone
	cmp	dword [rax+S_STATE],ST_FREE
	je	.next
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.next
	mov	ecx,[r15+H_RSIDE]
	mov	rax,[r15+H_RESULT]
	cmp	edx,1
	jne	.send
	call	http_recv_done
	jmp	.next
.send:
	call	http_send_done
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ep_dispatch, for a session of an http listener: edi = events, r8d = side.
hep_event:
	h_rec
	cmp	dword [r15+H_EPOP],0
	je	.out
	cmp	[r15+H_EPSIDE],r8d
	jne	.out
	cmp	dword [r15+H_EPOP],1
	je	.recv
	test	edi,EPOLLOUT or EPOLLERR or EPOLLHUP
	jz	.out
	jmp	hep_try_send
.recv:
	test	edi,EPOLLIN or EPOLLRDHUP or EPOLLHUP or EPOLLERR
	jz	.out
	jmp	hep_try_recv
.out:
	ret

; ebx = session: connect (state set by h_connect).
hep_connect:
	mov	edi,ebx
	jmp	ep_connect
