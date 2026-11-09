; Zero copy: the body of an answer from a file (`files`) or from the disk cache goes
; from the page cache to the client's socket without passing through okena's
; memory, when nothing in between needs to see it: HTTP/1.1, in the clear or with
; kTLS, not compressed, not chunk-framed. Anything else reads it into the buffer
; as before.
;
; io_uring: a SPLICE from the file into a pipe, linked to a poll for room on the
; socket, linked to a SPLICE from the pipe into the socket that does not wait
; (SPLICE_F_NONBLOCK): the kernel runs a SPLICE on a thread of its own (io-wq), and
; one that waited for a slow client would keep a thread for each. -EAGAIN: polled
; again. A splice costs that hand-over, so only bodies of ZC_MIN or more go so. Each worker has a pool of pipes, made at its start and
; registered with the ring (no descriptor to open later, none to run out of). A
; session holds one while its body goes, and gives it back at the end; one that
; still has bytes in it is emptied by a READ before it goes back to the pool. Both
; operations count as the session's (S_INFL), so the session and its socket's slot
; outlive them.
;
; epoll: sendfile, as much as the socket takes; when it is full, the rest when it
; is writable again.

ZC_PIPES	:= 64
ZC_PSZ		:= 1 shl 18			; a pipe's size: what one step moves
ZC_EP_MAX	:= 1 shl 20			; epoll: bytes per turn of the loop, at most
ZC_MIN		:= 1 shl 16			; smaller bodies: a copy is cheaper
SPLICE_F_NONBLOCK := 2
POLLOUT_	:= 4
SPLICE_F_FD_IN_FIXED := 1 shl 31
SYS_sendfile	:= 40
IORING_OP_SPLICE := 30
IORING_REGISTER_FILES_UPDATE := 6
SQE_SPLICE_OFF_IN := 16
SQE_SPLICE_FD_IN := 44

; a pipe
ZP_IN		:= 0				; d: bytes in it
ZP_NEXT		:= 4				; d: free list
ZP_SIZE		:= 8

bss
	align 8
	g_zc_pipes:	rb ZP_SIZE * ZC_PIPES
	g_zc_n		dd ?			; pipes made (0: none, copies as before)
	g_zc_room	dd ?			; slots for them in the ring's table
	g_zc_base	dd ?			; the ring's slot of pipe 0's read end
	g_zc_free	dd ?
	g_zc_fds	rd 2 * ZC_PIPES
	align 64
	g_zc_sink:	rb ZC_PSZ		; what a pipe given back had in it
end bss

; a worker with a ring, its files registered: the pipes
zc_init:
	push	rbx
	mov	dword [g_zc_n],0
	mov	dword [g_zc_free],NIL
	mov	eax,[g_sessions]
	imul	eax,eax,3
	mov	[g_zc_base],eax
	xor	ebx,ebx
	cmp	dword [g_zc_room],0
	je	.out
.make:
	lea	rdi,[g_zc_fds+rbx*8]
	mov	esi,O_CLOEXEC
	mov	eax,SYS_pipe2
	syscall
	test	eax,eax
	js	.made
	mov	edi,[g_zc_fds+rbx*8+4]
	mov	esi,F_SETPIPE_SZ
	mov	edx,ZC_PSZ
	mov	eax,SYS_fcntl
	syscall
	cmp	eax,ZC_PSZ
	jae	@f
	mov	edi,[g_zc_fds+rbx*8]		; (smaller than a step: not this one)
	mov	eax,SYS_close
	syscall
	mov	edi,[g_zc_fds+rbx*8+4]
	mov	eax,SYS_close
	syscall
	jmp	.made
@@:
	inc	ebx
	cmp	ebx,ZC_PIPES
	jb	.make
.made:
	test	ebx,ebx
	jz	.out
	; into the ring's table, after the sessions' slots
	sub	rsp,16
	mov	eax,[g_zc_base]
	mov	[rsp],eax
	mov	dword [rsp+4],0
	lea	rax,[g_zc_fds]
	mov	[rsp+8],rax
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_FILES_UPDATE
	mov	rdx,rsp
	lea	r10d,[rbx*2]
	mov	eax,SYS_io_uring_register
	syscall
	add	rsp,16
	push	rax
	; (the ring keeps its own references)
	xor	ecx,ecx
@@:
	push	rcx
	mov	edi,[g_zc_fds+rcx*4]
	mov	eax,SYS_close
	syscall
	pop	rcx
	inc	ecx
	lea	eax,[rbx*2]
	cmp	ecx,eax
	jb	@b
	pop	rax
	lea	ecx,[rbx*2]
	cmp	eax,ecx
	jne	.out
	mov	[g_zc_n],ebx
	; all free
	xor	ecx,ecx
@@:
	lea	eax,[rcx+1]
	cmp	eax,ebx
	jb	.link
	mov	eax,NIL
.link:
	mov	[g_zc_pipes+rcx*ZP_SIZE+ZP_NEXT],eax
	mov	dword [g_zc_pipes+rcx*ZP_SIZE+ZP_IN],0
	inc	ecx
	cmp	ecx,ebx
	jb	@b
	mov	dword [g_zc_free],0
.out:
	pop	rbx
	ret

; ebx = session, r15 = record, its answer framed by length with body still to go:
; CF unless it can go without copies (and, with io_uring, the session has a pipe).
zc_ok:
	call	session_ptr
	mov	ecx,[rax+S_FLAGS]
	test	ecx,SF_ZIP or SF_H2S or SF_H3S or SF_HSTRM or SF_MIR or SF_SLICE
	jnz	.no
	test	ecx,SF_FILE
	jnz	.source
	test	ecx,SF_CACHED
	jz	.no
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_CE]
	cmp	eax,NIL
	je	.no
	test	eax,CD_MARK
	jz	.no
.source:
	cmp	dword [r15+H_UTLS],0
	jne	.no
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_ZCP],0
	jne	@f				; (one under way: on)
	cmp	qword [r15+H_RREMAIN],ZC_MIN
	jb	.no
@@:
	test	dword [r15+H_FLAGS],HX_CHUNKOUT
	jnz	.no
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.yes
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_ZCP],0
	jne	.yes
	mov	ecx,[g_zc_free]
	cmp	ecx,NIL
	je	.no
	mov	edx,[g_zc_pipes+rcx*ZP_SIZE+ZP_NEXT]
	mov	[g_zc_free],edx
	mov	dword [g_zc_pipes+rcx*ZP_SIZE+ZP_IN],0
	inc	ecx
	mov	[rax+HB_ZCP],ecx
	mov	dword [rax+HB_ZCF],0
.yes:
	clc
	ret
.no:
	stc
	ret

; ebx, r15: rdi = its source's descriptor, rsi = where in it (-1: where the file is),
; rdx = how much of it is left
macro zc_source
	local file, done
	mov	r8,[r15+H_BUF]
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_FILE
	jnz	file
	mov	edi,[g_cd_fd]
	mov	rsi,[r8+HB_CPOSB]
	mov	edx,[r8+HB_CLEFT]
	jmp	done
file:
	mov	edi,[r8+HB_FFD]
	mov	rsi,-1
	mov	rdx,[r8+HB_FLEFT]
done:
end macro

; ebx, r15: the next piece of the body, without copies (zc_ok said yes)
zc_send:
	mov	dword [r15+H_STATE],HS_RESP_SEND
	cmp	dword [g_engine],ENGINE_EPOLL
	je	zc_ep_try
	; room for a whole chain: one split by a flush would not be linked
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_head_ptr]
	sub	eax,[rdx]
	add	eax,3
	cmp	eax,[g_sq_entries]
	jbe	@f
	call	ring_flush
@@:
	push	r12
	push	r13
	mov	rax,[r15+H_BUF]
	mov	r12d,[rax+HB_ZCP]
	dec	r12d				; the pipe
	imul	eax,r12d,ZP_SIZE
	mov	r13d,[g_zc_pipes+rax+ZP_IN]
	test	r13d,r13d
	jnz	.out_only			; (what a short step left in it first)
	zc_source
	mov	rcx,[r15+H_RREMAIN]
	cmp	rcx,rdx
	cmova	rcx,rdx
	mov	eax,ZC_PSZ
	cmp	rcx,rax
	cmova	rcx,rax
	mov	r13d,ecx
	push	rdi
	push	rsi
	mov	edi,OP_ZC_IN
	mov	esi,ebx
	call	sess_sqe
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_SPLICE
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_LINK
	lea	ecx,[r12*2+1]
	add	ecx,[g_zc_base]
	mov	[rax+SQE_FD],ecx		; the pipe's write end
	mov	qword [rax+SQE_OFF],-1
	mov	[rax+SQE_SPLICE_OFF_IN],rsi
	mov	[rax+SQE_SPLICE_FD_IN],edi
	mov	[rax+SQE_LEN],r13d
	mov	rax,[r15+H_BUF]
	inc	dword [rax+HB_ZCF]
.out_only:
	; room on the socket first
	call	session_ptr
	push	rax
	call	ring_get_sqe
	pop	rdx
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_LINK or IOSQE_CQE_SKIP_SUCCESS
	client_sqe rdx
	mov	dword [rax+SQE_OP_FLAGS],POLLOUT_
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	mov	edi,OP_ZC_OUT
	mov	esi,ebx
	call	sess_sqe			; (rdx = the session)
	mov	byte [rax+SQE_OPCODE],IORING_OP_SPLICE
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe rdx
	mov	qword [rax+SQE_OFF],-1
	mov	qword [rax+SQE_SPLICE_OFF_IN],-1
	lea	ecx,[r12*2]
	add	ecx,[g_zc_base]
	mov	[rax+SQE_SPLICE_FD_IN],ecx	; the pipe's read end
	mov	dword [rax+SQE_OP_FLAGS],SPLICE_F_FD_IN_FIXED or SPLICE_F_NONBLOCK
	mov	[rax+SQE_LEN],r13d
	mov	rax,[r15+H_BUF]
	inc	dword [rax+HB_ZCF]
	pop	r13
	pop	r12
	ret

; a step's first half: ebx = session, r12d = generation, r14 = bytes into the pipe
on_zc_in:
	call	sess_complete
	jc	.out
	h_rec
	mov	rcx,[r15+H_BUF]
	dec	dword [rcx+HB_ZCF]
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	zc_closing
	test	r14,r14
	jle	.out				; (the second half is cancelled: it says so)
	mov	edx,[rcx+HB_ZCP]
	dec	edx
	add	[g_zc_pipes+rdx*ZP_SIZE+ZP_IN],r14d
	test	dword [rax+S_FLAGS],SF_FILE
	jnz	.file
	add	[rcx+HB_CPOSB],r14
	sub	[rcx+HB_CLEFT],r14d
	ret
.file:
	sub	[rcx+HB_FLEFT],r14
.out:
	ret

; its second half: ebx = session, r12d = generation, r14 = bytes to the client
on_zc_out:
	call	sess_complete
	jc	.out
	h_rec
	mov	rcx,[r15+H_BUF]
	dec	dword [rcx+HB_ZCF]
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	zc_closing
	mov	edx,[rcx+HB_ZCP]
	dec	edx
	imul	edx,edx,ZP_SIZE
	test	r14,r14
	jle	.short
	sub	[g_zc_pipes+rdx+ZP_IN],r14d
	sub	[r15+H_RREMAIN],r14
	add	[r15+H_XBYTES],r14
	add	[g_st_zc_bytes],r14
	cmp	qword [r15+H_RREMAIN],0
	jne	.sent
	call	zc_release			; the whole body: the pipe is empty, back it goes
.sent:
	xor	eax,eax
	xor	ecx,ecx
	jmp	http_send_done			; and on, as after a send
.short:
	; the socket filled again (-EAGAIN), or the first half moved less than it was
	; asked (its link broke): what is in the pipe goes on its own; else it failed
	cmp	r14,-EAGAIN
	je	@f
	cmp	r14,-ECANCELED
	jne	.failed
@@:
	cmp	dword [g_zc_pipes+rdx+ZP_IN],0
	je	.failed
	jmp	zc_send
.failed:
	mov	rax,-1
	xor	ecx,ecx
	jmp	http_send_done
.out:
	ret

; a step completed on a session that is closing (rcx = its buffer): the pipe goes
; back once nothing of it is in flight
zc_closing:
	cmp	dword [rcx+HB_ZCF],0
	jne	@f
	call	zc_release
@@:
	mov	edi,ebx
	jmp	session_maybe_free

; ebx = a session closing (r15 its record, r12 the session): its pipe, if nothing
; is in flight. Only a hit from disk or a file has HB_ZCP.
zc_gone:
	mov	rax,[r15+H_BUF]
	test	dword [r12+S_FLAGS],SF_FILE
	jnz	@f
	test	dword [r12+S_FLAGS],SF_CACHED
	jz	.none
	mov	ecx,[rax+HB_CE]
	cmp	ecx,NIL
	je	.none
	test	ecx,CD_MARK
	jz	.none
@@:
	cmp	dword [rax+HB_ZCP],0
	je	.none
	cmp	dword [rax+HB_ZCF],0
	je	zc_release
.none:
	ret

; ebx, r15: the session's pipe back to the pool, emptied first if it must be.
; Keeps rbx, r12-r15.
zc_release:
	mov	rax,[r15+H_BUF]
	mov	edi,[rax+HB_ZCP]
	test	edi,edi
	jz	.none
	mov	dword [rax+HB_ZCP],0
	dec	edi
	imul	eax,edi,ZP_SIZE
	cmp	dword [g_zc_pipes+rax+ZP_IN],0
	jne	zc_drain
	jmp	zc_put
.none:
	ret

; edi = a pipe, empty: free
zc_put:
	imul	eax,edi,ZP_SIZE
	mov	ecx,[g_zc_free]
	mov	[g_zc_pipes+rax+ZP_NEXT],ecx
	mov	[g_zc_free],edi
	ret

; edi = a pipe with bytes in it: read out, into nothing
zc_drain:
	push	rdi
	call	ring_get_sqe
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	lea	ecx,[rdi*2]
	add	ecx,[g_zc_base]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_zc_sink]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],ZC_PSZ
	mov	qword [rax+SQE_OFF],-1
	mov	ecx,edi
	mov	rdx,OP_ZC_DRAIN shl 56
	or	rcx,rdx
	mov	[rax+SQE_USER_DATA],rcx
	ret

; ebx = the pipe, r14 = what was read out of it
on_zc_drain:
	test	r14,r14
	jle	.lost				; (a pipe that cannot be emptied stays out)
	imul	eax,ebx,ZP_SIZE
	sub	[g_zc_pipes+rax+ZP_IN],r14d
	mov	edi,ebx
	jnz	zc_drain
	jmp	zc_put
.lost:
	ret

; epoll: sendfile until the socket is full, the body is all out, or this turn's share
; is spent. ebx, r15.
zc_ep_try:
	push	r12
	mov	r12d,ZC_EP_MAX
.again:
	zc_source
	mov	rcx,[r15+H_RREMAIN]
	cmp	rcx,rdx
	cmova	rcx,rdx
	cmp	rcx,r12
	cmova	rcx,r12
	test	rcx,rcx
	jnz	@f
	cmp	qword [r15+H_RREMAIN],0
	je	.turn
	test	r12,r12
	jz	.turn
	jmp	.failed				; (the source ended before the body)
@@:
	mov	r10,rcx				; count
	lea	rdx,[r8+HB_CPOSB]		; the offset, moved on by the kernel
	cmp	rsi,-1
	jne	@f
	xor	edx,edx				; (a file: where it is)
@@:
	mov	esi,edi
	push	rdx
	push	r10
	xor	ecx,ecx
	call	hep_fd
	mov	edi,eax
	pop	r10
	pop	rdx
	mov	eax,SYS_sendfile
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	.again
	test	rax,rax
	jle	.failed
	sub	[r15+H_RREMAIN],rax
	add	[r15+H_XBYTES],rax
	add	[g_st_zc_bytes],rax
	sub	r12,rax
	mov	r8,[r15+H_BUF]
	push	rax
	call	session_ptr
	mov	rcx,rax
	pop	rax
	test	dword [rcx+S_FLAGS],SF_FILE
	jnz	.file
	sub	[r8+HB_CLEFT],eax
	jmp	.again
.file:
	sub	[r8+HB_FLEFT],rax
	jmp	.again
.turn:
	mov	dword [r15+H_EPOP],0
	xor	eax,eax
	jmp	.queue
.failed:
	mov	dword [r15+H_EPOP],0
	mov	rax,-1
.queue:
	pop	r12
	mov	edx,2
	xor	ecx,ecx
	jmp	hep_queue
.wait:
	mov	dword [r15+H_EPOP],3		; (hep_event: writable again, on)
	mov	dword [r15+H_EPSIDE],0
	pop	r12
	ret
