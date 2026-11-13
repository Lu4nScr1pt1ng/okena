; Bulk on io_uring: a `tcp` direction that moves a lot reads and writes in
; the loop, as epoll does, instead of receives that pick buffers from the
; ring.
;
; Why: the ring's receives all complete at once, in the task work of one
; ring_enter, each into a buffer of its own; the sends that empty them go
; after. With many connections streaming, megabytes of buffers are written
; and read back out of the caches: 256 connections through two cores moved
; 35 Gbit/s where 8 moved 50 (epoll, one connection after another through
; the same buffer: 64). Here a direction, once it reads into large buffers,
; waits for its source to be readable (a poll), then reads into the buffer
; given back last (still in the cache) and writes it to the other side at
; once, BK_BUDGET reads at most before the others have their turn. A
; destination that is full keeps what is left and waits to be writable; the
; source is not read meanwhile, so backpressure is end to end as before.
; A direction has one of these at a time: a poll for its source, a poll for
; its destination, or a place on the list of those whose turn ran out.
;
; The ring's sockets are direct descriptors: each side gets a normal one too
; (IORING_OP_FIXED_FD_INSTALL, Linux 6.8; without it nothing changes), held
; in g_bfd_c / g_bfd_u (descriptor + 1, 0 none) and closed with the session.
; The reads and writes do not wait (MSG_DONTWAIT) and raise no SIGPIPE.

BK_BUDGET	:= 4			; reads a turn (1 MiB of large buffers)
BK_PEND		:= 4096			; directions whose turn ran out, at most
BK_POLLOUT	:= 4

; Splice: a direction that holds a pipe moves its bytes socket -> pipe -> socket
; inside the kernel (pages handed on, not copied through okena's memory): one
; direction on loopback, 51 Gbit/s through a buffer, 69 through a pipe of 256 KiB,
; less CPU per byte. A worker makes its pipes at its start (pipe2 is not in its
; seccomp filter); a direction takes one for a read and gives it back once the
; pipe is empty, so the pipes in use are the directions moving or waiting for
; room. None free, or a kernel that refuses: the buffer, as before.
; In a direction's buffer id (bidf), BK_PIPE and the pipe's index; lenf and
; offf as for a buffer: what went into the pipe, what came out of it.
BK_PIPES	:= 64			; a worker's pipes
BK_PSZ		:= 1 shl 18		; each 256 KiB (64 per worker: 16 MiB of the user's pipe pages)
BK_PIPE		:= 0x40000000
SPLICE_F_MOVE	:= 1

bss
	align 4
	g_bfd_c		rd 1 shl 20
	g_bfd_u		rd 1 shl 20
	g_bk_pn		dd ?		; entries in g_bk_pend
	g_bkp_nfree	dd ?		; free pipes, on g_bkp_free
	g_bkp_off	dd ?		; 1: a splice was refused, pipes not used again
	g_bkp_max	dd ?		; pipes to make (the descriptor limit's share)
	g_bkp_fd	rd BK_PIPES * 2	; read end, write end
	g_bkp_free	rd BK_PIPES
	align 8
	g_bk_pend	rq BK_PEND	; gen << 32 | direction << 31 | session
	g_bk_snap	rq BK_PEND
	g_bkp_trash	rb 1 shl 16	; a pipe left with bytes is emptied here
end bss

; The worker's pipes, before its seccomp filter. As many as the kernel gives at
; BK_PSZ (the user's pipe pages run out: fewer, the buffers for the rest).
bulk_pipes_init:
	mov	dword [g_bkp_nfree],0
	mov	dword [g_bkp_off],0
	cmp	dword [g_zc_inst],0		; io_uring: no bulk without normal descriptors
	je	bulk_pipes_none
; (epoll: its sockets are normal descriptors already)
bulk_pipes_make:
	push	rbx
	mov	dword [g_bkp_nfree],0
	mov	dword [g_bkp_off],0
	; a pipe is two descriptors the connections might want: no more than a
	; 64th of what RLIMIT_NOFILE leaves them (none under a low limit)
	mov	rax,[g_nofile]
	sub	rax,64
	jbe	.out
	shr	rax,6
	cmp	rax,BK_PIPES
	jbe	@f
	mov	eax,BK_PIPES
@@:
	test	eax,eax
	jz	.out
	mov	[g_bkp_max],eax
	xor	ebx,ebx
.make:
	lea	rdi,[g_bkp_fd+rbx*8]
	mov	esi,O_CLOEXEC or O_NONBLOCK
	mov	eax,SYS_pipe2
	syscall
	test	eax,eax
	js	.out
	mov	edi,[g_bkp_fd+rbx*8+4]
	mov	esi,F_SETPIPE_SZ
	mov	edx,BK_PSZ
	mov	eax,SYS_fcntl
	syscall
	cmp	eax,BK_PSZ
	jae	.kept
	mov	edi,[g_bkp_fd+rbx*8]		; smaller than a step: not this one
	mov	eax,SYS_close
	syscall
	mov	edi,[g_bkp_fd+rbx*8+4]
	mov	eax,SYS_close
	syscall
	jmp	.out
.kept:
	mov	ecx,[g_bkp_nfree]
	mov	[g_bkp_free+rcx*4],ebx
	inc	dword [g_bkp_nfree]
	inc	ebx
	cmp	ebx,[g_bkp_max]
	jb	.make
.out:
	pop	rbx
bulk_pipes_none:
	ret

; edi = a pipe's buffer id (BK_PIPE | index), esi = bytes still in it: back to
; the free ones, emptied first (a session that went with bytes on their way).
; Keeps rbx, r12-r15.
bulk_pipe_put:
	and	edi,not BK_PIPE
	push	rdi
	test	esi,esi
	jz	.free
	mov	edi,[g_bkp_fd+rdi*8]
.drain:
	push	rdi
	lea	rsi,[g_bkp_trash]
	mov	edx,1 shl 16
	mov	eax,SYS_read
	syscall
	pop	rdi
	test	rax,rax
	jg	.drain				; (non-blocking: -EAGAIN once empty)
.free:
	pop	rdi
	mov	ecx,[g_bkp_nfree]
	mov	[g_bkp_free+rcx*4],edi
	inc	dword [g_bkp_nfree]
	ret

; ebx = session, r13 = its record: a direction moved to large buffers. The
; normal descriptors, once (a plain `tcp` session only). Keeps rbx, r13, r14.
bulk_want:
	cmp	dword [g_zc_inst],0
	je	.out
	test	byte [g_sbig+rbx],SX_FDREQ
	jnz	.out
	test	dword [r13+S_FLAGS],SF_TUNNEL or SF_TLS_HS or SF_PREFIX
	jnz	.out
	test	dword [r13+S_FLAGS],SF_UP_OPEN
	jz	.out
	mov	eax,[r13+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_TCP
	je	.wanted
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.out
	cmp	qword [g_cnt+rbx*8],0		; http: a body by the relay (counted.inc)
	je	.out
.wanted:
	or	byte [g_sbig+rbx],SX_FDREQ
	mov	edi,OP_B_FD_U
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_FIXED_FD_INSTALL
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	cmp	dword [g_bfd_c+rbx*4],0
	jne	.out				; (had from an earlier body)
	test	dword [r13+S_FLAGS],SF_RAW
	jz	.install_c
	mov	eax,[r13+S_CLIENT]		; a normal descriptor already
	inc	eax
	mov	[g_bfd_c+rbx*4],eax
	mov	edi,[r13+S_CLIENT]		; non-blocking: a splice must not wait
	jmp	zc_nonblock
.install_c:
	mov	edi,OP_B_FD_C
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_FIXED_FD_INSTALL
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[r13+S_CLIENT]
	mov	[rax+SQE_FD],ecx
.out:
	ret

; A descriptor made (r14 = it, or -errno). Not to keep when the session
; went meanwhile: closed.
macro bulk_fd_handler name, arr
name:
	local stale, failed
	local refused, maybe_free
	call	sess_complete
	jc	stale
	test	r14,r14
	js	refused
	lea	eax,[r14+1]
	mov	[arr+rbx*4],eax
	mov	edi,r14d			; non-blocking: a splice must not wait
	call	zc_nonblock			; (the ring's own operations do not look)
	cmp	dword [g_bfd_c+rbx*4],0
	je	maybe_free
	cmp	dword [g_bfd_u+rbx*4],0
	je	maybe_free
	or	byte [g_sbig+rbx],SX_FDS
	; an HTTP body that waited for them (counted.inc): the loop takes it
	cmp	qword [g_cnt+rbx*8],0
	je	maybe_free
	test	byte [g_sbig+rbx],SX_FDREQ
	jz	maybe_free
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	maybe_free
	mov	r13,rax
	or	byte [g_sbig+rbx],SX_SYNC_U
	jmp	bulk_pump_u
refused:
	; an HTTP body that waited for them: read through the ring after all
	; (once: the other descriptor's answer finds SX_FDREQ gone)
	cmp	qword [g_cnt+rbx*8],0
	je	maybe_free
	test	byte [g_sbig+rbx],SX_FDREQ
	jz	maybe_free
	and	byte [g_sbig+rbx],not SX_FDREQ
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	maybe_free
	mov	edi,ebx
	jmp	post_recv_u
maybe_free:
	mov	edi,ebx
	jmp	session_maybe_free
stale:
	test	r14,r14
	js	.r
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	[rax+SQE_FD],r14d
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
.r:
	ret
end macro
bulk_fd_handler on_b_fd_c, g_bfd_c
bulk_fd_handler on_b_fd_u, g_bfd_u

; Session ebx (record r12): its normal descriptors close with it
; (session_close_fds). Keeps rbx, r12.
bulk_close_fds:
	mov	eax,[g_bfd_u+rbx*4]
	test	eax,eax
	jz	.client
	mov	dword [g_bfd_u+rbx*4],0
	push	rax
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	dec	ecx
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	[rax+SQE_FD],ecx
.client:
	mov	eax,[g_bfd_c+rbx*4]
	test	eax,eax
	jz	.out
	mov	dword [g_bfd_c+rbx*4],0
	test	dword [r12+S_FLAGS],SF_RAW
	jnz	.out				; (the client's own: closed as always)
	push	rax
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	dec	ecx
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	[rax+SQE_FD],ecx
.out:
	ret

; A buffer for a read: the large one given back last, else a new one, else
; a small one the same way. eax = id or NIL. Keeps rbx, r13, r14.
bulk_buf_get:
	lea	r9,[g_pbgl]
	call	.take
	jnc	.ok
	lea	r9,[g_pbg]
	call	.take
	jnc	.ok
	mov	eax,NIL
.ok:
	ret
.take:
	cmp	dword [r9+PG_MAX],0
	je	.none
	mov	ecx,[r9+PG_SN]
	test	ecx,ecx
	jz	.new
	dec	ecx
	mov	[r9+PG_SN],ecx
	mov	rax,[r9+PG_STACK]
	mov	eax,[rax+rcx*4]
	clc
	ret
.new:
	mov	ecx,[r9+PG_GIVEN]
	cmp	ecx,[r9+PG_MAX]
	jae	.none
	inc	dword [r9+PG_GIVEN]
	mov	eax,ecx
	add	eax,[r9+PG_BID0]
	clc
	ret
.none:
	stc
	ret

; edi = a buffer read and written out: back on top of its stack, the next
; read's (a small one goes back as always, for whoever waits for one).
; Keeps rbx, r13, r14.
bulk_buf_put:
	test	edi,BK_PIPE
	jz	@f
	xor	esi,esi				; a pipe, empty here
	jmp	bulk_pipe_put
@@:
	cmp	edi,BUF_MAX
	jb	.small
	mov	eax,[g_pbgl+PG_SN]
	mov	rcx,[g_pbgl+PG_STACK]
	mov	[rcx+rax*4],edi
	inc	eax
	mov	[g_pbgl+PG_SN],eax
	ret
.small:
	push	rbx
	call	buf_release
	pop	rbx
	ret

; One direction's code. src, dst: the descriptor arrays; bidf, lenf, offf:
; its buffer in the session; eof, oeof: its source's end, the other's;
; sync: its g_sbig bit; stat: its byte counter; rst_rd: the side to reset
; when its source breaks, rst_wr when its destination does; dir: 0 or 1.
; Source and destination sockets for the ring (polls, the shutdown):
; macros src_sock and dst_sock (rax = SQE, rdx = session).
macro bulk_direction sfx, src, dst, bidf, lenf, offf, eof, oeof, sync, stat, rst_rd, rst_wr, dir, src_sock, dst_sock

; the poll for the source
bulk_arm_rd_#sfx:
	if dir
	cmp	qword [g_cnt+rbx*8],0		; an HTTP body: the backend's turn
	je	@f
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	dword [rax+H_STATE],HS_RESP_READ
@@:
	end if
	mov	edi,OP_B_RD_#sfx
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	src_sock
	mov	dword [rax+SQE_OP_FLAGS],POLLIN
	ret

; the poll for room on the destination
bulk_arm_wr_#sfx:
	mov	edi,OP_B_WR_#sfx
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	dst_sock
	mov	dword [rax+SQE_OP_FLAGS],BK_POLLOUT
	ret

; on the list of those whose turn ran out (full: polled instead)
bulk_pend_#sfx:
	mov	ecx,[g_bk_pn]
	cmp	ecx,BK_PEND
	jae	bulk_arm_rd_#sfx
	mov	eax,[r13+S_GEN]
	and	eax,0xFFFFFF
	shl	rax,32
	if dir
	bts	rax,31
	end if
	or	rax,rbx
	mov	[g_bk_pend+rcx*8],rax
	inc	dword [g_bk_pn]
	ret

; Write what the buffer holds. CF: not all of it (the poll for room is out)
; or the session is closing. Keeps rbx, r13, r14.
bulk_write_#sfx:
.again:
	mov	eax,[r13+offf]
	mov	edx,[r13+lenf]
	sub	edx,eax
	jz	.done
	mov	esi,[r13+bidf]
	test	esi,BK_PIPE
	jnz	.from_pipe
	buf_ptr rsi, esi
	add	rsi,rax
	mov	edi,[dst+rbx*4]
	dec	edi
	mov	r10d,MSG_DONTWAIT or MSG_NOSIGNAL
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	jmp	.sent
.from_pipe:					; pipe -> destination, in the kernel
	and	esi,not BK_PIPE
	mov	r8d,edx				; len
	mov	edi,[g_bkp_fd+rsi*8]		; the pipe's read end
	mov	edx,[dst+rbx*4]
	dec	edx
	xor	esi,esi
	xor	r10d,r10d
	mov	r9d,SPLICE_F_MOVE or SPLICE_F_NONBLOCK
	mov	eax,SYS_splice
	syscall
.sent:
	test	rax,rax
	jle	.short
	add	[r13+offf],eax
	jmp	.again
.short:
	cmp	rax,-EINTR
	je	.again
	cmp	rax,-EAGAIN
	je	.full
	or	byte [g_sbig+rbx],rst_wr	; the destination broke
	mov	edi,ebx
	call	session_close
	stc
	ret
.full:
	call	bulk_arm_wr_#sfx
	stc
	ret
.done:
	mov	edi,[r13+bidf]
	mov	dword [r13+bidf],NIL
	call	bulk_buf_put
	clc
	ret

; Read and write until the source has nothing, the destination is full or
; the turn ran out. ebx = session, r13 = its record.
bulk_pump_#sfx:
	test	dword [r13+S_FLAGS],eof
	jnz	.out
	cmp	dword [r13+bidf],NIL
	jne	.out				; (waits for room)
	if dir
	cmp	qword [g_cnt+rbx*8],1
	je	bulk_counted_end		; an HTTP body, all of it out
	end if
	push	r14
	mov	r14d,BK_BUDGET
.read:
	; a pipe when one is free: the bytes stay in the kernel
	cmp	dword [g_bkp_off],0
	jne	.buffer
	mov	ecx,[g_bkp_nfree]
	test	ecx,ecx
	jz	.buffer
	dec	ecx
	mov	[g_bkp_nfree],ecx
	mov	eax,[g_bkp_free+rcx*4]
	mov	ecx,eax
	or	eax,BK_PIPE
	mov	[r13+bidf],eax
	mov	edx,BK_PSZ
	if dir
	mov	r8,[g_cnt+rbx*8]		; an HTTP body: no more than is left
	test	r8,r8
	jz	@f
	dec	r8
	cmp	r8,rdx
	cmovb	edx,r8d
@@:
	end if
	push	rdx
	mov	r8d,edx				; len
	mov	edx,[g_bkp_fd+rcx*8+4]		; the pipe's write end
	mov	edi,[src+rbx*4]
	dec	edi
	xor	esi,esi
	xor	r10d,r10d
	mov	r9d,SPLICE_F_MOVE or SPLICE_F_NONBLOCK
	mov	eax,SYS_splice
	syscall
	pop	rdx
	cmp	rax,-EINVAL
	jne	.got
	; this kernel or socket takes no splice: the buffers, from now on
	mov	dword [g_bkp_off],1
	mov	edi,[r13+bidf]
	mov	dword [r13+bidf],NIL
	xor	esi,esi
	call	bulk_pipe_put
.buffer:
	call	bulk_buf_get
	cmp	eax,NIL
	je	.later
	mov	[r13+bidf],eax
	mov	esi,eax
	mov	edx,BUF_SIZE
	cmp	eax,BUF_MAX
	jb	@f
	mov	edx,BUFL_SIZE
@@:
	if dir
	mov	r8,[g_cnt+rbx*8]		; an HTTP body: no more than is left
	test	r8,r8
	jz	@f
	dec	r8
	cmp	r8,rdx
	cmovb	edx,r8d
@@:
	end if
	push	rdx
	buf_ptr rsi, esi
	mov	edi,[src+rbx*4]
	dec	edi
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	pop	rdx
.got:
	test	rax,rax
	jle	.no_data
	mov	ecx,[r13+S_LST]
	add	[stat+rcx*8],rax
	mov	[r13+lenf],eax
	mov	dword [r13+offf],0
	push	rax
	push	rdx
	if dir
	call	bulk_counted_took
	end if
	mov	edi,ebx
	call	idle_touch
	call	bulk_write_#sfx
	pop	rdx
	pop	rax
	jc	.done
	if dir
	cmp	qword [g_cnt+rbx*8],1
	jne	@f
	pop	r14
	jmp	bulk_counted_end
@@:
	end if
	cmp	eax,edx
	jb	.drained			; less than a buffer: likely all of it
	dec	r14d
	jnz	.read
	pop	r14
	jmp	bulk_pend_#sfx			; more, after the others
.drained:
	pop	r14
	jmp	bulk_arm_rd_#sfx
.later:
	pop	r14
	jmp	bulk_pend_#sfx			; (no buffer now)
.no_data:
	push	rax
	mov	edi,[r13+bidf]
	mov	dword [r13+bidf],NIL
	call	bulk_buf_put
	pop	rax
	pop	r14
	cmp	rax,-EAGAIN
	je	bulk_arm_rd_#sfx
	test	rax,rax
	jz	.eof
	cmp	rax,-EINTR
	je	bulk_pump_#sfx
	or	byte [g_sbig+rbx],rst_rd	; the source broke
	mov	edi,ebx
	jmp	session_close
.eof:
	if dir
	cmp	qword [g_cnt+rbx*8],0
	jne	.both				; an HTTP body cut short: both go
	end if
	; the source is done: pass the FIN on, keep the other way open
	or	dword [r13+S_FLAGS],eof
	test	dword [r13+S_FLAGS],oeof
	jnz	.both
	mov	edi,OP_S_SHUT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SHUTDOWN
	dst_sock
	mov	dword [rax+SQE_LEN],SHUT_WR
	ret
.both:
	mov	edi,ebx
	jmp	session_close
.done:
	pop	r14
.out:
	ret

; the source is readable
on_b_rd_#sfx:
	call	sess_complete
	jc	.out
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.gone
	test	r14,r14
	js	.failed
	jmp	bulk_pump_#sfx
.failed:
	mov	edi,ebx
	jmp	session_close
.gone:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; the destination has room
on_b_wr_#sfx:
	call	sess_complete
	jc	.out
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.gone
	test	r14,r14
	js	.failed
	call	bulk_write_#sfx
	jc	.out
	jmp	bulk_pump_#sfx
.failed:
	mov	edi,ebx
	jmp	session_close
.gone:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret
end macro

; An HTTP body's piece of rax bytes read (ebx = session): less of it to
; come, its bytes for the access log, now the client's to take, and
; body_idle's clock again (as h_send_clock). Keeps rbx, r13, r14.
bulk_counted_took:
	cmp	qword [g_cnt+rbx*8],0
	je	.out
	sub	[g_cnt+rbx*8],rax
	mov	ecx,ebx
	shl	rcx,H_SHIFT
	add	rcx,[g_http_base]
	add	[rcx+H_XBYTES],rax
	mov	dword [rcx+H_STATE],HS_RESP_SEND
	push	rbx
	push	r13
	push	r14
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	pop	r14
	pop	r13
	pop	rbx
.out:
	ret

; An HTTP body all relayed (ebx = session, r13 = it): the upstream's normal
; descriptor closes now (the connection goes back to its pool, where it
; must not stay held by it), the direction is the exchange's again.
bulk_counted_end:
	mov	qword [g_cnt+rbx*8],0
	and	byte [g_sbig+rbx],not (SX_SYNC_U or SX_FDS or SX_FDREQ)
	mov	eax,[g_bfd_u+rbx*4]
	test	eax,eax
	jz	@f
	mov	dword [g_bfd_u+rbx*4],0
	push	rax
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	dec	ecx
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	[rax+SQE_FD],ecx
@@:
	jmp	http_counted_done

macro bk_client_sock
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	client_sqe rdx
end macro
macro bk_up_sock
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
end macro

bulk_direction c, g_bfd_c, g_bfd_u, S_CU_BID, S_CU_LEN, S_CU_OFF, SF_C_EOF, SF_U_EOF, \
	SX_SYNC_C, g_st_l_in, SX_RST_U, SX_RST_C, 0, bk_client_sock, bk_up_sock
bulk_direction u, g_bfd_u, g_bfd_c, S_UC_BID, S_UC_LEN, S_UC_OFF, SF_U_EOF, SF_C_EOF, \
	SX_SYNC_U, g_st_l_out, SX_RST_C, SX_RST_U, 1, bk_up_sock, bk_client_sock

; The loop's turn: the directions whose turn ran out, again (each once).
bulk_resume:
	cmp	dword [g_bk_pn],0
	je	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r15d,[g_bk_pn]
	mov	dword [g_bk_pn],0
	xor	r12d,r12d
@@:
	mov	rax,[g_bk_pend+r12*8]
	mov	[g_bk_snap+r12*8],rax
	inc	r12d
	cmp	r12d,r15d
	jb	@b
	xor	r12d,r12d
.next:
	cmp	r12d,r15d
	jae	.done
	mov	r14,[g_bk_snap+r12*8]
	inc	r12d
	mov	ebx,r14d
	and	ebx,0x7FFFFFFF
	call	session_ptr
	mov	r13,rax
	mov	eax,[r13+S_GEN]
	and	eax,0xFFFFFF
	mov	rcx,r14
	shr	rcx,32
	cmp	eax,ecx
	jne	.next
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.next
	push	r12
	push	r15
	bt	r14d,31
	jc	.u
	call	bulk_pump_c
	jmp	.back
.u:
	call	bulk_pump_u
.back:
	pop	r15
	pop	r12
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
