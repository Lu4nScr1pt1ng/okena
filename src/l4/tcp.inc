; L4 TCP proxy: one session per client connection, one upstream connection
; per session, bytes moved in both directions through provided buffers.
;
; Reading: one receive armed per direction, with buffer selection, so an
; idle connection holds no buffer at all; the kernel picks one from the
; worker's provided ring when bytes arrive. Writing: the buffer is sent
; to the other side, and only when that send has completed is the next
; receive armed on the source. Backpressure is therefore end to end: a
; slow reader stops us reading from its peer, and TCP flow control slows
; the peer down. Each direction holds at most one buffer.
;
; Connecting: SOCKET, TCP_NODELAY and CONNECT go to the kernel as one
; linked chain, with a LINK_TIMEOUT for the pool's connect timeout. A
; failed attempt moves on to another server of the pool.
;
; Closing: cancel everything on both sockets, close both direct
; descriptors, and free the session when its last completion is in.

; Session (128 bytes)
S_STATE		:= 0
S_GEN		:= 4
S_INFL		:= 8		; completions still expected
S_FLAGS		:= 12
S_CLIENT	:= 16		; direct descriptor of the client
S_LST		:= 20		; listener
S_SERVER	:= 24		; server of the current attempt
S_TRIES		:= 28
S_LAST		:= 32		; tick of the last activity
S_PREV		:= 36		; idle list (per listener), -1 = none
S_NEXT		:= 40		; idle list, or the free list
S_CU_BID	:= 44		; client -> upstream buffer in flight, -1 = none
S_CU_LEN	:= 48
S_CU_OFF	:= 52
S_UC_BID	:= 56		; upstream -> client
S_UC_LEN	:= 60
S_UC_OFF	:= 64
S_WAIT_C	:= 68		; next in the buffer wait queue (client side)
S_WAIT_U	:= 72
S_POOL		:= 96		; pool of the current connection (a route's for http)
S_PH_PREV	:= 100		; http phase deadline list (per listener and phase)
S_PH_NEXT	:= 104
S_PH_AT		:= 108		; tick the phase started
S_PH_KIND	:= 112		; PH_*, 0 = no phase timer
S_SERVER2	:= 116		; the server tried before S_SERVER (a third try avoids both)
S_SIZE		:= 128
S_SHIFT		:= 7

ST_FREE		:= 0
ST_CONNECTING	:= 1
ST_OPEN		:= 2
ST_CLOSING	:= 3

SF_C_EOF	:= 1		; client sent FIN
SF_U_EOF	:= 2		; upstream sent FIN
SF_C_WAIT	:= 4		; client receive waits for a buffer
SF_U_WAIT	:= 8
SF_UP_OPEN	:= 16		; the upstream slot holds a socket
SF_COUNTED	:= 32		; counted in the server's active connections
SF_RAW		:= 64		; the client is a normal descriptor, not a direct one
SF_PEER		:= 128		; has a side record (client address features)
SF_FDS_CLOSING	:= 256		; closing: the descriptors' closes are submitted
SF_TUNNEL	:= 512		; an http session switched to a byte tunnel

; Jump to target when session ebx belongs to an http listener.
; Clobbers rax.
macro if_http target
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	je	target
end macro

; The SQE in rax works on the client of the session in reg: drop
; IOSQE_FIXED_FILE when that client is a normal descriptor.
macro client_sqe reg
	local fixed
	test	dword [reg+S_FLAGS],SF_RAW
	jz	fixed
	and	byte [rax+SQE_FLAGS],not IOSQE_FIXED_FILE
	fixed:
end macro

NIL		:= -1

BUF_SIZE	:= 16384
BUF_SHIFT	:= 14
BUF_GROW	:= 64		; buffers added to the ring at a time (1 MiB)
BUF_MAX		:= 8192		; per worker (128 MiB of address space)
MAX_TRIES	:= 3
FAIL_THRESHOLD	:= 3		; consecutive connect failures before ejection
EJECT_TICKS	:= 10

ACC_PER_SOCKET	:= 8		; accepts in flight per socket that needs addresses
ACC_MAX		:= 2048
AC_SID		:= 0		; d: socket id
AC_LEN		:= 4		; d: address length
AC_SA		:= 8		; 28 bytes
AC_SIZE		:= 40

bss
	align 8
	g_acc_count	dd ?
	g_acc:		rb AC_SIZE * ACC_MAX
	g_acc_addr:	rb 28
	g_sessions	dd ?		; slots per worker
	g_sess_hwm	dd ?		; slots ever used (memory follows load)
	g_sess_free	dd ?		; free list head
	g_active	dd ?		; sessions not free
	g_sess_base	dq ?
	g_buf_base	dq ?
	g_pbuf_ring	dq ?
	g_pbuf_tail	dd ?
	g_buf_given	dd ?		; buffers handed to the ring so far
	g_waitq_c_head	dd ?
	g_waitq_c_tail	dd ?
	g_waitq_u_head	dd ?
	g_waitq_u_tail	dd ?
	g_rand		dq ?
	g_ls_active	rd MAX_LISTENERS
	g_ls_cap	rd MAX_LISTENERS
	g_ls_head	rd MAX_LISTENERS	; idle list: oldest first
	g_ls_tail	rd MAX_LISTENERS
	g_sv_active	rd MAX_SERVERS
	g_sv_fails	rd MAX_SERVERS
	g_sv_down	rd MAX_SERVERS		; tick until which it is ejected
	g_sv_cw		rd MAX_SERVERS		; smooth round-robin current weight
	g_pbuf_reg:	rb 40
end bss

; Size and reserve the session table and the buffers. eax = 0 or -errno.
sessions_init:
	push	rbx
	push	r12
	; slots = sum over listeners of ceil(max connections / workers)
	xor	r12d,r12d
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.sized
	imul	rcx,rbx,LS_SIZE
	mov	eax,[g_listeners+rcx+LS_MAXCONN]
	add	eax,[g_workers]
	dec	eax
	xor	edx,edx
	div	dword [g_workers]
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	mov	[g_ls_cap+rbx*4],eax
	add	r12d,eax
	mov	dword [g_ls_head+rbx*4],NIL
	mov	dword [g_ls_tail+rbx*4],NIL
	imul	ecx,ebx,PH_KINDS
	mov	dword [g_ph_head+rcx*4],NIL
	mov	dword [g_ph_head+rcx*4+4],NIL
	mov	dword [g_ph_head+rcx*4+8],NIL
	mov	dword [g_ph_head+rcx*4+12],NIL
	mov	dword [g_ph_tail+rcx*4],NIL
	mov	dword [g_ph_tail+rcx*4+4],NIL
	mov	dword [g_ph_tail+rcx*4+8],NIL
	mov	dword [g_ph_tail+rcx*4+12],NIL
	inc	ebx
	jmp	.listener
.sized:
	; three direct descriptors per session (client, upstream, pooled),
	; within RLIMIT_NOFILE, and within the slot tables
	mov	rax,[g_nofile]
	sub	rax,64
	xor	edx,edx
	mov	ecx,3
	div	rcx
	cmp	rax,r12
	jae	@f
	mov	r12d,eax
@@:
	cmp	r12d,1 shl 20
	jbe	@f
	mov	r12d,1 shl 20
@@:
	mov	[g_sessions],r12d
	mov	dword [g_sess_free],NIL
	mov	dword [g_waitq_c_head],NIL
	mov	dword [g_waitq_u_head],NIL
	; session table: address space only until used
	xor	edi,edi
	mov	esi,r12d
	shl	rsi,S_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_sess_base],rax
	; buffers
	xor	edi,edi
	mov	esi,BUF_MAX * BUF_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_buf_base],rax
	; buffers come and go 16 KiB at a time: huge pages would commit (and
	; keep) 2 MiB for each buffer touched
	mov	rdi,rax
	mov	esi,BUF_MAX * BUF_SIZE
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	; the provided ring itself: 16 bytes per entry
	xor	edi,edi
	mov	esi,BUF_MAX * 16
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_POPULATE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_pbuf_ring],rax
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	ecx,[g_worker_id]
	mov	rdx,0x9E3779B97F4A7C15
	imul	rcx,rdx
	xor	rax,rcx
	or	rax,1
	mov	[g_rand],rax
	xor	rax,[g_seed]			; request ids: a base no other worker or run shares
	mov	rdx,0xBF58476D1CE4E5B9
	imul	rax,rdx
	mov	[g_rid_next],rax
	call	peer_worker_init
	test	eax,eax
	js	.done
	call	http_worker_init
	test	eax,eax
	js	.done
	mov	dword [g_force_server],NIL
	call	balance_stagger
	xor	eax,eax
.done:
	pop	r12
	pop	rbx
	ret

; Register the provided buffer ring (group 0) and hand it a first batch.
; eax = 0 or -errno.
pbuf_register:
	mov	rax,[g_pbuf_ring]
	mov	[g_pbuf_reg],rax		; ring_addr
	mov	dword [g_pbuf_reg+8],BUF_MAX	; ring_entries
	mov	dword [g_pbuf_reg+12],0		; bgid, flags
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_PBUF_RING
	lea	rdx,[g_pbuf_reg]
	mov	r10d,1
	mov	eax,SYS_io_uring_register
	syscall
	test	eax,eax
	js	.done
	call	pbuf_grow
	xor	eax,eax
.done:
	ret

; Hand BUF_GROW more buffers to the ring. CF when all are given already.
pbuf_grow:
	mov	ecx,[g_buf_given]
	cmp	ecx,BUF_MAX
	jae	.full
	mov	edx,ecx
	add	edx,BUF_GROW
	mov	[g_buf_given],edx
.add:
	mov	edi,ecx
	push	rcx
	push	rdx
	call	pbuf_put
	pop	rdx
	pop	rcx
	inc	ecx
	cmp	ecx,edx
	jb	.add
	clc
	ret
.full:
	stc
	ret

; edi = buffer id: give it (back) to the ring.
pbuf_put:
	mov	eax,[g_pbuf_tail]
	mov	ecx,eax
	and	ecx,BUF_MAX - 1
	shl	ecx,4
	add	rcx,[g_pbuf_ring]
	mov	edx,edi
	shl	rdx,BUF_SHIFT
	add	rdx,[g_buf_base]
	mov	[rcx+BUF_ADDR],rdx
	mov	dword [rcx+BUF_LEN],BUF_SIZE
	mov	[rcx+BUF_BID],di
	inc	eax
	mov	[g_pbuf_tail],eax
	mov	rcx,[g_pbuf_ring]
	mov	[rcx+BUF_TAIL],ax		; x86 stores are ordered: entry first
	ret

; edi = buffer id: back to the ring, then wake one session waiting for a
; buffer. Entries of sessions that stopped waiting are skipped. Clobbers
; rbx.
buf_release:
	call	pbuf_put
.client:
	mov	ebx,[g_waitq_c_head]
	cmp	ebx,NIL
	je	.upstream
	call	session_ptr
	mov	ecx,[rax+S_WAIT_C]
	mov	[g_waitq_c_head],ecx
	test	dword [rax+S_FLAGS],SF_C_WAIT
	jz	.client
	and	dword [rax+S_FLAGS],not SF_C_WAIT
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.client
	mov	edi,ebx
	jmp	post_recv_c
.upstream:
	mov	ebx,[g_waitq_u_head]
	cmp	ebx,NIL
	je	.done
	call	session_ptr
	mov	ecx,[rax+S_WAIT_U]
	mov	[g_waitq_u_head],ecx
	test	dword [rax+S_FLAGS],SF_U_WAIT
	jz	.upstream
	and	dword [rax+S_FLAGS],not SF_U_WAIT
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.upstream
	mov	edi,ebx
	jmp	post_recv_u
.done:
	ret

; ebx = session index. rax = session. Keeps everything else.
session_ptr:
	mov	eax,ebx
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	ret

; user_data for op (edi) on session esi: op << 56 | gen << 32 | index.
; rax = user_data.
sess_user_data:
	mov	eax,esi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	and	ecx,0xFFFFFF
	shl	rcx,32
	mov	eax,esi
	or	rax,rcx
	mov	ecx,edi
	shl	rcx,56
	or	rax,rcx
	ret

; Get an SQE for op edi on session esi, count the completion.
; rax = SQE (user_data set), rdx = session.
sess_sqe:
	push	rdi
	push	rsi
	call	ring_get_sqe
	mov	r8,rax
	pop	rsi
	pop	rdi
	call	sess_user_data
	mov	[r8+SQE_USER_DATA],rax
	mov	edx,esi
	shl	rdx,S_SHIFT
	add	rdx,[g_sess_base]
	inc	dword [rdx+S_INFL]
	mov	rax,r8
	ret

; Workers balance independently. Without a stagger, every worker would
; start each pool at the same server, and the first connections of all
; workers would land on it together. Advance each pool by the worker index.
balance_stagger:
	push	rbx
	push	r12
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_plan_pools]
	jae	.done
	imul	rax,rbx,PL_SIZE
	mov	eax,[g_pools+rax+PL_COUNT]
	test	eax,eax
	jz	.next
	mov	ecx,eax
	mov	eax,[g_worker_id]
	xor	edx,edx
	div	ecx
	mov	r12d,edx
.advance:
	test	r12d,r12d
	jz	.next
	mov	edi,ebx
	mov	esi,NIL
	call	server_pick
	dec	r12d
	jmp	.advance
.next:
	inc	ebx
	jmp	.pool
.done:
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- accept

; A listener has one socket per worker, or more after a reload that
; lowered the worker count: no socket is closed while it may hold queued
; connections. Worker w serves sockets w, w + workers, w + 2 * workers...
; A socket id is listener | index << 8.

; edi = socket id. eax = its fd.
listener_fd:
	mov	eax,edi
	and	eax,0xFF
	imul	eax,eax,MAX_WORKERS
	mov	ecx,edi
	shr	ecx,8
	add	eax,ecx
	mov	eax,[g_lfd+rax*4]
	ret

; Call rsi for every socket id of this worker (in edi). The callback may
; clobber what a normal routine does.
for_each_socket:
	push	rbx
	push	r12
	push	r13
	mov	r13,rsi
	xor	ebx,ebx				; listener
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	mov	r12d,[g_worker_id]		; socket index
.socket:
	cmp	r12d,[g_lsocks+rbx*4]
	jae	.next
	mov	edi,r12d
	shl	edi,8
	or	edi,ebx
	call	r13
	add	r12d,[g_workers]
	jmp	.socket
.next:
	inc	ebx
	jmp	.listener
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Multishot accept into direct descriptors on every socket of this worker.
arm_accepts:
	lea	rsi,[arm_accept]
	jmp	for_each_socket

; edi = socket id: a listener that needs client addresses gets
; ACC_PER_SOCKET single-shot accepts, each with its own address buffer;
; the others one multishot accept into direct descriptors.
arm_accept:
	mov	eax,edi
	and	eax,0xFF
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	arm_accept_multi
	push	rbx
	push	r12
	mov	r12d,edi
	mov	ebx,ACC_PER_SOCKET
.slot:
	mov	eax,[g_acc_count]
	cmp	eax,ACC_MAX
	jae	.done
	inc	dword [g_acc_count]
	imul	rcx,rax,AC_SIZE
	mov	[g_acc+rcx+AC_SID],r12d
	mov	edi,eax
	call	arm_accept_slot
	dec	ebx
	jnz	.slot
.done:
	pop	r12
	pop	rbx
	ret

; edi = accept slot.
arm_accept_slot:
	push	rbx
	mov	ebx,edi
	imul	rcx,rbx,AC_SIZE
	mov	dword [g_acc+rcx+AC_LEN],28
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ACCEPT
	imul	rcx,rbx,AC_SIZE
	lea	rdx,[g_acc+rcx+AC_SA]
	mov	[rax+SQE_ADDR],rdx
	lea	rdx,[g_acc+rcx+AC_LEN]
	mov	[rax+SQE_OFF],rdx
	mov	dword [rax+SQE_OP_FLAGS],SOCK_CLOEXEC
	push	rax
	mov	edi,[g_acc+rcx+AC_SID]
	call	listener_fd
	mov	ecx,eax
	pop	rax
	mov	[rax+SQE_FD],ecx
	mov	ecx,ebx
	mov	rdx,OP_ACCEPT_A shl 56
	or	rcx,rdx
	mov	[rax+SQE_USER_DATA],rcx
	pop	rbx
	ret

; ebx = accept slot, r14 = normal descriptor or -errno.
on_accept_a:
	mov	r12d,ebx
	; take the client's address out of the slot before re-arming it: a
	; re-armed accept may complete into the same buffer
	imul	rcx,r12,AC_SIZE
	lea	rsi,[g_acc+rcx+AC_SA]
	lea	rdi,[g_acc_addr]
	mov	ecx,28
	rep	movsb
	cmp	dword [g_draining],2
	jae	@f
	cmp	r14,-ECANCELED
	je	@f
	mov	edi,ebx
	call	arm_accept_slot			; ready for the next one
@@:
	test	r14,r14
	js	.out
	imul	rcx,r12,AC_SIZE
	mov	r13d,[g_acc+rcx+AC_SID]
	and	r13d,0xFF			; listener
	mov	eax,[g_ls_active+r13*4]
	cmp	eax,[g_ls_cap+r13*4]
	jae	.refuse
	call	session_alloc
	cmp	eax,NIL
	je	.refuse
	mov	ebx,eax
	inc	dword [g_ls_active+r13*4]
	inc	qword [g_st_l_accepted+r13*8]
	inc	dword [g_active]
	call	session_ptr
	mov	r15,rax
	mov	dword [r15+S_STATE],ST_CONNECTING
	mov	dword [r15+S_INFL],0
	mov	dword [r15+S_FLAGS],SF_RAW or SF_PEER
	mov	[r15+S_CLIENT],r14d
	mov	[r15+S_LST],r13d
	mov	dword [r15+S_TRIES],0
	mov	dword [r15+S_SERVER],NIL
	mov	dword [r15+S_CU_BID],NIL
	mov	dword [r15+S_UC_BID],NIL
	mov	ecx,[g_tick]
	mov	[r15+S_LAST],ecx
	imul	rcx,r13,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	mov	[r15+S_POOL],ecx
	mov	edi,ebx
	call	idle_append
	call	peer_ptr
	mov	rdi,rax
	lea	rsi,[g_acc_addr]
	mov	ecx,28
	rep	movsb
	call	peer_admit			; per_source, PROXY header
	jc	.over
	if_http http_start
	mov	edi,ebx
	jmp	session_connect
.over:
	; refused, not admitted: count it there only
	inc	qword [g_st_l_source+r13*8]
	dec	qword [g_st_l_accepted+r13*8]
	mov	edi,ebx
	jmp	session_close
.refuse:
	inc	qword [g_st_l_full+r13*8]
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	[rax+SQE_FD],r14d
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
.out:
	ret

; ebx = session (client address in its side record, client descriptor
; in S_CLIENT), r13d = listener. Applies per_source and builds the PROXY
; header. CF when the client is over its per-source limit.
peer_admit:
	call	peer_ptr
	mov	dword [rax+P_SLOT],-1
	mov	dword [rax+P_HLEN],0
	imul	rcx,r13,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_PER_SOURCE],0
	je	.pp
	call	src_acquire
	jc	.over
.pp:
	imul	rcx,r13,LS_SIZE
	test	dword [g_listeners+rcx+LS_FLAGS],LSF_PP_V1 or LSF_PP_V2
	jz	.ok
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	call	peer_local
	call	pp_build
.ok:
	clc
	ret
.over:
	stc
	ret

; edi = socket id: one multishot accept into direct descriptors.
arm_accept_multi:
	push	rbx
	mov	ebx,edi
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ACCEPT
	mov	word [rax+SQE_IOPRIO],IORING_ACCEPT_MULTISHOT
	push	rax
	mov	edi,ebx
	call	listener_fd
	mov	ecx,eax
	pop	rax
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_FILE_INDEX],IORING_FILE_INDEX_ALLOC
	mov	ecx,ebx
	mov	rdx,OP_ACCEPT shl 56
	or	rcx,rdx
	mov	[rax+SQE_USER_DATA],rcx
	pop	rbx
	ret

; ebx = socket id, r14 = direct descriptor or -errno, r15d = flags.
on_accept:
	test	r15d,IORING_CQE_F_MORE
	jnz	@f
	cmp	dword [g_draining],2
	jae	@f
	mov	edi,ebx
	call	arm_accept			; the multishot ended: re-arm it
@@:
	and	ebx,0xFF			; the listener
	test	r14,r14
	js	.error
	; room on this listener?
	mov	eax,[g_ls_active+rbx*4]
	cmp	eax,[g_ls_cap+rbx*4]
	jae	.refuse
	call	session_alloc
	cmp	eax,NIL
	je	.refuse
	mov	r12d,eax
	inc	dword [g_ls_active+rbx*4]
	inc	qword [g_st_l_accepted+rbx*8]
	inc	dword [g_active]
	mov	r13d,ebx			; listener
	mov	ebx,r12d
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],0
	mov	[rax+S_CLIENT],r14d
	mov	[rax+S_LST],r13d
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	imul	rcx,r13,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	mov	[rax+S_POOL],ecx
	mov	edi,ebx
	call	idle_append
	mov	edi,ebx
	jmp	session_connect
.refuse:
	; no slot: close the new connection at once
	inc	qword [g_st_l_full+rbx*8]
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	lea	ecx,[r14+1]
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret
.error:
	; ENFILE/EMFILE (table full), ECONNABORTED, ...: nothing to undo
	ret

; eax = free session index or NIL.
session_alloc:
	mov	eax,[g_sess_free]
	cmp	eax,NIL
	je	.fresh
	mov	ecx,eax
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	mov	edx,[rcx+S_NEXT]
	mov	[g_sess_free],edx
	ret
.fresh:
	mov	eax,[g_sess_hwm]
	cmp	eax,[g_sessions]
	jae	.none
	inc	dword [g_sess_hwm]
	ret
.none:
	mov	eax,NIL
	ret

; ------------------------------------------------------------ idle lists

; edi = session: append to its listener's idle list (newest last).
idle_append:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_LST]
	mov	edx,[g_ls_tail+rcx*4]
	mov	[rax+S_PREV],edx
	mov	dword [rax+S_NEXT],NIL
	mov	[g_ls_tail+rcx*4],edi
	cmp	edx,NIL
	je	.first
	shl	rdx,S_SHIFT
	add	rdx,[g_sess_base]
	mov	[rdx+S_NEXT],edi
	ret
.first:
	mov	[g_ls_head+rcx*4],edi
	ret

; edi = session: unlink from its idle list.
idle_remove:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_LST]
	mov	edx,[rax+S_PREV]
	mov	r8d,[rax+S_NEXT]
	cmp	edx,NIL
	je	.head
	mov	r9d,edx
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_NEXT],r8d
	jmp	.next
.head:
	mov	[g_ls_head+rcx*4],r8d
.next:
	cmp	r8d,NIL
	je	.tail
	mov	r9d,r8d
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_PREV],edx
	ret
.tail:
	mov	[g_ls_tail+rcx*4],edx
	ret

; edi = session: activity now; move it to the end of its list. A true
; LRU (not once per second): pressure closes the least recently used,
; and within a second that order still has to be right.
idle_touch:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	cmp	dword [rax+S_NEXT],NIL
	je	.done				; already the newest
	push	rdi
	call	idle_remove
	pop	rdi
	jmp	idle_append
.done:
	ret

; Close sessions idle for longer than their listener allows. Oldest first,
; so this stops at the first one still in time: O(expired).
;
; It is also the overload manager for connections. A listener holding
; 90% of its connections is under pressure: its idle timeout drops to at
; most PRESSURE_IDLE seconds. At 95%, the sessions idle the longest (at
; least a second) are closed until it is back to 90%, so new clients get
; room instead of being refused while idle ones sit on it. Each episode
; is logged once; closures are counted (okena_listener_evicted_total).
PRESSURE_IDLE	:= 10

idle_expire:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.done
	imul	rdx,r12,LS_SIZE
	mov	r13d,[g_listeners+rdx+LS_IDLE]	; idle limit
	mov	eax,[g_ls_cap+r12*4]
	imul	r14d,eax,9
	xor	edx,edx
	mov	eax,r14d
	mov	ecx,10
	div	ecx
	mov	r14d,eax			; 90%: pressure starts, eviction target
	mov	eax,[g_ls_cap+r12*4]
	imul	eax,eax,19
	xor	edx,edx
	mov	ecx,20
	div	ecx
	mov	r15d,eax			; 95%: eviction starts
	mov	eax,[g_ls_active+r12*4]
	cmp	eax,r14d
	jb	.calm
	cmp	r13d,PRESSURE_IDLE
	jbe	@f
	mov	r13d,PRESSURE_IDLE
@@:
	cmp	byte [g_ls_pressure+r12],0
	jne	.evict_check
	mov	byte [g_ls_pressure+r12],1
	call	log_begin
	out_lit 'listener '
	imul	rax,r12,LS_SIZE
	mov	rsi,[g_listeners+rax+LS_TEXT]
	mov	edx,[g_listeners+rax+LS_TLEN]
	call	out_str
	out_lit ' holds 90% of its connections: idle timeout down to 10 s, the longest idle closed above 95%'
	call	log_end
.evict_check:
	; above 95%: evict down to 90%
	xor	eax,eax
	mov	ecx,[g_ls_active+r12*4]
	cmp	ecx,r15d
	jb	@f
	inc	eax
@@:
	mov	[g_evicting],eax
	jmp	.head
.calm:
	mov	byte [g_ls_pressure+r12],0
	mov	dword [g_evicting],0
.head:
	mov	ebx,[g_ls_head+r12*4]
	cmp	ebx,NIL
	je	.next
	call	session_ptr
	mov	ecx,[g_tick]
	sub	ecx,[rax+S_LAST]
	jz	.fresh
	cmp	dword [rax+S_PH_KIND],PH_RESPONSE
	jne	.fresh
	mov	edi,ebx				; waiting on its backend: not idle,
	call	idle_touch			; the response timeout owns it
	jmp	.head
.fresh:
	cmp	ecx,r13d
	ja	.close				; never early: a tick may be a second late, not early
	cmp	dword [g_evicting],0
	je	.next
	test	ecx,ecx
	jz	.next				; active this second: keep it
	mov	eax,[g_ls_active+r12*4]
	sub	eax,[g_evicted_now]
	cmp	eax,r14d
	jbe	.stop_evicting
	inc	qword [g_st_l_evicted+r12*8]
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.close				; epoll frees the slot at once
	inc	dword [g_evicted_now]
.close:
	mov	edi,ebx
	call	session_close
	jmp	.head
.stop_evicting:
	mov	dword [g_evicting],0
.next:
	mov	dword [g_evicted_now],0
	inc	r12d
	jmp	.listener
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

bss
	g_ls_pressure	rb MAX_LISTENERS
	g_evicting	dd ?
	g_evicted_now	dd ?		; closures this tick (they free their slots later)
end bss

; ------------------------------------------------------------- balancing

; xorshift64. rax = random.
rand64:
	mov	rax,[g_rand]
	mov	rcx,rax
	shl	rcx,13
	xor	rax,rcx
	mov	rcx,rax
	shr	rcx,7
	xor	rax,rcx
	mov	rcx,rax
	shl	rcx,17
	xor	rax,rcx
	mov	[g_rand],rax
	ret

; r12 = session about to pick again: on a third try, also avoid the server
; tried before the last one (server_pick reads g_pick_avoid2 once).
pick_avoid_tried:
	mov	dword [g_pick_avoid2],0
	cmp	dword [r12+S_TRIES],2
	jbe	@f
	mov	eax,[r12+S_SERVER2]
	inc	eax
	mov	[g_pick_avoid2],eax		; server + 1, 0 = none
@@:
	ret

bss
	g_pick_avoid2	dd ?
end bss

; Slow start, per worker: when a server became usable again (health back
; up, passive ejection over, a connect that succeeded after it), in
; milliseconds of the TSC + 1; 0 once its pool's window has passed, or
; for a server that never left. Time is read only while one ramps.
bss
	g_sv_since	rd MAX_SERVERS
end bss

; edi = server: it is usable again from now.
sv_comeback:
	push	rdx
	call	sv_now_ms
	inc	eax				; stored + 1: 0 means not ramping
	jnz	@f
	inc	eax
@@:
	mov	[g_sv_since+rdi*4],eax
	pop	rdx
	ret

; eax = milliseconds of the TSC (wrapping; differences are what count).
; Clobbers rdx.
sv_now_ms:
	push	rcx
	rdtsc
	shl	rdx,32
	or	rax,rdx
	imul	rcx,[g_tsc_per_us],1000
	xor	edx,edx
	div	rcx
	pop	rcx
	ret

; edi = server (ramping), rbx = its pool. eax = milliseconds into its
; window; CF clear when the window is over (and its mark is cleared).
; Clobbers rdx.
sv_ramp:
	call	sv_now_ms
	inc	eax
	sub	eax,[g_sv_since+rdi*4]
	push	rcx
	imul	ecx,[rbx+PL_SLOW],1000
	cmp	eax,ecx
	pop	rcx
	jae	.over
	stc
	ret
.over:
	mov	dword [g_sv_since+rdi*4],0
	clc
	ret

; edi = server, rbx = its pool. eax = its weight, scaled down while it
; slow-starts. Keeps every register but rax.
sv_weight:
	imul	eax,edi,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
	cmp	dword [g_sv_since+rdi*4],0
	jne	.ramp
	ret
.ramp:
	push	rcx
	push	rdx
	push	rax
	call	sv_ramp				; eax = ms into the window
	jnc	.full
	lea	ecx,[rax+1]
	pop	rax
	mul	ecx				; weight * elapsed / window
	imul	ecx,[rbx+PL_SLOW],1000
	div	ecx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	pop	rdx
	pop	rcx
	ret
.full:
	pop	rax
	pop	rdx
	pop	rcx
	ret

; edi = server index. CF when it may be chosen in pass esi
; (0 = healthy primaries, 1 = healthy backups, 2 = every primary).
server_eligible:
	imul	rax,rdi,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.no				; a name slot without an address
	mov	ecx,[g_servers+rax+SV_BACKUP]
	cmp	esi,1
	je	.backups
	test	ecx,ecx
	jnz	.no
	cmp	esi,2
	je	.yes
	jmp	.health
.backups:
	test	ecx,ecx
	jz	.no
.health:
	mov	rax,[g_health_tbl]
	cmp	dword [rax+rdi*8],HC_UP
	jne	.no				; failing its active checks
	; came back since this worker last looked (the count of comebacks is
	; in the same 8 bytes as the state): out of any passive ejection,
	; and ramped up from now, not from the next tick
	mov	ecx,[rax+rdi*8+4]
	cmp	ecx,[g_hc_seen+rdi*4]
	jne	.health_back
	mov	eax,[g_sv_down+rdi*4]
	cmp	eax,[g_tick]
	ja	.no				; passively ejected here
	test	eax,eax
	jnz	.ejection_over
.yes:
	stc
	ret
.health_back:
	mov	[g_hc_seen+rdi*4],ecx
	mov	dword [g_sv_down+rdi*4],0
	mov	dword [g_sv_fails+rdi*4],0
	call	sv_comeback
	stc
	ret
.ejection_over:
	mov	dword [g_sv_down+rdi*4],0	; its time is up: back, slowly
	call	sv_comeback
	stc
	ret
.no:
	clc
	ret

; edi = pool, esi = server to avoid (a retry) or NIL. eax = server.
server_pick:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	imul	rbx,rdi,PL_SIZE
	lea	rbx,[g_pools+rbx]
	mov	ebp,esi
	xor	r13d,r13d			; pass
	; least-request: two random servers, the one with fewer requests in
	; flight per weight. O(1) whatever the pool size; the passes below
	; (backups, panic, avoidance with one server left) only when the
	; draws find nothing usable.
	cmp	dword [rbx+PL_BALANCE],BAL_LEAST_REQ
	jne	.pass
	mov	r14d,ebp
	call	.p2c
	cmp	eax,NIL
	jne	.out
.pass:
	; with more than one eligible server, skip the one to avoid
	mov	r14d,ebp
	call	.count
	test	eax,eax
	jnz	@f
	; none. A retry moves on to the next pass rather than back to a
	; server it already tried; only the last pass (every primary), with
	; nothing else left, may give the one tried before the last again
	cmp	dword [g_pick_avoid2],0
	je	@f
	cmp	r13d,2
	jb	@f				; (count 0: .next_pass below)
	mov	dword [g_pick_avoid2],0
	jmp	.pass
@@:
	cmp	eax,1
	ja	.balance
	mov	r14d,NIL
	test	eax,eax
	jz	.next_pass
	; one eligible server. A retry whose only choice here is the server
	; that just failed goes to the next pass (backups, then every
	; primary: panic) rather than back to it; health may simply not have
	; noticed yet that it is down while another one is back.
	cmp	ebp,NIL
	je	.balance
	cmp	r13d,2
	jae	.balance
	mov	edi,ebp
	mov	esi,r13d
	call	.eligible
	jnc	.balance
.next_pass:
	inc	r13d
	cmp	r13d,3
	jb	.pass
	mov	eax,NIL				; no address at all (names not resolved)
	jmp	.out
.balance:
	mov	eax,[rbx+PL_BALANCE]
	cmp	eax,BAL_LEAST_CONN
	je	.least
	cmp	eax,BAL_LEAST_REQ
	je	.least				; the draws failed: scan this pass
	cmp	eax,BAL_RANDOM
	je	.random
	; smooth weighted round robin
	xor	r15d,r15d			; total weight
	mov	r12d,NIL			; best
	mov	ecx,[rbx+PL_FIRST]
	mov	r8d,ecx
	add	r8d,[rbx+PL_COUNT]
.rr:
	cmp	ecx,r8d
	jae	.rr_done
	cmp	ecx,r14d
	je	.rr_next
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	push	r8
	call	.eligible
	pop	r8
	pop	rcx
	jnc	.rr_next
	mov	edi,ecx
	call	sv_weight
	add	r15d,eax
	add	[g_sv_cw+rcx*4],eax
	cmp	r12d,NIL
	je	.rr_best
	mov	eax,[g_sv_cw+rcx*4]
	cmp	eax,[g_sv_cw+r12*4]
	jle	.rr_next
.rr_best:
	mov	r12d,ecx
.rr_next:
	inc	ecx
	jmp	.rr
.rr_done:
	sub	[g_sv_cw+r12*4],r15d
	mov	eax,r12d
	jmp	.out
.least:
	; fewest active connections relative to weight; random start for ties
	call	rand64
	xor	edx,edx
	mov	ecx,[rbx+PL_COUNT]
	div	rcx
	mov	r15d,edx			; start offset
	mov	r12d,NIL
	xor	r9d,r9d				; visited
.lc:
	cmp	r9d,[rbx+PL_COUNT]
	jae	.lc_done
	mov	ecx,r15d
	add	ecx,r9d
	cmp	ecx,[rbx+PL_COUNT]
	jb	@f
	sub	ecx,[rbx+PL_COUNT]
@@:
	add	ecx,[rbx+PL_FIRST]
	inc	r9d
	cmp	ecx,r14d
	je	.lc
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	push	r9
	call	.eligible
	pop	r9
	pop	rcx
	jnc	.lc
	cmp	r12d,NIL
	je	.lc_best
	; active[c] * weight[best] < active[best] * weight[c]
	mov	edi,ecx
	call	sv_weight
	mov	r10d,eax
	mov	edi,r12d
	call	sv_weight
	mov	r11d,eax
	mov	eax,[g_sv_active+rcx*4]
	imul	rax,r11
	mov	edx,[g_sv_active+r12*4]
	imul	rdx,r10
	cmp	rax,rdx
	jae	.lc
.lc_best:
	mov	r12d,ecx
	jmp	.lc
.lc_done:
	mov	eax,r12d
	jmp	.out
.random:
	; weighted: pick r in [0, total) and walk
	xor	r15d,r15d
	mov	ecx,[rbx+PL_FIRST]
	mov	r8d,ecx
	add	r8d,[rbx+PL_COUNT]
.rw:
	cmp	ecx,r8d
	jae	.rw_total
	cmp	ecx,r14d
	je	@f
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	push	r8
	call	.eligible
	pop	r8
	pop	rcx
	jnc	@f
	mov	edi,ecx
	call	sv_weight
	add	r15d,eax
@@:
	inc	ecx
	jmp	.rw
.rw_total:
	call	rand64
	xor	edx,edx
	mov	ecx,r15d
	div	rcx
	mov	r15d,edx			; r
	mov	ecx,[rbx+PL_FIRST]
.rw_walk:
	mov	r12d,ecx
	cmp	ecx,r14d
	je	.rw_skip
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	call	.eligible
	pop	rcx
	jnc	.rw_skip
	mov	edi,ecx
	call	sv_weight
	cmp	r15d,eax
	jb	.rw_found
	sub	r15d,eax
.rw_skip:
	inc	ecx
	cmp	ecx,r8d
	jb	.rw_walk
.rw_found:
	mov	eax,r12d
	jmp	.out
; eax = eligible servers in pass r13d, not counting r14d
; eax = a usable server of the pool in rbx (pass r13d, avoiding r14d),
; or NIL after three draws found none.
.p2c:
	mov	r15d,3
.draw:
	mov	r12d,[rbx+PL_COUNT]
	cmp	r12d,2
	jb	.p2c_none
	call	rand64
	mov	r10,rax
	mov	eax,r10d
	mul	r12d				; edx = a in [0, n): multiply-shift, no div
	mov	r11d,edx
	shr	r10,32
	mov	eax,r10d
	lea	ecx,[r12-1]
	mul	ecx				; b in [0, n-1), then skip a
	cmp	edx,r11d
	jb	@f
	inc	edx
@@:
	add	r11d,[rbx+PL_FIRST]
	add	edx,[rbx+PL_FIRST]
	mov	r12d,edx
	mov	edi,r11d
	call	.usable
	setc	r10b
	mov	edi,r12d
	call	.usable
	jnc	.only_a
	test	r10b,r10b
	jz	.take_b
	; both: in_flight[a] * weight[b] against in_flight[b] * weight[a]
	mov	edi,r11d
	call	sv_weight
	mov	r8d,eax
	mov	edi,r12d
	call	sv_weight
	mov	r9d,eax
	mov	eax,[g_sv_active+r11*4]
	imul	rax,r9
	mov	edx,[g_sv_active+r12*4]
	imul	rdx,r8
	cmp	rax,rdx
	ja	.take_b
	mov	eax,r11d			; a tie keeps a (already random)
	ret
.take_b:
	mov	eax,r12d
	ret
.only_a:
	test	r10b,r10b
	jz	.redraw
	mov	eax,r11d
	ret
.redraw:
	dec	r15d
	jnz	.draw
.p2c_none:
	mov	eax,NIL
	ret
; edi = server, esi = pass: CF when eligible and not the server tried
; before the last (g_pick_avoid2). Every scan and count uses this.
.eligible:
	lea	eax,[rdi+1]
	cmp	eax,[g_pick_avoid2]
	je	.unusable
	jmp	server_eligible

; edi = server: CF when it may be picked now (not avoided, eligible).
.usable:
	cmp	edi,r14d
	je	.unusable
	lea	eax,[rdi+1]
	cmp	eax,[g_pick_avoid2]
	je	.unusable
	mov	esi,r13d
	cmp	dword [g_sv_since+rdi*4],0
	je	server_eligible			; the common case: not ramping
	push	rdi
	call	server_eligible
	pop	rdi
	jnc	.unusable
	; slow start: drawn with probability elapsed / window, so its share
	; grows smoothly from nothing to all of it
	call	sv_ramp				; eax = ms into the window
	jnc	.ramped
	push	rax
	push	rcx
	call	rand64
	pop	rcx
	imul	edx,[rbx+PL_SLOW],1000
	mul	edx				; edx = uniform in [0, window ms)
	pop	rax
	cmp	edx,eax
	jae	.unusable			; not this time
.ramped:
	stc
	ret
.unusable:
	clc
	ret

.count:
	push	r12
	xor	r12d,r12d
	mov	ecx,[rbx+PL_FIRST]
	mov	r8d,ecx
	add	r8d,[rbx+PL_COUNT]
.count_next:
	cmp	ecx,r8d
	jae	.count_done
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	push	r8
	call	.eligible
	pop	r8
	pop	rcx
	adc	r12d,0
	inc	ecx
	jmp	.count_next
.count_done:
	mov	eax,r12d
	pop	r12
	ret
.out:
	mov	dword [g_pick_avoid2],0
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- connect

; edi = session: (re)connect to a server of its listener's pool.
session_connect:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	call	session_ptr
	mov	r12,rax
	inc	dword [r12+S_TRIES]
	; release the previous attempt's server count
	call	session_uncount
	mov	eax,[g_force_server]
	mov	dword [g_force_server],NIL
	cmp	eax,NIL
	jne	@f
	call	pick_avoid_tried
	mov	edi,[r12+S_POOL]
	mov	esi,[r12+S_SERVER]
	call	server_pick
	cmp	eax,NIL
	je	.nowhere
@@:
	mov	ecx,[r12+S_SERVER]
	mov	[r12+S_SERVER2],ecx
	mov	[r12+S_SERVER],eax
	inc	dword [g_sv_active+rax*4]
	or	dword [r12+S_FLAGS],SF_COUNTED
	imul	r13,rax,SV_SIZE
	lea	r13,[g_servers+r13]
	; an earlier attempt left a socket in the upstream slot: close it first
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.socket
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	byte [rax+SQE_FLAGS],IOSQE_IO_HARDLINK
	mov	ecx,[g_upslot+rbx*4]
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	jmp	.slot_ready
.socket:
	; a slot for the upstream socket
	call	upslot_alloc
	cmp	eax,NIL
	je	.nowhere			; out of slots: as if unreachable
	mov	[g_upslot+rbx*4],eax
.slot_ready:
	or	dword [r12+S_FLAGS],SF_UP_OPEN
	mov	edi,OP_S_SOCKET
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SOCKET
	mov	byte [rax+SQE_FLAGS],IOSQE_IO_LINK
	mov	ecx,[r13+SV_FAMILY]
	mov	[rax+SQE_FD],ecx		; domain
	mov	qword [rax+SQE_OFF],SOCK_STREAM	; type
	mov	ecx,[g_upslot+rbx*4]
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	cmp	dword [r13+SV_FAMILY],AF_UNIX
	je	.connect
	; TCP_NODELAY on the upstream (a hard link: an old kernel without
	; socket commands must not cancel the connect)
	mov	edi,OP_S_OPT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_HARDLINK
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	dword [rax+SQE_LEVEL],IPPROTO_TCP
	mov	dword [rax+SQE_OPTNAME],TCP_NODELAY
	mov	dword [rax+SQE_OPTLEN],4
	lea	rcx,[one_int]
	mov	[rax+SQE_OPTVAL],rcx
.connect:
	mov	edi,OP_S_CONNECT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CONNECT
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_LINK
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[r13+SV_SA]
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[r13+SV_SALEN]
	mov	[rax+SQE_OFF],rcx
	mov	edi,OP_S_LTIMEOUT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_LINK_TIMEOUT
	mov	ecx,[r12+S_POOL]
	imul	rcx,rcx,PL_SIZE
	lea	rcx,[g_pools+rcx+PL_TIMEOUT]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	pop	r13
	pop	r12
	pop	rbx
	ret
.nowhere:
	pop	r13
	pop	r12
	pop	rbx
	if_http http_connect_failed		; no address: 502
	mov	edi,ebx
	jmp	session_close

; ebx = session: move bytes both ways.
start_relay:
	mov	edi,ebx
	call	post_recv_c
	mov	edi,ebx
	jmp	post_recv_u

; edi = session: send (the rest of) its PROXY header upstream.
post_send_pp:
	push	rbx
	mov	ebx,edi
	mov	esi,edi
	mov	edi,OP_S_SEND_PP
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	rdx,rax
	call	peer_ptr
	mov	ecx,[rax+P_HOFF]
	lea	rsi,[rax+P_HDR+rcx]
	mov	[rdx+SQE_ADDR],rsi
	mov	esi,[rax+P_HLEN]
	sub	esi,ecx
	mov	[rdx+SQE_LEN],esi
	mov	dword [rdx+SQE_OP_FLAGS],MSG_NOSIGNAL
	pop	rbx
	ret

on_s_send_pp:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.failed
	call	peer_ptr
	add	[rax+P_HOFF],r14d
	mov	ecx,[rax+P_HOFF]
	cmp	ecx,[rax+P_HLEN]
	jb	.more
	jmp	start_relay
.more:
	mov	edi,ebx
	jmp	post_send_pp
.failed:
	mov	edi,ebx
	jmp	session_close
.not_open:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; Drop the session (in r12) from its server's active count.
session_uncount:
	test	dword [r12+S_FLAGS],SF_COUNTED
	jz	.done
	and	dword [r12+S_FLAGS],not SF_COUNTED
	mov	eax,[r12+S_SERVER]
	dec	dword [g_sv_active+rax*4]
.done:
	ret

; Check the generation and count the completion. ebx = index,
; r12d = generation. rax = session, CF when stale.
sess_complete:
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	and	ecx,0xFFFFFF
	cmp	ecx,r12d
	jne	.stale
	dec	dword [rax+S_INFL]
	clc
	ret
.stale:
	stc
	ret

on_s_socket:
on_s_done:
	call	sess_complete
	jc	.out
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

on_s_connect:
	call	sess_complete
	jc	.out
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_CLOSING
	je	.free
	test	r14,r14
	js	.failed
	; connected
	mov	dword [r13+S_STATE],ST_OPEN
	mov	edi,[r13+S_SERVER]
	call	server_ok
	if_http http_connected
	; a PROXY protocol header goes before any byte of the client
	mov	eax,[r13+S_LST]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PP_V1 or LSF_PP_V2
	jz	start_relay
	mov	edi,ebx
	jmp	post_send_pp
.failed:
	mov	edi,[r13+S_SERVER]
	mov	rsi,r14
	call	server_failed
	cmp	dword [r13+S_TRIES],MAX_TRIES
	jae	.give_up
	mov	eax,[r13+S_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_COUNT]
	cmp	[r13+S_TRIES],ecx
	jae	.give_up
	mov	edi,ebx
	jmp	session_connect
.give_up:
	if_http http_connect_failed
	mov	edi,ebx
	jmp	session_close
.free:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; edi = server: a connection succeeded.
server_ok:
	inc	qword [g_st_s_connects+rdi*8]
	cmp	dword [g_sv_down+rdi*4],0
	je	@f
	mov	dword [g_sv_down+rdi*4],0
	call	sv_comeback
	push	rdi
	call	log_begin
	out_lit 'backend '
	pop	rdi
	push	rdi
	call	log_server
	out_lit ' is reachable again'
	call	log_end
	pop	rdi
@@:
	mov	dword [g_sv_fails+rdi*4],0
	ret

; edi = server, rsi = -errno of the failed attempt.
server_failed:
	inc	qword [g_st_s_fails+rdi*8]
	; a name's address that fails may be stale: ask for a fresh lookup
	imul	rax,rdi,SV_SIZE
	mov	eax,[g_servers+rax+SV_GROUP]
	test	eax,eax
	jz	@f
	mov	rcx,[g_dns_table]
	mov	dword [rcx+DT_WANT_OFF+rax*4-4],1
@@:
	inc	dword [g_sv_fails+rdi*4]
	cmp	dword [g_sv_fails+rdi*4],FAIL_THRESHOLD
	jb	.done
	mov	eax,[g_sv_down+rdi*4]
	cmp	eax,[g_tick]
	ja	.done				; already ejected
	mov	eax,[g_tick]
	add	eax,EJECT_TICKS
	mov	[g_sv_down+rdi*4],eax
	mov	dword [g_sv_fails+rdi*4],0
	push	rdi
	push	rsi
	call	log_begin
	out_lit 'backend '
	mov	rdi,[rsp+8]
	call	log_server
	out_lit ' ejected for 10 s after 3 failed connects ('
	pop	rax
	neg	rax
	call	errno_text
	out_lit ')'
	call	log_end
	pop	rdi
.done:
	ret

; edi = server: print its address.
log_server:
	imul	rax,rdi,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	jmp	out_str

; eax = errno: a short text.
errno_text:
	cmp	eax,ECONNREFUSED
	jne	@f
	out_lit 'connection refused'
	ret
@@:
	cmp	eax,ECANCELED
	jne	@f
	out_lit 'timed out'
	ret
@@:
	cmp	eax,ETIMEDOUT
	jne	@f
	out_lit 'timed out'
	ret
@@:
	cmp	eax,ENOENT
	jne	@f
	out_lit 'no such socket'
	ret
@@:
	push	rax
	out_lit 'errno '
	pop	rax
	jmp	out_u64

; ------------------------------------------------------------- data path

; edi = session: receive from the client.
post_recv_c:
	mov	esi,edi
	push	rsi
	mov	edi,OP_S_RECV_C
	call	sess_sqe
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_BUFFER_SELECT
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	word [rax+SQE_BUF_GROUP],0
	client_sqe rdx
	ret

; edi = session: receive from the upstream.
post_recv_u:
	mov	esi,edi
	push	rsi
	mov	edi,OP_S_RECV_U
	call	sess_sqe
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_BUFFER_SELECT
	mov	ecx,[g_upslot+rsi*4]
	mov	[rax+SQE_FD],ecx
	mov	word [rax+SQE_BUF_GROUP],0
	ret

; edi = session: send the client's bytes upstream (what is left of them).
post_send_u:
	mov	esi,edi
	push	rsi
	mov	edi,OP_S_SEND_U
	call	sess_sqe
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rsi*4]
	mov	[rax+SQE_FD],ecx
	mov	ecx,[rdx+S_CU_BID]
	shl	rcx,BUF_SHIFT
	add	rcx,[g_buf_base]
	mov	r8d,[rdx+S_CU_OFF]
	add	rcx,r8
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[rdx+S_CU_LEN]
	sub	ecx,r8d
	mov	[rax+SQE_LEN],ecx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	ret

; edi = session: send the upstream's bytes to the client.
post_send_c:
	mov	esi,edi
	push	rsi
	mov	edi,OP_S_SEND_C
	call	sess_sqe
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe rdx
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	ecx,[rdx+S_UC_BID]
	shl	rcx,BUF_SHIFT
	add	rcx,[g_buf_base]
	mov	r8d,[rdx+S_UC_OFF]
	add	rcx,r8
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[rdx+S_UC_LEN]
	sub	ecx,r8d
	mov	[rax+SQE_LEN],ecx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	ret

; Return the buffer a completion carried, if any (r15d = cqe flags).
release_cqe_buffer:
	test	r15d,IORING_CQE_F_BUFFER
	jz	.none
	mov	edi,r15d
	shr	edi,IORING_CQE_BUFFER_SHIFT
	push	rbx
	call	buf_release
	pop	rbx
.none:
	ret

on_s_recv_c:
	call	sess_complete
	jc	release_cqe_buffer
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.end_or_error
	mov	eax,[r13+S_LST]
	add	[g_st_l_in+rax*8],r14
	mov	eax,r15d
	shr	eax,IORING_CQE_BUFFER_SHIFT
	mov	[r13+S_CU_BID],eax
	mov	[r13+S_CU_LEN],r14d
	mov	dword [r13+S_CU_OFF],0
	mov	edi,ebx
	call	idle_touch
	mov	edi,ebx
	jmp	post_send_u
.end_or_error:
	jz	.eof
	cmp	r14,-ENOBUFS
	je	.no_buffer
	mov	edi,ebx
	jmp	session_close
.eof:
	; the client is done sending: pass the FIN on, keep the other way open
	or	dword [r13+S_FLAGS],SF_C_EOF
	test	dword [r13+S_FLAGS],SF_U_EOF
	jnz	.both
	mov	edi,OP_S_SHUT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SHUTDOWN
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_LEN],SHUT_WR
	ret
.both:
	mov	edi,ebx
	jmp	session_close
.no_buffer:
	call	pbuf_grow
	jc	.wait
	mov	edi,ebx
	jmp	post_recv_c
.wait:
	or	dword [r13+S_FLAGS],SF_C_WAIT
	mov	dword [r13+S_WAIT_C],NIL
	mov	eax,[g_waitq_c_head]
	cmp	eax,NIL
	jne	@f
	mov	[g_waitq_c_head],ebx
	mov	[g_waitq_c_tail],ebx
	ret
@@:
	mov	eax,[g_waitq_c_tail]
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	[rax+S_WAIT_C],ebx
	mov	[g_waitq_c_tail],ebx
	ret
.not_open:
	call	release_cqe_buffer
	mov	edi,ebx
	jmp	session_maybe_free

on_s_recv_u:
	call	sess_complete
	jc	release_cqe_buffer
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.end_or_error
	mov	eax,[r13+S_LST]
	add	[g_st_l_out+rax*8],r14
	mov	eax,r15d
	shr	eax,IORING_CQE_BUFFER_SHIFT
	mov	[r13+S_UC_BID],eax
	mov	[r13+S_UC_LEN],r14d
	mov	dword [r13+S_UC_OFF],0
	mov	edi,ebx
	call	idle_touch
	mov	edi,ebx
	jmp	post_send_c
.end_or_error:
	jz	.eof
	cmp	r14,-ENOBUFS
	je	.no_buffer
	mov	edi,ebx
	jmp	session_close
.eof:
	or	dword [r13+S_FLAGS],SF_U_EOF
	test	dword [r13+S_FLAGS],SF_C_EOF
	jnz	.both
	mov	edi,OP_S_SHUT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SHUTDOWN
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe r13
	mov	ecx,[r13+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_LEN],SHUT_WR
	ret
.both:
	mov	edi,ebx
	jmp	session_close
.no_buffer:
	call	pbuf_grow
	jc	.wait
	mov	edi,ebx
	jmp	post_recv_u
.wait:
	or	dword [r13+S_FLAGS],SF_U_WAIT
	mov	dword [r13+S_WAIT_U],NIL
	mov	eax,[g_waitq_u_head]
	cmp	eax,NIL
	jne	@f
	mov	[g_waitq_u_head],ebx
	mov	[g_waitq_u_tail],ebx
	ret
@@:
	mov	eax,[g_waitq_u_tail]
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	[rax+S_WAIT_U],ebx
	mov	[g_waitq_u_tail],ebx
	ret
.not_open:
	call	release_cqe_buffer
	mov	edi,ebx
	jmp	session_maybe_free

; client -> upstream send finished (or failed)
on_s_send_u:
	call	sess_complete
	jc	.out
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.failed
	add	[r13+S_CU_OFF],r14d
	mov	eax,[r13+S_CU_OFF]
	cmp	eax,[r13+S_CU_LEN]
	jb	.partial
	mov	edi,[r13+S_CU_BID]
	mov	dword [r13+S_CU_BID],NIL
	push	rbx
	call	buf_release
	pop	rbx
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_C_EOF
	jnz	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	mov	edi,ebx
	jmp	post_recv_c
.partial:
	mov	edi,ebx
	jmp	post_send_u
.failed:
	mov	edi,ebx
	jmp	session_close
.not_open:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; upstream -> client send finished (or failed)
on_s_send_c:
	call	sess_complete
	jc	.out
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.failed
	add	[r13+S_UC_OFF],r14d
	mov	eax,[r13+S_UC_OFF]
	cmp	eax,[r13+S_UC_LEN]
	jb	.partial
	mov	edi,[r13+S_UC_BID]
	mov	dword [r13+S_UC_BID],NIL
	push	rbx
	call	buf_release
	pop	rbx
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_U_EOF
	jnz	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	mov	edi,ebx
	jmp	post_recv_u
.partial:
	mov	edi,ebx
	jmp	post_send_c
.failed:
	mov	edi,ebx
	jmp	session_close
.not_open:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; ---------------------------------------------------------------- closing

; edi = session: close it, in two phases.
;
; 1. Cancel everything still in flight on both sockets.
; 2. Once every operation of the session has completed, close the
;    descriptors; free the session when the closes are in.
; The order matters: some operations (IORING_OP_SHUTDOWN, for one) are
; handed to a kernel worker and resolve their direct descriptor only when
; they run. Closed early, the slot could already be another client's by
; then, and the late operation would act on that client (it did: a
; SHUTDOWN of a finished session ended the next client's response).
session_close:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	ep_close
	push	rbx
	push	r12
	mov	ebx,edi
	call	session_ptr
	mov	r12,rax
	cmp	dword [r12+S_STATE],ST_CLOSING
	je	.done
	cmp	dword [r12+S_STATE],ST_FREE
	je	.done
	mov	dword [r12+S_STATE],ST_CLOSING
	mov	edi,ebx
	call	idle_remove
	mov	edi,ebx
	call	ph_disarm
	; phase 1: cancel
	mov	edi,OP_S_CANCEL
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,[r12+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED or IORING_ASYNC_CANCEL_ALL
	test	dword [r12+S_FLAGS],SF_RAW
	jz	@f
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_ALL
@@:
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	mov	edi,OP_S_CANCEL
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED or IORING_ASYNC_CANCEL_ALL
.done:
	pop	r12
	pop	rbx
	ret

; Phase 2 of session_close: rbx = session, r12 = it. Close both
; descriptors (nothing of the session is in flight any more).
session_close_fds:
	or	dword [r12+S_FLAGS],SF_FDS_CLOSING
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[r12+S_CLIENT]
	test	dword [r12+S_FLAGS],SF_RAW
	jz	.client_direct
	mov	[rax+SQE_FD],ecx		; a normal descriptor
	jmp	.client_closed
.client_direct:
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
.client_closed:
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[g_upslot+rbx*4]
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	edi,[g_upslot+rbx*4]
	call	upslot_free
.done:
	ret

; edi = session: once closing and nothing is in flight, close its
; descriptors (phase 2), and once those closes are in, free it.
session_maybe_free:
	push	rbx
	push	r12
	mov	ebx,edi
	call	session_ptr
	mov	r12,rax
	cmp	dword [r12+S_STATE],ST_CLOSING
	jne	.done
	cmp	dword [r12+S_INFL],0
	jne	.done
	test	dword [r12+S_FLAGS],SF_FDS_CLOSING
	jnz	.free
	call	session_close_fds
	jmp	.done
.free:
	; buffers still held (their sends completed with an error)
	mov	edi,[r12+S_CU_BID]
	cmp	edi,NIL
	je	@f
	mov	dword [r12+S_CU_BID],NIL
	push	rbx
	call	buf_release
	pop	rbx
@@:
	mov	edi,[r12+S_UC_BID]
	cmp	edi,NIL
	je	@f
	mov	dword [r12+S_UC_BID],NIL
	push	rbx
	call	buf_release
	pop	rbx
@@:
	call	session_uncount
	test	dword [r12+S_FLAGS],SF_PEER
	jz	@f
	call	src_release
@@:
	and	dword [r12+S_FLAGS],not (SF_C_WAIT or SF_U_WAIT or SF_FDS_CLOSING)
	mov	dword [r12+S_STATE],ST_FREE
	inc	dword [r12+S_GEN]
	mov	eax,[r12+S_LST]
	dec	dword [g_ls_active+rax*4]
	dec	dword [g_active]
	mov	eax,[g_sess_free]
	mov	[r12+S_NEXT],eax
	mov	[g_sess_free],ebx
.done:
	pop	r12
	pop	rbx
	ret

; Close every open session (drain deadline).
sessions_close_all:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_sess_hwm]
	jae	.done
	call	session_ptr
	mov	ecx,[rax+S_STATE]
	cmp	ecx,ST_CONNECTING
	je	.close
	cmp	ecx,ST_OPEN
	jne	.skip
.close:
	mov	edi,ebx
	call	session_close
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret
