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
S_STATE		= 0
S_GEN		= 4
S_INFL		= 8		; completions still expected
S_FLAGS		= 12
S_CLIENT	= 16		; direct descriptor of the client
S_LST		= 20		; listener
S_SERVER	= 24		; server of the current attempt
S_TRIES		= 28
S_LAST		= 32		; tick of the last activity
S_PREV		= 36		; idle list (per listener), -1 = none
S_NEXT		= 40		; idle list, or the free list
S_CU_BID	= 44		; client -> upstream buffer in flight, -1 = none
S_CU_LEN	= 48
S_CU_OFF	= 52
S_UC_BID	= 56		; upstream -> client
S_UC_LEN	= 60
S_UC_OFF	= 64
S_WAIT_C	= 68		; next in the buffer wait queue (client side)
S_WAIT_U	= 72
S_SIZE		= 128
S_SHIFT		= 7

ST_FREE		= 0
ST_CONNECTING	= 1
ST_OPEN		= 2
ST_CLOSING	= 3

SF_C_EOF	= 1		; client sent FIN
SF_U_EOF	= 2		; upstream sent FIN
SF_C_WAIT	= 4		; client receive waits for a buffer
SF_U_WAIT	= 8
SF_UP_OPEN	= 16		; the upstream slot holds a socket
SF_COUNTED	= 32		; counted in the server's active connections

NIL		= -1

BUF_SIZE	= 16384
BUF_SHIFT	= 14
BUF_GROW	= 64		; buffers added to the ring at a time (1 MiB)
BUF_MAX		= 8192		; per worker (128 MiB of address space)
MAX_TRIES	= 3
FAIL_THRESHOLD	= 3		; consecutive connect failures before ejection
EJECT_TICKS	= 10

bss
	align 8
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
	inc	ebx
	jmp	.listener
.sized:
	; two direct descriptors per session, within RLIMIT_NOFILE
	mov	rax,[g_nofile]
	sub	rax,64
	shr	rax,1
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

; Multishot accept into direct descriptors on every listener of this
; worker.
arm_accepts:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	mov	edi,ebx
	call	arm_accept
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; edi = listener.
arm_accept:
	push	rbx
	mov	ebx,edi
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ACCEPT
	mov	word [rax+SQE_IOPRIO],IORING_ACCEPT_MULTISHOT
	mov	ecx,ebx
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,[g_worker_id]
	mov	ecx,[g_lfd+rcx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_FILE_INDEX],IORING_FILE_INDEX_ALLOC
	mov	ecx,ebx
	mov	rdx,OP_ACCEPT shl 56
	or	rcx,rdx
	mov	[rax+SQE_USER_DATA],rcx
	pop	rbx
	ret

; ebx = listener, r14 = direct descriptor or -errno, r15d = flags.
on_accept:
	test	r15d,IORING_CQE_F_MORE
	jnz	@f
	cmp	dword [g_draining],2
	jae	@f
	mov	edi,ebx
	call	arm_accept			; the multishot ended: re-arm it
@@:
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
	mov	edi,ebx
	call	idle_append
	mov	edi,ebx
	jmp	session_connect
.refuse:
	; no slot: close the new connection at once
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

; edi = session: activity now; move it to the end of its list.
idle_touch:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[g_tick]
	cmp	[rax+S_LAST],ecx
	je	.done				; already touched this second
	mov	[rax+S_LAST],ecx
	push	rdi
	call	idle_remove
	pop	rdi
	jmp	idle_append
.done:
	ret

; Close sessions idle for longer than their listener allows. Oldest first,
; so this stops at the first one still in time: O(expired).
idle_expire:
	push	rbx
	push	r12
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.done
.head:
	mov	ebx,[g_ls_head+r12*4]
	cmp	ebx,NIL
	je	.next
	call	session_ptr
	mov	ecx,[g_tick]
	sub	ecx,[rax+S_LAST]
	imul	rdx,r12,LS_SIZE
	cmp	ecx,[g_listeners+rdx+LS_IDLE]
	jbe	.next				; never early: a tick may be a second late, not early
	mov	edi,ebx
	call	session_close
	jmp	.head
.next:
	inc	r12d
	jmp	.listener
.done:
	pop	r12
	pop	rbx
	ret

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

; edi = server index. CF when it may be chosen in pass esi
; (0 = healthy primaries, 1 = healthy backups, 2 = every primary).
server_eligible:
	imul	rax,rdi,SV_SIZE
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
	mov	eax,[g_sv_down+rdi*4]
	cmp	eax,[g_tick]
	ja	.no
.yes:
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
.pass:
	; with more than one eligible server, skip the one to avoid
	mov	r14d,ebp
	call	.count
	cmp	eax,1
	ja	@f
	mov	r14d,NIL
	test	eax,eax
	jnz	@f
	inc	r13d
	cmp	r13d,3
	jb	.pass
	mov	eax,[rbx+PL_FIRST]		; nothing at all: first server
	jmp	.out
@@:
	mov	eax,[rbx+PL_BALANCE]
	cmp	eax,BAL_LEAST_CONN
	je	.least
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
	call	server_eligible
	pop	r8
	pop	rcx
	jnc	.rr_next
	imul	rax,rcx,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
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
	call	server_eligible
	pop	r9
	pop	rcx
	jnc	.lc
	cmp	r12d,NIL
	je	.lc_best
	; active[c] * weight[best] < active[best] * weight[c]
	imul	rax,rcx,SV_SIZE
	mov	r10d,[g_servers+rax+SV_WEIGHT]
	imul	rax,r12,SV_SIZE
	mov	r11d,[g_servers+rax+SV_WEIGHT]
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
	call	server_eligible
	pop	r8
	pop	rcx
	jnc	@f
	imul	rax,rcx,SV_SIZE
	add	r15d,[g_servers+rax+SV_WEIGHT]
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
	call	server_eligible
	pop	rcx
	jnc	.rw_skip
	imul	rax,rcx,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
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
	call	server_eligible
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
	mov	eax,[r12+S_LST]
	imul	rax,rax,LS_SIZE
	mov	edi,[g_listeners+rax+LS_POOL]
	mov	esi,[r12+S_SERVER]
	call	server_pick
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
	mov	ecx,[g_sessions]
	add	ecx,ebx
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
.socket:
	or	dword [r12+S_FLAGS],SF_UP_OPEN
	mov	edi,OP_S_SOCKET
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SOCKET
	mov	byte [rax+SQE_FLAGS],IOSQE_IO_LINK
	mov	ecx,[r13+SV_FAMILY]
	mov	[rax+SQE_FD],ecx		; domain
	mov	qword [rax+SQE_OFF],SOCK_STREAM	; type
	mov	ecx,[g_sessions]
	add	ecx,ebx
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
	mov	ecx,[g_sessions]
	add	ecx,ebx
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
	mov	ecx,[g_sessions]
	add	ecx,ebx
	mov	[rax+SQE_FD],ecx
	lea	rcx,[r13+SV_SA]
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[r13+SV_SALEN]
	mov	[rax+SQE_OFF],rcx
	mov	edi,OP_S_LTIMEOUT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_LINK_TIMEOUT
	mov	ecx,[r12+S_LST]
	imul	rcx,rcx,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	imul	rcx,rcx,PL_SIZE
	lea	rcx,[g_pools+rcx+PL_TIMEOUT]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	pop	r13
	pop	r12
	pop	rbx
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
	mov	edi,ebx
	call	post_recv_c
	mov	edi,ebx
	jmp	post_recv_u
.failed:
	mov	edi,[r13+S_SERVER]
	mov	rsi,r14
	call	server_failed
	cmp	dword [r13+S_TRIES],MAX_TRIES
	jae	.give_up
	mov	eax,[r13+S_LST]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_COUNT]
	cmp	[r13+S_TRIES],ecx
	jae	.give_up
	mov	edi,ebx
	jmp	session_connect
.give_up:
	mov	edi,ebx
	jmp	session_close
.free:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; edi = server: a connection succeeded.
server_ok:
	cmp	dword [g_sv_down+rdi*4],0
	je	@f
	mov	dword [g_sv_down+rdi*4],0
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
	mov	ecx,[g_sessions]
	add	ecx,esi
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
	mov	ecx,[g_sessions]
	add	ecx,esi
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
	mov	ecx,[g_sessions]
	add	ecx,ebx
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

; edi = session: cancel everything on both sockets and close them.
session_close:
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
	; client
	mov	edi,OP_S_CANCEL
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,[r12+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED or IORING_ASYNC_CANCEL_ALL
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[r12+S_CLIENT]
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	mov	edi,OP_S_CANCEL
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,[g_sessions]
	add	ecx,ebx
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED or IORING_ASYNC_CANCEL_ALL
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[g_sessions]
	add	ecx,ebx
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
.done:
	pop	r12
	pop	rbx
	ret

; edi = session: free it once closing and nothing is in flight.
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
	and	dword [r12+S_FLAGS],not (SF_C_WAIT or SF_U_WAIT)
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
