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
S_T0		:= 120		; q: peak-ewma, tcp: TSC when the connect started, 0 = none
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
SF_TLS_HS	:= 1024		; a tcp session in its TLS handshake (src/http/tls.inc)
SF_PREFIX	:= 2048		; tls passthrough: the ClientHello read goes upstream first

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

; Two sizes of buffer. Every direction of a connection reads into small
; ones; one whose read filled a small buffer reads into large ones after,
; until a large one comes back holding less than a small one would: bulk
; moves in 256 KiB steps (16 KiB ones held a stream to 23 Gbit/s through two
; cores), and the many connections that move little keep costing 16 KiB a
; direction in flight. Large ids follow the small ones.
BUF_SIZE	:= 16384
BUF_SHIFT	:= 14
BUF_MAX		:= 8192		; per worker (128 MiB of address space)
BUFL_SIZE	:= 262144
BUFL_SHIFT	:= 18
BUFL_MAX	:= 512		; per worker (128 MiB); none left: small ones
BUF_GROW	:= 8		; a ring's wanted size grows by this much at a time
BUF_RING_MIN	:= 8		; and does not shrink below this

; g_sbig, a byte a session: its directions on large buffers, and the sides
; whose close resets (SO_LINGER 0) because the other one broke: an abort
; goes on as an abort, and leaves no TIME_WAIT behind on okena's ports (a
; new connection each, a client that resets: 17000 of them held there,
; every connect searching past them)
SX_BIG_C	:= 1		; client to upstream on large buffers
SX_BIG_U	:= 2		; upstream to client
SX_RST_U	:= 4		; the upstream's close resets
SX_RST_C	:= 8		; the client's
SX_SYNC_C	:= 16		; client to upstream reads in the loop (bulk.inc)
SX_SYNC_U	:= 32		; upstream to client
SX_FDS		:= 64		; both normal descriptors are had
SX_FDREQ	:= 128		; they were asked for

; a provided ring (io_uring), one for each size
PG_RING		:= 0		; q: its entries
PG_BASE		:= 8		; q: its buffers
PG_STACK	:= 16		; q: free ones not in the ring
PG_TAIL		:= 24
PG_GIVEN	:= 28		; buffers made so far (in the ring, the stack or held)
PG_RN		:= 32		; in the ring now
PG_WANT		:= 36		; how many it should hold
PG_SN		:= 40		; on the stack
PG_MAX		:= 44		; entries (0: this size is not had)
PG_SHIFT	:= 48
PG_BID0		:= 52		; its first id
PG_SIZE		:= 56
PG_REC		:= 64

; reg64, reg32 = a buffer id: its address (reg32's register only)
macro buf_ptr r64, r32
	local large, done
	cmp	r32,BUF_MAX
	jae	large
	shl	r64,BUF_SHIFT
	add	r64,[g_buf_base]
	jmp	done
large:
	sub	r32,BUF_MAX
	shl	r64,BUFL_SHIFT
	add	r64,[g_bufl_base]
done:
end macro
MAX_TRIES	:= 3
FAIL_THRESHOLD	:= 3		; consecutive connect failures before ejection
EJECT_TICKS	:= 10

ACC_PER_SOCKET	:= 8		; accepts in flight per socket that needs addresses
ACC_MAX		:= MAX_LISTENERS * ACC_PER_SOCKET	; (shared out when sockets are more)
AW_MAX		:= 4096		; sockets accept_watch looks at, in a worker
AC_SID		:= 0		; d: socket id
AC_LEN		:= 4		; d: address length
AC_SA		:= 8		; 28 bytes
AC_SIZE		:= 40

bss
	align 8
	g_acc_count	dd ?
	g_acc_per	dd ?		; accepts each such socket gets
	g_aw_n		dd ?		; accept_watch: this worker's sockets
	g_aw_pfd:	rb 8 * AW_MAX	; (struct pollfd)
	g_aw_sid	rd AW_MAX
	g_aw_seen	rq AW_MAX	; its listener's connections taken, at the last tick
	g_aw_was	rb AW_MAX	; readable then
	g_acc_live	dd ?		; io_uring accepts in the kernel: a draining
					; worker leaves only when none is (one that
					; completes takes a connection it must serve)
	g_acc_socks	dd ?		; (counting them)
	g_acc:		rb AC_SIZE * ACC_MAX
	g_acc_addr:	rb 28
	g_sessions	dd ?		; slots per worker
	g_sess_hwm	dd ?		; slots ever used (memory follows load)
	g_sess_free	dd ?		; free list head
	g_active	dd ?		; sessions not free
	g_sess_base	dq ?
	g_buf_base	dq ?
	g_bufl_base	dq ?
	align 8
	g_pbg:		rb PG_REC	; the small buffers' ring
	g_pbgl:		rb PG_REC	; the large ones'
	g_pb_stack	rd BUF_MAX	; (the last given back on top)
	g_pbl_stack	rd BUFL_MAX
	g_sbig		rb 1 shl 20	; a session's extras (SX_*)
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
	test	eax,eax
	jnz	.declared
	; auto: as many as the worker can hold, three descriptors a session
	; within RLIMIT_NOFILE (the table's own bound below)
	mov	rax,[g_nofile]
	sub	rax,64
	xor	edx,edx
	mov	ecx,3
	div	rcx
	cmp	rax,1 shl 20
	jbe	@f
	mov	eax,1 shl 20
@@:
	jmp	.capped
.declared:
	add	eax,[g_workers]
	dec	eax
	xor	edx,edx
	div	dword [g_workers]
	test	eax,eax
	jnz	.capped
	inc	eax
.capped:
	mov	[g_ls_cap+rbx*4],eax
	imul	rcx,rbx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_KIND],LK_UDP
	je	@f				; (flows are not sessions)
	add	r12d,eax
@@:
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
.ph_classes:
	xor	ecx,ecx				; a route's `timeout try=` lists
@@:
	mov	dword [g_ph_head+PH_CLASSES*4+rcx*4],NIL
	mov	dword [g_ph_tail+PH_CLASSES*4+rcx*4],NIL
	inc	ecx
	cmp	ecx,MAX_TRYC
	jb	@b
	ret
.sized:
	call	.ph_classes
	test	r12d,r12d			; (only `udp`: no sessions, but they are mapped)
	jnz	@f
	inc	r12d
@@:
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
	push	rax				; (a table touched a session at a time: huge
	mov	rdi,rax				; pages would commit 2 MiB for a few)
	mov	esi,r12d
	shl	rsi,S_SHIFT
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	pop	rax
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
	mov	[g_pbg+PG_BASE],rax
	; buffers come and go 16 KiB at a time: huge pages would commit (and
	; keep) 2 MiB for each buffer touched
	mov	rdi,rax
	mov	esi,BUF_MAX * BUF_SIZE
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	xor	edi,edi				; the large ones
	mov	esi,BUFL_MAX * BUFL_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_bufl_base],rax
	mov	[g_pbgl+PG_BASE],rax
	mov	rdi,rax
	mov	esi,BUFL_MAX * BUFL_SIZE
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	; the provided rings themselves: 16 bytes per entry
	xor	edi,edi
	mov	esi,(BUF_MAX + BUFL_MAX) * 16
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_POPULATE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_pbg+PG_RING],rax
	add	rax,BUF_MAX * 16
	mov	[g_pbgl+PG_RING],rax
	lea	rax,[g_pb_stack]
	mov	[g_pbg+PG_STACK],rax
	lea	rax,[g_pbl_stack]
	mov	[g_pbgl+PG_STACK],rax
	mov	dword [g_pbg+PG_MAX],BUF_MAX
	mov	dword [g_pbg+PG_SHIFT],BUF_SHIFT
	mov	dword [g_pbg+PG_BID0],0
	mov	dword [g_pbg+PG_SIZE],BUF_SIZE
	mov	dword [g_pbgl+PG_MAX],BUFL_MAX
	mov	dword [g_pbgl+PG_SHIFT],BUFL_SHIFT
	mov	dword [g_pbgl+PG_BID0],BUF_MAX
	mov	dword [g_pbgl+PG_SIZE],BUFL_SIZE
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
	lea	r9,[g_pbg]
	xor	ecx,ecx
	call	.one
	test	eax,eax
	js	.done
	lea	r9,[g_pbgl]			; (group 1) none: small ones only
	mov	ecx,1
	call	.one
	test	eax,eax
	jns	@f
	mov	dword [g_pbgl+PG_MAX],0
@@:
	xor	eax,eax
.done:
	ret
.one:
	mov	rax,[r9+PG_RING]
	mov	[g_pbuf_reg],rax		; ring_addr
	mov	eax,[r9+PG_MAX]
	mov	[g_pbuf_reg+8],eax		; ring_entries
	mov	[g_pbuf_reg+12],ecx		; bgid, flags
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_PBUF_RING
	lea	rdx,[g_pbuf_reg]
	mov	r10d,1
	mov	eax,SYS_io_uring_register
	syscall
	test	eax,eax
	js	@f
	call	pbuf_grow
	xor	eax,eax
@@:
	ret

; The ring is first in, first out: the kernel takes the buffer given back
; longest ago. Holding every free buffer, it would cycle through all of them
; (8192 x 256 KiB at worst), each copy into memory long out of the caches;
; at 8, bulk through two cores went from 40 to 54 Gbit/s. So the ring holds
; what the traffic needs (g_pb_want: up when a receive finds it empty, down
; each second) and the other free buffers wait on a stack, the most recently
; used on top.
;
; r9 = a ring that a receive found empty: room for BUF_GROW more, filled
; from its stack, else with new buffers. CF when none could be added.
; Keeps r9.
pbuf_grow:
	mov	eax,[r9+PG_WANT]
	add	eax,BUF_GROW
	cmp	eax,[r9+PG_MAX]
	jbe	@f
	mov	eax,[r9+PG_MAX]
@@:
	mov	[r9+PG_WANT],eax
	xor	r8d,r8d				; added
.more:
	mov	eax,[r9+PG_RN]
	cmp	eax,[r9+PG_WANT]
	jae	.done
	mov	ecx,[r9+PG_SN]
	test	ecx,ecx
	jz	.new
	dec	ecx
	mov	[r9+PG_SN],ecx
	mov	rax,[r9+PG_STACK]
	mov	edi,[rax+rcx*4]
	call	pbuf_put
	inc	r8d
	jmp	.more
.new:
	mov	ecx,[r9+PG_GIVEN]
	cmp	ecx,[r9+PG_MAX]
	jae	.done
	inc	dword [r9+PG_GIVEN]
	mov	edi,ecx
	add	edi,[r9+PG_BID0]
	call	pbuf_put
	inc	r8d
	jmp	.more
.done:
	cmp	r8d,1				; CF: none
	ret

; Each second: each ring's wanted size a quarter nearer the minimum (what
; is in it above that stays until taken)
pbuf_tick:
	lea	r9,[g_pbg]
	call	.one
	lea	r9,[g_pbgl]
.one:
	mov	eax,[r9+PG_WANT]
	mov	ecx,eax
	shr	ecx,2
	sub	eax,ecx
	cmp	eax,BUF_RING_MIN
	jae	@f
	mov	eax,BUF_RING_MIN
@@:
	mov	[r9+PG_WANT],eax
	ret

; edi = buffer id: free again, into its ring when that holds fewer than
; wanted, else on its stack. Clobbers eax, ecx, rdx.
pbuf_free:
	push	r9
	lea	r9,[g_pbg]
	cmp	edi,BUF_MAX
	jb	@f
	lea	r9,[g_pbgl]
@@:
	mov	eax,[r9+PG_RN]
	cmp	eax,[r9+PG_WANT]
	jb	.ring
	mov	eax,[r9+PG_SN]
	mov	rcx,[r9+PG_STACK]
	mov	[rcx+rax*4],edi
	inc	eax
	mov	[r9+PG_SN],eax
	pop	r9
	ret
.ring:
	call	pbuf_put
	pop	r9
	ret

; r9 = a ring, edi = one of its buffers: into it. Clobbers eax, ecx, rdx.
pbuf_put:
	mov	eax,[r9+PG_TAIL]
	mov	ecx,[r9+PG_MAX]
	dec	ecx
	and	ecx,eax
	shl	ecx,4
	add	rcx,[r9+PG_RING]
	push	rcx
	mov	edx,edi
	sub	edx,[r9+PG_BID0]
	mov	ecx,[r9+PG_SHIFT]
	shl	rdx,cl
	add	rdx,[r9+PG_BASE]
	pop	rcx
	mov	[rcx+BUF_ADDR],rdx
	mov	edx,[r9+PG_SIZE]
	mov	[rcx+BUF_LEN],edx
	mov	[rcx+BUF_BID],di
	inc	eax
	mov	[r9+PG_TAIL],eax
	mov	rcx,[r9+PG_RING]
	mov	[rcx+BUF_TAIL],ax		; x86 stores are ordered: entry first
	inc	dword [r9+PG_RN]
	ret

; edi = buffer id: back to the ring, then wake one session waiting for a
; buffer. Entries of sessions that stopped waiting are skipped. Clobbers
; rbx.
buf_release:
	call	pbuf_free
	cmp	edi,BUF_MAX
	jae	.done				; (a large one: nobody waits for those)
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
; A socket id is listener | index << SID_SHIFT (listeners: 16 bits).
SID_SHIFT	:= 16
SID_LISTENER	:= 0xFFFF
assert MAX_LISTENERS <= SID_LISTENER + 1

; edi = socket id. eax = its fd.
listener_fd:
	mov	eax,edi
	and	eax,SID_LISTENER
	imul	eax,eax,MAX_WORKERS
	mov	ecx,edi
	shr	ecx,SID_SHIFT
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
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	je	.next				; (not for accepting: see udp_each_socket)
	mov	edi,r12d
	shl	edi,SID_SHIFT
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

; Multishot accept into direct descriptors on every socket of this worker;
; ACC_MAX accepts with addresses shared out between the sockets that need
; them, ACC_PER_SOCKET each at most and one at least, so that no listener
; is left without any.
arm_accepts:
	mov	dword [g_acc_socks],0
	lea	rsi,[.count]
	call	for_each_socket
	mov	eax,ACC_MAX
	xor	edx,edx
	mov	ecx,[g_acc_socks]
	test	ecx,ecx
	jz	@f
	div	ecx
@@:
	cmp	eax,ACC_PER_SOCKET
	jbe	@f
	mov	eax,ACC_PER_SOCKET
@@:
	cmp	eax,1
	jae	@f
	mov	eax,1
@@:
	mov	[g_acc_per],eax
	mov	dword [g_aw_n],0
	lea	rsi,[.watch]
	call	for_each_socket
	lea	rsi,[arm_accept]
	jmp	for_each_socket
.watch:
	mov	eax,[g_aw_n]
	cmp	eax,AW_MAX
	jae	@f
	inc	dword [g_aw_n]
	mov	[g_aw_sid+rax*4],edi
	; as if seen waiting now: one already stuck when this worker starts is
	; taken at its first tick
	mov	byte [g_aw_was+rax],1
	mov	ecx,edi
	and	ecx,SID_LISTENER
	mov	rdx,[g_st_l_accepted+rcx*8]
	add	rdx,[g_st_l_full+rcx*8]
	mov	[g_aw_seen+rax*8],rdx
	push	rax
	call	listener_fd
	pop	rcx
	mov	[g_aw_pfd+rcx*8],eax
	mov	dword [g_aw_pfd+rcx*8+4],POLLIN
@@:
	ret
.count:
	mov	eax,edi
	and	eax,SID_LISTENER
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	@f
	inc	dword [g_acc_socks]
@@:
	ret

; edi = socket id: a listener that needs client addresses gets
; ACC_PER_SOCKET single-shot accepts, each with its own address buffer;
; the others one multishot accept into direct descriptors.
arm_accept:
	mov	eax,edi
	and	eax,SID_LISTENER
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	arm_accept_multi
	push	rbx
	push	r12
	mov	r12d,edi
	mov	ebx,[g_acc_per]
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

; io_uring, once a tick: the listening sockets looked at, and one that has
; had connections waiting for a whole tick while its listener took none gets
; one more accept, which takes the queue at once. Seen after reloads with a
; few hundred listeners: a connection that came as the old workers stopped
; stayed queued although the new worker had accepts armed there (an accept
; waits exclusively, one arrival waking one accept, and a wakeup that went to
; an accept cancelled before it ran is not given to another). It is served a
; tick late instead of never.
accept_watch:
	cmp	dword [g_aw_n],0
	je	.out
	cmp	dword [g_draining],0
	jne	.out
	push	rbx
	lea	rdi,[g_aw_pfd]
	mov	esi,[g_aw_n]
	xor	edx,edx				; now, no waiting
	mov	eax,SYS_poll
	syscall
	xor	ebx,ebx
.socket:
	cmp	ebx,[g_aw_n]
	jae	.done
	mov	edi,[g_aw_sid+rbx*4]
	mov	eax,edi
	and	eax,SID_LISTENER
	mov	rcx,[g_st_l_accepted+rax*8]
	add	rcx,[g_st_l_full+rax*8]		; (refused ones are taken too)
	xor	edx,edx
	test	word [g_aw_pfd+rbx*8+6],POLLIN
	setnz	dl
	jz	.mark
	cmp	byte [g_aw_was+rbx],0
	je	.mark
	cmp	rcx,[g_aw_seen+rbx*8]
	jne	.mark
	push	rcx
	push	rdx
	call	arm_accept_one
	pop	rdx
	pop	rcx
.mark:
	mov	[g_aw_was+rbx],dl
	mov	[g_aw_seen+rbx*8],rcx
	inc	ebx
	jmp	.socket
.done:
	pop	rbx
.out:
	ret

; edi = socket id: one more accept on it (a slot of its own, or a multishot).
arm_accept_one:
	mov	eax,edi
	and	eax,SID_LISTENER
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	arm_accept_multi
	mov	eax,[g_acc_count]
	cmp	eax,ACC_MAX
	jae	.none
	inc	dword [g_acc_count]
	imul	rcx,rax,AC_SIZE
	mov	[g_acc+rcx+AC_SID],edi
	mov	edi,eax
	jmp	arm_accept_slot
.none:
	ret

; edi = accept slot.
arm_accept_slot:
	inc	dword [g_acc_live]
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
	dec	dword [g_acc_live]		; (this one is over: re-armed below, or not)
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
	and	r13d,SID_LISTENER		; listener
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
	call	tcp_tls_wanted
	test	rax,rax
	jnz	tcp_tls_start			; TLS first, then the upstream
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
	mov	dword [rax+P_SLOT],-1		; (its PROXY header record: written by
						; pp_build, read only where the listener sends one)
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
	inc	dword [g_acc_live]
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
	dec	dword [g_acc_live]		; the multishot ended
	cmp	dword [g_draining],2
	jae	@f
	mov	edi,ebx
	call	arm_accept			; the multishot ended: re-arm it
@@:
	and	ebx,SID_LISTENER		; the listener
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
	call	tcp_tls_wanted
	test	rax,rax
	jnz	.tls
	mov	edi,ebx
	jmp	session_connect
.tls:
	jmp	tcp_tls_start			; TLS first, then the upstream
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
	mov	byte [g_sbig+rax],0		; (its extras start clear)
	mov	dword [g_bfd_c+rax*4],0
	mov	dword [g_bfd_u+rax*4],0
	mov	qword [g_cnt+rax*8],0
	ret
.fresh:
	mov	eax,[g_sess_hwm]
	cmp	eax,[g_sessions]
	jae	.none
	inc	dword [g_sess_hwm]
	mov	byte [g_sbig+rax],0
	mov	dword [g_bfd_c+rax*4],0
	mov	dword [g_bfd_u+rax*4],0
	mov	qword [g_cnt+rax*8],0
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
	cmp	byte [rax+S_PH_KIND],PH_RESPONSE	; (a class in the bits above)
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

; peak-ewma, per worker: each server's latency in microseconds, an
; exponentially weighted moving average that jumps to a slower sample at
; once (the peak) and otherwise follows samples and decays toward 0 with
; time constant EWMA_TAU: e' = (e * tau + s * dt) / (tau + dt), the
; rational form of e * w + s * (1 - w) with w = tau / (tau + dt). Read
; and written only for pools that balance by it.
EWMA_TAU_US	:= 10000000

bss
	g_sv_ewma	rq MAX_SERVERS		; microseconds
	g_sv_ewt	rq MAX_SERVERS		; when it was last updated (TSC us)
end bss

; rax = TSC microseconds. Clobbers rdx.
tsc_now_us:
	rdtsc
	shl	rdx,32
	or	rax,rdx
	xor	edx,edx
	div	qword [g_tsc_per_us]
	ret

; edi = server, rsi = sample in us (0: just let time pass). rax = the
; new value. Keeps every register but rax, rdx.
sv_ewma_observe:
	push	rcx
	push	r8
	push	r9
	call	tsc_now_us
	mov	rcx,rax
	sub	rcx,[g_sv_ewt+rdi*8]		; dt
	mov	[g_sv_ewt+rdi*8],rax
	mov	rax,[g_sv_ewma+rdi*8]
	cmp	rsi,rax
	ja	.peak
	; (e * tau + s * dt) / (tau + dt)
	mov	r8,EWMA_TAU_US
	mov	r9,EWMA_TAU_US * 16
	cmp	rcx,r9
	jbe	@f
	mov	rcx,r9				; capped: the old value weighs 1/17 at most
@@:
	imul	rax,r8
	mov	r9,rsi
	imul	r9,rcx
	add	rax,r9
	add	rcx,r8
	xor	edx,edx
	div	rcx
	jmp	.store
.peak:
	mov	rax,rsi
.store:
	mov	[g_sv_ewma+rdi*8],rax
	pop	r9
	pop	r8
	pop	rcx
	ret

; edi = server. rax = its latency, decayed to now. Keeps all but rax, rdx.
sv_ewma_cost:
	push	rsi
	xor	esi,esi
	call	sv_ewma_observe
	pop	rsi
	ret

; ebx = session, its connect just succeeded: for a tcp listener whose
; pool balances by peak-ewma, the connect time is the latency sample.
; Keeps every register.
sv_connect_sample:
	push	rax
	push	rdx
	push	rsi
	push	rdi
	call	session_ptr
	mov	rdx,rax
	mov	rax,[rdx+S_T0]
	test	rax,rax
	jz	.out
	mov	qword [rdx+S_T0],0
	push	rdx
	mov	rsi,rax
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,rsi
	xor	edx,edx
	div	qword [g_tsc_per_us]
	mov	rsi,rax
	pop	rdx
	mov	edi,[rdx+S_SERVER]
	call	sv_ewma_observe
.out:
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rax
	ret

; r12 = session (tcp listener), its server just picked: start the connect
; clock when the pool balances by peak-ewma. Keeps every register.
sv_connect_start:
	push	rax
	push	rdx
	push	rcx
	push	rdi
	mov	edi,[r12+S_SERVER]		; `connect rate=`: its token
	call	sv_rate_take
	pop	rdi
	mov	qword [r12+S_T0],0
	mov	eax,[r12+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_TCP
	jne	.out
	mov	eax,[r12+S_POOL]
	imul	rax,rax,PL_SIZE
	cmp	dword [g_pools+rax+PL_BALANCE],BAL_PEAK_EWMA
	jne	.out
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[r12+S_T0],rax
.out:
	pop	rcx
	pop	rdx
	pop	rax
	ret

; edi = server, rbx = its pool. eax = its weight, scaled down while it
; slow-starts. Keeps every register but rax.
sv_weight:
	mov	rax,[g_api_tbl]
	mov	eax,[rax+rdi*8+4]		; `okena backend weight`
	test	eax,eax
	jnz	@f
	imul	eax,edi,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
@@:
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
	mov	rax,[g_api_tbl]
	cmp	dword [rax+rdi*8],0
	jne	.no				; drained: not even when all else is down
	imul	rax,rdi,SV_SIZE
	cmp	dword [g_servers+rax+SV_MAX],0
	je	@f
	call	sv_has_room			; full: not by any pass
	jnc	.no
@@:
	call	sv_rate_ok			; `connect rate=`: no token, nothing to reuse
	jnc	.no
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
	mov	dword [g_pick_full],0
	xor	eax,eax
	xchg	eax,[g_pick_adm]
	test	eax,eax
	jz	@f
	cmp	dword [rbx+PL_HASMAX],0
	je	@f
	call	queue_anyone
	jnc	@f
	mov	dword [g_pick_full],1		; others wait: behind them
	mov	eax,NIL
	jmp	.out
@@:
	cmp	dword [rbx+PL_BALANCE],BAL_MAGLEV
	jb	.not_hashed
	cmp	dword [rbx+PL_BALANCE],BAL_RING
	ja	.not_hashed
	xor	eax,eax
	xchg	eax,[g_pick_hashed]
	test	eax,eax
	jz	.pass				; no key: as random, below
	call	hash_pick
	cmp	eax,NIL
	jne	.out
	jmp	.pass
.not_hashed:
	mov	dword [g_pick_hashed],0		; (a key is for one pick only)
	; least-request: two random servers, the one with fewer requests in
	; flight per weight. O(1) whatever the pool size; the passes below
	; (backups, panic, avoidance with one server left) only when the
	; draws find nothing usable.
	cmp	dword [rbx+PL_BALANCE],BAL_LEAST_REQ
	je	@f
	cmp	dword [rbx+PL_BALANCE],BAL_PEAK_EWMA
	jne	.pass
@@:
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
	cmp	eax,BAL_PEAK_EWMA
	je	.least
	cmp	eax,BAL_FIRST
	je	.first
	cmp	eax,BAL_RANDOM
	jae	.random				; (and the hashing ones, when their key gave nothing)
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
.first:
	; the first in the file's order that has room
	mov	ecx,[rbx+PL_FIRST]
	mov	r8d,ecx
	add	r8d,[rbx+PL_COUNT]
.fi:
	cmp	ecx,r8d
	jae	.next_pass
	cmp	ecx,r14d
	je	.fi_next
	mov	edi,ecx
	mov	esi,r13d
	push	rcx
	push	r8
	call	.eligible
	pop	r8
	pop	rcx
	jnc	.fi_next
	mov	eax,ecx
	jmp	.out
.fi_next:
	inc	ecx
	jmp	.fi
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
	cmp	dword [rbx+PL_BALANCE],BAL_PEAK_EWMA
	je	.ewma
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
.ewma:
	; (latency + 1) x (in flight + 1) / weight: the cheaper of the two
	mov	edi,r11d
	call	sv_ewma_cost			; rax = latency in us, decayed
	inc	rax
	mov	ecx,[g_sv_active+r11*4]
	inc	rcx
	imul	rax,rcx
	push	rax				; cost a, before weights
	mov	edi,r12d
	call	sv_ewma_cost
	inc	rax
	mov	ecx,[g_sv_active+r12*4]
	inc	rcx
	imul	rax,rcx
	push	rax				; cost b
	mov	edi,r11d
	call	sv_weight
	mov	r8d,eax				; weight a
	mov	edi,r12d
	call	sv_weight
	mov	r9d,eax				; weight b
	pop	rdx				; cost b
	pop	rax				; cost a
	imul	rax,r9				; cost a x weight b
	imul	rdx,r8				; cost b x weight a
	cmp	rax,rdx
	ja	.take_b
	mov	eax,r11d
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

bss
	g_src_next	rd MAX_POOLS	; each pool's next `source` address, in this worker
end bss

; edi = pool, esi = the server's family: rax = the `source` slot its next
; connection leaves from (sockaddr, then its length at +28), 0 for none of
; that family. Keeps all but rax.
pool_source:
	push	rcx
	push	rdx
	push	r8
	imul	r8,rdi,PL_SIZE
	lea	r8,[g_pools+r8]
	mov	ecx,[r8+PL_SRCN]
	test	ecx,ecx
	jz	.none
.try:
	mov	eax,[g_src_next+rdi*4]
	inc	dword [g_src_next+rdi*4]
	xor	edx,edx
	div	dword [r8+PL_SRCN]
	imul	eax,edx,PL_SRCSZ
	lea	rax,[r8+PL_SRC+rax]
	movzx	edx,word [rax]
	cmp	edx,esi
	je	.out
	dec	ecx
	jnz	.try
.none:
	xor	eax,eax
.out:
	pop	r8
	pop	rdx
	pop	rcx
	ret

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
	call	pick_key_l4
	mov	edi,[r12+S_POOL]
	mov	esi,[r12+S_SERVER]
	call	server_pick
	cmp	eax,NIL
	je	.nowhere
@@:
	mov	edi,eax
	call	sv_claim			; full since it was chosen: wait, or go
	jnc	.nowhere
	mov	ecx,[r12+S_SERVER]
	mov	[r12+S_SERVER2],ecx
	mov	[r12+S_SERVER],eax
	call	sv_connect_start
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
	; the pool's `source`: bound to the next address, the port left to the
	; connect (so a port is free per destination, not per host)
	cmp	dword [g_uring_bind],0
	je	.connect
	mov	edi,[r12+S_POOL]
	mov	esi,[r13+SV_FAMILY]
	call	pool_source
	test	rax,rax
	jz	.connect
	push	rax
	mov	edi,OP_S_OPT
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_HARDLINK
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	dword [rax+SQE_LEVEL],IPPROTO_IP
	mov	dword [rax+SQE_OPTNAME],IP_BIND_ADDRESS_NO_PORT
	mov	dword [rax+SQE_OPTLEN],4
	lea	rcx,[one_int]
	mov	[rax+SQE_OPTVAL],rcx
	mov	edi,OP_S_OPT
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	mov	byte [rax+SQE_OPCODE],IORING_OP_BIND	; (failing, it fails the connect)
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_LINK
	mov	edx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],edx
	mov	[rax+SQE_ADDR],rcx
	mov	edx,[rcx+28]
	mov	[rax+SQE_ADDR2],rdx
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

; ebx = session, its PROXY header (if any) sent: tls passthrough's
; ClientHello next, then bytes both ways.
relay_after_pp:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_PREFIX
	jz	start_relay
	mov	edi,ebx

; edi = session: send (the rest of) the bytes read before connecting.
post_send_pfx:
	push	rbx
	mov	ebx,edi
	mov	esi,edi
	mov	edi,OP_S_SEND_PFX
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	ecx,[r8+H_INOFF]
	mov	rsi,[r8+H_BUF]
	add	rsi,rcx
	mov	[rax+SQE_ADDR],rsi
	mov	esi,[r8+H_INLEN]
	sub	esi,ecx
	mov	[rax+SQE_LEN],esi
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	pop	rbx
	ret

on_s_send_pfx:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.failed
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	add	[r8+H_INOFF],r14d
	mov	ecx,[r8+H_INOFF]
	cmp	ecx,[r8+H_INLEN]
	jb	.more
	and	dword [rax+S_FLAGS],not SF_PREFIX
	jmp	start_relay
.more:
	mov	edi,ebx
	jmp	post_send_pfx
.failed:
	mov	edi,ebx
	jmp	session_close
.not_open:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

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
	call	px_ptr
	mov	ecx,[rax+PX_HOFF]
	lea	rsi,[rax+PX_HDR+rcx]
	mov	[rdx+SQE_ADDR],rsi
	mov	esi,[rax+PX_HLEN]
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
	call	px_ptr
	add	[rax+PX_HOFF],r14d
	mov	ecx,[rax+PX_HOFF]
	cmp	ecx,[rax+PX_HLEN]
	jb	.more
	jmp	relay_after_pp
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
	sv_count_dec rax
	cmp	dword [g_wq_waiting],0
	je	.done
	imul	rax,rax,SV_SIZE
	cmp	dword [g_servers+rax+SV_MAX],0
	je	.done
	push	rdi
	mov	edi,[r12+S_POOL]
	call	queue_wake			; a place: the first one waiting here
	pop	rdi
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
	call	sv_connect_sample
	if_http http_up_ready
	; L4 (tcp) to a TLS pool is not supported: refuse rather than leak plaintext
	mov	eax,[r13+S_POOL]
	imul	rax,rax,PL_SIZE
	cmp	dword [g_pools+rax+PL_TLS],0
	jne	.tls_l4
	; a PROXY protocol header goes before any byte of the client
	mov	eax,[r13+S_LST]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PP_V1 or LSF_PP_V2
	jz	relay_after_pp
	mov	edi,ebx
	jmp	post_send_pp
.tls_l4:
	mov	edi,ebx
	jmp	session_close
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
	mov	edi,AL_BACKEND
	call	log_end_alert
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
	call	sv_eject_secs			; the pool's `outlier eject=`
	add	eax,[g_tick]
	mov	[g_sv_down+rdi*4],eax
	mov	dword [g_sv_fails+rdi*4],0
	push	rdi
	push	rsi
	call	log_begin
	out_lit 'backend '
	mov	rdi,[rsp+8]
	call	log_server
	out_lit ' ejected for '
	mov	rdi,[rsp+8]
	call	sv_eject_secs
	call	out_u64
	out_lit ' s after 3 failed connects ('
	pop	rax
	neg	rax
	call	errno_text
	out_lit ')'
	mov	edi,AL_BACKEND
	call	log_end_alert
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
	movzx	ecx,byte [g_sbig+rsi]
	and	ecx,1				; group 1: the large buffers
	mov	[rax+SQE_BUF_GROUP],cx
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
	movzx	ecx,byte [g_sbig+rsi]
	shr	ecx,1
	and	ecx,1				; group 1: the large buffers
	mov	[rax+SQE_BUF_GROUP],cx
	mov	r8,[g_cnt+rsi*8]		; an HTTP body by the relay: no more than
	test	r8,r8				; what is left of it (counted.inc: + 1)
	jz	.out
	dec	r8
	mov	edx,BUF_SIZE
	test	ecx,ecx
	jz	@f
	mov	edx,BUFL_SIZE
@@:
	cmp	r8,rdx
	cmovb	edx,r8d
	mov	[rax+SQE_LEN],edx
.out:
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
	buf_ptr rcx, ecx
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
	buf_ptr rcx, ecx
	mov	r8d,[rdx+S_UC_OFF]
	add	rcx,r8
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[rdx+S_UC_LEN]
	sub	ecx,r8d
	mov	[rax+SQE_LEN],ecx
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL
	ret

; After a receive of r14 bytes into buffer eax, session ebx: the size its
; direction (bit) reads into next. Large after a small one came full, small
; after a large one held less than a small one.
macro buf_next_size bit
	local large, done
	cmp	eax,BUF_MAX
	jae	large
	cmp	r14d,BUF_SIZE
	jb	done
	cmp	dword [g_pbgl+PG_MAX],0
	je	done
	or	byte [g_sbig+rbx],bit
	call	bulk_want			; (its reads may go in the loop)
	jmp	done
large:
	cmp	r14d,BUF_SIZE
	jae	done
	and	byte [g_sbig+rbx],not bit
done:
end macro

; A receive's completion (r15d = cqe flags) that carries a buffer: one
; fewer in the ring
macro pbuf_taken
	local no, small
	test	r15d,IORING_CQE_F_BUFFER
	jz	no
	cmp	r15d,BUF_MAX shl IORING_CQE_BUFFER_SHIFT
	jb	small
	dec	dword [g_pbgl+PG_RN]
	jmp	no
small:
	dec	dword [g_pbg+PG_RN]
no:
end macro

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
	pbuf_taken
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
	buf_next_size 1
	mov	dword [r13+S_CU_OFF],0
	mov	edi,ebx
	call	idle_touch
	mov	edi,ebx
	jmp	post_send_u
.end_or_error:
	jz	.eof
	cmp	r14,-ENOBUFS
	je	.no_buffer
	or	byte [g_sbig+rbx],SX_RST_U	; the client broke: reset the upstream
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
	test	byte [g_sbig+rbx],1
	jz	.no_small
	lea	r9,[g_pbgl]
	call	pbuf_grow
	jnc	.recv_again
	and	byte [g_sbig+rbx],not 1	; the large ones all out: a small one
	jmp	.recv_again
.no_small:
	lea	r9,[g_pbg]
	call	pbuf_grow
	jc	.wait
.recv_again:
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
	pbuf_taken
	call	sess_complete
	jc	release_cqe_buffer
	mov	r13,rax
	cmp	dword [r13+S_STATE],ST_OPEN
	jne	.not_open
	test	r14,r14
	jle	.end_or_error
	mov	eax,[r13+S_LST]
	add	[g_st_l_out+rax*8],r14
	cmp	qword [g_cnt+rbx*8],0
	je	@f
	sub	[g_cnt+rbx*8],r14		; an HTTP body: less of it to come, and
	mov	eax,ebx				; its bytes for the access log
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	add	[rax+H_XBYTES],r14
	mov	dword [rax+H_STATE],HS_RESP_SEND	; (now the client's to take)
	push	rbx				; each piece starts body_idle's clock again,
	push	r13				; as h_send_clock does: a client that takes
	push	r14				; nothing for that long is let go
	push	r15
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
@@:
	mov	eax,r15d
	shr	eax,IORING_CQE_BUFFER_SHIFT
	mov	[r13+S_UC_BID],eax
	mov	[r13+S_UC_LEN],r14d
	buf_next_size 2
	mov	dword [r13+S_UC_OFF],0
	mov	edi,ebx
	call	idle_touch
	mov	edi,ebx
	jmp	post_send_c
.end_or_error:
	jz	.eof
	cmp	r14,-ENOBUFS
	je	.no_buffer
	or	byte [g_sbig+rbx],SX_RST_C	; the upstream broke: reset the client
	mov	edi,ebx
	jmp	session_close
.eof:
	cmp	qword [g_cnt+rbx*8],0
	jne	.both				; an HTTP body cut short: both go
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
	test	byte [g_sbig+rbx],2
	jz	.no_small
	lea	r9,[g_pbgl]
	call	pbuf_grow
	jnc	.recv_again
	and	byte [g_sbig+rbx],not 2	; the large ones all out: a small one
	jmp	.recv_again
.no_small:
	lea	r9,[g_pbg]
	call	pbuf_grow
	jc	.wait
.recv_again:
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
	mov	cl,[g_sbig+rbx]			; bulk, the descriptors had: from now on
	and	cl,SX_FDS or SX_BIG_C		; its reads go in the loop (bulk.inc)
	cmp	cl,SX_FDS or SX_BIG_C
	jne	@f
	or	byte [g_sbig+rbx],SX_SYNC_C
	mov	r13,rax
	jmp	bulk_arm_rd_c
@@:
	mov	edi,ebx
	jmp	post_recv_c
.partial:
	mov	edi,ebx
	jmp	post_send_u
.failed:
	or	byte [g_sbig+rbx],SX_RST_C	; the upstream broke: reset the client
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
	mov	rcx,[g_cnt+rbx*8]		; an HTTP body by the relay (counted.inc):
	cmp	rcx,1				; 1, all of it sent: the exchange ends;
	jb	.not_counted			; more, the next receive
	je	.counted_all
	mov	eax,ebx				; (the backend's turn: body_idle does
	shl	rax,H_SHIFT			; not count it against the client)
	add	rax,[g_http_base]
	mov	dword [rax+H_STATE],HS_RESP_READ
	test	byte [g_sbig+rbx],SX_FDS
	jz	@f
	or	byte [g_sbig+rbx],SX_SYNC_U	; the descriptors had: reads in the loop
	call	session_ptr
	mov	r13,rax
	jmp	bulk_arm_rd_u
@@:
	mov	edi,ebx
	jmp	post_recv_u
.counted_all:
	mov	qword [g_cnt+rbx*8],0
	jmp	http_counted_done
.not_counted:
	mov	cl,[g_sbig+rbx]
	and	cl,SX_FDS or SX_BIG_U
	cmp	cl,SX_FDS or SX_BIG_U
	jne	@f
	or	byte [g_sbig+rbx],SX_SYNC_U
	mov	r13,rax
	jmp	bulk_arm_rd_u
@@:
	mov	edi,ebx
	jmp	post_recv_u
.partial:
	mov	edi,ebx
	jmp	post_send_c
.failed:
	or	byte [g_sbig+rbx],SX_RST_U	; the client broke: reset the upstream
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
	call	cache_gone
	mov	edi,ebx
	call	idle_remove
	mov	edi,ebx
	call	ph_disarm
	test	dword [r12+S_FLAGS],SF_H2C
	jz	@f
	call	h2c_closing			; an HTTP/2 connection: its streams first
@@:
	test	dword [r12+S_FLAGS],SF_UPH2
	jz	@f
	call	h2u_detach			; its upstream stream goes too
@@:
	test	dword [r12+S_FLAGS],SF_H2U
	jz	@f
	call	h2uc_closing			; an upstream HTTP/2 connection: its requests are told
	jmp	.noclient
@@:
	test	dword [r12+S_FLAGS],SF_QC
	jz	@f
	call	qc_closing			; a QUIC connection: no socket of its own
	jmp	.noclient
@@:
	test	dword [r12+S_FLAGS],SF_H3S
	jz	@f
	call	h3s_closing			; an HTTP/3 stream: no socket either
	jmp	.noclient
@@:
	test	dword [r12+S_FLAGS],SF_MIR
	jz	@f
	dec	dword [g_mir_n]			; a mirrored request: no client at all
	call	fwd_gone
	jmp	.noclient
@@:
	test	dword [r12+S_FLAGS],SF_H2S
	jz	.client
	call	h2s_closing			; a stream: no socket of its own
.noclient:
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jnz	.upstream
	cmp	dword [r12+S_INFL],0
	jne	.done
	mov	edi,ebx
	call	session_maybe_free
	jmp	.done
.client:
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
.upstream:
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
	call	bulk_close_fds			; (the normal descriptors bulk made)
	test	dword [r12+S_FLAGS],SF_H2S or SF_H2U or SF_QC or SF_H3S or SF_MIR
	jnz	.client_closed			; no client socket
	test	byte [g_sbig+rbx],SX_RST_C
	jz	.client_close
	mov	edi,OP_S_OPT			; SO_LINGER 0 just before the close. Not
	mov	esi,ebx				; linked: a linked close would run later,
	call	sess_sqe			; from task work, when its slot may hold
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD	; the next session's socket
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[r12+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	test	dword [r12+S_FLAGS],SF_RAW
	jz	@f
	mov	byte [rax+SQE_FLAGS],0
@@:
	call	sqe_linger0
.client_close:
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
	test	byte [g_sbig+rbx],SX_RST_U
	jz	.up_close
	mov	edi,OP_S_OPT			; (not linked either)
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	call	sqe_linger0
.up_close:
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

; rax = an SQE (socket command): set SO_LINGER to 0 seconds
sqe_linger0:
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	dword [rax+SQE_LEVEL],SOL_SOCKET
	mov	dword [rax+SQE_OPTNAME],SO_LINGER
	mov	dword [rax+SQE_OPTLEN],8
	lea	rcx,[linger0]
	mov	[rax+SQE_OPTVAL],rcx
	ret

rodata
	align 4
	linger0		dd 1, 0		; on, 0 s: the close resets
end rodata

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
	test	dword [r12+S_FLAGS],SF_H2S or SF_H2U or SF_QC or SF_H3S or SF_MIR
	jz	@f
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.free				; no client socket, nothing else to close
@@:
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
	mov	ecx,[r12+S_FLAGS]
	and	dword [r12+S_FLAGS],not (SF_C_WAIT or SF_U_WAIT or SF_FDS_CLOSING)
	mov	dword [r12+S_STATE],ST_FREE
	inc	dword [r12+S_GEN]
	test	ecx,SF_MIR			; (a copy was not counted)
	jnz	@f
	mov	eax,[r12+S_LST]
	dec	dword [g_ls_active+rax*4]
	dec	dword [g_active]
@@:
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
