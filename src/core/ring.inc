; io_uring: one ring per worker, used from a single thread.
; Derived from fasm2crud's ring, where these choices were measured.
;
; Setup flags:
;   SINGLE_ISSUER + DEFER_TASKRUN  completions are processed only when we ask,
;                                  on our own thread, without IPIs
;   SUBMIT_ALL                     a failing SQE does not stall the ones after it
;   NO_SQARRAY                     SQ tail indexes the SQE array directly
;   CQSIZE                         completion queue 4x the submission queue
;   R_DISABLED                     created disabled, enabled by ring_lockdown
;                                  once its restrictions are in place

bss
	align 8
	g_sq_head_ptr	dq ?
	g_sq_tail_ptr	dq ?
	g_sqes		dq ?
	g_cq_head_ptr	dq ?
	g_cq_tail_ptr	dq ?
	g_cqes		dq ?
	g_ring_fd	dd ?
	g_sq_entries	dd ?
	g_sq_mask	dd ?
	g_cq_mask	dd ?
	g_sq_tail	dd ?		; local tail, published on ring_enter
	g_sq_flushed	dd ?		; SQEs the kernel has consumed
	g_enter_fd	dd ?		; ring fd, or its registered index
	g_enter_flags	dd ?
	g_reaped	dd ?		; completions handled so far
	g_uparams:	rb UP_SIZE
end bss

; eax = 0 or -errno (or -1 when the kernel lacks a required feature).
; The rings need contiguous kernel memory. When the kernel has none at
; that moment (ENOMEM: fragmentation, dying processes not torn down yet),
; try again with rings half the size, down to an eighth, pausing a little
; between attempts, before giving up.
RING_MIN_SHIFT	:= 3

ring_init:
	push	rbx
	push	r12
	push	r13
	xor	r13d,r13d			; size reduction (shift)
.attempt:
	lea	rdi,[g_uparams]
	xor	eax,eax
	mov	ecx,UP_SIZE/8
	rep	stosq
	mov	dword [g_uparams+UP_FLAGS],IORING_SETUP_SINGLE_ISSUER or IORING_SETUP_DEFER_TASKRUN or IORING_SETUP_SUBMIT_ALL or IORING_SETUP_NO_SQARRAY or IORING_SETUP_CQSIZE or IORING_SETUP_CLAMP or IORING_SETUP_R_DISABLED
	mov	eax,CQ_ENTRIES
	mov	ecx,r13d
	shr	eax,cl
	mov	[g_uparams+UP_CQ_ENTRIES],eax
	mov	edi,RING_ENTRIES
	shr	edi,cl
	lea	rsi,[g_uparams]
	mov	eax,SYS_io_uring_setup
	syscall
	cmp	eax,-ENOMEM
	jne	.created
	cmp	r13d,RING_MIN_SHIFT
	jae	.done				; still no memory: the caller decides
	inc	r13d
	mov	eax,20
	call	sleep_ms
	jmp	.attempt
.created:
	test	eax,eax
	js	.done
	mov	[g_ring_fd],eax
	test	r13d,r13d
	jz	@f
	push	rax
	call	log_begin
	out_lit 'kernel memory was short: io_uring rings made '
	mov	eax,1
	mov	ecx,r13d
	shl	eax,cl
	call	out_u64
	out_lit ' times smaller'
	call	log_end
	pop	rax
@@:
	mov	ebx,eax

	mov	eax,[g_uparams+UP_FEATURES]
	and	eax,IORING_FEAT_SINGLE_MMAP or IORING_FEAT_NODROP
	cmp	eax,IORING_FEAT_SINGLE_MMAP or IORING_FEAT_NODROP
	mov	eax,-1
	jne	.done

	; SQ and CQ rings share one mapping; it must cover the larger of the two.
	mov	eax,[g_uparams+UP_SQ_ENTRIES]
	mov	[g_sq_entries],eax
	shl	eax,2
	add	eax,[g_uparams+UP_SQ_ARRAY]
	mov	ecx,[g_uparams+UP_CQ_ENTRIES]
	shl	ecx,4
	add	ecx,[g_uparams+UP_CQ_CQES]
	cmp	ecx,eax
	cmova	eax,ecx
	xor	edi,edi
	mov	esi,eax
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_POPULATE
	mov	r8d,ebx
	mov	r9d,IORING_OFF_SQ_RING
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	r12,rax

	mov	eax,[g_uparams+UP_SQ_HEAD]
	add	rax,r12
	mov	[g_sq_head_ptr],rax
	mov	eax,[g_uparams+UP_SQ_TAIL]
	add	rax,r12
	mov	[g_sq_tail_ptr],rax
	mov	eax,[g_uparams+UP_SQ_MASK]
	mov	eax,[r12+rax]
	mov	[g_sq_mask],eax
	mov	eax,[g_uparams+UP_CQ_HEAD]
	add	rax,r12
	mov	[g_cq_head_ptr],rax
	mov	eax,[g_uparams+UP_CQ_TAIL]
	add	rax,r12
	mov	[g_cq_tail_ptr],rax
	mov	eax,[g_uparams+UP_CQ_MASK]
	mov	eax,[r12+rax]
	mov	[g_cq_mask],eax
	mov	eax,[g_uparams+UP_CQ_CQES]
	add	rax,r12
	mov	[g_cqes],rax

	xor	edi,edi
	mov	esi,[g_sq_entries]
	shl	esi,6
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_POPULATE
	mov	r8d,ebx
	mov	r9d,IORING_OFF_SQES
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4095
	jae	.done
	mov	[g_sqes],rax

	; Register the ring fd itself, so io_uring_enter skips the fd table
	; lookup on every call. Optional: fall back to the plain fd.
	mov	[g_enter_fd],ebx
	mov	dword [g_enter_flags],IORING_ENTER_GETEVENTS
	sub	rsp,16
	mov	dword [rsp],-1			; offset: any free slot
	mov	dword [rsp+4],0
	mov	[rsp+8],rbx			; data: the ring fd
	mov	edi,ebx
	mov	esi,IORING_REGISTER_RING_FDS
	mov	rdx,rsp
	mov	r10d,1
	mov	eax,SYS_io_uring_register
	syscall
	mov	ecx,[rsp]
	add	rsp,16
	cmp	eax,1
	jne	.registered
	mov	[g_enter_fd],ecx
	mov	dword [g_enter_flags],IORING_ENTER_GETEVENTS or IORING_ENTER_REGISTERED_RING
.registered:
	xor	eax,eax
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Direct descriptors: a sparse table of 3 * sessions. Accepts allocate
; from the first third (the kernel picks a free slot); upstream sockets
; take slots from the rest through upslot_alloc, so an idle upstream
; connection can outlive its session in a pool. Sockets never enter
; the process fd table, which saves the fd lookup and reference counting
; on every operation. eax = 0 or -errno.
ring_register_files:
	sub	rsp,40
	mov	eax,[g_sessions]
	imul	eax,eax,3			; clients, then twice as many upstreams
	mov	[rsp],eax				; nr
	mov	dword [rsp+4],IORING_RSRC_REGISTER_SPARSE
	xor	eax,eax
	mov	[rsp+8],rax				; resv2
	mov	[rsp+16],rax				; data
	mov	[rsp+24],rax				; tags
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_FILES2
	mov	rdx,rsp
	mov	r10d,32
	mov	eax,SYS_io_uring_register
	syscall
	test	eax,eax
	js	.done
	; struct io_uring_file_index_range { off, len, resv }
	mov	dword [rsp],0
	mov	eax,[g_sessions]
	mov	[rsp+4],eax
	mov	qword [rsp+8],0
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_FILE_ALLOC_RANGE
	mov	rdx,rsp
	xor	r10d,r10d
	mov	eax,SYS_io_uring_register
	syscall
.done:
	add	rsp,40
	ret

; Seccomp does not see io_uring operations, so the ring gets its own
; allowlist: only the opcodes and SQE flags okena uses, and no
; io_uring_register operation at all once it is enabled. eax = 0 or -errno.
rodata
	align 8
	ring_restrictions:
	irp op, IORING_OP_NOP, IORING_OP_TIMEOUT, IORING_OP_ACCEPT, IORING_OP_ASYNC_CANCEL, \
		IORING_OP_LINK_TIMEOUT, IORING_OP_CONNECT, IORING_OP_CLOSE, IORING_OP_READ, \
		IORING_OP_SEND, IORING_OP_RECV, IORING_OP_SHUTDOWN, IORING_OP_SOCKET, \
		IORING_OP_URING_CMD, IORING_OP_POLL_ADD, IORING_OP_RECVMSG
		dw IORING_RESTRICTION_SQE_OP
		db op, 0
		dd 0, 0, 0
	end irp
	dw IORING_RESTRICTION_SQE_FLAGS_ALLOWED
	db IOSQE_FIXED_FILE or IOSQE_IO_LINK or IOSQE_IO_HARDLINK or IOSQE_BUFFER_SELECT or IOSQE_CQE_SKIP_SUCCESS, 0
	dd 0, 0, 0
	RING_RESTRICTIONS_COUNT = ($ - ring_restrictions) / 16
end rodata

ring_lockdown:
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_RESTRICTIONS
	lea	rdx,[ring_restrictions]
	mov	r10d,RING_RESTRICTIONS_COUNT
	mov	eax,SYS_io_uring_register
	syscall
	test	eax,eax
	js	.done
	mov	edi,[g_ring_fd]
	mov	esi,IORING_REGISTER_ENABLE_RINGS
	xor	edx,edx
	xor	r10d,r10d
	mov	eax,SYS_io_uring_register
	syscall
.done:
	ret

; rax = zeroed SQE. Flushes the queue when it is full.
ring_get_sqe:
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_head_ptr]
	mov	ecx,eax
	sub	ecx,[rdx]
	cmp	ecx,[g_sq_entries]
	jae	.full
.take:
	mov	ecx,eax
	and	ecx,[g_sq_mask]
	shl	rcx,6
	add	rcx,[g_sqes]
	inc	eax
	mov	[g_sq_tail],eax
	vpxor	xmm0,xmm0,xmm0
	vmovdqu	[rcx],xmm0
	vmovdqu	[rcx+16],xmm0
	vmovdqu	[rcx+32],xmm0
	vmovdqu	[rcx+48],xmm0
	mov	rax,rcx
	ret
.full:
	call	ring_flush
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_head_ptr]
	mov	ecx,eax
	sub	ecx,[rdx]
	cmp	ecx,[g_sq_entries]
	jb	.take
	; The kernel refused new work: crash this worker and let the supervisor
	; start a clean one instead of spinning.
	call	log_begin
	log_lit 'submission queue stuck'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; Submit pending SQEs without waiting.
ring_flush:
	xor	edi,edi

; Submit pending SQEs and wait for at least edi completions.
ring_enter:
	mov	eax,[g_sq_tail]
	mov	rdx,[g_sq_tail_ptr]
	mov	[rdx],eax			; x86 stores are ordered: SQE contents first
	mov	esi,eax
	sub	esi,[g_sq_flushed]
	mov	edx,edi
	mov	edi,[g_enter_fd]
	mov	r10d,[g_enter_flags]
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_io_uring_enter
	syscall
	test	eax,eax
	js	.done				; EINTR, EBUSY, ...: the caller just retries
	add	[g_sq_flushed],eax
.done:
	ret

; Completion dispatch. user_data = op << 56 | generation << 32 | index.
; Every handler receives:
;   ebx = index, r12d = generation, r14 = res (sign extended),
;   r15d = cqe flags. Handlers may clobber rbx, r12-r15 but keep rbp.
OP_ACCEPT	:= 0
OP_TIMER	:= 1
OP_SIGNAL	:= 2
OP_IGNORE	:= 3
OP_S_SOCKET	:= 4		; session ops from here on
OP_S_CONNECT	:= 5
OP_S_LTIMEOUT	:= 6
OP_S_RECV_C	:= 7		; from the client
OP_S_RECV_U	:= 8		; from the upstream
OP_S_SEND_C	:= 9		; to the client
OP_S_SEND_U	:= 10		; to the upstream
OP_S_SHUT	:= 11
OP_S_CLOSE	:= 12
OP_S_CANCEL	:= 13
OP_S_OPT	:= 14
OP_ACCEPT_A	:= 15		; single-shot accept with the client's address
OP_S_SEND_PP	:= 16		; PROXY protocol header
OP_H_RECV_C	:= 17		; http
OP_H_RECV_U	:= 18
OP_H_SEND_C	:= 19
OP_H_SEND_U	:= 20
OP_POOL_WATCH	:= 21		; an idle pooled connection changed
OP_H_KTLS	:= 22		; https: the keys are in the kernel
OP_H_ULP	:= 23		; https: the TLS ULP on the socket (its errno kept)
OP_S_SEND_PFX	:= 24		; tls passthrough: the ClientHello, upstream
OP_H_UKTLS	:= 25		; upstream TLS: the keys are in the kernel
OP_H_UDRAIN	:= 26		; upstream TLS: drain a kTLS control record (a ticket)
OP_COUNT	:= 27

rodata
	align 8
	dispatch_tbl	dq on_accept, on_timer, on_signal, on_ignore
			dq on_s_socket, on_s_connect, on_s_done, on_s_recv_c, on_s_recv_u
			dq on_s_send_c, on_s_send_u, on_s_done, on_s_done, on_s_done, on_s_done
			dq on_accept_a, on_s_send_pp
			dq on_h_recv_c, on_h_recv_u, on_h_send_c, on_h_send_u
			dq on_pool_watch, on_h_ktls, on_h_ulp, on_s_send_pfx
			dq on_h_uktls, on_h_udrain
end rodata

ring_reap:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebp,REAP_BUDGET
.next:
	mov	rax,[g_cq_head_ptr]
	mov	ecx,[rax]
	mov	rdx,[g_cq_tail_ptr]
	cmp	ecx,[rdx]
	je	.done
	mov	edx,ecx
	and	edx,[g_cq_mask]
	shl	edx,4
	add	rdx,[g_cqes]
	mov	rbx,[rdx+CQE_USER_DATA]
	movsxd	r14,dword [rdx+CQE_RES]
	mov	r15d,[rdx+CQE_FLAGS]
	inc	ecx
	mov	[rax],ecx			; release the CQE before handling it
	mov	rax,rbx
	shr	rax,56
	mov	r12,rbx
	shr	r12,32
	and	r12d,0xFFFFFF
	mov	ebx,ebx
	cmp	eax,OP_COUNT
	jae	.next
	inc	dword [g_reaped]
	call	qword [dispatch_tbl+rax*8]
	dec	ebp
	jnz	.next
	; long batch: hand the kernel what is queued so far
	call	ring_flush
	mov	ebp,REAP_BUDGET
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

on_ignore:
	ret
