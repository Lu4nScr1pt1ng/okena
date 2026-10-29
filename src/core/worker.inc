; Worker process: one per CPU, shared-nothing, single-threaded event loop.

bss
	g_sigfd		dd ?
	g_tick		dd ?
	g_draining	dd ?		; 0 serving, 1 drain delay, 2 draining
	g_drain_until	dd ?		; tick that ends the current phase
	g_sig_buf:	rb SIGINFO_SIZE
end bss

rodata
	align 8
	ts_tick		dq 1, 0			; __kernel_timespec: one second
	worker_name	db 'okena-worker',0
end rodata

; edi = worker index. Never returns.
worker_main:
	mov	[g_worker_id],edi
	mov	dword [g_is_worker],1
	mov	ebx,edi
	; Die with the supervisor, and never outlive one we lost the race with.
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	mov	edi,EXIT_OK
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[worker_name]
	mov	eax,SYS_prctl
	syscall
	mov	edi,ebx
	call	pin_to_cpu

	; SIGTERM/SIGINT stay blocked (inherited) and arrive through a signalfd
	; read on the ring. It is a blocking fd on purpose: io_uring then waits
	; for it with an internal poll instead of failing with EAGAIN.
	mov	qword [g_sigmask],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1))
	mov	edi,-1
	lea	rsi,[g_sigmask]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.no_signalfd
	mov	[g_sigfd],eax

	call	sessions_init
	test	eax,eax
	js	.no_memory
	cmp	dword [g_plan_engine],2
	je	.no_epoll
	call	ring_init
	test	eax,eax
	js	.no_ring
	call	ring_register_files
	test	eax,eax
	js	.no_files
	call	pbuf_register
	test	eax,eax
	js	.no_pbuf
	call	ring_lockdown
	test	eax,eax
	js	.no_lockdown

	call	arm_accepts
	call	arm_timer
	call	arm_signal

.loop:
	mov	edi,1
	call	ring_enter
	call	ring_reap
	cmp	dword [g_draining],2
	jne	.loop
	cmp	dword [g_active],0
	jne	.loop
	mov	edi,EXIT_OK
	jmp	exit_process

.no_signalfd:
	push	rax
	call	log_begin
	out_lit 'signalfd failed (errno '
	jmp	.fatal
.no_memory:
	push	rax
	call	log_begin
	out_lit 'cannot reserve memory (errno '
	jmp	.fatal
.no_epoll:
	call	log_begin
	out_lit 'io_engine epoll is not built yet; use auto or io_uring'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
.no_ring:
	push	rax
	call	log_begin
	out_lit 'io_uring is not available (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit '); the epoll engine is not built yet. In Docker, run with the okena seccomp profile'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
.no_files:
	push	rax
	call	log_begin
	out_lit 'cannot register the descriptor table (errno '
	jmp	.fatal
.no_pbuf:
	push	rax
	call	log_begin
	out_lit 'cannot register provided buffers, kernel 5.19 or newer is needed (errno '
	jmp	.fatal
.no_lockdown:
	push	rax
	call	log_begin
	out_lit 'cannot restrict the io_uring operations (errno '
.fatal:
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; Multishot one-second tick: idle timeouts and drain deadlines.
arm_timer:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[ts_tick]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],IORING_TIMEOUT_MULTISHOT
	mov	rcx,OP_TIMER shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

on_timer:
	test	r15d,IORING_CQE_F_MORE
	jnz	@f
	call	arm_timer
@@:
	inc	dword [g_tick]
	call	idle_expire
	cmp	dword [g_draining],0
	je	.done
	mov	eax,[g_tick]
	cmp	eax,[g_drain_until]
	jb	.done
	cmp	dword [g_draining],1
	je	stop_accepting
	; drain timeout: close what is left
	call	sessions_close_all
.done:
	ret

arm_signal:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	ecx,[g_sigfd]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_sig_buf]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],SIGINFO_SIZE
	mov	rcx,OP_SIGNAL shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

; SIGTERM/SIGINT: keep serving for the drain delay, then stop accepting
; and give open connections until the drain timeout.
on_signal:
	call	arm_signal
	cmp	dword [g_draining],0
	jne	.done
	mov	dword [g_draining],1
	mov	rax,[g_plan_drain_delay]
	call	us_to_ticks
	add	eax,[g_tick]
	mov	[g_drain_until],eax
	cmp	qword [g_plan_drain_delay],0
	je	stop_accepting
.done:
	ret

; rax = microseconds. eax = whole ticks, rounded up.
us_to_ticks:
	add	rax,999999
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	ret

stop_accepting:
	mov	dword [g_draining],2
	mov	rax,[g_plan_drain_timeout]
	call	us_to_ticks
	add	eax,[g_tick]
	mov	[g_drain_until],eax
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,ebx
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,[g_worker_id]
	mov	ecx,[g_lfd+rcx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_ALL
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret
