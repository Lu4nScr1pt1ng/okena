; Active health checks: one health process for the whole instance, so a
; backend is checked once per interval, not once per worker.
;
; TCP checks connect without blocking, many in parallel on one epoll; a
; check passes when the connect completes within the timeout. `rise`
; passes in a row bring a server back, `fall` failures take it out; each
; change is logged once with its reason. The state goes to a shared table
; that workers read with one load per decision (0 = up). A server starts
; up: a restart must not take the whole service down until checks pass.
; When every server of a pool is down, workers try them anyway (panic).

HC_UP		= 0
HC_DOWN		= 1
HC_TICK_MS	= 100

bss
	align 8
	g_health_tbl	dq ?		; shared: one dword per server
	g_health_pid	dd ?
	g_hc_epfd	dd ?
	g_hc_now	dq ?
	g_hc_next	rq MAX_SERVERS	; when to check next (ms)
	g_hc_deadline	rq MAX_SERVERS	; in-flight check timeout (ms)
	g_hc_fd		rd MAX_SERVERS	; in-flight socket, -1 = none
	g_hc_ok		rd MAX_SERVERS	; consecutive passes
	g_hc_bad	rd MAX_SERVERS	; consecutive failures
	g_hc_active	rd MAX_SERVERS	; slot held an address at the last look
	g_hc_events:	rb EPOLL_EVENT * 64
end bss

rodata
	health_name	db 'okena-health',0
end rodata

; Shared table, before forking a generation (zero: everyone up).
health_table_init:
	xor	edi,edi
	mov	esi,MAX_SERVERS * 8
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_health_tbl],rax
	ret

; Worker tick: a server the health checks bring back up is also let out
; of this worker's passive ejection, so it returns as soon as it is
; confirmed, not when the ejection time runs out. The tick is a second
; and a server can go down and up within one, so workers follow the
; count of comebacks, not the state.
bss
	g_hc_seen	rd MAX_SERVERS		; worker: state at the last tick
end bss

health_follow:
	cmp	dword [g_plan_health],0
	je	.done
	mov	rdx,[g_health_tbl]
	xor	ecx,ecx
.next:
	cmp	ecx,[g_plan_servers]
	jae	.done
	mov	eax,[rdx+rcx*8+4]
	cmp	eax,[g_hc_seen+rcx*4]
	je	.skip
	mov	[g_hc_seen+rcx*4],eax
	mov	dword [g_sv_down+rcx*4],0
	mov	dword [g_sv_fails+rcx*4],0
.skip:
	inc	ecx
	jmp	.next
.done:
	ret

; Supervisor: start the health process when some pool has checks.
spawn_health:
	cmp	dword [g_plan_health],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	health_main
	js	.none
	mov	[g_health_pid],eax
.none:
	ret

; Never returns.
health_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[health_name]
	mov	eax,SYS_prctl
	syscall
	mov	edi,EPOLL_CLOEXEC
	mov	eax,SYS_epoll_create1
	syscall
	test	eax,eax
	js	.fatal
	mov	[g_hc_epfd],eax
	xor	ecx,ecx
@@:
	mov	dword [g_hc_fd+rcx*4],-1
	inc	ecx
	cmp	ecx,MAX_SERVERS
	jb	@b
	; a restarted health process carries on from the shared state: a
	; server already down stays down until it passes `rise` checks
	call	groups_refresh
	xor	ebx,ebx
.resume:
	cmp	ebx,[g_plan_servers]
	jae	.confine
	imul	rax,rbx,SV_SIZE
	mov	ecx,[g_servers+rax+SV_ACTIVE]
	mov	[g_hc_active+rbx*4],ecx
	inc	ebx
	jmp	.resume
.confine:
	seccomp_for filter_health
.loop:
	call	hc_clock
	call	groups_refresh			; addresses of names, as workers do
	call	hc_start_due
	mov	edi,[g_hc_epfd]
	lea	rsi,[g_hc_events]
	mov	edx,64
	mov	r10d,HC_TICK_MS
	mov	eax,SYS_epoll_wait
	syscall
	mov	r12,rax
	call	hc_clock
	xor	ebx,ebx
.event:
	cmp	rbx,r12
	jge	.timeouts
	imul	rax,rbx,EPOLL_EVENT
	mov	edi,dword [g_hc_events+rax+4]	; data: server index
	call	hc_connect_done
	inc	ebx
	jmp	.event
.timeouts:
	call	hc_check_deadlines
	jmp	.loop
.fatal:
	mov	edi,EXIT_FAILURE
	jmp	exit_process

hc_clock:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000
	mov	rcx,rax
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	r8d,1000000
	div	r8
	add	rax,rcx
	mov	[g_hc_now],rax
	add	rsp,24
	ret

; Start the checks that are due.
hc_start_due:
	push	rbx
	push	r12
	push	r13
	xor	r12d,r12d			; pool
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.done
	imul	r13,r12,PL_SIZE
	lea	r13,[g_pools+r13]
	cmp	dword [r13+PL_HEALTH],0
	je	.next_pool
	mov	ebx,[r13+PL_FIRST]
.server:
	mov	eax,[r13+PL_FIRST]
	add	eax,[r13+PL_COUNT]
	cmp	ebx,eax
	jae	.next_pool
	imul	rax,rbx,SV_SIZE
	mov	ecx,[g_servers+rax+SV_ACTIVE]
	cmp	ecx,[g_hc_active+rbx*4]
	je	@f
	; a slot that just got (or lost) an address starts over, as up
	mov	[g_hc_active+rbx*4],ecx
	mov	rdx,[g_health_tbl]
	mov	dword [rdx+rbx*8],HC_UP
	mov	dword [g_hc_ok+rbx*4],0
	mov	dword [g_hc_bad+rbx*4],0
	mov	qword [g_hc_next+rbx*8],0
@@:
	test	ecx,ecx
	jz	.next_server
	cmp	dword [g_hc_fd+rbx*4],-1
	jne	.next_server			; in flight
	mov	rax,[g_hc_now]
	cmp	rax,[g_hc_next+rbx*8]
	jb	.next_server
	mov	edi,ebx
	mov	rsi,r13
	call	hc_start
.next_server:
	inc	ebx
	jmp	.server
.next_pool:
	inc	r12d
	jmp	.pool
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = server, rsi = pool: open a check connection.
hc_start:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	mov	r13,rsi
	imul	r12,rbx,SV_SIZE
	lea	r12,[g_servers+r12]
	mov	edi,[r12+SV_FAMILY]
	mov	esi,SOCK_STREAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.out				; out of descriptors: try next round
	mov	[g_hc_fd+rbx*4],eax
	mov	eax,[r13+PL_H_TIMEOUT]
	add	rax,[g_hc_now]
	mov	[g_hc_deadline+rbx*8],rax
	mov	eax,[r13+PL_H_EVERY]
	add	rax,[g_hc_now]
	mov	[g_hc_next+rbx*8],rax
	mov	edi,[g_hc_fd+rbx*4]
	lea	rsi,[r12+SV_SA]
	mov	edx,[r12+SV_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jz	.passed
	cmp	eax,-EINPROGRESS
	jne	.failed
	sub	rsp,16
	mov	dword [rsp],EPOLLOUT
	mov	[rsp+4],rbx
	mov	edi,[g_hc_epfd]
	mov	esi,EPOLL_CTL_ADD
	mov	edx,[g_hc_fd+rbx*4]
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	jmp	.out
.passed:
	mov	edi,ebx
	xor	esi,esi
	call	hc_result
	jmp	.out
.failed:
	mov	edi,ebx
	movsxd	rsi,eax
	call	hc_result
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = server whose check connection became writable.
hc_connect_done:
	push	rbx
	mov	ebx,edi
	cmp	ebx,MAX_SERVERS
	jae	.out
	mov	eax,[g_hc_fd+rbx*4]
	cmp	eax,-1
	je	.out
	sub	rsp,16
	mov	dword [rsp],0
	mov	dword [rsp+8],4
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_ERROR
	mov	r10,rsp
	lea	r8,[rsp+8]
	mov	eax,SYS_getsockopt
	syscall
	mov	ecx,[rsp]
	add	rsp,16
	neg	ecx
	movsxd	rsi,ecx				; 0 or -errno
	mov	edi,ebx
	call	hc_result
.out:
	pop	rbx
	ret

; Checks past their timeout fail.
hc_check_deadlines:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_servers]
	jae	.done
	cmp	dword [g_hc_fd+rbx*4],-1
	je	.skip
	mov	rax,[g_hc_now]
	cmp	rax,[g_hc_deadline+rbx*8]
	jb	.skip
	mov	edi,ebx
	mov	rsi,-ETIMEDOUT
	call	hc_result
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; edi = server, rsi = 0 (passed) or -errno. Closes the check socket and
; moves the server up or down when rise/fall is reached.
hc_result:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	mov	r13,rsi
	mov	edi,[g_hc_fd+rbx*4]
	cmp	edi,-1
	je	@f
	mov	dword [g_hc_fd+rbx*4],-1
	mov	eax,SYS_close			; also leaves the epoll set
	syscall
@@:
	call	hc_pool_of			; r12 = pool
	mov	rcx,[g_health_tbl]
	test	r13,r13
	jnz	.bad
	mov	dword [g_hc_bad+rbx*4],0
	inc	dword [g_hc_ok+rbx*4]
	cmp	dword [rcx+rbx*8],HC_DOWN
	jne	.out
	mov	eax,[g_hc_ok+rbx*4]
	cmp	eax,[r12+PL_H_RISE]
	jb	.out
	mov	dword [rcx+rbx*8],HC_UP
	inc	dword [rcx+rbx*8+4]		; workers follow this, not the state
	call	log_begin
	out_lit 'backend '
	mov	edi,ebx
	call	log_server_addr
	out_lit ' is up (health check passed '
	mov	eax,[r12+PL_H_RISE]
	call	out_u64
	out_lit ' times)'
	call	log_end
	jmp	.out
.bad:
	mov	dword [g_hc_ok+rbx*4],0
	inc	dword [g_hc_bad+rbx*4]
	cmp	dword [rcx+rbx*8],HC_UP
	jne	.out
	mov	eax,[g_hc_bad+rbx*4]
	cmp	eax,[r12+PL_H_FALL]
	jb	.out
	mov	dword [rcx+rbx*8],HC_DOWN
	call	log_begin
	out_lit 'backend '
	mov	edi,ebx
	call	log_server_addr
	out_lit ' is down (health check: '
	mov	rax,r13
	neg	rax
	call	errno_text
	out_lit ', '
	mov	eax,[r12+PL_H_FALL]
	call	out_u64
	out_lit ' times)'
	call	log_end
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = server. r12 = its pool.
hc_pool_of:
	xor	ecx,ecx
.next:
	imul	r12,rcx,PL_SIZE
	lea	r12,[g_pools+r12]
	mov	eax,[r12+PL_FIRST]
	cmp	ebx,eax
	jb	.skip
	add	eax,[r12+PL_COUNT]
	cmp	ebx,eax
	jb	.done
.skip:
	inc	ecx
	cmp	ecx,[g_plan_pools]
	jb	.next
.done:
	ret

; edi = server: its address as written, and for names the address in use.
log_server_addr:
	push	rbx
	mov	ebx,edi
	call	log_server
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_GROUP],0
	je	.done
	out_lit ' ('
	imul	rax,rbx,SV_SIZE
	lea	rsi,[g_servers+rax+SV_SA+4]	; sin_addr
	mov	edi,4
	cmp	word [g_servers+rax+SV_SA],AF_INET6
	jne	@f
	lea	rsi,[g_servers+rax+SV_SA+8]	; sin6_addr
	mov	edi,6
@@:
	call	out_ip
	out_lit ')'
.done:
	pop	rbx
	ret
