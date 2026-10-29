; Active health checks: one health process for the whole instance, so a
; backend is checked once per interval, not once per worker.
;
; TCP checks connect without blocking, many in parallel on one epoll; a
; check passes when the connect completes within the timeout. An HTTP
; check then sends one request (Connection: close) and passes when the
; status line arrives in time with a status in `expect` (200..399 by
; default); the rest of the answer is not read. `rise`
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
	g_hc_phase	rd MAX_SERVERS	; 0 connecting, 1 waiting for the HTTP answer
	g_hc_rlen	rd MAX_SERVERS
	g_hc_rbuf	rb MAX_SERVERS * HC_RBUF	; the start of the answer
	g_hc_ok		rd MAX_SERVERS	; consecutive passes
	g_hc_bad	rd MAX_SERVERS	; consecutive failures
	g_hc_active	rd MAX_SERVERS	; slot held an address at the last look
	g_hc_events:	rb EPOLL_EVENT * 64
end bss

rodata
	health_name	db 'okena-health',0
end rodata

assert 1 shl 4 = 16
HC_RBUF		= 16		; "HTTP/1.1 200 " is all a check reads
HC_STATUS_BASE	= 100000	; -(HC_STATUS_BASE + N): answered with status N

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
	push	rcx
	push	rdx
	mov	edi,ecx
	call	sv_comeback			; health says it is back: ramp it up
	pop	rdx
	pop	rcx
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
	cmp	edi,MAX_SERVERS
	jae	.next_event
	cmp	dword [g_hc_phase+rdi*4],1
	je	.answer
	call	hc_connect_done
	jmp	.next_event
.answer:
	call	hc_http_read
.next_event:
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
	mov	dword [g_hc_phase+rbx*4],0	; connecting
	mov	dword [g_hc_rlen+rbx*4],0
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
	push	r12
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
	test	rsi,rsi
	jnz	.result
	call	hc_pool_of			; r12 = pool (rbx = server)
	cmp	dword [r12+PL_H_HTTP],0
	je	.result
	mov	edi,ebx
	call	hc_http_send			; connected: now the request
	jmp	.out
.result:
	mov	edi,ebx
	call	hc_result
.out:
	pop	r12
	pop	rbx
	ret

; edi = server whose check connection is up: write the request, then
; wait for the answer.
hc_http_send:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	call	hc_pool_of			; r12 = pool
	sub	rsp,2304
	mov	rdi,rsp
	cmp	dword [r12+PL_H_HEAD],0
	jne	@f
	mov	dword [rdi],'GET '
	add	rdi,4
	jmp	.target
@@:
	mov	dword [rdi],'HEAD'
	mov	byte [rdi+4],' '
	add	rdi,5
.target:
	mov	rsi,[r12+PL_H_PATH]
	mov	ecx,[r12+PL_H_PLEN]
	rep	movsb
	lea	rsi,[hc_req_mid]
	mov	ecx,hc_req_mid.len
	rep	movsb
	mov	rsi,[r12+PL_H_HOST]
	mov	ecx,[r12+PL_H_HLEN]
	test	rsi,rsi
	jnz	@f
	imul	rax,rbx,SV_SIZE			; Host: the server as written
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	ecx,[g_servers+rax+SV_TLEN]
	cmp	ecx,256
	jbe	@f
	mov	ecx,256
@@:
	rep	movsb
	lea	rsi,[hc_req_end]
	mov	ecx,hc_req_end.len
	rep	movsb
	mov	rdx,rdi
	sub	rdx,rsp
	mov	edi,[g_hc_fd+rbx*4]
	mov	rsi,rsp
	mov	eax,SYS_write
	syscall
	mov	r13,rax
	add	rsp,2304
	test	r13,r13
	js	.failed				; (a short write of a small request: the next read fails it)
	; wait for the answer on the same epoll registration
	mov	dword [g_hc_phase+rbx*4],1
	sub	rsp,16
	mov	dword [rsp],EPOLLIN or EPOLLRDHUP
	mov	[rsp+4],rbx
	mov	edi,[g_hc_epfd]
	mov	esi,EPOLL_CTL_MOD
	mov	edx,[g_hc_fd+rbx*4]
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	jmp	.out
.failed:
	mov	edi,ebx
	mov	rsi,r13
	call	hc_result
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring hc_req_mid, ' HTTP/1.1',13,10,'Host: '
cstring hc_req_end, 13,10,'User-Agent: okena-health',13,10,'Connection: close',13,10,13,10

; edi = server with answer bytes: once "HTTP/1.x NNN" is in, judge NNN.
hc_http_read:
	push	rbx
	push	r12
	mov	ebx,edi
	mov	edi,[g_hc_fd+rbx*4]
	cmp	edi,-1
	je	.out
	mov	eax,[g_hc_rlen+rbx*4]
	mov	ecx,ebx
	shl	ecx,4				; HC_RBUF
	lea	rsi,[g_hc_rbuf+rcx+rax]
	mov	edx,HC_RBUF
	sub	edx,eax
	xor	eax,eax				; SYS_read
	syscall
	cmp	rax,-EAGAIN
	je	.out
	test	rax,rax
	jle	.closed
	add	[g_hc_rlen+rbx*4],eax
	cmp	dword [g_hc_rlen+rbx*4],12
	jb	.out				; not the whole status code yet
	mov	ecx,ebx
	shl	ecx,4
	lea	rsi,[g_hc_rbuf+rcx]
	cmp	dword [rsi],'HTTP'
	jne	.not_http
	cmp	word [rsi+4],'/1'
	jne	.not_http
	cmp	byte [rsi+8],' '
	jne	.not_http
	xor	eax,eax
	mov	ecx,9
@@:
	movzx	edx,byte [rsi+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.not_http
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,12
	jb	@b
	push	rax
	call	hc_pool_of			; r12 = pool (clobbers eax)
	pop	rax
	cmp	eax,[r12+PL_H_LO]
	jb	.status
	cmp	eax,[r12+PL_H_HI]
	ja	.status
	mov	edi,ebx
	xor	esi,esi				; passed
	call	hc_result
	jmp	.out
.status:
	neg	eax
	sub	eax,HC_STATUS_BASE		; reported as "HTTP status N"
	movsxd	rsi,eax
	mov	edi,ebx
	call	hc_result
	jmp	.out
.not_http:
	mov	edi,ebx
	mov	rsi,-EPROTO
	call	hc_result
	jmp	.out
.closed:
	mov	rsi,rax
	test	rsi,rsi
	jnz	@f
	mov	rsi,-ECONNRESET			; closed before a status line
@@:
	mov	edi,ebx
	call	hc_result
.out:
	pop	r12
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
	cmp	rax,HC_STATUS_BASE
	jb	.errno
	sub	rax,HC_STATUS_BASE
	push	rax
	out_lit 'HTTP status '
	pop	rax
	call	out_u64
	jmp	.reason
.errno:
	call	errno_text
.reason:
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
