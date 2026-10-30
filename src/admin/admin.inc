; Admin process: /metrics (Prometheus text format), /live and /ready on
; the `metrics` address. It reads the workers' statistics pages and sums
; them when scraped, so a scrape costs the workers nothing.
;
; One request per connection, with two-second socket timeouts, so a
; slow or silent client can hold it at most that long. /ready answers 503
; once the instance drains, so orchestrators stop sending traffic first.

ADMIN_BUF	:= 8 shl 20

bss
	align 8
	g_admin_pid	dd ?
	g_metrics_fd	dd ?		; -1 = none
	g_admin_buf	dq ?		; response being built
	g_admin_req:	rb 4096
end bss

rodata
	admin_name	db 'okena-admin',0
	align 8
	ts_admin_io	dq 2, 0
end rodata

; Supervisor, at startup: the metrics socket (kept across reloads).
metrics_open:
	mov	dword [g_metrics_fd],-1
	cmp	dword [g_plan_metrics],0
	je	.done
	movzx	edi,word [g_plan_metrics_sa]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.failed
	mov	[g_metrics_fd],eax
	cmp	word [g_plan_metrics_sa],AF_INET6
	jne	@f
	mov	edi,eax
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	lea	r10,[zero_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
@@:
	mov	edi,[g_metrics_fd]
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_metrics_fd]
	lea	rsi,[g_plan_metrics_sa]
	mov	edx,[g_plan_metrics_salen]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.failed
	mov	edi,[g_metrics_fd]
	mov	esi,64
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.failed
	call	log_begin
	out_lit 'metrics on '
	mov	rsi,[g_plan_metrics_text]
	mov	edx,[g_plan_metrics_tlen]
	call	out_str
	out_lit ' (/metrics, /live, /ready)'
	call	log_end
.done:
	ret
.failed:
	push	rax
	call	log_begin
	out_lit 'cannot open the metrics address '
	mov	rsi,[g_plan_metrics_text]
	mov	edx,[g_plan_metrics_tlen]
	call	out_str
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; Supervisor: start the admin process when there is a metrics socket.
spawn_admin:
	cmp	dword [g_metrics_fd],0
	jl	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	admin_main
	js	.none
	mov	[g_admin_pid],eax
.none:
	ret

; Never returns.
admin_main:
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
	lea	rsi,[admin_name]
	mov	eax,SYS_prctl
	syscall
	xor	edi,edi
	mov	esi,ADMIN_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_admin_buf],rax
	seccomp_for filter_admin
.loop:
	mov	edi,[g_metrics_fd]
	xor	esi,esi
	xor	edx,edx
	mov	r10d,SOCK_CLOEXEC
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.loop
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	call	admin_serve
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	jmp	.loop

; edi = connection: read one request, answer it.
admin_serve:
	push	rbx
	push	r12
	mov	ebx,edi
	xor	r12d,r12d			; bytes read
.read:
	mov	edi,ebx
	lea	rsi,[g_admin_req+r12]
	mov	edx,4095
	sub	edx,r12d
	jz	.parse
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.parse				; closed or timed out: use what came
	add	r12d,eax
	; the request line is enough
	xor	ecx,ecx
@@:
	cmp	ecx,r12d
	jae	.read
	cmp	byte [g_admin_req+rcx],10
	je	.parse
	inc	ecx
	jmp	@b
.parse:
	mov	byte [g_admin_req+r12],0
	cmp	r12d,5
	jb	.out
	cmp	dword [g_admin_req],'GET '
	jne	.not_found
	lea	rsi,[g_admin_req+4]
	cstring str_p_metrics, '/metrics'
	lea	rdi,[str_p_metrics]
	mov	edx,str_p_metrics.len
	call	admin_path_is
	jz	.metrics
	cstring str_p_live, '/live'
	lea	rdi,[str_p_live]
	mov	edx,str_p_live.len
	call	admin_path_is
	jz	.live
	cstring str_p_ready, '/ready'
	lea	rdi,[str_p_ready]
	mov	edx,str_p_ready.len
	call	admin_path_is
	jz	.ready
.not_found:
	cstring str_404, 'HTTP/1.1 404 Not Found',13,10,'Content-Length: 10',13,10,'Connection: close',13,10,13,10,'not found',10
	lea	rsi,[str_404]
	mov	edx,str_404.len
	jmp	.send
.live:
	cstring str_live, 'HTTP/1.1 200 OK',13,10,'Content-Length: 5',13,10,'Connection: close',13,10,13,10,'live',10
	lea	rsi,[str_live]
	mov	edx,str_live.len
	jmp	.send
.ready:
	mov	rax,[g_stats_tbl]
	cmp	qword [rax+SG_OFF+SG_DRAINING],0
	jne	.draining
	cstring str_ready, 'HTTP/1.1 200 OK',13,10,'Content-Length: 6',13,10,'Connection: close',13,10,13,10,'ready',10
	lea	rsi,[str_ready]
	mov	edx,str_ready.len
	jmp	.send
.draining:
	cstring str_draining, 'HTTP/1.1 503 Service Unavailable',13,10,'Content-Length: 9',13,10,'Connection: close',13,10,13,10,'draining',10
	lea	rsi,[str_draining]
	mov	edx,str_draining.len
	jmp	.send
.metrics:
	call	metrics_render			; rsi/edx = whole response
.send:
	mov	edi,ebx
	call	write_all
.out:
	pop	r12
	pop	rbx
	ret

; rsi = request target, rdi/edx = path. ZF when the target is that path
; (followed by a space or a query).
admin_path_is:
	xor	ecx,ecx
@@:
	cmp	ecx,edx
	jae	@f
	mov	al,[rsi+rcx]
	cmp	al,[rdi+rcx]
	jne	.no
	inc	ecx
	jmp	@b
@@:
	mov	al,[rsi+rcx]
	cmp	al,' '
	je	.yes
	cmp	al,'?'
	je	.yes
.no:
	or	eax,1				; ZF clear
	ret
.yes:
	xor	eax,eax
	ret

; edi = fd, rsi/edx = bytes.
write_all:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	mov	r12,rsi
	mov	r13d,edx
.next:
	test	r13d,r13d
	jz	.done
	mov	edi,ebx
	mov	rsi,r12
	mov	edx,r13d
	mov	eax,SYS_write
	syscall
	cmp	rax,-EINTR
	je	.next
	test	rax,rax
	jle	.done
	add	r12,rax
	sub	r13d,eax
	jmp	.next
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------- rendering

; rdi = output, rsi = NUL-terminated text. rdi = after it.
fmt_cstr:
@@:
	mov	al,[rsi]
	test	al,al
	jz	@f
	mov	[rdi],al
	inc	rdi
	inc	rsi
	jmp	@b
@@:
	ret

; rdi = output, rsi/edx = text as a label value (" and \ escaped).
fmt_label:
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.done
	mov	al,[rsi+rcx]
	cmp	al,'"'
	je	.esc
	cmp	al,'\'
	jne	.put
.esc:
	mov	byte [rdi],'\'
	inc	rdi
.put:
	mov	[rdi],al
	inc	rdi
	inc	ecx
	jmp	.next
.done:
	ret

; rdi = output, rax = value. rdi = after it.
fmt_u64:
	sub	rsp,24
	lea	rsi,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	rcx
	add	dl,'0'
	dec	rsi
	mov	[rsi],dl
	test	rax,rax
	jnz	@b
	lea	rcx,[rsp+24]
	sub	rcx,rsi
	rep	movsb
	add	rsp,24
	ret

macro memit text&
	local s
	cstring s, text,0
	lea	rsi,[s]
	call	fmt_cstr
end macro

; rax = sum over the current workers of the qword at offset rcx of
; their pages.
stats_sum_q:
	push	rbx
	mov	r8,[g_stats_tbl]
	xor	ebx,ebx
	xor	eax,eax
.next:
	cmp	ebx,[g_workers]
	jae	.done
	imul	rdx,rbx,STP_SIZE
	add	rdx,r8
	add	rax,[rdx+rcx]
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

stats_sum_d:
	push	rbx
	mov	r8,[g_stats_tbl]
	xor	ebx,ebx
	xor	eax,eax
.next:
	cmp	ebx,[g_workers]
	jae	.done
	imul	rdx,rbx,STP_SIZE
	add	rdx,r8
	mov	r9d,[rdx+rcx]
	add	rax,r9
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; offsets of the counters inside a page
OFF_L_ACCEPTED	:= g_st_l_accepted - g_st_begin
OFF_L_FULL	:= g_st_l_full - g_st_begin
OFF_L_SOURCE	:= g_st_l_source - g_st_begin
OFF_L_IN	:= g_st_l_in - g_st_begin
OFF_L_OUT	:= g_st_l_out - g_st_begin
OFF_S_CONNECTS	:= g_st_s_connects - g_st_begin
OFF_S_FAILS	:= g_st_s_fails - g_st_begin
OFF_L_EVICTED	:= g_st_l_evicted - g_st_begin
OFF_SRC_OPEN	:= g_st_src_open - g_st_begin
OFF_L_HTTP	:= g_st_l_http - g_st_begin
OFF_ALOG_DROPPED := g_st_alog_dropped - g_st_begin
OFF_HTTP_TRIMMED := g_st_http_trimmed - g_st_begin
OFF_TLS_DEFERRED := g_st_tls_deferred - g_st_begin
OFF_TLS_SHED	:= g_st_tls_shed - g_st_begin
OFF_L_RETRIES	:= g_st_l_retries - g_st_begin

; rdi = output, ebx = listener: {listener="..."
listener_label:
	memit '{listener="'
	imul	rax,rbx,LS_SIZE
	mov	rsi,[g_listeners+rax+LS_TEXT]
	mov	edx,[g_listeners+rax+LS_TLEN]
	call	fmt_label
	mov	byte [rdi],'"'
	inc	rdi
	ret

; Build the /metrics response. rsi/edx = it.
metrics_render:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	groups_refresh			; current addresses of names
	mov	rdi,[g_admin_buf]
	add	rdi,256				; headers go in front at the end
	mov	r15,rdi
	memit '# TYPE okena_info gauge',10,'okena_info{version="', OKENA_VERSION, '"} 1',10
	memit '# TYPE okena_workers gauge',10,'okena_workers '
	mov	eax,[g_workers]
	call	fmt_u64
	memit 10,'# TYPE okena_restarts_total counter',10,'okena_restarts_total '
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RESTARTS]
	call	fmt_u64
	memit 10,'# TYPE okena_reloads_total counter',10,'okena_reloads_total '
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOADS]
	call	fmt_u64
	memit 10,'# TYPE okena_reload_failures_total counter',10,'okena_reload_failures_total '
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOAD_FAILS]
	call	fmt_u64
	memit 10,'# HELP okena_per_source_untracked_total Connections let in without per_source counting (table neighbourhood full).',10
	memit '# TYPE okena_per_source_untracked_total counter',10,'okena_per_source_untracked_total '
	mov	ecx,OFF_SRC_OPEN
	call	stats_sum_q
	call	fmt_u64
	memit 10,'# HELP okena_access_log_dropped_total Access log lines lost because the logger could not keep up.',10
	memit '# TYPE okena_access_log_dropped_total counter',10,'okena_access_log_dropped_total '
	mov	ecx,OFF_ALOG_DROPPED
	call	stats_sum_q
	call	fmt_u64
	memit 10,'# HELP okena_http_idle_trimmed_total Idle keep-alive connections whose buffers went back to the kernel.',10
	memit '# TYPE okena_http_idle_trimmed_total counter',10,'okena_http_idle_trimmed_total '
	mov	ecx,OFF_HTTP_TRIMMED
	call	stats_sum_q
	call	fmt_u64
	memit 10,'# HELP okena_tls_handshakes_deferred_total ClientHellos that waited for the handshake budget.',10
	memit '# TYPE okena_tls_handshakes_deferred_total counter',10,'okena_tls_handshakes_deferred_total '
	mov	ecx,OFF_TLS_DEFERRED
	call	stats_sum_q
	call	fmt_u64
	memit 10,'# HELP okena_tls_handshakes_shed_total ClientHellos closed by the handshake budget (queue full, or waited too long).',10
	memit '# TYPE okena_tls_handshakes_shed_total counter',10,'okena_tls_handshakes_shed_total '
	mov	ecx,OFF_TLS_SHED
	call	stats_sum_q
	call	fmt_u64
	memit 10
	; listeners
	memit '# HELP okena_listener_connections_total Connections admitted (refused ones are in okena_listener_refused_total).',10
	memit '# TYPE okena_listener_connections_total counter',10
	xor	ebx,ebx
.l1:
	cmp	ebx,[g_plan_listeners]
	jae	.l1_done
	memit 'okena_listener_connections_total'
	call	listener_label
	memit '} '
	lea	rcx,[OFF_L_ACCEPTED+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
	inc	ebx
	jmp	.l1
.l1_done:
	memit '# TYPE okena_listener_refused_total counter',10
	xor	ebx,ebx
.l2:
	cmp	ebx,[g_plan_listeners]
	jae	.l2_done
	memit 'okena_listener_refused_total'
	call	listener_label
	memit ',reason="full"} '
	lea	rcx,[OFF_L_FULL+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10,'okena_listener_refused_total'
	call	listener_label
	memit ',reason="per_source"} '
	lea	rcx,[OFF_L_SOURCE+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
	inc	ebx
	jmp	.l2
.l2_done:
	memit '# TYPE okena_listener_active gauge',10
	xor	ebx,ebx
.l3:
	cmp	ebx,[g_plan_listeners]
	jae	.l3_done
	memit 'okena_listener_active'
	call	listener_label
	memit '} '
	lea	rcx,[STP_LACTIVE+rbx*4]
	call	stats_sum_d
	call	fmt_u64
	memit 10
	inc	ebx
	jmp	.l3
.l3_done:
	memit '# TYPE okena_listener_bytes_total counter',10
	xor	ebx,ebx
.l4:
	cmp	ebx,[g_plan_listeners]
	jae	.l4_done
	memit 'okena_listener_bytes_total'
	call	listener_label
	memit ',direction="in"} '
	lea	rcx,[OFF_L_IN+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10,'okena_listener_bytes_total'
	call	listener_label
	memit ',direction="out"} '
	lea	rcx,[OFF_L_OUT+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
	inc	ebx
	jmp	.l4
.l4_done:
	memit '# HELP okena_listener_evicted_total Idle connections closed to make room under pressure.',10
	memit '# TYPE okena_listener_evicted_total counter',10
	xor	ebx,ebx
.l5:
	cmp	ebx,[g_plan_listeners]
	jae	.l5_done
	memit 'okena_listener_evicted_total'
	call	listener_label
	memit '} '
	lea	rcx,[OFF_L_EVICTED+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
	inc	ebx
	jmp	.l5
.l5_done:
	memit '# HELP okena_http_responses_total HTTP responses sent to clients, by status class; source="okena" for the ones okena answered itself (errors, timeouts).',10
	memit '# TYPE okena_http_responses_total counter',10
	xor	ebx,ebx
.l6:
	cmp	ebx,[g_plan_listeners]
	jae	.l6_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.l6_next
	xor	r12d,r12d			; source * 5 + class
.l6_cell:
	memit 'okena_http_responses_total'
	call	listener_label
	memit ',code="'
	mov	eax,r12d
	xor	edx,edx
	mov	ecx,5
	div	ecx
	push	rax
	lea	eax,[rdx+'1']
	mov	[rdi],al
	mov	word [rdi+1],'xx'
	add	rdi,3
	pop	rax
	test	eax,eax
	jnz	@f
	memit '",source="backend"} '
	jmp	.l6_value
@@:
	memit '",source="okena"} '
.l6_value:
	imul	ecx,ebx,10
	add	ecx,r12d
	lea	rcx,[OFF_L_HTTP+rcx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
	inc	r12d
	cmp	r12d,10
	jb	.l6_cell
.l6_next:
	inc	ebx
	jmp	.l6
.l6_done:
	memit '# HELP okena_http_retries_total Requests sent again to another server after a failing answer.',10
	memit '# TYPE okena_http_retries_total counter',10
	xor	ebx,ebx
.l7:
	cmp	ebx,[g_plan_listeners]
	jae	.l7_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.l7_next
	memit 'okena_http_retries_total'
	call	listener_label
	memit '} '
	lea	rcx,[OFF_L_RETRIES+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
.l7_next:
	inc	ebx
	jmp	.l7
.l7_done:
	; backends
	memit '# TYPE okena_backend_connects_total counter',10
	mov	r12d,OFF_S_CONNECTS
	lea	r13,[str_m_connects]
	call	.servers_q
	memit '# TYPE okena_backend_connect_failures_total counter',10
	mov	r12d,OFF_S_FAILS
	lea	r13,[str_m_fails]
	call	.servers_q
	memit '# TYPE okena_backend_active gauge',10
	mov	r12d,STP_SACTIVE
	lea	r13,[str_m_active]
	call	.servers_d
	cmp	dword [g_plan_health],0
	je	.health_done
	memit '# TYPE okena_backend_health_up gauge',10
	xor	ebx,ebx
.h:
	cmp	ebx,[g_plan_servers]
	jae	.health_done
	call	.server_shown
	jnc	.h_next
	call	.server_has_health
	jnc	.h_next
	memit 'okena_backend_health_up'
	call	server_labels
	memit '} '
	mov	rax,[g_health_tbl]
	xor	ecx,ecx
	cmp	dword [rax+rbx*8],HC_UP
	sete	cl
	mov	eax,ecx
	call	fmt_u64
	memit 10
.h_next:
	inc	ebx
	jmp	.h
.health_done:
	; headers in front of the body
	mov	r14,rdi
	sub	r14,r15				; body length
	sub	rsp,128
	mov	rdi,rsp
	memit 'HTTP/1.1 200 OK',13,10,'Content-Type: text/plain; version=0.0.4',13,10,'Content-Length: '
	mov	rax,r14
	call	fmt_u64
	memit 13,10,'Connection: close',13,10,13,10
	mov	rcx,rdi
	sub	rcx,rsp				; header length (< 128)
	mov	rdi,r15
	sub	rdi,rcx
	mov	rsi,rsp
	push	rdi
	push	rcx
	rep	movsb
	pop	rcx
	pop	rsi
	add	rsp,128
	lea	edx,[r14+rcx]
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; one line per shown server: r13 = metric name, r12d = qword offset
.servers_q:
	xor	ebx,ebx
.sq:
	cmp	ebx,[g_plan_servers]
	jae	.sq_done
	call	.server_shown
	jnc	.sq_next
	mov	rsi,r13
	call	fmt_cstr
	call	server_labels
	memit '} '
	lea	rcx,[r12+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10
.sq_next:
	inc	ebx
	jmp	.sq
.sq_done:
	ret
.servers_d:
	xor	ebx,ebx
.sd:
	cmp	ebx,[g_plan_servers]
	jae	.sd_done
	call	.server_shown
	jnc	.sd_next
	mov	rsi,r13
	call	fmt_cstr
	call	server_labels
	memit '} '
	lea	rcx,[r12+rbx*4]
	call	stats_sum_d
	call	fmt_u64
	memit 10
.sd_next:
	inc	ebx
	jmp	.sd
.sd_done:
	ret
; CF when server ebx is shown: an address, or a name slot that has one
.server_shown:
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.hidden
	stc
	ret
.hidden:
	clc
	ret
; CF when server ebx's pool runs health checks
.server_has_health:
	push	r12
	call	hc_pool_of
	cmp	dword [r12+PL_HEALTH],0
	pop	r12
	je	.hidden
	stc
	ret

str_m_connects	db 'okena_backend_connects_total',0
str_m_fails	db 'okena_backend_connect_failures_total',0
str_m_active	db 'okena_backend_active',0

; rdi = output, ebx = server: {pool="...",server="...",address="..."
server_labels:
	push	r12
	memit '{pool="'
	call	hc_pool_of			; r12 = pool
	mov	rsi,[r12+PL_NAME]
	mov	edx,[r12+PL_NLEN]
	call	fmt_label
	memit '",server="'
	imul	rax,rbx,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	call	fmt_label
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_GROUP],0
	je	.done
	; a name: also the address in use
	memit '",address="'
	imul	rax,rbx,SV_SIZE
	cmp	word [g_servers+rax+SV_SA],AF_INET6
	je	.v6
	lea	rsi,[g_servers+rax+SV_SA+4]
	mov	edx,4
	call	fmt_ip
	jmp	.done
.v6:
	lea	rsi,[g_servers+rax+SV_SA+8]
	mov	edx,6
	call	fmt_ip
.done:
	mov	byte [rdi],'"'
	inc	rdi
	pop	r12
	ret

; ------------------------------------------------------------ okena health

; `okena health`: ask the running instance's /ready (the metrics address
; of the configuration). Exit 0 when ready, 1 otherwise. For Docker's
; HEALTHCHECK in an image without a shell.
cli_health:
	call	cli_load_config
	call	plan_compile
	cmp	dword [g_plan_metrics],0
	jne	@f
	call	log_begin
	out_lit 'okena health needs `metrics ADDRESS` in the okena block'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
@@:
	movzx	edi,word [g_plan_metrics_sa]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.unhealthy
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,ebx
	lea	rsi,[g_plan_metrics_sa]
	mov	edx,[g_plan_metrics_salen]
	mov	eax,SYS_connect			; to :: or 0.0.0.0 means this host
	syscall
	test	eax,eax
	js	.unhealthy
	cstring str_ready_req, 'GET /ready HTTP/1.0',13,10,13,10
	mov	edi,ebx
	lea	rsi,[str_ready_req]
	mov	edx,str_ready_req.len
	call	write_all
	mov	edi,ebx
	lea	rsi,[g_admin_req]
	mov	edx,16
	xor	eax,eax
	syscall
	cmp	eax,12
	jb	.unhealthy
	cmp	dword [g_admin_req+8],' 200'
	jne	.unhealthy
	mov	edi,1
	call	out_select
	out_lit 'ready',10
	xor	edi,edi
	jmp	exit_process
.unhealthy:
	mov	edi,1
	call	out_select
	out_lit 'not ready',10
	mov	edi,1
	jmp	exit_process
