; Admin process: /metrics (Prometheus text format), /live and /ready on
; the `metrics` address. It reads the workers' statistics pages and sums
; them when scraped, so a scrape costs the workers nothing.
;
; One request per connection. Requests are read as they come, up to ADM_SLOTS
; connections at once, each given two seconds to say what it wants (then what
; came is taken); a request is answered once it is whole. All slots taken, the
; one waiting longest goes for the newcomer, so a crowd of silent connections
; cannot keep a health check out. /ready answers 503 once the instance drains,
; so orchestrators stop sending traffic first. HEAD is answered as GET, without
; the body.

ADMIN_BUF	:= 8 shl 20
ADM_SLOTS	:= 128
ADM_BUFSZ	:= 4096
ADM_WAIT_MS	:= 2000

bss
	align 8
	g_admin_pid	dd ?
	g_metrics_fd	dd ?		; -1 = none
	g_admin_buf	dq ?		; response being built
	g_admin_req:	rb 4096
	g_admin_b64:	rb 512		; a Basic credential, decoded
	align 8
	g_adm_fd	rd ADM_SLOTS	; connections being read: descriptor + 1, 0 free
	g_adm_len	rd ADM_SLOTS	; bytes read
	g_adm_due	rq ADM_SLOTS	; ms (monotonic) it has to say what it wants
	g_adm_pfds:	rq 2 + ADM_SLOTS ; what the loop polls
	g_adm_slot	rd 2 + ADM_SLOTS ; the slot each polled connection is
	g_adm_now	dq ?
	g_adm_npoll	dd ?
	g_adm_head	dd ?		; a HEAD: the body not sent
	g_adm_bufs:	rb ADM_SLOTS * ADM_BUFSZ
end bss

rodata
	admin_name	db 'okena-admin',0
	align 8
	ts_admin_io	dq 2, 0
	ts_admin_tick	dq 1, 0
end rodata

; Supervisor, at startup: the metrics socket (kept across reloads).
metrics_open:
	mov	dword [g_metrics_fd],-1
	cmp	dword [g_plan_metrics],0
	je	.done
	mov	eax,[g_up_metrics]		; (a new binary: the old one's)
	test	eax,eax
	jz	@f
	dec	eax
	mov	[g_metrics_fd],eax
	jmp	.done
@@:
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
	out_lit ' (/metrics, /status, /dashboard, /live, /ready)'
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
	jge	@f
	cmp	dword [g_api_fd],0
	jge	@f
	cmp	qword [g_plan_bird],0		; (`bird` and `vrrp`'s health are the admin
	jne	@f				; process's too)
	cmp	dword [g_plan_vrrp+VC_ON],0
	je	.none
@@:
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
	call	helper_close_sockets
	mov	eax,SYS_getuid_
	syscall
	mov	[g_api_uid],eax			; (the supervisor's: whom the API answers)
	call	api_apply			; (what came in while it was gone)
	mov	dword [g_cd_attach],1		; the store's purge ring, if there is one
	call	cd_init
	call	priv_drop
	call	ll_confine_none			; (Landlock: no file at all)
	seccomp_for filter_admin
	mov	eax,[g_metrics_fd]
	mov	[g_admin_pfd],eax
	mov	word [g_admin_pfd+4],POLLIN_
	mov	eax,[g_api_fd]
	mov	[g_admin_pfd+8],eax
	mov	word [g_admin_pfd+12],POLLIN_
.loop:
	call	top_sample			; (rates for `top` and /status)
	call	bird_tick			; (the anycast address, announced or not: bird.inc)
	call	vrrp_ready_tick			; (and whether vrrp may hold its address)
	call	adm_poll_set			; ecx = how many to poll
	mov	[g_adm_npoll],ecx
	lea	rdi,[g_adm_pfds]
	mov	esi,ecx
	lea	rdx,[ts_admin_tick]
	cmp	ecx,2
	jbe	@f
	lea	rdx,[ts_admin_short]		; (connections being read: their deadlines)
@@:
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_ppoll_
	syscall
	push	rax
	call	adm_clock
	pop	rax
	test	eax,eax
	jle	.expire
	cmp	word [g_adm_pfds+6],0
	je	@f
	call	adm_accept			; new connections, to be read
@@:
	cmp	word [g_adm_pfds+14],0
	je	@f
	mov	edi,[g_api_fd]
	lea	r12,[api_serve]
	call	.one
@@:
	call	adm_read_ready
.expire:
	call	adm_expire			; those out of time: what came is taken
	jmp	.loop
; edi = a listening socket, r12 = who serves what came
.one:
	xor	esi,esi
	xor	edx,edx
	mov	r10d,SOCK_CLOEXEC
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.none_came
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
	call	r12
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.none_came:
	ret

; edi = connection, esi = the bytes of its request already in g_admin_req: answer
; it
admin_serve_req:
	push	rbx
	push	r12
	mov	ebx,edi
	mov	r12d,esi
	jmp	admin_serve.parse

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
	; the request line is enough; with a token, the head (its Authorization)
	xor	ecx,ecx
@@:
	cmp	ecx,r12d
	jae	.read
	cmp	byte [g_admin_req+rcx],10
	jne	.on
	cmp	dword [g_plan_mtlen],0
	je	.parse
	cmp	ecx,2
	jb	.on
	cmp	byte [g_admin_req+rcx-1],10	; "\n\n"
	je	.parse
	cmp	word [g_admin_req+rcx-2],0x0D0A	; "\n\r\n": the blank line
	je	.parse
.on:
	inc	ecx
	jmp	@b
.parse:
	mov	byte [g_admin_req+r12],0
	cmp	r12d,5
	jb	.out
	mov	dword [g_adm_head],0
	cmp	dword [g_admin_req],'HEAD'
	jne	@f
	cmp	byte [g_admin_req+4],' '
	jne	@f
	mov	dword [g_adm_head],1		; HEAD: as GET, the body not sent
	mov	dword [g_admin_req+1],'GET '
	lea	rdi,[g_admin_req]
	lea	rsi,[g_admin_req+1]
	mov	ecx,r12d
	rep	movsb
	dec	r12d
@@:
	cmp	dword [g_admin_req],'POST'
	je	.post
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
	; the rest is the token's, when there is one
	call	admin_authorized
	jnz	.unauthorized
	cstring str_p_status, '/status'
	lea	rdi,[str_p_status]
	mov	edx,str_p_status.len
	lea	rsi,[g_admin_req+4]
	call	admin_path_is
	jz	.status
	cstring str_p_dash, '/dashboard'
	lea	rdi,[str_p_dash]
	mov	edx,str_p_dash.len
	lea	rsi,[g_admin_req+4]
	call	admin_path_is
	jz	.dashboard
	cstring str_p_root, '/'
	lea	rdi,[str_p_root]
	mov	edx,str_p_root.len
	lea	rsi,[g_admin_req+4]
	call	admin_path_is
	jz	.dashboard
.not_found:
	cstring str_404, 'HTTP/1.1 404 Not Found',13,10,'Content-Length: 10',13,10,'Connection: close',13,10,13,10,'not found',10
	lea	rsi,[str_404]
	mov	edx,str_404.len
	jmp	.send
.post:
	; POST /purge: the token's, and only when there is one
	cmp	byte [g_admin_req+4],' '
	jne	.not_found
	cstring str_p_purge, '/purge'
	lea	rsi,[g_admin_req+5]
	lea	rdi,[str_p_purge]
	mov	ecx,str_p_purge.len
	repe	cmpsb
	jne	.not_found
	cmp	dword [g_plan_mtlen],0
	je	.forbidden
	push	rsi
	call	admin_authorized
	pop	rsi
	jnz	.unauthorized
	call	admin_purge
	jmp	.send
.forbidden:
	cstring str_403p, 'HTTP/1.1 403 Forbidden',13,10,'Content-Length: 31',13,10,'Connection: close',13,10,13,10,'purge needs a token on metrics',10
	lea	rsi,[str_403p]
	mov	edx,str_403p.len
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
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_DRAIN],0
	jne	.draining			; `okena drain`
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
	call	admin_authorized
	jnz	.unauthorized
	call	metrics_render			; rsi/edx = whole response
	jmp	.send
.unauthorized:
	cstring str_401, 'HTTP/1.1 401 Unauthorized',13,10,'WWW-Authenticate: Basic realm="okena", charset="UTF-8"',13,10,'Content-Length: 13',13,10,'Connection: close',13,10,13,10,'unauthorized',10
	lea	rsi,[str_401]
	mov	edx,str_401.len
	jmp	.send
.status:
	mov	rdi,[g_admin_buf]
	add	rdi,256
	push	rdi
	call	status_json
	pop	rsi
	cstring str_ct_json, 'application/json'
	lea	rcx,[str_ct_json]
	mov	r8d,str_ct_json.len
	call	admin_framed
	jmp	.send
.dashboard:
	lea	rsi,[dashboard_html]
	mov	rdi,[g_admin_buf]
	add	rdi,256
	push	rdi
	mov	ecx,dashboard_html.len
	rep	movsb
	pop	rsi
	cstring str_ct_html, 'text/html; charset=utf-8'
	lea	rcx,[str_ct_html]
	mov	r8d,str_ct_html.len
	call	admin_framed
.send:
	cmp	dword [g_adm_head],0
	je	.write
	xor	ecx,ecx				; HEAD: the head alone
@@:
	lea	eax,[rcx+4]
	cmp	eax,edx
	ja	.write
	cmp	dword [rsi+rcx],0x0A0D0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	edx,[rcx+4]
.write:
	mov	edi,ebx
	call	write_all
.out:
	pop	r12
	pop	rbx
	ret

; rsi = a body at g_admin_buf + 256, rdi = its end, rcx/r8d = its type: the
; whole response in front of it, rsi/edx = it
admin_framed:
	push	rbx
	mov	rbx,rdi
	sub	rbx,rsi				; body length
	push	rsi
	sub	rsp,256
	mov	rdi,rsp
	push	rcx
	memit 'HTTP/1.1 200 OK',13,10,'Content-Type: '
	pop	rsi
	mov	ecx,r8d
	rep	movsb
	memit 13,10,'Cache-Control: no-store',13,10,'X-Content-Type-Options: nosniff',13,10,'Content-Length: '
	mov	rax,rbx
	call	fmt_u64
	memit 13,10,'Connection: close',13,10,13,10
	mov	rcx,rdi
	sub	rcx,rsp				; head length (< 256)
	mov	rdi,[rsp+256]			; the body
	sub	rdi,rcx
	mov	rsi,rsp
	push	rdi
	push	rcx
	rep	movsb
	pop	rcx
	pop	rsi
	add	rsp,256 + 8
	lea	edx,[rbx+rcx]
	pop	rbx
	ret

; The request head in g_admin_req: ZF when it may see what the metrics
; address shows (no token, or `Authorization: Bearer TOKEN`, or Basic with
; the token as its password). Compared in constant time.
admin_authorized:
	mov	ecx,[g_plan_mtlen]
	test	ecx,ecx
	jz	.yes
	push	rbx
	push	r12
	; each line: "authorization:", without case
	lea	rsi,[g_admin_req]
.line:
	cmp	byte [rsi],0
	je	.no
	cmp	byte [rsi],10
	jne	.next
	inc	rsi
	lea	rdi,[str_h_authz]
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	or	al,0x20
	cmp	al,[rdi+rcx]
	jne	.line
	inc	ecx
	cmp	ecx,str_h_authz.len
	jb	@b
	add	rsi,rcx
@@:
	cmp	byte [rsi],' '
	jne	@f
	inc	rsi
	jmp	@b
@@:
	; its value, to the line's end
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,13
	je	@f
	cmp	al,10
	je	@f
	test	al,al
	jz	@f
	inc	ecx
	jmp	@b
@@:
	cmp	ecx,7
	jb	.no
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'bear'
	jne	.basic
	mov	eax,[rsi+3]
	or	eax,0x20202020
	cmp	eax,'rer '
	jne	.basic
	add	rsi,7
	sub	ecx,7
	jmp	.compare
.basic:
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'basi'
	jne	.no
	mov	ax,[rsi+4]
	or	al,0x20
	cmp	ax,'c '
	jne	.no
	add	rsi,6
	sub	ecx,6
	cmp	ecx,512
	ja	.no
	lea	rdi,[g_admin_b64]
	mov	edx,ecx
	call	base64_decode
	test	rax,rax
	js	.no
	; the password: after the first ':'
	lea	rsi,[g_admin_b64]
	xor	ecx,ecx
@@:
	cmp	rcx,rax
	jae	.no
	cmp	byte [rsi+rcx],':'
	je	@f
	inc	ecx
	jmp	@b
@@:
	inc	ecx
	add	rsi,rcx
	sub	eax,ecx
	mov	ecx,eax
.compare:
	; rsi/ecx = what was given
	cmp	ecx,[g_plan_mtlen]
	jne	.no
	xor	eax,eax
	xor	edx,edx
@@:
	movzx	r8d,byte [rsi+rdx]
	xor	r8b,[g_plan_mtoken+rdx]
	or	eax,r8d
	inc	edx
	cmp	edx,ecx
	jb	@b
	test	eax,eax
	jnz	.no
	pop	r12
	pop	rbx
.yes:
	xor	eax,eax
	ret
.next:
	inc	rsi
	jmp	.line
.no:
	pop	r12
	pop	rbx
	or	eax,1
	ret

cstring str_h_authz, 'authorization:'

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
	add	rdx,STP_BASE
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
	add	rdx,STP_BASE
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
OFF_L_PROTO	:= g_st_l_proto - g_st_begin
OFF_L_CODES	:= g_st_l_codes - g_st_begin
OFF_L_WS	:= g_st_l_ws - g_st_begin
OFF_L_CACHE	:= g_st_l_cache - g_st_begin
OFF_L_TLS	:= g_st_l_tls - g_st_begin
OFF_L_QUIC	:= g_st_l_quic - g_st_begin
OFF_L_DGIN	:= g_st_l_dgin - g_st_begin
OFF_L_DGOUT	:= g_st_l_dgout - g_st_begin
OFF_L_LAT	:= g_st_l_lat - g_st_begin
OFF_L_LATSUM	:= g_st_l_latsum - g_st_begin
OFF_UD_DROPS	:= g_st_ud_drops - g_st_begin
OFF_ZC_BYTES	:= g_st_zc_bytes - g_st_begin
OFF_CD_HITS	:= g_st_cd_hits - g_st_begin
OFF_CD_WRITES	:= g_st_cd_writes - g_st_begin
OFF_CD_FULL	:= g_st_cd_full - g_st_begin

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
	call	metrics_more
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

; rdi = output: what the workers count by protocol, status, handshake and
; datagram, and the request durations as a histogram
metrics_more:
	push	rbx
	push	r12
	push	r13
	memit '# HELP okena_http_requests_by_protocol_total HTTP responses sent, by the protocol of the request.',10
	memit '# TYPE okena_http_requests_by_protocol_total counter',10
	xor	ebx,ebx
.p:
	cmp	ebx,[g_plan_listeners]
	jae	.p_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.p_next
	xor	r12d,r12d
.p_one:
	memit 'okena_http_requests_by_protocol_total'
	call	listener_label
	memit ',protocol="'
	lea	rsi,[mt_protos]
	mov	eax,r12d
	call	st_word
	call	fmt_cstr
	memit '"} '
	lea	ecx,[rbx*2+rbx]
	add	ecx,r12d
	lea	rcx,[OFF_L_PROTO+rcx*8]
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	inc	r12d
	cmp	r12d,3
	jb	.p_one
.p_next:
	inc	ebx
	jmp	.p
.p_done:
	memit '# HELP okena_http_responses_by_code_total HTTP responses with these statuses: 401, 403, 404, 429.',10
	memit '# TYPE okena_http_responses_by_code_total counter',10
	xor	ebx,ebx
.c:
	cmp	ebx,[g_plan_listeners]
	jae	.c_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.c_next
	xor	r12d,r12d
.c_one:
	memit 'okena_http_responses_by_code_total'
	call	listener_label
	memit ',code="'
	lea	rsi,[mt_codes]
	mov	eax,r12d
	call	st_word
	call	fmt_cstr
	memit '"} '
	lea	ecx,[rbx*4]
	add	ecx,r12d
	lea	rcx,[OFF_L_CODES+rcx*8]
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	inc	r12d
	cmp	r12d,4
	jb	.c_one
.c_next:
	inc	ebx
	jmp	.c
.c_done:
	memit '# HELP okena_websocket_upgrades_total Requests whose protocol was switched (101): WebSocket and the like.',10
	memit '# TYPE okena_websocket_upgrades_total counter',10
	mov	r12d,OFF_L_WS
	lea	r13,[str_mt_ws]
	mov	eax,LK_HTTP
	call	.per_listener
	memit '# HELP okena_cache_hits_total Answers from the cache.',10
	memit '# TYPE okena_cache_hits_total counter',10
	mov	r12d,OFF_L_CACHE
	lea	r13,[str_mt_cache]
	mov	eax,LK_HTTP
	call	.per_listener
	memit '# HELP okena_quic_handshakes_total QUIC handshakes done.',10
	memit '# TYPE okena_quic_handshakes_total counter',10
	mov	r12d,OFF_L_QUIC
	lea	r13,[str_mt_quic]
	mov	eax,LK_HTTP
	call	.per_listener
	memit '# HELP okena_tls_handshakes_total TLS handshakes: done (by version; resumed ones too), or failed or abandoned.',10
	memit '# TYPE okena_tls_handshakes_total counter',10
	xor	ebx,ebx
.t:
	cmp	ebx,[g_plan_listeners]
	jae	.t_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_TLS],0
	jne	@f
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3
	jz	.t_next
@@:
	xor	r12d,r12d
.t_one:
	memit 'okena_tls_handshakes_total'
	call	listener_label
	lea	rsi,[mt_tls]
	mov	eax,r12d
	call	st_word
	call	fmt_cstr
	memit '} '
	lea	ecx,[rbx*4]
	add	ecx,r12d
	lea	rcx,[OFF_L_TLS+rcx*8]
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	inc	r12d
	cmp	r12d,4
	jb	.t_one
.t_next:
	inc	ebx
	jmp	.t
.t_done:
	call	cert_metrics			; certificates' ends (certexpiry.inc)
	memit '# HELP okena_udp_datagrams_total UDP datagrams, from clients (in) and to them (out).',10
	memit '# TYPE okena_udp_datagrams_total counter',10
	xor	ebx,ebx
.u:
	cmp	ebx,[g_plan_listeners]
	jae	.u_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	.u_next
	memit 'okena_udp_datagrams_total'
	call	listener_label
	memit ',direction="in"} '
	lea	rcx,[OFF_L_DGIN+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit 10,'okena_udp_datagrams_total'
	call	listener_label
	memit ',direction="out"} '
	lea	rcx,[OFF_L_DGOUT+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.u_next:
	inc	ebx
	jmp	.u
.u_done:
	memit '# HELP okena_udp_dropped_total UDP datagrams lost: no flow to take them, or a socket buffer full.',10
	memit '# TYPE okena_udp_dropped_total counter',10,'okena_udp_dropped_total '
	mov	ecx,OFF_UD_DROPS
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	memit '# HELP okena_zero_copy_bytes_total Body bytes sent from the page cache to the socket without copies.',10
	memit '# TYPE okena_zero_copy_bytes_total counter',10,'okena_zero_copy_bytes_total '
	mov	ecx,OFF_ZC_BYTES
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	memit '# HELP okena_cache_disk_hits_total Answers served from cache_disk.',10
	memit '# TYPE okena_cache_disk_hits_total counter',10,'okena_cache_disk_hits_total '
	mov	ecx,OFF_CD_HITS
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	memit '# HELP okena_cache_disk_writes_total Answers written to cache_disk.',10
	memit '# TYPE okena_cache_disk_writes_total counter',10,'okena_cache_disk_writes_total '
	mov	ecx,OFF_CD_WRITES
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	memit '# HELP okena_cache_disk_full_total Answers not written to cache_disk: no room, its oldest part still being sent.',10
	memit '# TYPE okena_cache_disk_full_total counter',10,'okena_cache_disk_full_total '
	mov	ecx,OFF_CD_FULL
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	; the durations: a histogram a listener
	memit '# HELP okena_http_request_duration_seconds From a request head to the end of its answer.',10
	memit '# TYPE okena_http_request_duration_seconds histogram',10
	xor	ebx,ebx
.h:
	cmp	ebx,[g_plan_listeners]
	jae	.h_done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.h_next
	xor	r12d,r12d
	xor	r13d,r13d			; the buckets counted so far
	mov	qword [g_mt_cum],0		; and what they hold
.h_one:
	memit 'okena_http_request_duration_seconds_bucket'
	call	listener_label
	memit ',le="'
	cmp	r12d,LAT_EXPORT - 1
	jne	@f
	memit '+Inf'
	jmp	.h_le
@@:
	mov	rax,[lat_export+r12*8]		; µs, as seconds
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,6
	call	fmt_pad
.h_le:
	memit '"} '
	; the buckets that end at or below it (all of them for +Inf)
	push	r14
	mov	r14d,r13d			; the next bucket to add
.h_add:
	cmp	r14d,LAT_B
	jae	.h_sum
	cmp	r12d,LAT_EXPORT - 1
	je	@f
	mov	ecx,r14d
	call	lat_bucket
	cmp	rax,[lat_export+r12*8]
	ja	.h_sum
@@:
	imul	ecx,ebx,LAT_B
	add	ecx,r14d
	lea	rcx,[OFF_L_LAT+rcx*8]
	call	stats_sum_q
	add	[g_mt_cum],rax
	inc	r14d
	jmp	.h_add
.h_sum:
	mov	r13d,r14d
	pop	r14
	mov	rax,[g_mt_cum]
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	inc	r12d
	cmp	r12d,LAT_EXPORT
	jb	.h_one
	memit 'okena_http_request_duration_seconds_sum'
	call	listener_label
	memit '} '
	lea	rcx,[OFF_L_LATSUM+rbx*8]
	call	stats_sum_q
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,6
	call	fmt_pad
	memit 10,'okena_http_request_duration_seconds_count'
	call	listener_label
	memit '} '
	mov	rax,[g_mt_cum]
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.h_next:
	inc	ebx
	jmp	.h
.h_done:
	pop	r13
	pop	r12
	pop	rbx
	ret
; r12d = a per-listener qword's offset, r13 = the metric's name, eax = the
; kind of listener that has it
.per_listener:
	push	r14
	mov	r14d,eax
	xor	ebx,ebx
.pl:
	cmp	ebx,[g_plan_listeners]
	jae	.pl_done
	imul	rax,rbx,LS_SIZE
	cmp	[g_listeners+rax+LS_KIND],r14d
	jne	.pl_next
	mov	rsi,r13
	call	fmt_cstr
	call	listener_label
	memit '} '
	lea	rcx,[r12+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.pl_next:
	inc	ebx
	jmp	.pl
.pl_done:
	pop	r14
	ret

LAT_EXPORT	:= 14
bss
	align 8
	g_mt_cum	dq ?
end bss
rodata
	; the histogram's bounds as /metrics gives them (µs; the last is +Inf):
	; each counts the buckets that end at or below it (a bucket is 1/8 wide)
	align 8
	lat_export	dq 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000
			dq 1000000, 2500000, 5000000, 10000000, -1
	mt_protos	db 'http/1.1',0,'h2',0,'h3',0
	mt_codes	db '401',0,'403',0,'404',0,'429',0
	mt_tls		db ',version="1.2"',0,',version="1.3"',0,',result="resumed"',0,',result="failed"',0
	str_mt_ws	db 'okena_websocket_upgrades_total',0
	str_mt_cache	db 'okena_cache_hits_total',0
	str_mt_quic	db 'okena_quic_handshakes_total',0
end rodata

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

rodata
	align 8
	ts_admin_short	dq 0, 100000000
end rodata

; g_adm_now = ms, monotonic
adm_clock:
	sub	rsp,16
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
	mov	[g_adm_now],rax
	add	rsp,16
	ret

; the poll set: the metrics socket, the API's, then each connection being read.
; ecx = how many
adm_poll_set:
	mov	eax,[g_metrics_fd]
	mov	[g_adm_pfds],eax
	mov	dword [g_adm_pfds+4],POLLIN_
	mov	eax,[g_api_fd]
	mov	[g_adm_pfds+8],eax
	mov	dword [g_adm_pfds+12],POLLIN_
	mov	ecx,2
	xor	edx,edx
.slot:
	cmp	edx,ADM_SLOTS
	jae	.out
	mov	eax,[g_adm_fd+rdx*4]
	test	eax,eax
	jz	.next
	dec	eax
	mov	[g_adm_pfds+rcx*8],eax
	mov	dword [g_adm_pfds+rcx*8+4],POLLIN_
	mov	[g_adm_slot+rcx*4],edx
	inc	ecx
.next:
	inc	edx
	jmp	.slot
.out:
	ret

; the metrics socket is readable: what has come, each into a slot (the oldest
; one given up when none is free)
adm_accept:
	push	rbx
	push	r12
	mov	r12d,1				; (one a turn: the socket blocks, and the poll
						; comes back at once while more wait)
.next:
	mov	edi,[g_metrics_fd]
	xor	esi,esi
	xor	edx,edx
	mov	r10d,SOCK_CLOEXEC
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.out
	mov	ebx,eax
	mov	edi,ebx				; writes: blocking, two seconds at most
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	call	adm_free_slot			; edx = it
	lea	eax,[rbx+1]
	mov	[g_adm_fd+rdx*4],eax
	mov	dword [g_adm_len+rdx*4],0
	mov	rax,[g_adm_now]
	add	rax,ADM_WAIT_MS
	mov	[g_adm_due+rdx*8],rax
	dec	r12d
	jnz	.next
.out:
	pop	r12
	pop	rbx
	ret

; edx = a free slot, the one waiting longest closed when none is
adm_free_slot:
	xor	edx,edx
	mov	ecx,-1
	mov	r8,-1				; (the earliest deadline)
.find:
	cmp	edx,ADM_SLOTS
	jae	.full
	cmp	dword [g_adm_fd+rdx*4],0
	je	.out
	mov	rax,[g_adm_due+rdx*8]
	cmp	rax,r8
	jae	@f
	mov	r8,rax
	mov	ecx,edx
@@:
	inc	edx
	jmp	.find
.full:
	mov	edx,ecx
	push	rdx
	mov	edi,[g_adm_fd+rdx*4]
	dec	edi
	mov	eax,SYS_close
	syscall
	pop	rdx
	mov	dword [g_adm_fd+rdx*4],0
.out:
	ret

; connections the poll said have something: read; a whole request answered
adm_read_ready:
	push	rbx
	push	r12
	push	r13
	mov	r13d,2
.next:
	mov	eax,r13d
	sub	eax,2
	cmp	eax,ADM_SLOTS
	jae	.out
	cmp	r13d,[g_adm_npoll]
	jae	.out
	cmp	word [g_adm_pfds+r13*8+6],0
	je	.skip
	mov	r12d,[g_adm_slot+r13*4]
	mov	ebx,[g_adm_fd+r12*4]
	test	ebx,ebx
	jz	.skip
	dec	ebx
	mov	eax,r12d
	shl	eax,12
	lea	rsi,[g_adm_bufs+rax]
	mov	ecx,[g_adm_len+r12*4]
	add	rsi,rcx
	mov	edx,ADM_BUFSZ - 1
	sub	edx,ecx
	jz	.whole
	mov	edi,ebx
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.skip
	test	rax,rax
	jle	.whole				; closed, or failed: what came
	add	[g_adm_len+r12*4],eax
	mov	edi,r12d
	call	adm_complete
	jnc	.skip
.whole:
	mov	edi,r12d
	call	adm_answer
.skip:
	inc	r13d
	jmp	.next
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = a slot: CF when its request is whole: its request line, or with a token
; its head (the Authorization)
adm_complete:
	mov	eax,edi
	shl	eax,12
	lea	rsi,[g_adm_bufs+rax]
	mov	r8d,[g_adm_len+rdi*4]
	xor	ecx,ecx
.at:
	cmp	ecx,r8d
	jae	.no
	cmp	byte [rsi+rcx],10
	jne	.on
	cmp	dword [g_plan_mtlen],0
	je	.yes
	cmp	ecx,2
	jb	.on
	cmp	byte [rsi+rcx-1],10
	je	.yes
	cmp	word [rsi+rcx-2],0x0D0A
	je	.yes
.on:
	inc	ecx
	jmp	.at
.no:
	clc
	ret
.yes:
	stc
	ret

; edi = a slot: its request answered (admin_serve's way), the connection closed,
; the slot free. Keeps rbx, r12-r15.
adm_answer:
	push	rbx
	push	r12
	push	r13
	mov	r13d,edi
	mov	ebx,[g_adm_fd+r13*4]
	dec	ebx
	mov	r12d,[g_adm_len+r13*4]
	mov	eax,r13d
	shl	eax,12
	lea	rsi,[g_adm_bufs+rax]
	lea	rdi,[g_admin_req]
	mov	ecx,r12d
	rep	movsb
	mov	edi,ebx
	mov	esi,r12d
	call	admin_serve_req
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	dword [g_adm_fd+r13*4],0
	pop	r13
	pop	r12
	pop	rbx
	ret

; connections whose two seconds are up: what came is taken
adm_expire:
	push	r12
	xor	r12d,r12d
.next:
	cmp	r12d,ADM_SLOTS
	jae	.out
	cmp	dword [g_adm_fd+r12*4],0
	je	.skip
	mov	rax,[g_adm_now]
	cmp	rax,[g_adm_due+r12*8]
	jb	.skip
	mov	edi,r12d
	call	adm_answer
.skip:
	inc	r12d
	jmp	.next
.out:
	pop	r12
	ret
