; `okena explain [FILE]`: the configuration as okena will run it, every
; default written out: the okena block, each pool (balancing, connections,
; queue, passive health, retry budget, servers), each listener (limits,
; timeouts, TLS, protocols) and its routes (methods, where they go, retries,
; timeouts). Read from the compiled plan, so it is what a start would do.

cstring str_cmd_explain, 'explain',0

cli_explain:
	mov	edi,2
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	mov	edi,1
	call	out_select
	push	rbx
	push	r12
	push	r13
	; ---- okena
	out_lit 'okena {',10,'    workers '
	call	cpu_worker_count
	call	out_u64
	out_lit 10,'    io_engine '
	mov	eax,[g_plan_engine]
	lea	rsi,[.engines]
	call	.word_n
	out_lit 10,'    watchdog '
	mov	rax,[g_plan_watchdog]
	call	.dur
	out_lit 10,'    drain delay='
	mov	rax,[g_plan_drain_delay]
	call	.dur
	out_lit ' timeout='
	mov	rax,[g_plan_drain_timeout]
	call	.dur
	out_lit 10,'    last_good '
	mov	eax,[g_plan_last_good]
	call	.onoff
	out_lit 10,'    reload '
	lea	rsi,[.rl_signal]
	cmp	dword [g_plan_reload_watch],0
	je	@f
	lea	rsi,[.rl_change]
@@:
	call	out_cstr
	out_lit 10,'}',10
	; ---- pools
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_plan_pools]
	jae	.pools_done
	imul	r12,rbx,PL_SIZE
	lea	r12,[g_pools+r12]
	out_lit 10,'pool '
	mov	edx,[r12+PL_NLEN]
	test	edx,edx
	jz	.unnamed
	mov	rsi,[r12+PL_NAME]
	call	out_str
	jmp	@f
.unnamed:
	out_lit '(inline '
	mov	eax,ebx
	call	out_u64
	out_lit ')'
@@:
	out_lit ' {',10,'    balance '
	mov	eax,[r12+PL_BALANCE]
	lea	rsi,[.balances]
	call	.word_n
	out_lit 10,'    connect timeout='
	imul	rax,[r12+PL_TIMEOUT],1000000
	push	rax
	mov	rax,[r12+PL_TIMEOUT+8]
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	pop	rcx
	add	rax,rcx
	call	.dur
	out_lit ' max='
	mov	eax,[r12+PL_CMAX]
	call	out_u64
	out_lit ' idle='
	mov	eax,[r12+PL_CIDLE]
	call	out_u64
	out_lit 's warm='
	mov	eax,[r12+PL_CWARM]
	call	out_u64
	cmp	dword [r12+PL_CRATE],0
	je	@f
	out_lit ' rate='
	mov	eax,[r12+PL_CRATE]
	call	out_u64
	out_lit '/s'
@@:
	out_lit 10,'    queue timeout='
	mov	rax,[r12+PL_QTIMEOUT]
	test	rax,rax
	jnz	@f
	imul	rax,[r12+PL_TIMEOUT],1000000	; (the connect timeout)
@@:
	call	.dur
	out_lit 10,'    outlier errors='
	mov	eax,[r12+PL_OERR]
	call	out_u64
	out_lit ' eject='
	mov	eax,[r12+PL_OEJECT]
	call	out_u64
	out_lit 's max_ejected='
	mov	eax,[r12+PL_OMAX]
	call	.pct
	out_lit 10,'    retry_budget '
	mov	eax,[r12+PL_RBPCT]
	call	.pct
	out_lit ' min='
	mov	eax,[r12+PL_RBMIN]
	xor	edx,edx
	mov	ecx,RETRY_COST
	div	ecx
	call	out_u64
	out_lit '/s'
	cmp	dword [r12+PL_SLOW],0
	je	@f
	out_lit 10,'    slow_start '
	mov	eax,[r12+PL_SLOW]
	call	out_u64
	out_lit 's'
@@:
	cmp	dword [r12+PL_HEALTH],0
	je	@f
	out_lit 10,'    health '
	lea	rsi,[.h_tcp]
	mov	eax,[r12+PL_H_HTTP]
	test	eax,eax
	jz	.h_kind
	lea	rsi,[.h_http]
	cmp	eax,1
	je	.h_kind
	lea	rsi,[.h_grpc]
.h_kind:
	call	out_cstr
	out_lit ' every='
	mov	eax,[r12+PL_H_EVERY]
	imul	rax,rax,1000
	call	.dur
	out_lit ' timeout='
	mov	eax,[r12+PL_H_TIMEOUT]
	imul	rax,rax,1000
	call	.dur
	out_lit ' rise='
	mov	eax,[r12+PL_H_RISE]
	call	out_u64
	out_lit ' fall='
	mov	eax,[r12+PL_H_FALL]
	call	out_u64
@@:
	cmp	dword [r12+PL_H2],0
	je	@f
	out_lit 10,'    protocol h2'
@@:
	cmp	dword [r12+PL_FCGI],0
	je	@f
	out_lit 10,'    protocol fastcgi'
@@:
	cmp	dword [r12+PL_TLS],0
	je	@f
	out_lit 10,'    tls { ... }'
@@:
	mov	r13d,[r12+PL_FIRST]
.server:
	mov	eax,[r12+PL_FIRST]
	add	eax,[r12+PL_COUNT]
	cmp	r13d,eax
	jae	.servers_done
	imul	rcx,r13,SV_SIZE
	lea	rcx,[g_servers+rcx]
	cmp	dword [rcx+SV_TLEN],0
	je	.server_next			; (a slot a name's other addresses fill)
	push	rcx
	out_lit 10,'    server '
	mov	rcx,[rsp]
	mov	rsi,[rcx+SV_TEXT]
	mov	edx,[rcx+SV_TLEN]
	call	out_str
	out_lit ' weight='
	mov	rcx,[rsp]
	mov	eax,[rcx+SV_WEIGHT]
	call	out_u64
	mov	rcx,[rsp]
	cmp	dword [rcx+SV_MAX],0
	je	@f
	out_lit ' max='
	mov	rcx,[rsp]
	mov	eax,[rcx+SV_MAX]
	call	out_u64
@@:
	pop	rcx
	cmp	dword [rcx+SV_BACKUP],0
	je	.server_next
	out_lit ' backup'
.server_next:
	inc	r13d
	jmp	.server
.servers_done:
	out_lit 10,'}',10
	inc	ebx
	jmp	.pool
.pools_done:
	; ---- listeners
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	imul	r12,rbx,LS_SIZE
	lea	r12,[g_listeners+r12]
	out_lit 10
	mov	eax,[r12+LS_KIND]
	lea	rsi,[.kinds]
	call	.word_n
	out_lit ' '
	mov	rsi,[r12+LS_TEXT]
	mov	edx,[r12+LS_TLEN]
	call	out_str
	out_lit ' {',10,'    limits { connections '
	mov	eax,[r12+LS_MAXCONN]
	call	out_u64
	cmp	dword [r12+LS_PER_SOURCE],0	; (0: no limit, not said)
	je	@f
	out_lit '; per_source '
	mov	eax,[r12+LS_PER_SOURCE]
	call	out_u64
@@:
	cmp	dword [r12+LS_BODYMAX],0
	je	@f
	out_lit '; body_size '
	mov	eax,[r12+LS_BODYMAX]
	call	out_u64
@@:
	out_lit ' }',10,'    timeout { idle '
	mov	eax,[r12+LS_IDLE]
	call	out_u64
	out_lit 's'
	cmp	dword [r12+LS_KIND],LK_HTTP
	jne	@f
	out_lit '; header '
	mov	eax,[r12+LS_T_HEADER]
	call	out_u64
	out_lit 's; body_idle '
	mov	eax,[r12+LS_T_BODY]
	call	out_u64
	out_lit 's; response '
	mov	eax,[r12+LS_T_RESPONSE]
	call	out_u64
	out_lit 's'
@@:
	out_lit ' }'
	cmp	dword [r12+LS_MSS],0
	je	@f
	out_lit 10,'    mss '
	mov	eax,[r12+LS_MSS]
	call	out_u64
@@:
	cmp	dword [r12+LS_CANONLEN],0
	je	@f
	out_lit 10,'    canonical '
	mov	rsi,[r12+LS_CANON]
	mov	edx,[r12+LS_CANONLEN]
	call	out_str
@@:
	mov	r13d,[r12+LS_FLAGS]
	cmp	dword [r12+LS_TLS],0
	je	.no_tls
	out_lit 10,'    tls { ktls '
	mov	eax,r13d
	and	eax,LSF_KTLS
	call	.onoff
	out_lit '; versions'
	test	r13d,LSF_NO12
	jnz	@f
	out_lit ' 1.2'
@@:
	test	r13d,LSF_NO13
	jnz	@f
	out_lit ' 1.3'
@@:
	cmp	dword [r12+LS_KIND],LK_HTTP
	jne	.tls_end
	out_lit '; alpn'
	test	r13d,LSF_H1FIRST
	jz	@f
	out_lit ' http/1.1'
@@:
	test	r13d,LSF_H2
	jz	@f
	out_lit ' h2'
@@:
	test	r13d,LSF_H1FIRST or LSF_NOH1
	jnz	.tls_end
	out_lit ' http/1.1'
.tls_end:
	out_lit ' }'
.no_tls:
	cmp	dword [r12+LS_KIND],LK_HTTP
	jne	.l4
	out_lit 10,'    http2 '
	mov	eax,r13d
	and	eax,LSF_H2
	call	.onoff
	out_lit 10,'    http3 '
	mov	eax,r13d
	and	eax,LSF_H3
	call	.onoff
	; its routes, then each host block's
	mov	edi,[r12+LS_RFIRST]
	mov	esi,[r12+LS_RCOUNT]
	mov	edx,4
	call	.routes
	mov	r13d,[r12+LS_HFIRST]
.host:
	mov	eax,[r12+LS_HFIRST]
	add	eax,[r12+LS_HCOUNT]
	cmp	r13d,eax
	jae	.listener_end
	imul	rcx,r13,HO_SIZE
	lea	rcx,[g_hosts+rcx]
	push	rcx
	out_lit 10,'    host '
	mov	rcx,[rsp]
	cmp	dword [rcx+HO_WILD],0
	je	@f
	out_lit '*'
	mov	rcx,[rsp]
@@:
	mov	rsi,[rcx+HO_NAME]
	mov	edx,[rcx+HO_NLEN]
	call	out_str
	out_lit ' {'
	pop	rcx
	mov	edi,[rcx+HO_RFIRST]
	mov	esi,[rcx+HO_RCOUNT]
	mov	edx,8
	call	.routes
	out_lit 10,'    }'
	inc	r13d
	jmp	.host
.l4:
	cmp	dword [r12+LS_POOL],-1
	je	.listener_end
	out_lit 10,'    to pool '
	mov	eax,[r12+LS_POOL]
	call	.pool_name
.listener_end:
	out_lit 10,'}',10
	inc	ebx
	jmp	.listener
.done:
	pop	r13
	pop	r12
	pop	rbx
	xor	edi,edi
	jmp	exit_process

; edi = first route, esi = how many, edx = indentation
.routes:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	ebx,edi
	lea	r13d,[rdi+rsi]
	mov	r14d,edx
.route:
	cmp	ebx,r13d
	jae	.routes_done
	imul	r12,rbx,RT_SIZE
	lea	r12,[g_routes+r12]
	mov	edi,10
	call	out_char
	mov	edi,r14d
	call	out_spaces
	out_lit 'route '
	mov	rsi,[r12+RT_PATH]
	mov	edx,[r12+RT_PLEN]
	call	out_str
	cmp	dword [r12+RT_PREFIX],1
	jne	@f
	out_lit '*'
@@:
	mov	r8d,[r12+RT_METHODS]		; its methods
	lea	r9,[method_names]
.m:
	test	r8d,r8d
	jz	.m_done
	cmp	byte [r9],0
	je	.m_done
	test	r8d,1
	jz	@f
	push	r8
	push	r9
	mov	edi,' '
	call	out_char
	mov	rsi,[rsp]
	call	out_cstr
	pop	r9
	pop	r8
@@:
	shr	r8d,1
@@:
	cmp	byte [r9],0			; the next name
	je	@f
	inc	r9
	jmp	@b
@@:
	inc	r9
	jmp	.m
.m_done:
	out_lit ' { '
	mov	eax,[r12+RT_ACT]
	test	eax,eax
	jz	.target
	dec	eax
	imul	rax,rax,RA_SIZE
	lea	rcx,[g_acts+rax]
	push	rcx
	mov	eax,[rcx+RA_CODE]
	test	eax,eax
	jz	.target_act
	cmp	dword [rcx+RA_TLEN],0
	je	.respond
	out_lit 'redirect '
	mov	rcx,[rsp]
	mov	eax,[rcx+RA_CODE]
	call	out_u64
	out_lit ' '
	mov	rcx,[rsp]
	mov	rsi,[rcx+RA_TGT]
	mov	edx,[rcx+RA_TLEN]
	call	out_str
	jmp	.act_more
.respond:
	out_lit 'respond '
	mov	rcx,[rsp]
	mov	eax,[rcx+RA_CODE]
	call	out_u64
	mov	rcx,[rsp]
	cmp	dword [rcx+RA_RBLEN],0
	je	.act_more
	out_lit ' "'
	mov	rcx,[rsp]
	mov	rsi,[rcx+RA_RBODY]
	mov	edx,[rcx+RA_RBLEN]
	cmp	edx,60
	jbe	@f
	mov	edx,60				; (a long one: its start)
@@:
	call	out_str
	mov	edi,'"'
	call	out_char
	jmp	.act_more
.target_act:
	call	.to
.act_more:
	mov	rcx,[rsp]
	mov	eax,[rcx+RA_RTRY]		; retries: its own, or the default
	mov	edx,[rcx+RA_RON]
	test	eax,eax
	jnz	@f
	mov	eax,2
	mov	edx,RON_DEFAULT
@@:
	cmp	dword [r12+RT_POOL],-1
	je	.no_retry
	dec	eax
	push	rdx
	push	rax
	out_lit '; retry '
	pop	rax
	call	out_u64
	out_lit ' on='
	pop	rdx
	call	.ron
.no_retry:
	pop	rcx
	cmp	dword [rcx+RA_TRYC],0
	jne	.tmo
	cmp	dword [rcx+RA_TOTAL],0
	je	.route_end
.tmo:
	push	rcx
	out_lit '; timeout'
	mov	rcx,[rsp]
	mov	eax,[rcx+RA_TRYC]
	test	eax,eax
	jz	@f
	out_lit ' try='
	mov	rcx,[rsp]
	mov	eax,[rcx+RA_TRYC]
	mov	eax,[g_try_secs+rax*4-4]
	call	out_u64
	out_lit 's'
@@:
	pop	rcx
	cmp	dword [rcx+RA_TOTAL],0
	je	.route_end
	push	rcx
	out_lit ' total='
	pop	rcx
	mov	eax,[rcx+RA_TOTAL]
	call	out_u64
	out_lit 's'
	jmp	.route_end
.target:
	call	.to
	out_lit '; retry 1 on='
	mov	edx,RON_DEFAULT
	call	.ron
.route_end:
	out_lit ' }'
	inc	ebx
	jmp	.route
.routes_done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; r12 = route: "to pool NAME" (or files, a split...: said as such)
.to:
	mov	eax,[r12+RT_POOL]
	cmp	eax,-1
	jne	@f
	out_lit '(answered by okena)'
	ret
@@:
	push	rax
	out_lit 'to pool '
	pop	rax
	jmp	.pool_name
; edx = RON_* bits, said as a list
.ron:
	push	rbx
	mov	ebx,edx
	lea	rsi,[.ron_names]
	xor	ecx,ecx				; said one
.ron_bit:
	cmp	byte [rsi],0
	je	.ron_done
	test	ebx,1
	jz	.ron_skip
	push	rsi
	push	rcx
	test	ecx,ecx
	jz	@f
	mov	edi,','
	call	out_char
@@:
	mov	rsi,[rsp+8]
	call	out_cstr
	pop	rcx
	pop	rsi
	inc	ecx
.ron_skip:
	shr	ebx,1
@@:
	lodsb
	test	al,al
	jnz	@b
	jmp	.ron_bit
.ron_done:
	pop	rbx
	ret
; eax = pool: its name
.pool_name:
	imul	rax,rax,PL_SIZE
	mov	edx,[g_pools+rax+PL_NLEN]
	mov	rsi,[g_pools+rax+PL_NAME]
	test	edx,edx
	jnz	out_str
	out_lit '(inline)'
	ret
; eax = index, rsi = NUL-separated words: the eax-th
.word_n:
	mov	ecx,eax
.wn:
	test	ecx,ecx
	jz	out_cstr
@@:
	lodsb
	test	al,al
	jnz	@b
	dec	ecx
	jmp	.wn
; eax: "on" when not zero, else "off"
.onoff:
	test	eax,eax
	jz	@f
	out_lit 'on'
	ret
@@:
	out_lit 'off'
	ret
; eax = hundredths of a percent: "50%", "0.5%"
.pct:
	xor	edx,edx
	mov	ecx,100
	div	ecx
	push	rdx
	call	out_u64
	pop	rax
	test	eax,eax
	jz	@f
	push	rax
	mov	edi,'.'
	call	out_char
	pop	rax
	cmp	eax,10
	jae	.pct2
	push	rax
	mov	edi,'0'
	call	out_char
	pop	rax
.pct2:
	call	out_u64
@@:
	mov	edi,'%'
	jmp	out_char
; rax = microseconds: "2s", "250ms" or "50us"
.dur:
	xor	edx,edx
	mov	ecx,1000000
	push	rax
	div	rcx
	test	rdx,rdx
	jnz	@f
	add	rsp,8
	call	out_u64
	mov	edi,'s'
	jmp	out_char
@@:
	pop	rax
	xor	edx,edx
	mov	ecx,1000
	push	rax
	div	rcx
	test	rdx,rdx
	jnz	@f
	add	rsp,8
	call	out_u64
	out_lit 'ms'
	ret
@@:
	pop	rax
	call	out_u64
	out_lit 'us'
	ret
.engines	db 'auto',0,'io_uring',0,'epoll',0
.balances	db 'round-robin',0,'least-conn',0,'random',0,'least-request',0,'peak-ewma',0,'maglev',0,'ring-hash',0,'source-hash',0,'first',0
.kinds		db 'tcp',0,'http',0,'udp',0
.h_tcp		db 'tcp',0
.h_http		db 'http',0
.h_grpc		db 'grpc',0
.rl_signal	db 'signal',0
.rl_change	db 'on-change',0
.ron_names	db 'reset',0,'timeout',0,'5xx',0,'500',0,'502',0,'503',0,'504',0,0
