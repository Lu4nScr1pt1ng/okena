; What the instance is doing, now: for `okena top` (the admin socket's `top`,
; a table) and the dashboard (`/status`, JSON, and `/dashboard`, a page that
; reads it). The admin process samples the workers' counters once a second
; and keeps the last two samples, so rates (connections, requests, 5xx and
; bytes a second, by listener; connections and failures, by server) are the
; same for everyone who asks and cost the workers nothing.

TOP_L		:= 0			; a listener: 5 qwords
TSL_ACC		:= 0
TSL_REQ		:= 8
TSL_ERR		:= 16
TSL_IN		:= 24
TSL_OUT		:= 32
TSL_SIZE	:= 40
TOP_S		:= MAX_LISTENERS * TSL_SIZE	; a server: 2 qwords
TSS_CON		:= 0
TSS_FAIL	:= 8
TSS_SIZE	:= 16
TOP_SIZE		:= TOP_S + MAX_SERVERS * TSS_SIZE

bss
	align 8
	g_top_cur	rb TOP_SIZE
	g_top_prev	rb TOP_SIZE
	g_top_t		dq ?		; ms of the current sample
	g_top_pt	dq ?		; and of the one before
	g_top_n		dd ?		; samples taken
	g_top_tmp	rb 64
end bss

; The admin process, each turn: a sample when a second has passed
top_sample:
	call	ln_ms
	cmp	dword [g_top_n],0
	je	.take
	mov	rcx,rax
	sub	rcx,[g_top_t]
	cmp	rcx,950
	jb	.none
.take:
	push	rbx
	push	rax
	lea	rsi,[g_top_cur]
	lea	rdi,[g_top_prev]
	mov	ecx,TOP_SIZE / 8
	rep	movsq
	mov	rax,[g_top_t]
	mov	[g_top_pt],rax
	pop	rax
	mov	[g_top_t],rax
	inc	dword [g_top_n]
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.servers
	imul	rdi,rbx,TSL_SIZE
	lea	rdi,[g_top_cur+TOP_L+rdi]
	lea	rcx,[OFF_L_ACCEPTED+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSL_ACC],rax
	call	top_requests
	mov	[rdi+TSL_REQ],rax
	mov	[rdi+TSL_ERR],rdx
	lea	rcx,[OFF_L_IN+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSL_IN],rax
	lea	rcx,[OFF_L_OUT+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSL_OUT],rax
	inc	ebx
	jmp	.listener
.servers:
	xor	ebx,ebx
.server:
	cmp	ebx,[g_plan_servers]
	jae	.done
	imul	rdi,rbx,TSS_SIZE
	lea	rdi,[g_top_cur+TOP_S+rdi]
	lea	rcx,[OFF_S_CONNECTS+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSS_CON],rax
	lea	rcx,[OFF_S_FAILS+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSS_FAIL],rax
	inc	ebx
	jmp	.server
.done:
	pop	rbx
.none:
	ret

; ebx = listener: rax = HTTP responses sent, rdx = the 5xx of them. Keeps
; rdi.
top_requests:
	push	r12
	push	r13
	xor	r12d,r12d
	xor	r13d,r13d
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.out
	push	r14
	xor	r14d,r14d			; source * 5 + class
.cell:
	imul	ecx,ebx,10
	add	ecx,r14d
	lea	rcx,[OFF_L_HTTP+rcx*8]
	call	stats_sum_q
	add	r12,rax
	cmp	r14d,4
	je	.five
	cmp	r14d,9
	jne	@f
.five:
	add	r13,rax
@@:
	inc	r14d
	cmp	r14d,10
	jb	.cell
	pop	r14
.out:
	mov	rax,r12
	mov	rdx,r13
	pop	r13
	pop	r12
	ret

; ecx = an offset in a sample: rax = its rate a second, times ten (0 until
; there are two samples; a counter that went back, a worker restarted, is 0)
top_rate10:
	xor	eax,eax
	cmp	dword [g_top_n],2
	jb	.out
	mov	rax,qword [g_top_cur+rcx]
	sub	rax,qword [g_top_prev+rcx]
	jbe	.zero
	mov	rcx,[g_top_t]
	sub	rcx,[g_top_pt]
	jz	.zero
	imul	rax,rax,10000
	xor	edx,edx
	div	rcx
.out:
	ret
.zero:
	xor	eax,eax
	ret

; rdi = output, rax = a rate times ten: "12.5"
top_fmt_rate:
	xor	edx,edx
	mov	ecx,10
	div	rcx
	push	rdx
	call	fmt_u64
	pop	rax
	mov	byte [rdi],'.'
	add	al,'0'
	mov	[rdi+1],al
	add	rdi,2
	ret

; rdi = output, rax = bytes a second times ten: "850", "12.3k", "4.1M", "1.2G"
top_fmt_bytes:
	cmp	rax,10000
	jb	.plain
	mov	ecx,1000
	mov	r8b,'k'
	cmp	rax,10000000
	jb	.scaled
	mov	ecx,1000000
	mov	r8b,'M'
	mov	rdx,10000000000
	cmp	rax,rdx
	jb	.scaled
	mov	ecx,1000000000
	mov	r8b,'G'
.scaled:
	xor	edx,edx
	div	rcx
	push	r8
	call	top_fmt_rate
	pop	r8
	mov	[rdi],r8b
	inc	rdi
	ret
.plain:
	xor	edx,edx
	mov	ecx,10
	div	rcx
	jmp	fmt_u64

; ebx = server: eax = 0 up, 1 down, 2 drained
top_state:
	mov	rax,[g_api_tbl]
	test	rax,rax
	jz	@f
	cmp	dword [rax+rbx*8],0
	jne	.drained
@@:
	mov	rax,[g_health_tbl]
	cmp	dword [rax+rbx*8],HC_UP
	jne	.down
	xor	eax,eax
	ret
.down:
	mov	eax,1
	ret
.drained:
	mov	eax,2
	ret

; ebx = server: eax = its weight now (the API's, or the file's)
top_weight:
	mov	rax,[g_api_tbl]
	test	rax,rax
	jz	@f
	mov	eax,[rax+rbx*8+4]
	test	eax,eax
	jnz	.out
@@:
	imul	rax,rbx,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
.out:
	ret

; ebx = server, rdi = output: the address in use when it is a name's
top_address:
	imul	rax,rbx,SV_SIZE
	cmp	word [g_servers+rax+SV_SA],AF_INET6
	je	.v6
	lea	rsi,[g_servers+rax+SV_SA+4]
	mov	edx,4
	jmp	fmt_ip
.v6:
	lea	rsi,[g_servers+rax+SV_SA+8]
	mov	edx,6
	jmp	fmt_ip

rodata
	top_kinds	db 'tcp',0,'http',0,'udp',0
	top_states	db 'up',0,0,0,0,'down',0,0,'drain',0
end rodata

; ------------------------------------------------------------------ JSON

; rdi = output: the instance now, as JSON (/status)
status_json:
	push	rbx
	push	r12
	push	r13
	push	rdi
	call	groups_refresh			; names: the addresses they have now
	pop	rdi
	memit '{"version":"', OKENA_VERSION, '","workers":'
	mov	eax,[g_workers]
	call	fmt_u64
	memit ',"draining":'
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_DRAIN],0
	jne	.drained
	mov	rax,[g_stats_tbl]
	cmp	qword [rax+SG_OFF+SG_DRAINING],0
	jne	.drained
	memit 'false'
	jmp	.counts
.drained:
	memit 'true'
.counts:
	memit ',"reloads":'
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOADS]
	call	fmt_u64
	memit ',"reload_failures":'
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOAD_FAILS]
	call	fmt_u64
	memit ',"restarts":'
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RESTARTS]
	call	fmt_u64
	memit ',"listeners":['
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.pools
	test	ebx,ebx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	imul	r12,rbx,LS_SIZE
	lea	r12,[g_listeners+r12]
	memit '{"address":"'
	mov	rsi,[r12+LS_TEXT]
	mov	edx,[r12+LS_TLEN]
	mov	ecx,256
	call	json_text
	memit '","kind":"'
	call	.kind
	memit '","routes":'
	mov	eax,[r12+LS_RCOUNT]
	call	fmt_u64
	memit ',"active":'
	lea	rcx,[STP_LACTIVE+rbx*4]
	call	stats_sum_d
	call	fmt_u64
	memit ',"limit":'
	mov	eax,[r12+LS_MAXCONN]
	imul	eax,[g_workers]
	call	fmt_u64
	memit ',"accepted":'
	lea	rcx,[OFF_L_ACCEPTED+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"refused":'
	lea	rcx,[OFF_L_FULL+rbx*8]
	call	stats_sum_q
	push	rax
	lea	rcx,[OFF_L_SOURCE+rbx*8]
	call	stats_sum_q
	pop	rcx
	add	rax,rcx
	call	fmt_u64
	memit ',"requests":'
	call	top_requests
	push	rdx
	call	fmt_u64
	memit ',"errors":'
	pop	rax
	call	fmt_u64
	memit ',"bytes_in":'
	lea	rcx,[OFF_L_IN+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"bytes_out":'
	lea	rcx,[OFF_L_OUT+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	imul	r13,rbx,TSL_SIZE
	memit ',"conn_rate":'
	lea	ecx,[r13+TOP_L+TSL_ACC]
	call	top_rate10
	call	top_fmt_rate
	memit ',"req_rate":'
	lea	ecx,[r13+TOP_L+TSL_REQ]
	call	top_rate10
	call	top_fmt_rate
	memit ',"err_rate":'
	lea	ecx,[r13+TOP_L+TSL_ERR]
	call	top_rate10
	call	top_fmt_rate
	memit ',"in_rate":'
	lea	ecx,[r13+TOP_L+TSL_IN]
	call	top_rate10
	call	top_fmt_rate
	memit ',"out_rate":'
	lea	ecx,[r13+TOP_L+TSL_OUT]
	call	top_rate10
	call	top_fmt_rate
	mov	byte [rdi],'}'
	inc	rdi
	inc	ebx
	jmp	.listener
.pools:
	memit '],"pools":['
	xor	r13d,r13d
.pool:
	cmp	r13d,[g_plan_pools]
	jae	.end
	test	r13d,r13d
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	imul	r12,r13,PL_SIZE
	lea	r12,[g_pools+r12]
	memit '{"name":"'
	mov	rsi,[r12+PL_NAME]
	mov	edx,[r12+PL_NLEN]
	mov	ecx,256
	call	json_text
	memit '","health":'
	cmp	dword [r12+PL_HEALTH],0
	jne	@f
	memit 'false'
	jmp	.servers
@@:
	memit 'true'
.servers:
	memit ',"servers":['
	mov	ebx,[r12+PL_FIRST]
	mov	ecx,ebx
	add	ecx,[r12+PL_COUNT]
	push	rcx
	push	rbx				; (the first: no comma before it)
.server:
	cmp	ebx,[rsp+8]
	jae	.servers_done
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.server_next			; a name with no address yet
	cmp	ebx,[rsp]
	je	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	memit '{"server":"'
	imul	rax,rbx,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	mov	ecx,256
	call	json_text
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_GROUP],0
	je	@f
	memit '","address":"'			; (a name: the address it is at now)
	call	top_address
@@:
	memit '","state":"'
	call	top_state
	lea	rsi,[top_states+rax*4]
	add	rsi,rax
	add	rsi,rax				; (6 bytes each)
	call	fmt_cstr
	memit '","weight":'
	call	top_weight
	call	fmt_u64
	memit ',"active":'
	lea	rcx,[STP_SACTIVE+rbx*4]
	call	stats_sum_d
	call	fmt_u64
	memit ',"max":'
	imul	rax,rbx,SV_SIZE
	mov	eax,[g_servers+rax+SV_MAX]
	call	fmt_u64
	memit ',"connects":'
	lea	rcx,[OFF_S_CONNECTS+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"failures":'
	lea	rcx,[OFF_S_FAILS+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"conn_rate":'
	imul	ecx,ebx,TSS_SIZE
	add	ecx,TOP_S + TSS_CON
	call	top_rate10
	call	top_fmt_rate
	memit ',"fail_rate":'
	imul	ecx,ebx,TSS_SIZE
	add	ecx,TOP_S + TSS_FAIL
	call	top_rate10
	call	top_fmt_rate
	mov	byte [rdi],'}'
	inc	rdi
	jmp	.server_next2
.server_next:
	cmp	ebx,[rsp]
	jne	.server_next2
	inc	dword [rsp]			; (a hidden first: the next is first)
.server_next2:
	inc	ebx
	jmp	.server
.servers_done:
	add	rsp,16
	memit ']}'
	inc	r13d
	jmp	.pool
.end:
	memit ']}',10
	pop	r13
	pop	r12
	pop	rbx
	ret
; r12 = listener: its kind's name
.kind:
	mov	eax,[r12+LS_KIND]
	lea	rsi,[top_kinds]
	test	eax,eax
	jz	.k
	add	rsi,4
	dec	eax
	jz	.k
	add	rsi,5
.k:
	jmp	fmt_cstr

; ----------------------------------------------------------------- table

; rdi = output, r9 = the line's start, ecx = a column: spaces up to it (one
; at least)
top_tab:
	mov	byte [rdi],' '
	inc	rdi
@@:
	mov	rax,rdi
	sub	rax,r9
	cmp	eax,ecx
	jae	@f
	mov	byte [rdi],' '
	inc	rdi
	jmp	@b
@@:
	ret

; rdi = output, rsi/edx = text, ecx = most bytes: it, cut to fit
top_text:
	cmp	edx,ecx
	jbe	@f
	mov	edx,ecx
@@:
	mov	ecx,edx
	rep	movsb
	ret

; rdi = output, r9 = line start, ecx = the column it ends at, g_top_tmp ..
; r8 = what to put there: right-aligned
top_right:
	push	rsi
	lea	rsi,[g_top_tmp]
	mov	rdx,r8
	sub	rdx,rsi				; its length
	mov	rax,rdi
	sub	rax,r9
	add	rax,rdx
	inc	rax				; one space at least
@@:
	cmp	eax,ecx
	jae	@f
	mov	byte [rdi],' '
	inc	rdi
	inc	eax
	jmp	@b
@@:
	mov	byte [rdi],' '
	inc	rdi
	mov	rcx,rdx
	rep	movsb
	pop	rsi
	ret

macro top_cell col*, fmt*
	push	rdi
	lea	rdi,[g_top_tmp]
	call	fmt
	mov	r8,rdi
	pop	rdi
	mov	ecx,col
	call	top_right
end macro

; rdi = output: the instance now, as a table (`okena top`)
top_table:
	push	rbx
	push	r12
	push	r13
	push	rdi
	call	groups_refresh
	pop	rdi
	mov	r9,rdi
	memit 'okena ', OKENA_VERSION, '   workers '
	mov	eax,[g_workers]
	call	fmt_u64
	memit '   reloads '
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOADS]
	call	fmt_u64
	memit ' ('
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RELOAD_FAILS]
	call	fmt_u64
	memit ' refused)   restarts '
	mov	rax,[g_stats_tbl]
	mov	rax,[rax+SG_OFF+SG_RESTARTS]
	call	fmt_u64
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_DRAIN],0
	je	@f
	memit '   DRAINED'
@@:
	memit 10,10
	mov	r9,rdi
	memit 'LISTENER'
	mov	ecx,26
	call	top_tab
	memit 'KIND   ACTIVE  CONN/S   REQ/S   5XX/S    IN B/S   OUT B/S',10
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.pools
	mov	r9,rdi
	imul	r12,rbx,LS_SIZE
	lea	r12,[g_listeners+r12]
	mov	rsi,[r12+LS_TEXT]
	mov	edx,[r12+LS_TLEN]
	mov	ecx,25
	call	top_text
	mov	ecx,26
	call	top_tab
	call	status_json.kind
	imul	r13,rbx,TSL_SIZE
	push	r9
	lea	rcx,[STP_LACTIVE+rbx*4]
	call	stats_sum_d
	pop	r9
	top_cell 39, fmt_u64
	lea	ecx,[r13+TOP_L+TSL_ACC]
	call	top_rate10
	top_cell 47, top_fmt_rate
	lea	ecx,[r13+TOP_L+TSL_REQ]
	call	top_rate10
	top_cell 55, top_fmt_rate
	lea	ecx,[r13+TOP_L+TSL_ERR]
	call	top_rate10
	top_cell 63, top_fmt_rate
	lea	ecx,[r13+TOP_L+TSL_IN]
	call	top_rate10
	top_cell 73, top_fmt_bytes
	lea	ecx,[r13+TOP_L+TSL_OUT]
	call	top_rate10
	top_cell 83, top_fmt_bytes
	mov	byte [rdi],10
	inc	rdi
	inc	ebx
	jmp	.listener
.pools:
	mov	byte [rdi],10
	inc	rdi
	mov	r9,rdi
	memit 'POOL'
	mov	ecx,16
	call	top_tab
	memit 'SERVER'
	mov	ecx,44
	call	top_tab
	memit 'STATE  WEIGHT  ACTIVE  CONN/S  FAIL/S',10
	xor	r13d,r13d
.pool:
	cmp	r13d,[g_plan_pools]
	jae	.end
	imul	r12,r13,PL_SIZE
	lea	r12,[g_pools+r12]
	mov	ebx,[r12+PL_FIRST]
.server:
	mov	eax,[r12+PL_FIRST]
	add	eax,[r12+PL_COUNT]
	cmp	ebx,eax
	jae	.pool_next
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.server_next
	mov	r9,rdi
	mov	rsi,[r12+PL_NAME]
	mov	edx,[r12+PL_NLEN]
	mov	ecx,15
	call	top_text
	mov	ecx,16
	call	top_tab
	imul	rax,rbx,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	mov	ecx,27
	call	top_text
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_GROUP],0
	je	@f
	mov	byte [rdi],' '
	inc	rdi
	push	r9
	call	top_address			; (a name: the address it is at)
	pop	r9
@@:
	mov	ecx,44
	call	top_tab
	call	top_state
	lea	rsi,[top_states+rax*4]
	add	rsi,rax
	add	rsi,rax
	call	fmt_cstr
	push	r9
	call	top_weight
	pop	r9
	top_cell 57, fmt_u64
	push	r9
	lea	rcx,[STP_SACTIVE+rbx*4]
	call	stats_sum_d
	pop	r9
	top_cell 65, fmt_u64
	imul	ecx,ebx,TSS_SIZE
	add	ecx,TOP_S + TSS_CON
	call	top_rate10
	top_cell 73, top_fmt_rate
	imul	ecx,ebx,TSS_SIZE
	add	ecx,TOP_S + TSS_FAIL
	call	top_rate10
	top_cell 81, top_fmt_rate
	mov	byte [rdi],10
	inc	rdi
.server_next:
	inc	ebx
	jmp	.server
.pool_next:
	inc	r13d
	jmp	.pool
.end:
	pop	r13
	pop	r12
	pop	rbx
	ret

rodata
	dashboard_html	file 'dashboard.html'
	dashboard_html.len = $ - dashboard_html
end rodata
