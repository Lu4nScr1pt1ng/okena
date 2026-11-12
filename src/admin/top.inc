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
TSL_H1		:= 40			; responses by protocol
TSL_H2		:= 48
TSL_H3		:= 56
TSL_DGIN	:= 64			; udp datagrams
TSL_DGOUT	:= 72
TSL_SIZE	:= 80
TOP_S		:= MAX_LISTENERS * TSL_SIZE	; a server: 2 qwords
TSS_CON		:= 0
TSS_FAIL	:= 8
TSS_SIZE	:= 16
TOP_SIZE		:= TOP_S + MAX_SERVERS * TSS_SIZE
LAT_RING	:= 11

bss
	align 8
	g_top_cur	rb TOP_SIZE
	g_top_prev	rb TOP_SIZE
	g_top_t		dq ?		; ms of the current sample
	g_top_pt	dq ?		; and of the one before
	g_top_n		dd ?		; samples taken
	; the latency histograms of the last LAT_RING samples: percentiles over
	; ten seconds (one is too few requests for a quiet listener)
	align 8
	g_top_lat	rb LAT_RING * MAX_LISTENERS * LAT_B * 8
	g_top_tmp	rb 64
	g_top_ub	dq ?		; status_used_by: where its list starts
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
	lea	ecx,[rbx*2+rbx]
	lea	rcx,[OFF_L_PROTO+rcx*8]
	push	rcx
	call	stats_sum_q
	mov	[rdi+TSL_H1],rax
	mov	rcx,[rsp]
	add	rcx,8
	call	stats_sum_q
	mov	[rdi+TSL_H2],rax
	pop	rcx
	add	rcx,16
	call	stats_sum_q
	mov	[rdi+TSL_H3],rax
	lea	rcx,[OFF_L_DGIN+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSL_DGIN],rax
	lea	rcx,[OFF_L_DGOUT+rbx*8]
	call	stats_sum_q
	mov	[rdi+TSL_DGOUT],rax
	; its latency histogram, into the ring
	push	rdi
	mov	eax,[g_top_n]
	dec	eax
	xor	edx,edx
	mov	ecx,LAT_RING
	div	ecx
	imul	rdi,rdx,MAX_LISTENERS * LAT_B * 8
	imul	rax,rbx,LAT_B * 8
	add	rdi,rax
	add	rdi,g_top_lat
	xor	r8d,r8d
@@:
	imul	ecx,ebx,LAT_B
	add	ecx,r8d
	lea	rcx,[OFF_L_LAT+rcx*8]
	push	r8
	call	stats_sum_q
	pop	r8
	mov	[rdi+r8*8],rax
	inc	r8d
	cmp	r8d,LAT_B
	jb	@b
	pop	rdi
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

; ebx = listener, ecx = a fraction in thousandths: rax = that percentile of
; its request durations over the last ten seconds, µs, from its histogram
; (linear within a bucket); CF when it served none then
top_pct:
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r15d,ecx
	mov	eax,[g_top_n]
	test	eax,eax
	jz	.none
	; now, and ten samples ago (or the first there is)
	dec	eax
	mov	r12d,eax
	sub	eax,LAT_RING - 1
	jns	@f
	xor	eax,eax
@@:
	cmp	eax,r12d
	je	.none
	xor	edx,edx
	mov	ecx,LAT_RING
	div	ecx
	imul	r13,rdx,MAX_LISTENERS * LAT_B * 8
	mov	eax,r12d
	xor	edx,edx
	div	ecx
	imul	r12,rdx,MAX_LISTENERS * LAT_B * 8
	imul	rax,rbx,LAT_B * 8
	lea	r12,[g_top_lat+r12+rax]		; now
	lea	r13,[g_top_lat+r13+rax]		; then
	; how many, and the one wanted
	xor	r14d,r14d
	xor	ecx,ecx
@@:
	mov	rax,[r12+rcx*8]
	sub	rax,[r13+rcx*8]
	jbe	.empty_b
	add	r14,rax
.empty_b:
	inc	ecx
	cmp	ecx,LAT_B
	jb	@b
	test	r14,r14
	jz	.none
	mov	rax,r14
	imul	rax,r15
	add	rax,999
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	mov	r15,rax				; its rank, from 1
	xor	ecx,ecx
	xor	r8d,r8d				; seen below this bucket
.bucket:
	mov	rax,[r12+rcx*8]
	sub	rax,[r13+rcx*8]
	jbe	.next
	lea	r9,[r8+rax]
	cmp	r9,r15
	jae	.here
	mov	r8,r9
.next:
	inc	ecx
	cmp	ecx,LAT_B
	jb	.bucket
	dec	ecx
	mov	rax,1
.here:
	; lower + (upper - lower) * (rank - below) / in it
	mov	r9,rax
	call	lat_bucket			; r10 = lower, rax = upper
	cmp	ecx,LAT_B - 1
	jne	@f
	mov	rax,r10				; past the last bound: that bound
	jmp	.done
@@:
	sub	rax,r10
	mov	rdx,r15
	sub	rdx,r8
	imul	rax,rdx
	xor	edx,edx
	div	r9
	add	rax,r10
.done:
	clc
	jmp	.out
.none:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

; ecx = a latency bucket: r10 = its lower bound, rax = its upper one (µs, the
; upper one not in it). Keeps all else.
lat_bucket:
	cmp	ecx,16
	jae	@f
	mov	r10d,ecx
	lea	eax,[rcx+1]
	ret
@@:
	push	rcx
	push	rdx
	lea	edx,[rcx-16]
	mov	eax,edx
	and	eax,7				; m
	shr	edx,3
	add	edx,1				; e - 3
	lea	r10d,[rax+8]			; (8 + m) << (e - 3)
	lea	eax,[rax+9]
	mov	ecx,edx
	shl	r10,cl
	shl	rax,cl
	pop	rdx
	pop	rcx
	ret

; rdi = output, rax = µs: milliseconds, three digits after the point
top_fmt_ms:
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,3
	jmp	fmt_pad

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
	memit ',"engine":"'
	mov	rax,[g_stats_tbl]
	cmp	dword [rax+STP_BASE+STP_ENGINE],ENGINE_EPOLL	; (worker 0's: they all have the same)
	je	@f
	memit 'io_uring"'
	jmp	.uptime
@@:
	memit 'epoll"'
.uptime:
	memit ',"uptime_s":'
	sub	rsp,16
	push	rdi
	mov	edi,CLOCK_REALTIME
	lea	rsi,[rsp+8]
	mov	eax,SYS_clock_gettime
	syscall
	pop	rdi
	mov	rax,[rsp]
	add	rsp,16
	mov	rcx,[g_stats_tbl]
	sub	rax,[rcx+SG_OFF+SG_STARTED]
	jns	@f
	xor	eax,eax
@@:
	call	fmt_u64
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
	memit ',"maintenance":{"on":'
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_MAINT],0
	call	status_bool
	memit ',"routes":['
	push	rbx
	xor	ebx,ebx
.mroute:
	mov	rax,[g_api_ov]
	cmp	ebx,[rax+AP_MNUM]
	jae	.mroutes
	test	ebx,ebx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	byte [rdi],'"'
	inc	rdi
	imul	rsi,rbx,MP_SIZE
	lea	rsi,[rax+AP_MPATHS+rsi]
	mov	edx,[rsi]
	add	rsi,4
	mov	ecx,MP_SIZE
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	inc	ebx
	jmp	.mroute
.mroutes:
	pop	rbx
	memit ']}'
	memit ',"udp_dropped":'
	mov	ecx,OFF_UD_DROPS
	call	stats_sum_q
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
	mov	byte [rdi],'"'
	inc	rdi
	call	status_listener
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
	call	status_counts
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
	mov	byte [rdi],'"'
	inc	rdi
	call	status_pool
	call	status_used_by
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
	memit ',"backup":'
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_BACKUP],0
	call	status_bool
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

; rdi = output, ebx = listener, r12 = it, r13 = its place in a sample: what
; its kind counts: HTTP by protocol, some statuses, WebSocket, the cache,
; TLS and QUIC handshakes and latency; UDP datagrams
status_counts:
	mov	eax,[r12+LS_KIND]
	cmp	eax,LK_UDP
	je	.udp
	cmp	eax,LK_HTTP
	jne	.tls
	memit ',"by_protocol":{"http/1.1":'
	lea	ecx,[rbx*2+rbx]
	lea	rcx,[OFF_L_PROTO+rcx*8]
	push	rcx
	call	stats_sum_q
	call	fmt_u64
	memit ',"h2":'
	mov	rcx,[rsp]
	add	rcx,8
	call	stats_sum_q
	call	fmt_u64
	memit ',"h3":'
	pop	rcx
	add	rcx,16
	call	stats_sum_q
	call	fmt_u64
	memit '},"by_protocol_rate":{"http/1.1":'
	lea	ecx,[r13+TOP_L+TSL_H1]
	call	top_rate10
	call	top_fmt_rate
	memit ',"h2":'
	lea	ecx,[r13+TOP_L+TSL_H2]
	call	top_rate10
	call	top_fmt_rate
	memit ',"h3":'
	lea	ecx,[r13+TOP_L+TSL_H3]
	call	top_rate10
	call	top_fmt_rate
	memit '},"statuses":{"401":'
	lea	ecx,[rbx*4]
	lea	rcx,[OFF_L_CODES+rcx*8]
	push	rcx
	call	stats_sum_q
	call	fmt_u64
	memit ',"403":'
	mov	rcx,[rsp]
	add	rcx,8
	call	stats_sum_q
	call	fmt_u64
	memit ',"404":'
	mov	rcx,[rsp]
	add	rcx,16
	call	stats_sum_q
	call	fmt_u64
	memit ',"429":'
	pop	rcx
	add	rcx,24
	call	stats_sum_q
	call	fmt_u64
	memit '},"websocket_upgrades":'
	lea	rcx,[OFF_L_WS+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"cache_hits":'
	lea	rcx,[OFF_L_CACHE+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	; latency over the last ten seconds
	memit ',"latency_ms":'
	mov	ecx,500
	call	top_pct
	jnc	@f
	memit 'null'
	jmp	.tls
@@:
	push	rax
	memit '{"p50":'
	pop	rax
	call	top_fmt_ms
	memit ',"p90":'
	mov	ecx,900
	call	top_pct
	call	top_fmt_ms
	memit ',"p99":'
	mov	ecx,990
	call	top_pct
	call	top_fmt_ms
	memit ',"window_s":10}'
.tls:
	cmp	dword [r12+LS_TLS],0
	jne	@f
	test	dword [r12+LS_FLAGS],LSF_H3
	jz	.out
@@:
	memit ',"tls_handshakes":{"1.2":'
	lea	ecx,[rbx*4]
	lea	rcx,[OFF_L_TLS+rcx*8]
	push	rcx
	call	stats_sum_q
	call	fmt_u64
	memit ',"1.3":'
	mov	rcx,[rsp]
	add	rcx,8
	call	stats_sum_q
	call	fmt_u64
	memit ',"resumed":'
	mov	rcx,[rsp]
	add	rcx,16
	call	stats_sum_q
	call	fmt_u64
	memit ',"failed":'
	pop	rcx
	add	rcx,24
	call	stats_sum_q
	call	fmt_u64
	memit '},"quic_handshakes":'
	lea	rcx,[OFF_L_QUIC+rbx*8]
	call	stats_sum_q
	call	fmt_u64
.out:
	ret
.udp:
	memit ',"datagrams_in":'
	lea	rcx,[OFF_L_DGIN+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"datagrams_out":'
	lea	rcx,[OFF_L_DGOUT+rbx*8]
	call	stats_sum_q
	call	fmt_u64
	memit ',"dgin_rate":'
	lea	ecx,[r13+TOP_L+TSL_DGIN]
	call	top_rate10
	call	top_fmt_rate
	memit ',"dgout_rate":'
	lea	ecx,[r13+TOP_L+TSL_DGOUT]
	call	top_rate10
	call	top_fmt_rate
	memit ',"responses":'
	mov	eax,[r12+LS_RESP]
	cmp	eax,-1
	jne	@f
	memit '"any"'
	jmp	.udp_pool
@@:
	call	fmt_u64
.udp_pool:
	ret

; rdi = output, ZF: false, else true
status_bool:
	jz	@f
	memit 'true'
	ret
@@:
	memit 'false'
	ret

rodata
	st_balance	db 'round-robin',0,'least-conn',0,'random',0,'least-request',0,'peak-ewma',0
			db 'maglev',0,'ring-hash',0,'source-hash',0,'first',0
	st_hkeys	db 'source',0,'header',0,'cookie',0,'path',0,'query',0
	st_health	db 'tcp',0,'http',0,'grpc',0
	st_methods	db 'GET',0,'HEAD',0,'POST',0,'PUT',0,'DELETE',0,'PATCH',0,'OPTIONS',0,'other',0
end rodata

; rsi = a table of NUL-terminated words, eax = which: rsi = it (keeps rdi)
st_word:
	mov	ecx,eax
.word:
	test	ecx,ecx
	jz	.out
@@:
	lodsb
	test	al,al
	jnz	@b
	dec	ecx
	jmp	.word
.out:
	ret

; rdi = output, r12 = listener, ebx = its index: what it is set up to do
; (protocols, TLS and its certificates, QUIC's options, limits, logs, routes)
status_listener:
	push	r13
	push	r14
	mov	r13d,[r12+LS_FLAGS]
	memit ',"protocols":['
	mov	eax,[r12+LS_KIND]
	cmp	eax,LK_HTTP
	je	.http
	cmp	eax,LK_UDP
	je	.udp
	memit '"tcp"'
	cmp	dword [r12+LS_TLS],0
	je	.protocols
	memit ',"tls"'
	jmp	.protocols
.udp:
	memit '"udp"'
	jmp	.protocols
.http:
	memit '"http/1.1"'
	test	r13d,LSF_H2
	jz	@f
	memit ',"h2"'
@@:
	test	r13d,LSF_H3
	jz	.protocols
	memit ',"h3"'
.protocols:
	mov	byte [rdi],']'
	inc	rdi
	; TLS: who it is, as its certificates say
	memit ',"tls":'
	mov	eax,[r12+LS_TLS]
	test	eax,eax
	jnz	@f
	memit 'null'
	jmp	.quic
@@:
	dec	eax
	mov	r14d,eax			; the listener's first entry
	memit '{"versions":["1.2","1.3"],"ktls":'
	test	r13d,LSF_KTLS
	call	status_bool
	memit ',"client_cert":"'
	test	r13d,LSF_CCA_REQ
	jz	@f
	memit 'required"'
	jmp	.certs
@@:
	test	r13d,LSF_CCA
	jz	@f
	memit 'asked"'
	jmp	.certs
@@:
	memit 'off"'
.certs:
	memit ',"certificates":['
	xor	ecx,ecx
	xor	edx,edx				; written
.cert:
	cmp	ecx,[g_plan_tls]
	jae	.certs_done
	imul	rax,rcx,TL_SIZE
	cmp	[g_tls+rax+TL_GROUP],r14d
	jne	.cert_next
	push	rcx
	push	rdx
	test	edx,edx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	lea	rsi,[g_tls+rax]
	call	status_cert
	pop	rdx
	pop	rcx
	inc	edx
.cert_next:
	inc	ecx
	jmp	.cert
.certs_done:
	memit ']}'
.quic:
	test	r13d,LSF_H3
	jz	@f
	memit ',"quic":{"retry":'
	test	r13d,LSF_H3RETRY
	call	status_bool
	memit ',"v2":'
	test	r13d,LSF_H3V2
	call	status_bool
	memit ',"early_data":'
	test	r13d,LSF_0RTT
	call	status_bool
	mov	byte [rdi],'}'
	inc	rdi
@@:
	memit ',"proxy_protocol":'
	test	r13d,LSF_PP_V2
	jz	@f
	memit '"v2"'
	jmp	.limits
@@:
	test	r13d,LSF_PP_V1
	jz	@f
	memit '"v1"'
	jmp	.limits
@@:
	memit 'null'
.limits:
	memit ',"per_source":'
	mov	eax,[r12+LS_PER_SOURCE]
	call	fmt_u64
	memit ',"idle_s":'
	mov	eax,[r12+LS_IDLE]
	call	fmt_u64
	cmp	dword [r12+LS_KIND],LK_HTTP
	je	.http_more
	; L4: where it goes
	memit ',"pool":"'
	mov	eax,[r12+LS_POOL]
	imul	rax,rax,PL_SIZE
	mov	rsi,[g_pools+rax+PL_NAME]
	mov	edx,[g_pools+rax+PL_NLEN]
	mov	ecx,256
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	jmp	.out
.http_more:
	memit ',"maintenance":'
	mov	eax,[r12+LS_MAINT]
	test	eax,eax
	jnz	@f
	memit 'null'
	jmp	.alog
@@:
	dec	eax
	imul	rax,rax,MT_SIZE
	lea	r8,[g_maints+rax]
	push	r8
	memit '{"retry_s":'
	mov	r8,[rsp]
	mov	eax,[r8+MT_RETRY]
	call	fmt_u64
	memit ',"page":'
	mov	r8,[rsp]
	cmp	dword [r8+MT_PAGE],0
	call	status_bool
	memit ',"allow":'
	mov	r8,[rsp]
	cmp	dword [r8+MT_ACL],0
	call	status_bool
	memit ',"except":['
	xor	ecx,ecx
.mx:
	mov	r8,[rsp]
	cmp	ecx,[r8+MT_XN]
	jae	.mx_done
	test	ecx,ecx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	push	rcx
	imul	rsi,rcx,MP_SIZE
	lea	rsi,[r8+MT_X+rsi]
	mov	byte [rdi],'"'
	inc	rdi
	mov	edx,[rsi]
	add	rsi,4
	mov	ecx,MP_SIZE
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	pop	rcx
	inc	ecx
	jmp	.mx
.mx_done:
	pop	r8
	memit ']}'
.alog:
	memit ',"access_log":'
	cmp	dword [r12+LS_ALOG],0
	call	status_bool
	memit ',"tracing":'
	cmp	dword [r12+LS_TRACE],0
	call	status_bool
	memit ',"timeouts_s":{"header":'
	mov	eax,[r12+LS_T_HEADER]
	call	fmt_u64
	memit ',"body_idle":'
	mov	eax,[r12+LS_T_BODY]
	call	fmt_u64
	memit ',"response":'
	mov	eax,[r12+LS_T_RESPONSE]
	call	fmt_u64
	memit '},"routes":['
	mov	r14d,[r12+LS_RFIRST]
	mov	r13d,r14d
	add	r13d,[r12+LS_RCOUNT]
.route:
	cmp	r14d,r13d
	jae	.routes_done
	cmp	r14d,[r12+LS_RFIRST]
	je	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	imul	rax,r14,RT_SIZE
	lea	r8,[g_routes+rax]
	push	r8
	memit '{"path":"'
	mov	r8,[rsp]
	mov	rsi,[r8+RT_PATH]
	mov	edx,[r8+RT_PLEN]
	mov	ecx,600
	call	json_text
	mov	r8,[rsp]
	cmp	dword [r8+RT_PREFIX],1
	jne	@f
	mov	byte [rdi],'*'
	inc	rdi
@@:
	memit '","methods":['
	mov	r8,[rsp]
	mov	r9d,[r8+RT_METHODS]
	xor	ecx,ecx
	xor	edx,edx
.method:
	cmp	ecx,8
	jae	.methods_done
	bt	r9d,ecx
	jnc	.method_next
	push	rcx
	push	rdx
	test	edx,edx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	byte [rdi],'"'
	inc	rdi
	lea	rsi,[st_methods]
	mov	eax,ecx
	call	st_word
	call	fmt_cstr
	mov	byte [rdi],'"'
	inc	rdi
	pop	rdx
	pop	rcx
	inc	edx
.method_next:
	inc	ecx
	jmp	.method
.methods_done:
	mov	byte [rdi],']'
	inc	rdi
	mov	r8,[rsp]
	call	status_route_does
	memit ',"pool":'
	pop	r8
	mov	eax,[r8+RT_POOL]
	cmp	eax,-1
	je	.okena
	cmp	eax,[g_plan_pools]
	jae	.okena
	mov	byte [rdi],'"'
	inc	rdi
	imul	rax,rax,PL_SIZE
	mov	rsi,[g_pools+rax+PL_NAME]
	mov	edx,[g_pools+rax+PL_NLEN]
	mov	ecx,256
	call	json_text
	memit '"}'
	jmp	.route_next
.okena:
	memit 'null}'				; okena answers: a redirect, files, a response
.route_next:
	inc	r14d
	jmp	.route
.routes_done:
	mov	byte [rdi],']'
	inc	rdi
.out:
	pop	r14
	pop	r13
	ret

; rdi = output, r8 = route: what it does besides choosing a pool: how
; okena answers it itself, and the filters it passes through
status_route_does:
	push	rbx
	mov	eax,[r8+RT_ACT]
	test	eax,eax
	jnz	@f
	memit ',"answer":null,"filters":[]'
	pop	rbx
	ret
@@:
	dec	eax
	imul	rbx,rax,RA_SIZE
	add	rbx,g_acts
	memit ',"answer":'
	cmp	dword [rbx+RA_CODE],0
	je	.not_redirect
	memit '"redirect '
	mov	eax,[rbx+RA_CODE]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[rbx+RA_TGT]
	mov	edx,[rbx+RA_TLEN]
	mov	ecx,600
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	jmp	.filters
.not_redirect:
	cmp	dword [rbx+RA_FILES],0
	je	@f
	memit '"files"'
	jmp	.filters
@@:
	memit 'null'
.filters:
	memit ',"filters":['
	push	rdi
	irp f, RA_AUTH:auth, RA_CACHE:cache, RA_CORS:cors, RA_SPLIT:split
		match field:name, f
			cmp	dword [rbx+field],0
			je	@f
			memit '"', `name, '",'
		@@:
		end match
	end irp
	cmp	dword [rbx+RA_LCOUNT],0
	je	@f
	memit '"limit",'
@@:
	cmp	dword [rbx+RA_ZMIN],0
	je	@f
	memit '"compress",'
@@:
	cmp	qword [rbx+RA_WFROM],0
	je	@f
	memit '"rewrite",'
@@:
	mov	eax,[rbx+RA_QCOUNT]
	or	eax,[rbx+RA_PCOUNT]
	jz	@f
	memit '"headers",'
@@:
	cmp	dword [rbx+RA_FCODE],0
	jne	.fault
	cmp	qword [rbx+RA_FDELAY],0
	je	@f
.fault:
	memit '"fault",'
@@:
	cmp	qword [rbx+RA_HAFTER],0
	jne	.hedge
	cmp	dword [rbx+RA_HPCT],0
	je	@f
.hedge:
	memit '"hedge",'
@@:
	cmp	dword [rbx+RA_MPCT],0
	je	@f
	memit '"mirror '
	mov	eax,[rbx+RA_MPOOL]
	imul	rax,rax,PL_SIZE
	mov	rsi,[g_pools+rax+PL_NAME]
	mov	edx,[g_pools+rax+PL_NLEN]
	mov	ecx,256
	call	json_text
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,[rbx+RA_MPCT]
	call	fmt_u64
	memit '%",'
@@:
	cmp	dword [rbx+RA_PRIO],RP_CRITICAL
	jne	@f
	memit '"priority critical",'
@@:
	cmp	dword [rbx+RA_PRIO],RP_BULK
	jne	@f
	memit '"priority bulk",'
@@:
	pop	rax
	cmp	rdi,rax
	je	@f
	dec	rdi				; (the last comma)
@@:
	mov	byte [rdi],']'
	inc	rdi
	pop	rbx
	ret

; rdi = output, r13d = pool: who sends to it ("used_by": the L4 listeners
; that go to it, the routes that choose it or mirror to it)
status_used_by:
	push	rbx
	push	r12
	push	r14
	memit ',"used_by":['
	mov	[g_top_ub],rdi			; (nothing written yet)
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	imul	r12,rbx,LS_SIZE
	lea	r12,[g_listeners+r12]
	cmp	dword [r12+LS_KIND],LK_HTTP
	je	.routes
	cmp	[r12+LS_POOL],r13d
	jne	.next
	call	.comma
	memit '{"listener":"'
	call	.address
	memit '"}'
	jmp	.next
.routes:
	mov	r14d,[r12+LS_RFIRST]
.route:
	mov	eax,[r12+LS_RFIRST]
	add	eax,[r12+LS_RCOUNT]
	cmp	r14d,eax
	jae	.next
	imul	rax,r14,RT_SIZE
	lea	r8,[g_routes+rax]
	inc	r14d
	cmp	[r8+RT_POOL],r13d
	je	.use
	; a mirror to it
	mov	eax,[r8+RT_ACT]
	test	eax,eax
	jz	.route
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_MPCT],0
	je	.route
	cmp	[g_acts+rax+RA_MPOOL],r13d
	jne	.route
	push	r8
	call	.comma
	memit '{"listener":"'
	call	.address
	memit '","route":"'
	mov	r8,[rsp]
	call	.path
	memit '","as":"mirror"}'
	pop	r8
	jmp	.route
.use:
	push	r8
	call	.comma
	memit '{"listener":"'
	call	.address
	memit '","route":"'
	mov	r8,[rsp]
	call	.path
	memit '"}'
	pop	r8
	jmp	.route
.next:
	inc	ebx
	jmp	.listener
.done:
	mov	byte [rdi],']'
	inc	rdi
	pop	r14
	pop	r12
	pop	rbx
	ret
.comma:
	cmp	[g_top_ub],rdi
	je	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	ret
.address:
	mov	rsi,[r12+LS_TEXT]
	mov	edx,[r12+LS_TLEN]
	mov	ecx,256
	jmp	json_text
.path:
	mov	rsi,[r8+RT_PATH]
	mov	edx,[r8+RT_PLEN]
	push	r8
	mov	ecx,600
	call	json_text
	pop	r8
	cmp	dword [r8+RT_PREFIX],1
	jne	@f
	mov	byte [rdi],'*'
	inc	rdi
@@:
	ret

; rdi = output, rsi = a tls entry: its first certificate's names, key and
; days left
status_cert:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rsi
	mov	eax,[rbx+TL_CHAIN]
	lea	r12,[g_tls_store+rax]
	movzx	eax,byte [r12]			; uint24 length | DER
	shl	eax,16
	movzx	ecx,word [r12+1]
	xchg	cl,ch
	or	eax,ecx
	mov	r13d,eax
	add	r12,3
	memit '{"key":"'
	mov	eax,[rbx+TL_KEYTYPE]
	test	eax,eax
	jnz	@f
	memit 'P-256"'
	jmp	.names
@@:
	cmp	eax,2
	jne	@f
	memit 'Ed25519"'
	jmp	.names
@@:
	memit 'RSA-'
	mov	eax,[rbx+TL_RSA_NLEN]
	shl	eax,3
	call	fmt_u64
	mov	byte [rdi],'"'
	inc	rdi
.names:
	memit ',"names":['
	push	rdi
	mov	rsi,r12
	mov	edx,r13d
	call	x509_locate
	pop	rdi
	test	eax,eax
	jz	.end
	; subjectAltName's dNSNames
	xor	ebx,ebx				; written
	mov	r8,[g_x509_ext]
	test	r8,r8
	jz	.dates
.ext:
	cmp	r8,[g_x509_extend]
	jae	.dates
	push	rdi
	mov	rsi,r8
	mov	rdx,[g_x509_extend]
	call	der_read
	pop	rdi
	jc	.dates
	push	r8				; the next extension
	push	rdi
	mov	rdx,r8
	call	der_read			; extnID
	jc	.not_san
	cmp	al,6
	jne	.not_san
	push	r8
	lea	rdi,[oid_san]
	mov	edx,3
	call	der_oid_is
	pop	r8
	jne	.not_san
	mov	rsi,r8
	mov	rdx,[rsp+8]
	call	der_read
	jc	.not_san
	cmp	al,1				; an optional critical BOOLEAN
	jne	@f
	mov	rsi,r8
	mov	rdx,[rsp+8]
	call	der_read
	jc	.not_san
@@:
	cmp	al,4
	jne	.not_san
	mov	rdx,r8
	call	der_read			; GeneralNames
	jc	.not_san
	cmp	al,0x30
	jne	.not_san
	mov	r12,rsi
	mov	r13,r8
	pop	rdi
.gn:
	cmp	r12,r13
	jae	.gn_done
	push	rdi
	mov	rsi,r12
	mov	rdx,r13
	call	der_read
	pop	rdi
	jc	.gn_done
	mov	r12,r8
	cmp	al,0x82				; dNSName
	jne	.gn
	test	ebx,ebx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	inc	ebx
	mov	byte [rdi],'"'
	inc	rdi
	mov	edx,ecx
	push	rcx
	mov	ecx,300
	call	json_text
	pop	rcx
	mov	byte [rdi],'"'
	inc	rdi
	cmp	ebx,16
	jb	.gn
.gn_done:
	pop	r8
	jmp	.dates
.not_san:
	pop	rdi
	pop	r8
	jmp	.ext
.dates:
	; notAfter, and the days left
	memit '],"not_after":"'
	mov	rsi,[g_x509_val]
	mov	rdx,[g_x509_valend]
	push	rdi
	call	der_read			; notBefore
	jc	.no_date
	mov	rsi,r8
	mov	rdx,[g_x509_valend]
	call	der_read			; notAfter
	jc	.no_date
	lea	rdi,[g_top_tmp]
	call	x509_time_norm			; YYYYMMDDHHMMSS
	jc	.no_date
	pop	rdi
	; as an ISO time, and through it the days left
	lea	rsi,[g_top_tmp]
	lea	r8,[g_top_tmp+16]
	mov	ecx,4
	rep	movsb
	mov	byte [rdi],'-'
	inc	rdi
	movsw
	mov	byte [rdi],'-'
	inc	rdi
	movsw
	mov	byte [rdi],'T'
	inc	rdi
	movsw
	mov	byte [rdi],':'
	inc	rdi
	movsw
	mov	byte [rdi],':'
	inc	rdi
	movsw
	mov	byte [rdi],'Z'
	inc	rdi
	memit '","days_left":'
	call	status_days_left
	jmp	.end
.no_date:
	pop	rdi
	memit '","days_left":null'
.end:
	mov	byte [rdi],'}'
	inc	rdi
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_top_tmp = YYYYMMDDHHMMSS (a certificate's notAfter), rdi = output: the
; whole days from now to it (negative once past)
status_days_left:
	push	rdi
	; as ln_iso_ns reads times: "YYYY-MM-DDTHH:MM:SS.000Z"
	lea	rsi,[g_top_tmp]
	lea	rdi,[g_top_tmp+24]
	mov	ecx,4
	rep	movsb
	mov	al,'-'
	stosb
	movsw
	stosb
	movsw
	mov	al,'T'
	stosb
	movsw
	mov	al,':'
	stosb
	movsw
	stosb
	movsw
	mov	dword [rdi],'.000'
	mov	byte [rdi+4],'Z'
	sub	rsp,LP_SIZE
	lea	rax,[g_top_tmp+24]
	mov	[rsp+LP_VAL],rax
	mov	dword [rsp+LP_VLEN],24
	mov	r8,rsp
	xor	edi,edi
	call	ln_iso_ns
	add	rsp,LP_SIZE
	pop	rdi
	jc	.none
	push	rax
	push	rdi
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rcx,[rsp],1000000000
	add	rsp,16
	pop	rdi
	pop	rax
	sub	rax,rcx
	mov	rcx,86400000000000
	cqo
	idiv	rcx
	test	rax,rax
	jns	@f
	mov	byte [rdi],'-'
	inc	rdi
	neg	rax
@@:
	jmp	fmt_u64
.none:
	memit 'null'
	ret

; rdi = output, r12 = pool: how it balances, checks, speaks to its servers
status_pool:
	memit ',"balance":"'
	lea	rsi,[st_balance]
	mov	eax,[r12+PL_BALANCE]
	call	st_word
	call	fmt_cstr
	mov	byte [rdi],'"'
	inc	rdi
	mov	eax,[r12+PL_BALANCE]
	cmp	eax,BAL_MAGLEV
	je	.keyed
	cmp	eax,BAL_RING
	jne	.health
.keyed:
	memit ',"key":"'
	lea	rsi,[st_hkeys]
	mov	eax,[r12+PL_HKEY]
	call	st_word
	call	fmt_cstr
	cmp	dword [r12+PL_HNLEN],0
	je	@f
	mov	byte [rdi],':'
	inc	rdi
	mov	rsi,[r12+PL_HNAME]
	mov	edx,[r12+PL_HNLEN]
	mov	ecx,256
	call	json_text
@@:
	mov	byte [rdi],'"'
	inc	rdi
	cmp	dword [r12+PL_HBOUND],0
	je	.health
	memit ',"bound_pct":'
	mov	eax,[r12+PL_HBOUND]
	call	fmt_u64
.health:
	memit ',"health":'
	cmp	dword [r12+PL_HEALTH],0
	jne	@f
	memit 'null'
	jmp	.tls
@@:
	memit '{"kind":"'
	lea	rsi,[st_health]
	mov	eax,[r12+PL_H_HTTP]
	call	st_word
	call	fmt_cstr
	mov	byte [rdi],'"'
	inc	rdi
	cmp	dword [r12+PL_H_HTTP],1
	jne	@f
	memit ',"path":"'
	mov	rsi,[r12+PL_H_PATH]
	mov	edx,[r12+PL_H_PLEN]
	mov	ecx,600
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
@@:
	memit ',"every_ms":'
	mov	eax,[r12+PL_H_EVERY]
	call	fmt_u64
	memit ',"timeout_ms":'
	mov	eax,[r12+PL_H_TIMEOUT]
	call	fmt_u64
	memit ',"rise":'
	mov	eax,[r12+PL_H_RISE]
	call	fmt_u64
	memit ',"fall":'
	mov	eax,[r12+PL_H_FALL]
	call	fmt_u64
	mov	byte [rdi],'}'
	inc	rdi
.tls:
	memit ',"tls":'
	cmp	dword [r12+PL_TLS],0
	call	status_bool
	memit ',"sticky":'
	cmp	qword [r12+PL_SNAME],0
	jne	@f
	memit 'null'
	jmp	.slow
@@:
	mov	byte [rdi],'"'
	inc	rdi
	mov	rsi,[r12+PL_SNAME]
	mov	edx,[r12+PL_SNLEN]
	mov	ecx,256
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
.slow:
	memit ',"slow_start_s":'
	mov	eax,[r12+PL_SLOW]
	call	fmt_u64
	ret

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
