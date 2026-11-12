; Statistics. Workers count in their own private memory, on the hot path,
; with plain increments; once a second (their tick) they copy the whole
; block to their page of a shared table. No shared cache line is written
; while serving, and the admin process sums the pages when scraped
; (values are at most a second old).

bss
	align 64
	g_st_begin:
	g_st_l_accepted	rq MAX_LISTENERS
	g_st_l_full	rq MAX_LISTENERS	; refused: no slot left
	g_st_l_source	rq MAX_LISTENERS	; refused: per_source
	g_st_l_in	rq MAX_LISTENERS	; bytes from clients
	g_st_l_out	rq MAX_LISTENERS	; bytes to clients
	g_st_s_connects	rq MAX_SERVERS
	g_st_s_fails	rq MAX_SERVERS
	g_st_l_evicted	rq MAX_LISTENERS	; idle sessions closed under pressure
	g_st_l_http	rq MAX_LISTENERS * 10	; responses: [source: backend, okena][1xx..5xx]
	g_st_l_retries	rq MAX_LISTENERS	; requests sent again to another server
	g_st_l_proto	rq MAX_LISTENERS * 3	; responses by protocol: HTTP/1, h2, h3
	g_st_l_codes	rq MAX_LISTENERS * 4	; and by some statuses: 401, 403, 404, 429
	g_st_l_ws	rq MAX_LISTENERS	; 101: protocols switched (WebSocket)
	g_st_l_cache	rq MAX_LISTENERS	; answers from the cache
	g_st_l_tls	rq MAX_LISTENERS * 4	; handshakes: TLS 1.2, 1.3, of them resumed, failed
	g_st_l_quic	rq MAX_LISTENERS	; QUIC handshakes done
	g_st_l_dgin	rq MAX_LISTENERS	; udp: datagrams from clients
	g_st_l_dgout	rq MAX_LISTENERS	; and to them
	g_st_l_lat	rq MAX_LISTENERS * LAT_B	; http: request durations, by bucket
	g_st_l_latsum	rq MAX_LISTENERS	; and their sum, µs
	; (stats_publish names each table above)
	g_st_ud_drops	dq ?			; udp: datagrams lost (no flow to go in, a full buffer)
	g_st_src_open	dq ?			; let in uncounted: per_source table full
	g_st_alog_dropped dq ?			; access log lines lost to a full pipe
	g_st_http_trimmed dq ?			; idle http records given back to the kernel
	g_st_tls_deferred dq ?			; ClientHellos queued by the handshake budget
	g_st_tls_shed	dq ?			; ... closed: queue full, or waited too long
	g_st_zc_bytes	dq ?			; body bytes sent without copies (zc.inc)
	g_st_cd_hits	dq ?			; cache_disk: answers served from disk
	g_st_cd_writes	dq ?			; answers written to it
	g_st_cd_full	dq ?			; not written: no room (the oldest still read)
	g_st_end:
	g_stats_tbl	dq ?			; shared: one page set per worker
end bss

ST_BLOCK	:= g_st_end - g_st_begin
; every table stats_publish copies, and nothing else before the scalars
assert g_st_ud_drops - g_st_begin = 8 * (MAX_LISTENERS * (34 + LAT_B) + MAX_SERVERS * 2)
; a worker's page: counters, then active connections per listener and
; per server, then its engine
STP_LACTIVE	:= ST_BLOCK
STP_SACTIVE	:= STP_LACTIVE + MAX_LISTENERS * 4
STP_ENGINE	:= STP_SACTIVE + MAX_SERVERS * 4
STP_ALIVE	:= STP_ENGINE + 4
STP_SIZE	:= (STP_ALIVE + 4 + 4095) and not 4095

; The supervisor's own counters, at the start of the table, the workers'
; pages after them (STP_BASE): a thousand workers' pages are past what a
; displacement reaches.
SG_RESTARTS	:= 0
SG_RELOADS	:= 8
SG_RELOAD_FAILS	:= 16
SG_DRAINING	:= 24
SG_STARTED	:= 32			; wall clock seconds when okena started
SG_OFF		:= 0
STP_BASE	:= 4096

; Before forking a generation: a fresh table (old workers keep theirs).
stats_table_init:
	push	rbx
	mov	rbx,[g_stats_tbl]
	xor	edi,edi
	mov	rsi,STP_BASE + STP_SIZE * MAX_WORKERS
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_stats_tbl],rax
	; the supervisor's counters carry over a reload
	test	rbx,rbx
	jz	.done
	mov	rcx,[rbx+SG_OFF+SG_RESTARTS]
	mov	[rax+SG_OFF+SG_RESTARTS],rcx
	mov	rcx,[rbx+SG_OFF+SG_RELOADS]
	mov	[rax+SG_OFF+SG_RELOADS],rcx
	mov	rcx,[rbx+SG_OFF+SG_RELOAD_FAILS]
	mov	[rax+SG_OFF+SG_RELOAD_FAILS],rcx
	mov	rcx,[rbx+SG_OFF+SG_STARTED]
	mov	[rax+SG_OFF+SG_STARTED],rcx
	jmp	.out
.done:
	; the first: when it started
	push	rax
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rcx,[rsp]
	add	rsp,16
	pop	rax
	mov	[rax+SG_OFF+SG_STARTED],rcx
.out:
	pop	rbx
	ret

; Supervisor counter: edi = SG_* offset.
stats_global_inc:
	mov	rax,[g_stats_tbl]
	inc	qword [rax+SG_OFF+rdi]
	ret

; Worker tick: publish.
stats_publish:
	mov	edi,[g_worker_id]
	imul	rdi,rdi,STP_SIZE
	add	rdi,STP_BASE
	add	rdi,[g_stats_tbl]
	mov	rdx,rdi
	; only the listeners and servers there are: the tables are sized for
	; the largest configuration, and a second's copy stays what is used
	irp <sym,per,cnt>, g_st_l_accepted,1,g_plan_listeners, g_st_l_full,1,g_plan_listeners, \
		g_st_l_source,1,g_plan_listeners, g_st_l_in,1,g_plan_listeners, \
		g_st_l_out,1,g_plan_listeners, g_st_s_connects,1,g_plan_servers, \
		g_st_s_fails,1,g_plan_servers, g_st_l_evicted,1,g_plan_listeners, \
		g_st_l_http,10,g_plan_listeners, g_st_l_retries,1,g_plan_listeners, \
		g_st_l_proto,3,g_plan_listeners, g_st_l_codes,4,g_plan_listeners, \
		g_st_l_ws,1,g_plan_listeners, g_st_l_cache,1,g_plan_listeners, \
		g_st_l_tls,4,g_plan_listeners, g_st_l_quic,1,g_plan_listeners, \
		g_st_l_dgin,1,g_plan_listeners, g_st_l_dgout,1,g_plan_listeners, \
		g_st_l_lat,LAT_B,g_plan_listeners, g_st_l_latsum,1,g_plan_listeners
		lea	rdi,[rdx + sym - g_st_begin]
		lea	rsi,[sym]
		mov	ecx,[cnt]
		imul	ecx,ecx,per
		rep	movsq
	end irp
	lea	rdi,[rdx + g_st_ud_drops - g_st_begin]
	lea	rsi,[g_st_ud_drops]
	mov	ecx,(g_st_end - g_st_ud_drops) / 8
	rep	movsq
	lea	rdi,[rdx+STP_LACTIVE]
	lea	rsi,[g_ls_active]
	mov	ecx,[g_plan_listeners]
	rep	movsd
	lea	rdi,[rdx+STP_SACTIVE]
	lea	rsi,[g_sv_active]
	mov	ecx,[g_plan_servers]
	rep	movsd
	mov	eax,[g_engine]
	mov	[rdx+STP_ENGINE],eax
	mov	dword [rdx+STP_ALIVE],1
	ret
