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
	g_st_src_open	dq ?			; let in uncounted: per_source table full
	g_st_alog_dropped dq ?			; access log lines lost to a full pipe
	g_st_http_trimmed dq ?			; idle http records given back to the kernel
	g_st_end:
	g_stats_tbl	dq ?			; shared: one page set per worker
end bss

ST_BLOCK	:= g_st_end - g_st_begin
; a worker's page: counters, then active connections per listener and
; per server, then its engine
STP_LACTIVE	:= ST_BLOCK
STP_SACTIVE	:= STP_LACTIVE + MAX_LISTENERS * 4
STP_ENGINE	:= STP_SACTIVE + MAX_SERVERS * 4
STP_ALIVE	:= STP_ENGINE + 4
STP_SIZE	:= (STP_ALIVE + 4 + 4095) and not 4095

; The supervisor's own counters, at the end of the table.
SG_RESTARTS	:= 0
SG_RELOADS	:= 8
SG_RELOAD_FAILS	:= 16
SG_DRAINING	:= 24
SG_OFF		:= STP_SIZE * MAX_WORKERS

; Before forking a generation: a fresh table (old workers keep theirs).
stats_table_init:
	push	rbx
	mov	rbx,[g_stats_tbl]
	xor	edi,edi
	mov	esi,SG_OFF + 4096
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
.done:
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
	add	rdi,[g_stats_tbl]
	push	rdi
	lea	rsi,[g_st_begin]
	mov	ecx,ST_BLOCK / 8
	rep	movsq
	pop	rdx
	lea	rdi,[rdx+STP_LACTIVE]
	lea	rsi,[g_ls_active]
	mov	ecx,MAX_LISTENERS
	rep	movsd
	lea	rdi,[rdx+STP_SACTIVE]
	lea	rsi,[g_sv_active]
	mov	ecx,MAX_SERVERS
	rep	movsd
	mov	eax,[g_engine]
	mov	[rdx+STP_ENGINE],eax
	mov	dword [rdx+STP_ALIVE],1
	ret
