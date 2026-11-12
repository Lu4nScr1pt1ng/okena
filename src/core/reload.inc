; Reload without dropping a connection (SIGHUP).
;
;   1. Read the file once into memory, into the other of two arena sets,
;      so validating and applying see the same bytes and the running
;      configuration's text stays untouched.
;   2. A compiler child parses, checks and compiles those bytes. Invalid
;      configuration, or a crash in that code, ends the child, never the
;      supervisor; the running configuration stays.
;   3. The supervisor compiles the same bytes (a snapshot of the old plan
;      is kept), opens the sockets of new addresses, keeps the sockets of
;      addresses that stay (no moment where a connection is refused), and
;      only then commits: a new generation of workers starts, the old one
;      stops accepting at once and finishes its sessions within its drain
;      timeout. Sockets of removed addresses close when the old
;      generation is gone. Any failure before the commit restores the old
;      plan and closes what was opened.

MAX_OLD		:= MAX_WORKERS * 4

bss
	align 8
	g_gen		dd ?		; worker generation
	g_hb_slot	dd ?		; this worker's heartbeat line
	g_reloading	dd ?		; listener errors are reported, not fatal
	g_old_count	dd ?
	g_old_pid	rd MAX_OLD
	g_old_deadline	dq ?		; monotonic second to kill stragglers
	g_close_count	dd ?
	g_close_fd	rd MAX_LISTENERS * MAX_WORKERS
	g_prev_lfd	rd MAX_LISTENERS * MAX_WORKERS
	g_prev_lsocks	rd MAX_LISTENERS
	g_taken		rb MAX_LISTENERS * MAX_WORKERS
	g_prev_nls	dd ?
	g_prev_workers	dd ?
	g_new_count	dd ?
	g_new_fd	rd MAX_LISTENERS * MAX_WORKERS	; sockets opened by this reload
	g_ar_alt:	rq 9		; the other arena set
end bss

; Plan state saved before applying, restored if the reload fails.
macro plan_regions action
	action g_plan_listeners, 4
	action g_plan_pools, 4
	action g_plan_servers, 4
	action g_plan_groups, 4
	action g_plan_discs, 4
	action g_plan_dk, DK_SIZE * DISC_SOURCES, g_plan_discs, DK_SIZE
	action g_plan_kb, KB_SIZE * DISC_SOURCES, g_plan_discs, KB_SIZE
	action g_plan_cs, CS_SIZE * DISC_SOURCES, g_plan_discs, CS_SIZE
	action g_plan_gw, GWP_SIZE
	action g_plan_dshare, 4 * DISC_SOURCES
	action g_plan_echn, 4
	action g_plan_echlen, 4
	action g_plan_ech, ECC_SIZE * ECH_MAX
	action g_plan_echlist, ECH_LIST_MAX
	action g_plan_al_n, 4
	action g_plan_al_on, 4
	action g_plan_al_every, 4
	action g_plan_al_nlen, 4
	action g_plan_al_name, 8
	action g_plan_al, ATG_SIZE * AL_TARGETS
	action g_plan_workers, 4
	action g_plan_engine, 4
	action g_plan_drain_delay, 8
	action g_plan_drain_timeout, 8
	action g_plan_watchdog, 8
	action g_plan_last_good, 4
	action g_plan_reload_watch, 4
	action g_plan_profile, 4
	action g_plan_tryc, 4
	action g_try_secs, 4 * MAX_TRYC
	action g_plan_busy_poll, 8
	action g_plan_qcc, 4
	action g_plan_qlb_len, 4
	action g_plan_qlb_sid, 4
	action g_plan_qlb_keyed, 4
	action g_plan_qlb_rot, 4
	action g_plan_qlb_key, 16
	action g_plan_hs_budget, 8
	action g_plan_hs_wait, 8
	action g_plan_health, 4
	action g_plan_metrics, 4
	action g_plan_metrics_salen, 4
	action g_plan_metrics_text, 8
	action g_plan_metrics_tlen, 4
	action g_plan_user, 4
	action g_plan_uid, 4
	action g_plan_gid, 4
	action g_plan_metrics_sa, 28
	action g_plan_mtlen, 4
	action g_plan_mtoken, 256
	action g_listeners, LS_SIZE * MAX_LISTENERS, g_plan_listeners, LS_SIZE
	action g_pools, PL_SIZE * MAX_POOLS, g_plan_pools, PL_SIZE
	action g_servers, SV_SIZE * MAX_SERVERS, g_plan_servers, SV_SIZE
	action g_groups, GR_SIZE * MAX_GROUPS
	action g_plan_routes, 4
	action g_routes, RT_SIZE * MAX_ROUTES, g_plan_routes, RT_SIZE
	action g_plan_trust, 4
	action g_trust, TR_SIZE * MAX_TRUST, g_plan_trust, TR_SIZE
	action g_plan_hhsize, 4
	action g_plan_hhmask, 4
	action g_hhash, 8 * HHASH_SIZE, g_plan_hhsize, 8
	action g_plan_rhsize, 4
	action g_plan_rhmask, 4
	action g_rhash, 8 * RHASH_SIZE, g_plan_rhsize, 8
	action g_plan_tls, 4
	action g_plan_tkeys, TKF_SIZE
	action g_plan_tkpath, 8
	action g_plan_tkplen, 4
	action g_tls_ntab, TN_CAP * TN_SIZE
	action g_tls_nstore, TN_STORE, g_tls_nused, 1
	action g_tls_nused, 8
	action g_tls_used, 4
	action g_tls, TL_SIZE * MAX_TLS, g_plan_tls, TL_SIZE
	action g_tls_store, TLS_STORE, g_tls_used, 1
	action g_plan_acts, 4
	action g_plan_eps, 4
	action g_ep_used, 4
	action g_eps, EP_SIZE * MAX_EPS, g_plan_eps, EP_SIZE
	action g_ep_store, EP_STORE, g_ep_used, 1
	action g_plan_maints, 4
	action g_maints, MT_SIZE * MAX_MAINTS
	action g_acts, RA_SIZE * MAX_ACTS, g_plan_acts, RA_SIZE
	action g_limits, LM_SIZE * MAX_LIMITS, g_plan_limits, LM_SIZE
	action g_plan_limits, 4
	action g_cors, CO_SIZE * MAX_CORS, g_plan_cors, CO_SIZE
	action g_plan_cors, 4
	action g_splits, SL_SIZE * MAX_SPLITS, g_plan_splits, SL_SIZE
	action g_plan_splits, 4
	action g_auths, AU_SIZE * MAX_AUTHS, g_plan_auths, AU_SIZE
	action g_plan_auths, 4
	action g_plan_akeys, 4
	action g_jwk, JK_SIZE * MAX_JWK, g_plan_jwk, JK_SIZE
	action g_plan_jwk, 4
	action g_jsrc, JS_SIZE * MAX_JWKS, g_plan_jsrc, JS_SIZE
	action g_cca, PK_SIZE * CCA_MAX
	action g_cca_nh, 8 * CCA_MAX
	action g_cca_next, 8 * CCA_MAX
	action g_crl_tab, 8 * CRL_SLOTS
	action g_plan_crln, 4
	action g_caches, CA_SIZE * MAX_CACHES, g_plan_caches, CA_SIZE
	action g_files, FI_SIZE * MAX_FILES, g_plan_files, FI_SIZE
	action g_plan_files, 4
	action g_rmaps, RM_SIZE * MAX_RMAPS, g_plan_rmaps, RM_SIZE
	action g_plan_rmaps, 4
	action g_plan_up, 8
	action g_plan_uplen, 4
	action g_plan_api, 8
	action g_plan_apilen, 4
	action g_geo_base, 8
	action g_geo_end, 8
	action g_geo_data, 8
	action g_geo_tree, 8
	action g_geo_nodes, 4
	action g_geo_rec, 4
	action g_geo_ver, 4
	action g_geo_v4, 4
	action g_acls, ACL_SIZE * MAX_ACLS, g_plan_acls, ACL_SIZE
	action g_plan_acls, 4
	action g_idems, IC_SIZE * MAX_IDEMS, g_plan_idems, IC_SIZE
	action g_plan_idems, 4
	action g_plan_zip, 4
	action g_mroutes, RT_SIZE * MAX_MATCH, g_plan_mroutes, RT_SIZE
	action g_mblocks, MB_SIZE * MAX_MATCH, g_plan_mroutes, MB_SIZE
	action g_mconds, MC_SIZE * MAX_MCOND, g_plan_mconds, MC_SIZE
	action g_plan_mroutes, 4
	action g_plan_mconds, 4
	action g_plan_caches, 4
	action g_plan_cmem, 8
	action g_plan_cdpath, 8
	action g_plan_cdplen, 4
	action g_plan_cdsize, 8
	action g_plan_fleet, 4
	action g_plan_slices, 4
	action g_plan_cdnl, 8
	action g_plan_cdnll, 4
	action g_plan_cdnmax, 4
	action g_plan_bird, 8
	action g_plan_birdl, 4
	action g_plan_birdpl, 4
	action g_plan_birdp, 8
	action g_plan_birdpool, 8
	action g_plan_birdpooll, 4
	action g_plan_vrrp, VC_SIZE
	action g_plan_acme, ACM_SIZE
	action g_rx, RXE_SIZE * RX_MAX, g_plan_rx, RXE_SIZE
	action g_rx_prog, RI_SIZE * RX_POOL, g_plan_rxpc, RI_SIZE
	action g_rx_cls, 32 * RX_CLASSES, g_plan_rxcls, 32
	action g_plan_rx, 4
	action g_plan_rxpc, 4
	action g_plan_rxcls, 4
	action g_plan_rxroutes, 4
	action g_plan_lca, LCA_SIZE
	action g_plan_ocspoff, MAX_TLS
	action g_plan_odn, 4
	action g_plan_od, OC_SIZE * OD_CFGS
	action g_signed, SU_SIZE * MAX_SIGNED, g_plan_signed, SU_SIZE
	action g_plan_signed, 4
	action g_plan_fleet_sa, 32 * MAX_FLEET
	action g_plan_fleet_sl, 4 * MAX_FLEET
	action g_plan_fleet_tx, 8 * MAX_FLEET
	action g_plan_fleet_tl, 4 * MAX_FLEET
	action g_plan_cca, 4
	action g_plan_jsrc, 4
	action g_claims, CM_SIZE * MAX_CLAIMS, g_plan_claims, CM_SIZE
	action g_plan_claims, 4
	action g_auth_tab, AT_SIZE * AT_N
	action g_plan_hdrops, 4
	action g_hdrops, HD_SIZE * MAX_HDROPS, g_plan_hdrops, HD_SIZE
	action g_plan_hosts, 4
	action g_hosts, HO_SIZE * MAX_HOSTS, g_plan_hosts, HO_SIZE
end macro

PLAN_SAVE_SIZE = 0
PLAN_HW_N = 0
; offsets of the regions read back from the snapshot
macro plan_size_of sym, size, cnt, elem:0
	match =g_listeners, sym
		PLAN_SAVE_LISTENERS = PLAN_SAVE_SIZE
	end match
	match =g_plan_drain_timeout, sym
		PLAN_SAVE_DRAIN_TIMEOUT = PLAN_SAVE_SIZE
	end match
	PLAN_SAVE_SIZE = PLAN_SAVE_SIZE + size
	if elem
		PLAN_HW_N = PLAN_HW_N + 1
	end if
end macro
plan_regions plan_size_of

; A table sized for the largest configuration (cnt entries of elem bytes in
; use) is copied and cleared only as far as it is used, so its untouched
; pages cost nothing: a table's watermark is the most entries it has held
; since it was last cleared (a compile that failed may leave more than the
; count restored says).
bss
	align 8
	g_plan_save:	rb PLAN_SAVE_SIZE
	g_plan_hw	rd PLAN_HW_N
end bss

macro plan_copy_out sym, size, cnt, elem:0
	lea	rdi,[g_plan_save + PLAN_OFF]
	lea	rsi,[sym]
	if elem
		mov	ecx,[cnt]
		imul	ecx,ecx,elem
	else
		mov	ecx,size
	end if
	rep	movsb
	PLAN_OFF = PLAN_OFF + size
end macro

; restored in two passes: everything but the sized tables first, so that
; their counts are back wherever they are in the list
macro plan_copy_in_fixed sym, size, cnt, elem:0
	if ~ elem
		lea	rsi,[g_plan_save + PLAN_OFF]
		lea	rdi,[sym]
		mov	ecx,size
		rep	movsb
	end if
	PLAN_OFF = PLAN_OFF + size
end macro

macro plan_copy_in_sized sym, size, cnt, elem:0
	if elem
		lea	rsi,[g_plan_save + PLAN_OFF]
		lea	rdi,[sym]
		mov	ecx,[cnt]
		imul	ecx,ecx,elem
		rep	movsb
	end if
	PLAN_OFF = PLAN_OFF + size
end macro

; before a restore: what the failed plan used stays to be cleared
macro plan_hw_note sym, size, cnt, elem:0
	if elem
		mov	eax,[cnt]
		cmp	eax,[g_plan_hw + PLAN_HWI*4]
		jbe	@f
		mov	[g_plan_hw + PLAN_HWI*4],eax
	@@:
		PLAN_HWI = PLAN_HWI + 1
	end if
end macro

plan_save:
	PLAN_OFF = 0
	plan_regions plan_copy_out
	ret

plan_restore:
	PLAN_HWI = 0
	plan_regions plan_hw_note
	PLAN_OFF = 0
	plan_regions plan_copy_in_fixed
	PLAN_OFF = 0
	plan_regions plan_copy_in_sized
	ret

; sized tables first, while their counts are still there
macro plan_zero_sized sym, size, cnt, elem:0
	if elem
		mov	ecx,[cnt]
		cmp	ecx,[g_plan_hw + PLAN_HWI*4]
		jae	@f
		mov	ecx,[g_plan_hw + PLAN_HWI*4]
	@@:
		mov	dword [g_plan_hw + PLAN_HWI*4],0
		imul	ecx,ecx,elem
		lea	rdi,[sym]
		rep	stosb
		PLAN_HWI = PLAN_HWI + 1
	end if
end macro

; a large one by giving its pages back: clearing with stores would make
; resident what was never touched
macro plan_zero sym, size, cnt, elem:0
	if ~ elem
		lea	rdi,[sym]
		if size >= 65536
			mov	esi,size
			call	region_zero
		else
			mov	ecx,size
			rep	stosb
		end if
	end if
end macro

; rdi = start, esi = length: zero; whole pages inside by MADV_DONTNEED.
; eax = 0 after.
region_zero:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12d,esi
	call	pages_release
	; the part pages_release leaves: up to the first page, from the last
	lea	rcx,[rbx+4095]
	and	rcx,not 4095
	sub	rcx,rbx
	cmp	ecx,r12d
	jbe	@f
	mov	ecx,r12d
@@:
	mov	rdi,rbx
	xor	eax,eax
	rep	stosb
	lea	rdi,[rbx+r12]
	mov	rcx,rdi
	and	rdi,not 4095
	cmp	rdi,rbx
	jae	@f
	mov	rdi,rbx
@@:
	sub	rcx,rdi
	xor	eax,eax
	rep	stosb
	pop	r12
	pop	rbx
	ret

; Empty plan, as before the first compile.
plan_reset:
	xor	eax,eax
	PLAN_HWI = 0
	plan_regions plan_zero_sized
	xor	eax,eax
	plan_regions plan_zero
	ret

; Swap the current arena set with the other one, and empty the one that
; becomes current (its pages go back to the kernel).
arenas_swap:
	xor	ecx,ecx
@@:
	mov	rax,[g_ar_nodes+rcx*8]
	mov	rdx,[g_ar_alt+rcx*8]
	mov	[g_ar_nodes+rcx*8],rdx
	mov	[g_ar_alt+rcx*8],rax
	inc	ecx
	cmp	ecx,9
	jb	@b
	ret

arenas_empty:
	lea	rdi,[g_ar_nodes]
	; rdi = an arena set (three arenas): emptied, its pages given back
arenas_empty_at:
	push	rbx
	mov	rbx,rdi
	mov	ecx,3
.next:
	push	rcx
	mov	rdi,[rbx+AR_BASE]
	test	rdi,rdi
	jz	.skip
	mov	rsi,[rbx+AR_NEXT]
	sub	rsi,rdi
	jz	.skip
	add	rsi,4095
	and	rsi,-4096
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
	mov	rax,[rbx+AR_BASE]
	mov	[rbx+AR_NEXT],rax
.skip:
	pop	rcx
	add	rbx,AR_SIZE
	dec	ecx
	jnz	.next
	pop	rbx
	ret

cstring str_reload_inline, 'the configuration came from the command line or OKENA_CONFIG: nothing to reload'

supervisor_reload:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	cmp	dword [g_shutdown],0
	jne	.out
	call	sd_reloading			; (systemd: RELOADING=1)
	cmp	qword [g_cli_text],0
	je	@f
	call	log_begin
	lea	rsi,[str_reload_inline]
	mov	edx,str_reload_inline.len
	call	out_str
	call	log_end
	jmp	.out
@@:
	call	log_begin
	out_lit 'reloading '
	mov	rsi,[g_cli_path]
	call	out_cstr
	call	log_end
	; remember what runs now
	call	plan_save
	mov	eax,[g_plan_listeners]
	mov	[g_prev_nls],eax
	mov	eax,[g_workers]
	mov	[g_prev_workers],eax
	lea	rdi,[g_prev_lfd]
	lea	rsi,[g_lfd]
	imul	ecx,[g_plan_listeners],MAX_WORKERS * 4	; (the rows there are)
	rep	movsb
	lea	rdi,[g_prev_lsocks]
	lea	rsi,[g_lsocks]
	imul	ecx,[g_plan_listeners],4
	rep	movsb
	call	arenas_swap
	call	arenas_empty
	call	cw_mark				; (reload on-change: when the files were read)
	call	cfg_read_source
	test	rax,rax
	js	.read_failed
	; validate in a child: a parser bug or a bad file ends it, not us
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.compiler
	js	.fork_failed
	mov	ebx,eax
.wait:
	lea	rdi,[g_siginfo]
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,1				; P_PID
	mov	esi,ebx
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	cmp	rax,-EINTR
	je	.wait
	cmp	dword [g_siginfo+SI_CODE],CLD_EXITED
	jne	.child_crashed
	cmp	dword [g_siginfo+SI_STATUS],0
	jne	.rejected
	; apply: the same bytes, now here
	call	cfg_parse_checked
	call	plan_reset
	call	plan_compile
	call	cpu_worker_count
	mov	r15d,eax			; new worker count
	call	reload_sockets
	test	eax,eax
	jnz	.sockets_failed
	; commit. The old plan's snapshot and the old configuration's text and
	; tree are not needed again (the old workers have their own copies):
	; given back now, before any process is forked, or each would keep them
	lea	rdi,[g_plan_save]
	mov	esi,PLAN_SAVE_SIZE
	call	pages_release
	lea	rdi,[g_ar_alt]
	call	arenas_empty_at
	call	tls_tickets_apply		; the ticket_keys file again (an operator's rotation)
	call	retire_workers
	mov	[g_workers],r15d
	mov	edi,[g_control_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_control_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	disc_table_init
	call	dns_table_init			; a new table: the old workers keep theirs
	call	alerts_prepare
	call	groups_resolve_all
	call	spawn_control
	mov	edi,[g_keys_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_keys_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	jwks_table_init
	call	idem_table_init
	call	spawn_keys
	call	jwks_wait
	mov	edi,[g_health_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_health_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	health_table_init
	call	api_table_init
	call	sv_live_init
	call	spawn_health
	call	stats_table_init		; the old workers keep their pages
	mov	edi,[g_admin_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_admin_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	spawn_admin
	call	logger_restart			; destinations may have changed
	call	keeper_reload			; the store may have changed
	call	vrrp_reload			; (kept when it is as it was: its state too)
	call	acme_reload
	call	gateway_reload
	call	ocsp_reload
	mov	edi,SG_RELOADS
	call	stats_global_inc
	call	api_reloaded
	inc	dword [g_gen]
	xor	ebx,ebx
.spawn:
	cmp	ebx,r15d
	jae	.spawned
	mov	edi,ebx
	call	spawn_worker
	inc	ebx
	jmp	.spawn
.spawned:
	push	rdi
	mov	edi,1
	call	gw_reload_result
	call	lg_save				; FILE.good, when last_good is on
	pop	rdi
	call	log_begin
	out_lit 'configuration reloaded: '
	mov	eax,r15d
	call	out_u64
	out_lit ' new workers, '
	mov	eax,[g_old_count]
	call	out_u64
	out_lit ' finishing their connections'
	call	log_end
	jmp	.out
.compiler:
	call	ll_confine_reader		; (and reads, writing nothing)
	seccomp_for filter_compiler		; the parser runs boxed in
	call	cfg_parse_checked
	call	plan_reset
	call	plan_compile
	call	tls_serve_check		; kTLS there, nothing served in plaintext
	xor	edi,edi
	jmp	exit_process
.read_failed:
	push	rax
	call	log_begin
	out_lit 'reload failed: cannot read '
	mov	rsi,[g_cli_path]
	call	out_cstr
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit '); keeping the running configuration'
	mov	edi,AL_RELOAD
	call	log_end_alert
	jmp	.undo_arenas
.fork_failed:
	call	log_begin
	out_lit 'reload failed: fork failed; keeping the running configuration'
	mov	edi,AL_RELOAD
	call	log_end_alert
	jmp	.undo_arenas
.child_crashed:
	call	log_begin
	out_lit 'reload failed: the configuration compiler crashed (signal '
	mov	eax,[g_siginfo+SI_STATUS]
	call	out_u64
	out_lit '); keeping the running configuration'
	mov	edi,AL_RELOAD
	call	log_end_alert
	jmp	.undo_arenas
.rejected:
	mov	edi,2
	call	gw_reload_result
	call	log_begin
	out_lit 'reload rejected (errors above); keeping the running configuration'
	mov	edi,AL_RELOAD
	call	log_end_alert
	jmp	.undo_arenas
.sockets_failed:
	mov	edi,2
	call	gw_reload_result
	call	log_begin
	out_lit 'reload rejected (cannot listen, see above); keeping the running configuration'
	mov	edi,AL_RELOAD
	call	log_end_alert
	call	plan_restore
.undo_arenas:
	call	arenas_swap
	mov	edi,SG_RELOAD_FAILS
	call	stats_global_inc
.out:
	call	cw_snapshot			; (reload on-change: the files now, either way)
	cmp	dword [g_shutdown],0
	jne	@f
	call	sd_ready			; (systemd: READY=1, the reload over either way)
@@:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Sockets for the new plan (r15d workers). Addresses that stay keep their
; sockets; new ones are probed and opened. eax = 0, or 1 after closing
; everything this reload opened.
reload_sockets:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	dword [g_reloading],1
	mov	dword [g_new_count],0
	lea	rdi,[g_taken]
	xor	eax,eax
	imul	ecx,[g_prev_nls],MAX_WORKERS	; (only old listeners are taken)
	rep	stosb
	xor	r12d,r12d			; new listener
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.closing
	mov	edi,r12d
	call	previous_listener		; eax = old index or -1
	mov	r13d,eax
	test	r13d,r13d
	jns	.reuse
	mov	edi,r12d
	call	listener_probe
	test	eax,eax
	jnz	.failed
.reuse:
	; sockets: one per new worker, and every old one of an address that
	; stays (queued connections must not be reset)
	mov	r14d,r15d
	test	r13d,r13d
	js	@f
	mov	eax,[g_prev_lsocks+r13*4]
	cmp	eax,r14d
	cmova	r14d,eax
@@:
	mov	[g_lsocks+r12*4],r14d
	xor	ebx,ebx				; socket
.socket:
	cmp	ebx,r14d
	jae	.next_listener
	test	r13d,r13d
	js	.open
	cmp	ebx,[g_prev_lsocks+r13*4]
	jae	.open
	mov	eax,r13d
	imul	eax,eax,MAX_WORKERS
	add	eax,ebx
	mov	byte [g_taken+rax],1
	mov	ecx,[g_prev_lfd+rax*4]
	push	rcx
	imul	rdi,r12,LS_SIZE
	lea	rdi,[g_listeners+rdi]
	mov	esi,ecx
	call	listener_tune			; (its `mss` may have changed)
	pop	rcx
	jmp	.store
.open:
	mov	edi,r12d
	call	listener_open
	test	eax,eax
	js	.failed
	mov	ecx,[g_new_count]
	mov	[g_new_fd+rcx*4],eax
	inc	dword [g_new_count]
	mov	ecx,eax
.store:
	mov	eax,r12d
	imul	eax,eax,MAX_WORKERS
	add	eax,ebx
	mov	[g_lfd+rax*4],ecx
	inc	ebx
	jmp	.socket
.next_listener:
	test	r13d,r13d
	jns	@f
	push	r12
	call	log_listener			; a new address
	pop	r12
@@:
	inc	r12d
	jmp	.listener
.closing:
	; old sockets nobody takes over close when the old workers are gone
	xor	r12d,r12d
.old:
	cmp	r12d,[g_prev_nls]
	jae	.ok
	xor	ebx,ebx
	xor	r14d,r14d			; any socket of it kept?
.old_socket:
	cmp	ebx,[g_prev_lsocks+r12*4]
	jae	.old_done
	mov	eax,r12d
	imul	eax,eax,MAX_WORKERS
	add	eax,ebx
	cmp	byte [g_taken+rax],0
	jne	.kept
	mov	ecx,[g_prev_lfd+rax*4]
	mov	edx,[g_close_count]
	mov	[g_close_fd+rdx*4],ecx
	inc	dword [g_close_count]
	jmp	.old_next
.kept:
	inc	r14d
.old_next:
	inc	ebx
	jmp	.old_socket
.old_done:
	test	r14d,r14d
	jnz	@f
	; its text is in the previous arena set, still intact
	call	log_begin
	out_lit 'stopped listening on '
	imul	rax,r12,LS_SIZE
	mov	rsi,[g_plan_save+PLAN_SAVE_LISTENERS+rax+LS_TEXT]
	mov	edx,[g_plan_save+PLAN_SAVE_LISTENERS+rax+LS_TLEN]
	call	out_str
	out_lit ' (open connections finish first)'
	call	log_end
@@:
	inc	r12d
	jmp	.old
.ok:
	mov	dword [g_reloading],0
	xor	eax,eax
	jmp	.out
.failed:
	; close what this reload opened; the old plan comes back
	xor	ebx,ebx
@@:
	cmp	ebx,[g_new_count]
	jae	@f
	mov	edi,[g_new_fd+rbx*4]
	mov	eax,SYS_close
	syscall
	inc	ebx
	jmp	@b
@@:
	lea	rdi,[g_lfd]
	lea	rsi,[g_prev_lfd]
	imul	ecx,[g_prev_nls],MAX_WORKERS * 4
	rep	movsb
	lea	rdi,[g_lsocks]
	lea	rsi,[g_prev_lsocks]
	imul	ecx,[g_prev_nls],4
	rep	movsb
	mov	dword [g_reloading],0
	mov	eax,1
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = new listener. eax = the old listener with the same address, or
; -1. The old plan is in g_plan_save (first regions: counters, then the
; listener table).
previous_listener:
	push	rbx
	push	r12
	imul	r12,rdi,LS_SIZE
	lea	r12,[g_listeners+r12]
	xor	ebx,ebx
.next:
	cmp	ebx,[g_prev_nls]
	jae	.none
	imul	rsi,rbx,LS_SIZE
	lea	rsi,[g_plan_save+PLAN_SAVE_LISTENERS+rsi]
	mov	eax,[rsi+LS_FAMILY]
	cmp	eax,[r12+LS_FAMILY]
	jne	.skip
	mov	eax,[rsi+LS_KIND]		; (tcp and http are the same socket)
	xor	eax,[r12+LS_KIND]
	cmp	eax,LK_UDP
	jae	.skip
	mov	edx,[rsi+LS_SALEN]
	cmp	edx,[r12+LS_SALEN]
	jne	.skip
	lea	rdi,[r12+LS_SA]
	call	mem_eq
	test	eax,eax
	jnz	.found
.skip:
	inc	ebx
	jmp	.next
.found:
	mov	eax,ebx
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r12
	pop	rbx
	ret

; The running workers become the old generation: they stop accepting at
; once (SIGUSR1) and finish their sessions within their drain timeout.
retire_workers:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_workers]
	jae	.done
	mov	edi,[g_worker_pid+rbx*4]
	test	edi,edi
	jz	.skip
	mov	dword [g_worker_pid+rbx*4],0
	mov	ecx,[g_old_count]
	cmp	ecx,MAX_OLD
	jae	.kill
	mov	[g_old_pid+rcx*4],edi
	inc	dword [g_old_count]
	dec	dword [g_alive]
	mov	esi,SIGUSR1
	mov	eax,SYS_kill
	syscall
	jmp	.skip
.kill:
	dec	dword [g_alive]
	mov	esi,SIGKILL			; too many generations at once
	mov	eax,SYS_kill
	syscall
.skip:
	inc	ebx
	jmp	.next
.done:
	; stragglers are killed after the drain timeout and a margin
	call	monotonic_seconds
	mov	rcx,rax
	mov	rax,[g_plan_save+PLAN_SAVE_DRAIN_TIMEOUT]	; old drain timeout (us)
	xor	edx,edx
	mov	r8d,1000000
	div	r8
	add	rax,rcx
	add	rax,5
	mov	[g_old_deadline],rax
	pop	rbx
	ret

; edi = pid that exited: an old worker? CF when it was one.
reap_old:
	xor	ecx,ecx
.next:
	cmp	ecx,[g_old_count]
	jae	.no
	cmp	[g_old_pid+rcx*4],edi
	je	.found
	inc	ecx
	jmp	.next
.found:
	; keep the list dense
	mov	edx,[g_old_count]
	dec	edx
	mov	[g_old_count],edx
	mov	eax,[g_old_pid+rdx*4]
	mov	[g_old_pid+rcx*4],eax
	test	edx,edx
	jnz	.yes
	call	close_retired
.yes:
	stc
	ret
.no:
	clc
	ret

; Close sockets of removed addresses: the last old worker is gone.
close_retired:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_close_count]
	jae	.done
	mov	edi,[g_close_fd+rbx*4]
	mov	eax,SYS_close
	syscall
	inc	ebx
	jmp	.next
.done:
	mov	dword [g_close_count],0
	pop	rbx
	ret

; Watchdog tick: old workers past their deadline are killed.
old_workers_check:
	cmp	dword [g_old_count],0
	je	.done
	call	monotonic_seconds
	cmp	rax,[g_old_deadline]
	jb	.done
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_old_count]
	jae	.killed
	mov	edi,[g_old_pid+rbx*4]
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
	inc	ebx
	jmp	.next
.killed:
	mov	qword [g_old_deadline],-1
	pop	rbx
.done:
	ret
