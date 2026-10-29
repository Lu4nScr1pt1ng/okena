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

MAX_OLD		= MAX_WORKERS * 4

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
	action g_plan_workers, 4
	action g_plan_engine, 4
	action g_plan_drain_delay, 8
	action g_plan_drain_timeout, 8
	action g_plan_watchdog, 8
	action g_plan_busy_poll, 8
	action g_plan_health, 4
	action g_plan_metrics, 4
	action g_plan_metrics_salen, 4
	action g_plan_metrics_text, 8
	action g_plan_metrics_tlen, 4
	action g_plan_metrics_sa, 28
	action g_listeners, LS_SIZE * MAX_LISTENERS
	action g_pools, PL_SIZE * MAX_POOLS
	action g_servers, SV_SIZE * MAX_SERVERS
	action g_groups, GR_SIZE * MAX_GROUPS
	action g_plan_routes, 4
	action g_routes, RT_SIZE * MAX_ROUTES
end macro

PLAN_SAVE_SIZE = 0
; offsets of the regions read back from the snapshot
macro plan_size_of sym, size
	match =g_listeners, sym
		PLAN_SAVE_LISTENERS = PLAN_SAVE_SIZE
	end match
	match =g_plan_drain_timeout, sym
		PLAN_SAVE_DRAIN_TIMEOUT = PLAN_SAVE_SIZE
	end match
	PLAN_SAVE_SIZE = PLAN_SAVE_SIZE + size
end macro
plan_regions plan_size_of

bss
	align 8
	g_plan_save:	rb PLAN_SAVE_SIZE
end bss

macro plan_copy_out sym, size
	lea	rsi,[sym]
	mov	ecx,size
	rep	movsb
end macro

macro plan_copy_in sym, size
	lea	rdi,[sym]
	mov	ecx,size
	rep	movsb
end macro

plan_save:
	lea	rdi,[g_plan_save]
	plan_regions plan_copy_out
	ret

plan_restore:
	lea	rsi,[g_plan_save]
	plan_regions plan_copy_in
	ret

macro plan_zero sym, size
	lea	rdi,[sym]
	mov	ecx,size
	rep	stosb
end macro

; Empty plan, as before the first compile.
plan_reset:
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
	push	rbx
	lea	rbx,[g_ar_nodes]
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
	mov	ecx,MAX_LISTENERS * MAX_WORKERS * 4
	rep	movsb
	lea	rdi,[g_prev_lsocks]
	lea	rsi,[g_lsocks]
	mov	ecx,MAX_LISTENERS * 4
	rep	movsb
	call	arenas_swap
	call	arenas_empty
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
	; commit
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
	call	dns_table_init			; a new table: the old workers keep theirs
	call	groups_resolve_all
	call	spawn_control
	mov	edi,[g_health_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_health_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	health_table_init
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
	mov	edi,SG_RELOADS
	call	stats_global_inc
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
	seccomp_for filter_compiler		; the parser runs boxed in
	call	cfg_parse_checked
	call	plan_reset
	call	plan_compile
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
	call	log_end
	jmp	.undo_arenas
.fork_failed:
	call	log_begin
	out_lit 'reload failed: fork failed; keeping the running configuration'
	call	log_end
	jmp	.undo_arenas
.child_crashed:
	call	log_begin
	out_lit 'reload failed: the configuration compiler crashed (signal '
	mov	eax,[g_siginfo+SI_STATUS]
	call	out_u64
	out_lit '); keeping the running configuration'
	call	log_end
	jmp	.undo_arenas
.rejected:
	call	log_begin
	out_lit 'reload rejected (errors above); keeping the running configuration'
	call	log_end
	jmp	.undo_arenas
.sockets_failed:
	call	log_begin
	out_lit 'reload rejected (cannot listen, see above); keeping the running configuration'
	call	log_end
	call	plan_restore
.undo_arenas:
	call	arenas_swap
	mov	edi,SG_RELOAD_FAILS
	call	stats_global_inc
.out:
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
	mov	ecx,MAX_LISTENERS * MAX_WORKERS
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
	mov	ecx,MAX_LISTENERS * MAX_WORKERS * 4
	rep	movsb
	lea	rdi,[g_lsocks]
	lea	rsi,[g_prev_lsocks]
	mov	ecx,MAX_LISTENERS * 4
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
