; Addons in the supervisor: the shared memory of each addon, the eventfds that
; wake workers, and the launcher that runs the programs.
;
; execve is forbidden in every okena process (seccomp.inc), so the addons are
; started by a process forked before the supervisor's filter: the launcher
; (launcher.inc). It only forks, runs and reaps the programs it is told about,
; over a socket pair; it reads nothing else. The supervisor makes what an
; addon shares with the workers (a memfd, its bell) before the workers fork,
; and hands the descriptors to the launcher.
;
; Across a reload an addon whose name and run line are the same keeps its
; process and its memory; the old workers go on calling the process they knew
; until they are gone, then an addon the new plan dropped is stopped.

MAX_ADRT	:= 64				; addon processes, the live and the retiring
AD_MAXW		:= 4096				; worker slots
AD_READY_WAIT	:= 5000				; ms okena waits for a new addon to serve
AD_LAUNCH_FDS	:= 240

; a process (g_adrt)
ADPR_USED	:= 0				; d: 0 free, 1 the plan's, 2 the plan dropped it
ADPR_MEMFD	:= 4				; d
ADPR_BELL	:= 8				; d
ADPR_NEW		:= 12				; d: started by this sync: waited for
ADPR_BASE	:= 16				; q
ADPR_LEN		:= 24				; q
ADPR_HASH	:= 32				; q
ADPR_SIZE	:= 40

; a message to the launcher
ALM_OP		:= 0				; d: ALMO_*
ALM_ID		:= 4				; d: the process (g_adrt's index)
ALM_FIRST	:= 8				; d: ALMO_WAKE: the first slot
ALM_COUNT	:= 12				; d: and how many
ALM_ARGC		:= 16				; d
ALM_BLEN		:= 20				; d
ALM_NAME		:= 24				; 64
ALM_BLOB		:= 88				; run's words, each NUL-terminated
ALM_BLOB_MAX	:= 4096
ALM_SIZE		:= ALM_BLOB + ALM_BLOB_MAX
ALMO_WAKE	:= 1				; descriptors: worker slots' eventfds
ALMO_START	:= 2				; descriptors: the memfd, the bell
ALMO_STOP	:= 3

SYS_memfd_create_ := 319
SYS_eventfd2_	:= 290
SYS_munmap_	:= 11
MFD_CLOEXEC_	:= 1
EFD_CLOEXEC_	:= 0x80000
AF_UNIX_	:= 1
SOCK_CLOEXEC_	:= 0x80000

bss
	align 8
	g_adrt:		rb ADPR_SIZE * MAX_ADRT
	g_ad_claim	dq ?			; worker slots: the pid holding each (shared)
	g_ad_nrw	dd ?			; worker slots, 0 until the first addon
	g_ad_lsock	dd ?			; the launcher's socket
	g_ad_lpid	dd ?
	g_ad_lever	dd ?			; it was started
	g_ad_next	dd ?			; where to look for a free process entry
	g_ad_wake	rd AD_MAXW
	align 8
	g_ad_msg	rq 7
	g_ad_iov	rq 2
	g_ad_cmsg:	rb 16 + 4 * AD_LAUNCH_FDS + 8
	align 8
	g_ad_lm:	rb ALM_SIZE
end bss

rodata
	launcher_name	db 'okena-addons',0
	ad_memfd_name	db 'okena-addon',0
end rodata

; supervisor, before its filter: the launcher, waiting for work, when the
; configuration has addons (a helper process exists only when it is needed).
; It is okena again, run anew (/proc/self/exe), so that it holds none of the
; supervisor's memory; where that cannot be, the forked copy serves.
addon_launcher_spawn:
	cmp	dword [g_plan_addons],0
	je	.none
	sub	rsp,16
	mov	edi,AF_UNIX_
	mov	esi,SOCK_SEQPACKET_ or SOCK_CLOEXEC_
	xor	edx,edx
	mov	r10,rsp
	mov	eax,SYS_socketpair
	syscall
	test	eax,eax
	js	.failed
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	js	.failed
	jnz	.parent
	mov	edi,[rsp]
	mov	eax,SYS_close
	syscall
	mov	edi,[rsp+4]
	call	ln_exec				; returns only when it could not
	mov	edi,[rsp+4]
	jmp	launcher_main
.parent:
	mov	[g_ad_lpid],eax
	mov	dword [g_ad_lever],1
	mov	edi,[rsp+4]
	mov	eax,SYS_close
	syscall
	mov	eax,[rsp]
	mov	[g_ad_lsock],eax
	add	rsp,16
.none:
	ret
.failed:
	add	rsp,16
	call	log_begin
	out_lit 'cannot start the addon launcher: addons cannot run'
	call	log_end
	ret

; a reload, its plan compiled: CF when it has addons and okena started with
; none (no launcher: it can only be made before the supervisor's filter)
addon_reload_ok:
	cmp	dword [g_plan_addons],0
	je	.ok
	cmp	dword [g_ad_lever],0
	jne	.ok
	call	log_begin
	out_lit 'reload rejected: okena started with no addon, and can only run them when it starts with one (okena upgrade starts it again with no connection lost)'
	mov	edi,AL_RELOAD
	call	log_end_alert
	stc
	ret
.ok:
	clc
	ret

; supervisor, the plan just compiled (at the start and on each reload, before
; workers fork): each addon of the plan has its process; those the plan
; dropped are marked to go once no worker that knew them is left.
addon_sync:
	push	rbx
	push	r12
	push	r13
	; all dropped, unless the plan keeps them
	xor	ebx,ebx
.mark:
	imul	rax,rbx,ADPR_SIZE
	mov	dword [g_adrt+rax+ADPR_NEW],0
	cmp	dword [g_adrt+rax+ADPR_USED],1
	jne	@f
	mov	dword [g_adrt+rax+ADPR_USED],2
@@:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.mark
	cmp	dword [g_plan_addons],0
	je	.done
	cmp	dword [g_ad_lpid],0
	je	.no_launcher
	call	ad_wake_make
	jc	.done
	xor	r12d,r12d
.addon:
	cmp	r12d,[g_plan_addons]
	jae	.done
	imul	r13,r12,ADE_SIZE
	lea	r13,[g_addons+r13]
	; the same process?
	mov	rax,[r13+ADE_HASH]
	xor	ebx,ebx
.same:
	imul	rcx,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rcx+ADPR_USED],0
	je	.other
	cmp	[g_adrt+rcx+ADPR_HASH],rax
	je	.found
.other:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.same
	call	ad_start			; ebx = it, or -1
	cmp	ebx,-1
	je	.next
	jmp	.slot
.found:
	mov	dword [g_adrt+rcx+ADPR_USED],1
.slot:
	mov	[r13+ADE_SLOT],ebx
	imul	rcx,rbx,ADPR_SIZE
	mov	rdx,[g_adrt+rcx+ADPR_BASE]
	mov	rax,[r13+ADE_TIMEOUT]
	mov	[rdx+ADH_TIMEOUT],rax
	mov	eax,[r13+ADE_PHASES]
	mov	[rdx+ADH_PHASES],eax
	mov	eax,[r13+ADE_POLL]
	mov	[rdx+ADH_POLL],eax
	mov	[rdx+ADH_INDEX],r12d
.next:
	inc	r12d
	jmp	.addon
.no_launcher:
	call	log_begin
	out_lit 'the addon launcher is gone: addons cannot be started until okena restarts'
	call	log_end
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; the worker slots' eventfds and the table of who holds each, once: CF when
; they cannot be made
ad_wake_make:
	cmp	dword [g_ad_nrw],0
	jne	.made
	push	rbx
	mov	eax,[g_workers]
	imul	eax,eax,3
	add	eax,2
	cmp	eax,AD_MAXW
	jbe	@f
	mov	eax,AD_MAXW
@@:
	mov	ebx,eax
	xor	edi,edi
	lea	rsi,[rbx*4+4095]
	and	rsi,not 4095
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.failed
	mov	[g_ad_claim],rax
	xor	ecx,ecx
.fd:
	cmp	ecx,ebx
	jae	.fds
	push	rcx
	xor	edi,edi
	mov	esi,EFD_CLOEXEC_
	mov	eax,SYS_eventfd2_
	syscall
	pop	rcx
	test	eax,eax
	js	.failed
	mov	[g_ad_wake+rcx*4],eax
	inc	ecx
	jmp	.fd
.fds:
	mov	[g_ad_nrw],ebx
	; to the launcher, AD_LAUNCH_FDS at a time
	xor	ecx,ecx
.send:
	cmp	ecx,ebx
	jae	.sent
	mov	edx,ebx
	sub	edx,ecx
	cmp	edx,AD_LAUNCH_FDS
	jbe	@f
	mov	edx,AD_LAUNCH_FDS
@@:
	push	rcx
	push	rdx
	lea	rdi,[g_ad_lm]
	mov	dword [rdi+ALM_OP],ALMO_WAKE
	mov	[rdi+ALM_FIRST],ecx
	mov	[rdi+ALM_COUNT],edx
	lea	r8,[g_ad_wake+rcx*4]
	mov	ecx,edx
	mov	esi,ALM_NAME
	call	ad_send
	pop	rdx
	pop	rcx
	add	ecx,edx
	jmp	.send
.sent:
	pop	rbx
.made:
	clc
	ret
.failed:
	pop	rbx
	call	log_begin
	out_lit 'addons: cannot make their eventfds or shared pages'
	call	log_end
	stc
	ret

; r13 = a plan addon: its memory, its bell, and the launcher told to run it.
; ebx = its process entry, or -1.
ad_start:
	; a free entry, looked for from after the last one taken
	mov	ecx,MAX_ADRT
	mov	ebx,[g_ad_next]
.free:
	cmp	ebx,MAX_ADRT
	jb	@f
	xor	ebx,ebx
@@:
	imul	rax,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rax+ADPR_USED],0
	je	.take
	inc	ebx
	dec	ecx
	jnz	.free
	call	log_begin
	out_lit 'addons: too many processes at once (reload less often)'
	call	log_end
	mov	ebx,-1
	ret
.take:
	lea	eax,[rbx+1]
	mov	[g_ad_next],eax
	push	r12
	push	r14
	imul	r14,rbx,ADPR_SIZE
	lea	r14,[g_adrt+r14]
	lea	rdi,[ad_memfd_name]
	mov	esi,MFD_CLOEXEC_
	mov	eax,SYS_memfd_create_
	syscall
	test	eax,eax
	js	.failed
	mov	[r14+ADPR_MEMFD],eax
	mov	eax,[g_ad_nrw]
	imul	rax,rax,AD_STRIDE
	add	rax,AD_HDR
	mov	[r14+ADPR_LEN],rax
	mov	edi,[r14+ADPR_MEMFD]
	mov	rsi,rax
	mov	eax,SYS_ftruncate
	syscall
	test	eax,eax
	js	.failed_fd
	xor	edi,edi
	mov	rsi,[r14+ADPR_LEN]
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_NORESERVE
	mov	r8d,[r14+ADPR_MEMFD]
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.failed_fd
	mov	[r14+ADPR_BASE],rax
	mov	r12,rax
	xor	edi,edi
	mov	esi,EFD_CLOEXEC_
	mov	eax,SYS_eventfd2_
	syscall
	test	eax,eax
	js	.failed_map
	mov	[r14+ADPR_BELL],eax
	; the header
	mov	rax,AD_MAGIC
	mov	[r12+ADH_MAGIC],rax
	mov	dword [r12+ADH_VERSION],AD_VERSION
	mov	eax,[g_ad_nrw]
	mov	[r12+ADH_NRINGS],eax
	mov	dword [r12+ADH_RBYTES],AD_RING
	mov	dword [r12+ADH_HBYTES],AD_HDR
	mov	qword [r12+ADH_STRIDE],AD_STRIDE
	mov	dword [r12+ADH_BELL],4		; (where the launcher puts them)
	mov	dword [r12+ADH_WAKE0],5
	mov	dword [r12+ADH_SLEEP],1
	mov	dword [r12+ADH_MAXHEAD],H_IN_CAP
	lea	rdi,[r12+ADH_NAME]
	mov	rsi,[r13+ADE_NAME]
	mov	ecx,[r13+ADE_NLEN]
	rep	movsb
	mov	byte [rdi],0
	mov	rax,[r13+ADE_HASH]
	mov	[r14+ADPR_HASH],rax
	mov	dword [r14+ADPR_USED],1
	mov	dword [r14+ADPR_NEW],1
	; the launcher: its name, its words
	lea	rdi,[g_ad_lm]
	mov	dword [rdi+ALM_OP],ALMO_START
	mov	[rdi+ALM_ID],ebx
	lea	rdi,[g_ad_lm+ALM_NAME]
	mov	rsi,[r13+ADE_NAME]
	mov	ecx,[r13+ADE_NLEN]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_ad_lm+ALM_BLOB]
	mov	r8,[r13+ADE_ARGS]
	mov	r9d,[r13+ADE_ARGC]
	mov	[g_ad_lm+ALM_ARGC],r9d
.word:
	test	r9d,r9d
	jz	.words
	mov	ecx,[r8+A_VLEN]
	add	ecx,[r8+A_KLEN]
	lea	rax,[rdi+rcx+2]
	lea	rdx,[g_ad_lm+ALM_BLOB+ALM_BLOB_MAX]
	cmp	rax,rdx
	ja	.too_long
	cmp	dword [r8+A_KIND],ARG_KV	; a word with = in it: as it was written
	jne	@f
	mov	rsi,[r8+A_KEY]
	mov	ecx,[r8+A_KLEN]
	rep	movsb
	mov	byte [rdi],'='
	inc	rdi
@@:
	mov	ecx,[r8+A_VLEN]
	mov	rsi,[r8+A_VAL]
	rep	movsb
	mov	byte [rdi],0
	inc	rdi
	add	r8,A_SIZE
	dec	r9d
	jmp	.word
.words:
	lea	rax,[g_ad_lm+ALM_BLOB]
	sub	rdi,rax
	mov	[g_ad_lm+ALM_BLEN],edi
	lea	esi,[rdi+ALM_BLOB]
	sub	rsp,8
	mov	eax,[r14+ADPR_MEMFD]
	mov	[rsp],eax
	mov	eax,[r14+ADPR_BELL]
	mov	[rsp+4],eax
	mov	r8,rsp
	mov	ecx,2
	lea	rdi,[g_ad_lm]
	call	ad_send
	add	rsp,8
	pop	r14
	pop	r12
	ret
.too_long:
	call	log_begin
	out_lit 'addon: its run line is longer than 4096 bytes'
	call	log_end
	jmp	.undo
.failed_map:
	mov	rdi,[r14+ADPR_BASE]
	mov	rsi,[r14+ADPR_LEN]
	mov	eax,SYS_munmap_
	syscall
.failed_fd:
	mov	edi,[r14+ADPR_MEMFD]
	mov	eax,SYS_close
	syscall
.failed:
	call	log_begin
	out_lit 'addon: cannot make its shared memory'
	call	log_end
	mov	dword [r14+ADPR_USED],0
	mov	ebx,-1
	pop	r14
	pop	r12
	ret
.undo:
	mov	dword [r14+ADPR_USED],2		; (made: it goes like a dropped one)
	mov	ebx,-1
	pop	r14
	pop	r12
	ret

; rdi = a message, esi = its length, r8 = descriptors, ecx = how many
ad_send:
	mov	[g_ad_iov],rdi
	mov	[g_ad_iov+8],rsi
	lea	rax,[g_ad_iov]
	xor	edx,edx
	mov	[g_ad_msg],rdx
	mov	[g_ad_msg+8],rdx
	mov	[g_ad_msg+16],rax
	mov	qword [g_ad_msg+24],1
	mov	[g_ad_msg+32],rdx
	mov	[g_ad_msg+40],rdx
	mov	[g_ad_msg+48],rdx
	test	ecx,ecx
	jz	.send
	mov	eax,ecx
	shl	eax,2
	add	eax,16
	mov	[g_ad_cmsg],rax
	mov	dword [g_ad_cmsg+8],SOL_SOCKET
	mov	dword [g_ad_cmsg+12],SCM_RIGHTS_
	mov	rsi,r8
	lea	rdi,[g_ad_cmsg+16]
	rep	movsd
	lea	rcx,[g_ad_cmsg]
	mov	[g_ad_msg+32],rcx
	add	rax,7
	and	rax,not 7
	mov	[g_ad_msg+40],rax
.send:
	mov	edi,[g_ad_lsock]
	lea	rsi,[g_ad_msg]
	xor	edx,edx
	mov	eax,SYS_sendmsg_
	syscall
	ret

; supervisor, after addon_sync: the addons it started serve, or AD_READY_WAIT
; passes (or they exit: those follow on_error meanwhile)
addon_wait_ready:
	push	rbx
	push	r12
	xor	r12d,r12d			; ms waited
.again:
	xor	ebx,ebx
	xor	ecx,ecx				; still waited for
.each:
	imul	rax,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rax+ADPR_NEW],0
	je	.next
	mov	rdx,[g_adrt+rax+ADPR_BASE]
	cmp	dword [rdx+ADH_READY],1
	je	.ready
	cmp	dword [rdx+ADH_EPOCH],2		; it ran and exited
	jae	.ready
	inc	ecx
	jmp	.next
.ready:
	mov	dword [g_adrt+rax+ADPR_NEW],0
.next:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.each
	test	ecx,ecx
	jz	.done
	cmp	r12d,AD_READY_WAIT
	jae	.late
	lea	rdi,[.tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	r12d,5
	jmp	.again
.late:
	xor	ebx,ebx
.say:
	imul	rax,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rax+ADPR_NEW],0
	je	.said
	mov	dword [g_adrt+rax+ADPR_NEW],0
	mov	r8,[g_adrt+rax+ADPR_BASE]
	call	log_begin
	out_lit 'addon '
	lea	rsi,[r8+ADH_NAME]
	call	out_cstr
	out_lit ' is not ready yet: its routes follow on_error until it is'
	call	log_end
.said:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.say
.done:
	pop	r12
	pop	rbx
	ret
.tick	dq 0, 5000000

; supervisor, a child gone (edi = its pid): the worker slot it held is free.
; CF when it was the launcher.
addon_reaped:
	cmp	edi,[g_ad_lpid]
	je	.launcher
	mov	rsi,[g_ad_claim]
	test	rsi,rsi
	jz	.out
	xor	ecx,ecx
.slot:
	cmp	ecx,[g_ad_nrw]
	jae	.out
	cmp	[rsi+rcx*4],edi
	jne	@f
	mov	dword [rsi+rcx*4],0
@@:
	inc	ecx
	jmp	.slot
.out:
	clc
	ret
.launcher:
	mov	dword [g_ad_lpid],0
	push	rbx
	call	log_begin
	out_lit 'the addon launcher exited: addons cannot be started again until okena restarts'
	call	log_end
	xor	ebx,ebx
.dead:
	imul	rax,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rax+ADPR_USED],0
	je	@f
	mov	rdx,[g_adrt+rax+ADPR_BASE]
	mov	dword [rdx+ADH_READY],0
	lock inc dword [rdx+ADH_EPOCH]
@@:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.dead
	pop	rbx
	stc
	ret

; supervisor, once a second: addons a reload dropped go once no old worker is left
addon_tick:
	cmp	dword [g_old_count],0
	jne	.out
	push	rbx
	xor	ebx,ebx
.each:
	imul	rax,rbx,ADPR_SIZE
	cmp	dword [g_adrt+rax+ADPR_USED],2
	jne	.next
	push	rax
	lea	rdi,[g_ad_lm]
	mov	dword [rdi+ALM_OP],ALMO_STOP
	mov	[rdi+ALM_ID],ebx
	mov	esi,ALM_NAME
	xor	ecx,ecx
	call	ad_send
	pop	rax
	lea	rax,[g_adrt+rax]
	push	rax
	mov	rdi,[rax+ADPR_BASE]
	mov	rsi,[rax+ADPR_LEN]
	mov	eax,SYS_munmap_
	syscall
	mov	rax,[rsp]
	mov	edi,[rax+ADPR_MEMFD]
	mov	eax,SYS_close
	syscall
	mov	rax,[rsp]
	mov	edi,[rax+ADPR_BELL]
	mov	eax,SYS_close
	syscall
	pop	rax
	mov	dword [rax+ADPR_USED],0
	mov	qword [rax+ADPR_HASH],0
.next:
	inc	ebx
	cmp	ebx,MAX_ADRT
	jb	.each
	pop	rbx
.out:
	ret

; admin, /metrics: each addon's counters, summed over the worker slots (each
; slot's are written by the worker holding it), and whether it serves
addon_metrics:
	cmp	dword [g_plan_addons],0
	je	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	memit '# HELP okena_addon_calls_total Calls to an addon, by what came of them: answered, timeout (no answer in time), crashed (the addon exited first), error (not asked: not ready, concurrency, circuit open; or a bad answer).',10
	memit '# TYPE okena_addon_calls_total counter',10
	lea	r14,[.results]
	call	.each
	memit '# HELP okena_addon_on_error_total Requests that went on (allow) or were refused (deny) for want of an answer.',10
	memit '# TYPE okena_addon_on_error_total counter',10
	lea	r14,[.onerr]
	call	.each
	memit '# HELP okena_addon_responses_total Requests the addon answered itself.',10
	memit '# TYPE okena_addon_responses_total counter',10
	lea	r14,[.resp]
	call	.each
	memit '# HELP okena_addon_circuit_opened_total Times a worker stopped asking an addon after failures in a row.',10
	memit '# TYPE okena_addon_circuit_opened_total counter',10
	lea	r14,[.opened]
	call	.each
	memit '# HELP okena_addon_call_seconds Round trip of answered calls, from posting the call to taking its answer.',10
	memit '# TYPE okena_addon_call_seconds histogram',10
	xor	ebx,ebx
.h:
	cmp	ebx,[g_plan_addons]
	jae	.h_done
	call	.base
	test	r12,r12
	jz	.h_next
	xor	r13d,r13d			; bucket
	xor	r14d,r14d			; cumulative
.hb:
	mov	ecx,r13d
	lea	r8,[r12+AD_HDR+ADR_HIST+rcx*8]
	call	.slots
	add	r14,rax
	memit 'okena_addon_call_seconds_bucket{addon="'
	call	.name
	memit '",le="'
	cmp	r13d,AD_NB - 1
	jae	.inf
	mov	rax,[ad_hbounds+r13*8]
	call	.seconds
	jmp	.le
.inf:
	memit '+Inf'
.le:
	memit '"} '
	mov	rax,r14
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	inc	r13d
	cmp	r13d,AD_NB
	jb	.hb
	memit 'okena_addon_call_seconds_sum{addon="'
	call	.name
	memit '"} '
	lea	r8,[r12+AD_HDR+ADR_COUNT+ADC_HSUM]
	call	.slots
	call	.seconds
	mov	byte [rdi],10
	inc	rdi
	memit 'okena_addon_call_seconds_count{addon="'
	call	.name
	memit '"} '
	mov	rax,r14
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.h_next:
	inc	ebx
	jmp	.h
.h_done:
	memit '# HELP okena_addon_starts_total Times the addon was started (restarts are this less one).',10
	memit '# TYPE okena_addon_starts_total counter',10
	xor	ebx,ebx
.s:
	cmp	ebx,[g_plan_addons]
	jae	.s_done
	call	.base
	test	r12,r12
	jz	.s_next
	memit 'okena_addon_starts_total{addon="'
	call	.name
	memit '"} '
	mov	eax,[r12+ADH_EPOCH]
	inc	eax
	shr	eax,1
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.s_next:
	inc	ebx
	jmp	.s
.s_done:
	memit '# HELP okena_addon_up Whether the addon serves (it said it is ready).',10
	memit '# TYPE okena_addon_up gauge',10
	xor	ebx,ebx
.u:
	cmp	ebx,[g_plan_addons]
	jae	.u_done
	call	.base
	test	r12,r12
	jz	.u_next
	memit 'okena_addon_up{addon="'
	call	.name
	memit '"} '
	mov	eax,[r12+ADH_READY]
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
.u_next:
	inc	ebx
	jmp	.u
.u_done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
; r14 = a list (counter offset, label text; 0 ends it): a line for each addon
; and entry
.each:
	xor	ebx,ebx
.e_addon:
	cmp	ebx,[g_plan_addons]
	jae	.e_done
	call	.base
	test	r12,r12
	jz	.e_next
	mov	r13,r14
.e_item:
	cmp	qword [r13],-1
	je	.e_next
	mov	rsi,[r13+8]
	call	fmt_cstr
	call	.name
	mov	rsi,[r13+16]
	call	fmt_cstr
	; the sum over the slots
	xor	eax,eax
	xor	ecx,ecx
	mov	rdx,[r13]
	lea	r8,[r12+AD_HDR+ADR_COUNT+rdx]
.sum:
	cmp	ecx,[g_ad_nrw]
	jae	.summed
	add	rax,[r8]
	add	r8,AD_STRIDE
	inc	ecx
	jmp	.sum
.summed:
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	add	r13,24
	jmp	.e_item
.e_next:
	inc	ebx
	jmp	.e_addon
.e_done:
	ret
; r8 = a counter in ring pair 0: rax = its sum over the slots
.slots:
	xor	eax,eax
	xor	ecx,ecx
.sl:
	cmp	ecx,[g_ad_nrw]
	jae	.sl_done
	add	rax,[r8]
	add	r8,AD_STRIDE
	inc	ecx
	jmp	.sl
.sl_done:
	ret
; rax = ns: written as seconds (up to 9 decimals, trailing zeros dropped)
.seconds:
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	push	rdx
	call	fmt_u64
	pop	rax
	test	rax,rax
	jz	.s_out
	mov	byte [rdi],'.'
	inc	rdi
	mov	r8,100000000
.digit:
	xor	edx,edx
	div	r8
	add	al,'0'
	mov	[rdi],al
	inc	rdi
	mov	rax,rdx
	test	rax,rax
	jz	.s_out
	push	rax
	mov	rax,r8
	xor	edx,edx
	mov	r8d,10
	div	r8
	mov	r8,rax
	pop	rax
	test	r8,r8
	jnz	.digit
.s_out:
	ret
; ebx = an addon: r12 = its memory, 0 when it has none
.base:
	xor	r12d,r12d
	imul	rax,rbx,ADE_SIZE
	mov	eax,[g_addons+rax+ADE_SLOT]
	cmp	eax,-1
	je	.b_out
	imul	rax,rax,ADPR_SIZE
	mov	r12,[g_adrt+rax+ADPR_BASE]
.b_out:
	ret
.name:
	imul	rax,rbx,ADE_SIZE
	mov	rsi,[g_addons+rax+ADE_NAME]
	mov	edx,[g_addons+rax+ADE_NLEN]
	jmp	fmt_label
.results:
	dq ADC_OK, .m_calls, .r_answered
	dq ADC_TIMEOUT, .m_calls, .r_timeout
	dq ADC_CRASHED, .m_calls, .r_crashed
	dq ADC_ERROR, .m_calls, .r_error
	dq -1
.onerr:
	dq ADC_ALLOWED, .m_onerr, .a_allow
	dq ADC_DENIED, .m_onerr, .a_deny
	dq -1
.resp:
	dq ADC_RESPOND, .m_resp, .close
	dq -1
.opened:
	dq ADC_OPENED, .m_opened, .close
	dq -1
.m_calls	db 'okena_addon_calls_total{addon="',0
.m_onerr	db 'okena_addon_on_error_total{addon="',0
.m_resp		db 'okena_addon_responses_total{addon="',0
.m_opened	db 'okena_addon_circuit_opened_total{addon="',0
.r_answered	db '",result="answered"} ',0
.r_timeout	db '",result="timeout"} ',0
.r_crashed	db '",result="crashed"} ',0
.r_error	db '",result="error"} ',0
.a_allow	db '",action="allow"} ',0
.a_deny		db '",action="deny"} ',0
.close		db '"} ',0
