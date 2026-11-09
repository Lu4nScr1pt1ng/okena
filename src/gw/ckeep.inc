; The cache keeper: a process of its own, while `cache_disk` is on, that makes room in
; the store ahead of the writers, S3-FIFO (cdisk.inc says how). Workers only ever
; write into room it made; when there is none, an answer is not kept on disk, and
; nobody waits.
;
; One keeper works at a time, on any number of okena processes sharing a store (an
; upgrade): CH_KEEPER holds its pid, taken with a compare-and-swap from 0 or from
; one that is gone; the others look again every 100 ms. A segment is reclaimed in
; steps that survive the keeper dying between any two: marked (no new pins), its
; records dealt with (moved: copied, then the slot pointed at the copy, if it still
; pointed at the original; a keeper that starts over finds the slot moved already),
; then, once nobody pins it, handed over with its new generation.
;
; It joins the store like a worker, so that the last one out, whoever it is, writes
; it down and marks it clean; on SIGTERM it leaves at once (the supervisor waits).

CK_IDLE_NS	:= 50000000			; nothing to do: asleep until woken, 50 ms at most
CK_WAIT_NS	:= 100000000			; another keeper at work: every 100 ms
SYS_pwrite64	:= 18
SYS_copy_file_range := 326
SYS_rt_sigtimedwait := 128

bss
	align 8
	g_keeper_pid	dd ?			; supervisor: the keeper, 0 none
	g_keeper_old	dd ?			; one told to go (a reload), still going
	g_ck_me		dd ?			; keeper: its pid
	g_ck_seen	dd ?			; CH_WAKE when it last looked
	g_ck_walked	rq 2			; per log: the generation (+ 1) whose records were dealt with
	g_ck_ts		rq 2
	g_ck_set	dq ?
	g_ck_hdr:	rb CD_RH
	g_ck_src	dq ?
	g_ck_dst	dq ?
end bss

rodata
	keeper_name	db 'okena-cache',0
end rodata

; supervisor: the keeper, when there is a store
spawn_keeper:
	cmp	dword [g_plan_cdplen],0
	je	.none
	cmp	dword [g_plan_caches],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	keeper_main
	js	.none
	mov	[g_keeper_pid],eax
.none:
	ret

; supervisor, a reload: the keeper goes (it leaves the store whole), a new one comes
; for the new plan and works once the old one is gone
keeper_reload:
	mov	edi,[g_keeper_pid]
	test	edi,edi
	jz	spawn_keeper
	mov	[g_keeper_old],edi
	mov	dword [g_keeper_pid],0
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	jmp	spawn_keeper

; supervisor, stopping: the keeper leaves, and is waited for (5 s at most)
keeper_finish:
	mov	edi,[g_keeper_pid]
	test	edi,edi
	jz	.none
	push	rbx
	mov	ebx,edi
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	mov	ecx,500
.wait:
	push	rcx
	mov	edi,P_PID
	mov	esi,ebx
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	dword [g_siginfo+SI_PID],0
	mov	eax,SYS_waitid
	syscall
	pop	rcx
	test	rax,rax
	js	.gone
	cmp	dword [g_siginfo+SI_PID],0
	jne	.gone
	push	rcx
	lea	rdi,[.tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	pop	rcx
	dec	ecx
	jnz	.wait
	mov	edi,ebx
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
.gone:
	mov	dword [g_keeper_pid],0
	pop	rbx
.none:
	ret
.tick	dq 0, 10000000

; Never returns.
keeper_main:
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
	lea	rsi,[keeper_name]
	mov	eax,SYS_prctl
	syscall
	mov	qword [g_ck_set],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1))
	mov	eax,SYS_getpid
	syscall
	mov	[g_ck_me],eax
	mov	qword [g_ck_walked],0
	mov	qword [g_ck_walked+8],0
	call	cd_init
	call	priv_drop
	call	ll_confine_none
	seccomp_for filter_keeper
	cmp	dword [g_cd_on],0
	jne	.loop
	; no store: nothing to keep; wait to be told to go
@@:
	mov	qword [g_ck_ts],1
	mov	qword [g_ck_ts+8],0
	call	.sleep
	jmp	@b
.loop:
	call	keeper_own
	jc	.other
	mov	rax,[g_cd_base]
	mov	eax,[rax+CH_WAKE]
	mov	[g_ck_seen],eax			; (a wake after this is not lost)
	call	keeper_step
	test	eax,eax
	jnz	.busy
	; until a writer wakes it
	mov	qword [g_ck_ts],0
	mov	qword [g_ck_ts+8],CK_IDLE_NS
	mov	rdi,[g_cd_base]
	add	rdi,CH_WAKE
	mov	esi,FUTEX_WAIT
	mov	edx,[g_ck_seen]
	lea	r10,[g_ck_ts]
	mov	eax,SYS_futex
	syscall
.busy:
	mov	qword [g_ck_ts],0		; told to go?
	mov	qword [g_ck_ts+8],0
	call	.sleep
	jmp	.loop
.other:
	mov	qword [g_ck_ts],0
	mov	qword [g_ck_ts+8],CK_WAIT_NS
	call	.sleep
	jmp	.loop
; a wait that a SIGTERM ends: then the store is left, whole
.sleep:
	lea	rdi,[g_ck_set]
	xor	esi,esi
	lea	rdx,[g_ck_ts]
	mov	r10d,8
	mov	eax,SYS_rt_sigtimedwait
	syscall
	test	rax,rax
	jle	.slept				; (-EAGAIN: the time passed)
	cmp	dword [g_cd_on],0
	je	.leave
	mov	rcx,[g_cd_base]
	mov	eax,[g_ck_me]
	xor	edx,edx
	lock cmpxchg [rcx+CH_KEEPER],edx	; (if it is this one)
.leave:
	call	cd_leave
	xor	edi,edi
	jmp	exit_process
.slept:
	ret

; CF unless this keeper is the one at work (it becomes so when nobody is, or the one
; that was is gone)
keeper_own:
	mov	rdx,[g_cd_base]
	mov	eax,[rdx+CH_KEEPER]
	cmp	eax,[g_ck_me]
	je	.mine
	test	eax,eax
	jz	.take
	push	rax
	push	rdx
	mov	edi,eax
	xor	esi,esi
	mov	eax,SYS_kill
	syscall
	mov	ecx,eax
	pop	rdx
	pop	rax
	cmp	ecx,-ESRCH
	jne	.not
.take:
	mov	ecx,[g_ck_me]
	lock cmpxchg [rdx+CH_KEEPER],ecx
	jne	.not
	mov	qword [g_ck_walked],0		; (whatever a gone one left half done: again)
	mov	qword [g_ck_walked+8],0
.mine:
	clc
	ret
.not:
	stc
	ret

; eax = 1 when something was done (more may be to do)
keeper_step:
	push	rbx
	push	r12
	xor	r12d,r12d
	xor	ebx,ebx				; S, then M
.log:
	; a whole segment free past the one being written: room for any record
	mov	rdx,[g_cd_base]
	mov	ecx,ebx
	shl	ecx,4
	mov	rsi,[g_cd_seg]
	mov	rax,[rdx+CH_LOGS+rcx]
	lea	rax,[rax+rsi-1]
	mov	r8,rsi
	neg	r8
	and	rax,r8				; the head, at its segment's end
	mov	r8,[rdx+CH_LOGS+rcx+8]
	sub	r8,rax
	cmp	r8,rsi
	jae	.next
	mov	edi,ebx
	call	keeper_reclaim
	jc	.next				; (still read: later)
	mov	r12d,1
.next:
	inc	ebx
	cmp	ebx,2
	jb	.log
	mov	eax,r12d
	pop	r12
	pop	rbx
	ret

; edi = a log: its oldest segment made room. CF: not yet (someone reads it).
keeper_reclaim:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r15d,edi			; the log
	mov	rbx,[g_cd_base]
	mov	ecx,edi
	shl	ecx,4
	lea	rbx,[rbx+rcx+CH_LOGS]		; its head, its ready
	mov	r12,[rbx+8]			; the place that becomes room
	mov	rdi,r12
	call	cd_segof
	mov	r13d,eax			; the segment
	lea	r14,[r8*2]			; its word once it is room
	mov	ecx,[g_cd_ns]
	test	r15d,r15d
	jz	@f
	mov	ecx,[g_cd_nm]
@@:
	mov	rax,r8
	sub	rax,rcx
	add	rax,rax				; its word now: the generation it holds
	mov	rcx,[g_cd_segs]
	lea	rcx,[rcx+r13*8]
	mov	rdx,[rcx]
	cmp	rdx,r14
	je	.handed				; (done, all but `ready`: a keeper went)
	cmp	rdx,rax
	jne	@f
	lea	rsi,[rax+1]
	push	rax
	push	rcx
	mov	rax,rdx
	lock cmpxchg [rcx],rsi		; marked: no new pins
	pop	rcx
	pop	rax
	jne	.not
	mov	rdx,rsi
@@:
	lea	rsi,[rax+1]
	cmp	rdx,rsi
	jne	.not
	; its records, once
	mov	rdx,r14
	inc	rdx
	cmp	[g_ck_walked+r15*8],rdx
	je	.walked
	push	rcx
	push	rax
	mov	edi,r15d
	mov	esi,r13d
	mov	rdx,r12
	mov	ecx,[g_cd_ns]
	test	r15d,r15d
	jz	@f
	mov	ecx,[g_cd_nm]
@@:
	; the place of its first record: the generation it holds, in this log
	mov	rax,[g_cd_seg]
	imul	rax,rcx
	sub	rdx,rax
	call	keeper_walk
	pop	rax
	pop	rcx
	lea	rdx,[r14+1]
	mov	[g_ck_walked+r15*8],rdx
.walked:
	; nobody pins it any more?
	mov	rsi,[g_cd_pins]
	mov	edx,r13d
	shl	rdx,10				; * CD_REG * 4
	add	rsi,rdx
	mov	edx,CD_REG
.pins:
	cmp	dword [rsi],0
	jne	.not
	add	rsi,4
	dec	edx
	jnz	.pins
	inc	rax
	lock cmpxchg [rcx],r14		; its new generation
	jne	.not
.handed:
	mov	rax,r12
	add	rax,[g_cd_seg]
	mov	[rbx+8],rax			; (only the keeper moves it)
	clc
	jmp	.out
.not:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = the log, esi = the segment, rdx = the place in the log of its start: each
; record still in the index moves on (to M) or goes (from S, its key a ghost)
keeper_walk:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	r15d,edi
	mov	r12,rdx				; the place of the segment's start
	mov	eax,esi
	mov	ecx,[g_cd_segsh]
	shl	rax,cl
	mov	r13,rax				; and where that is in okena.dat
	xor	r14d,r14d			; how far in
	call	cd_clock
.rec:
	lea	rax,[r14+CD_RH]
	cmp	rax,[g_cd_seg]
	ja	.done
	mov	edi,[g_cd_fd]
	lea	rsi,[g_ck_hdr]
	mov	edx,CD_RH
	lea	r10,[r13+r14]
	mov	eax,SYS_pread64
	syscall
	cmp	eax,CD_RH
	jne	.done
	lea	rbx,[g_ck_hdr]
	cmp	dword [rbx+RH_MAGIC],'OKR1'
	jne	.done				; (past the last record written)
	lea	rax,[r12+r14]
	cmp	[rbx+RH_ABS],rax
	jne	.done
	movzx	eax,word [rbx+RH_HLEN]
	movzx	ecx,word [rbx+RH_MLEN]
	add	eax,ecx
	add	eax,[rbx+RH_BLEN]
	jc	.done
	lea	rbp,[rax+CD_RH+63]
	and	rbp,not 63			; its length
	mov	rax,[g_cd_seg]
	sub	rax,r14
	cmp	rbp,rax
	ja	.done
	call	keeper_record
	add	r14,rbp
	jmp	.rec
.done:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_ck_hdr = a record at r12 + r14 in the log (r13 + r14 in okena.dat), rbp long,
; r15d its log: dealt with. Keeps rbx-r15, rbp.
keeper_record:
	push	rbx
	; its slot, if it still names it
	mov	r8,qword [g_ck_hdr+RH_KEY]
	mov	rax,qword [g_ck_hdr+RH_KEY+8]
	mov	ecx,[g_cd_nslot]
	shr	ecx,3
	dec	ecx
	and	rax,rcx
	shl	rax,8
	add	rax,[g_cd_slots]
	mov	r9,rax
	lea	r10,[r12+r14]			; its place
	mov	r11d,8
.slot:
	mov	eax,[r9+IS_SEQ]
	test	eax,1
	jnz	.next
	cmp	[r9+IS_TAG],r8
	jne	.next
	cmp	[r9+IS_ABS],r10
	jne	.next
	mov	edx,[r9+IS_LEN]
	mov	ecx,[r9+IS_STALE]
	cmp	eax,[r9+IS_SEQ]
	jne	.next
	test	edx,CD_LENM
	jz	.next
	jmp	.found
.next:
	add	r9,IS_SIZE
	dec	r11d
	jnz	.slot
	jmp	.out				; (replaced, or gone from the index: nothing)
.found:
	mov	rbx,r9				; the slot
	cmp	[g_cd_rnow],rcx
	jae	.out				; past any use: it just goes
	shr	edx,30				; asked for again
	test	r15d,r15d
	jnz	.main
	test	edx,edx
	jnz	.move				; S, asked for: to M, from nothing
	; S, never asked for again: a ghost
	lea	rsi,[g_ck_hdr+RH_KEY]
	call	cd_ghost_add
	jmp	.out
.main:
	test	edx,edx
	jz	.out				; M, never asked for again: goes
	dec	edx
	shl	edx,30
	jmp	.copy
.move:
	xor	edx,edx
.copy:
	push	rdx				; its count from now on
	mov	ecx,ebp
	mov	esi,1
	call	cd_reserve
	pop	rdx
	jc	.no_room
	push	rdx
	push	rax
	mov	rdi,rax
	call	cd_segof			; (a place of M below its ready: its generation)
	mov	rdi,[rsp]
	cd_pos
	mov	[g_ck_dst],rax
	lea	rax,[r13+r14]
	mov	[g_ck_src],rax
	; the bytes, kernel to kernel
	mov	r9d,ebp
.copying:
	mov	edi,[g_cd_fd]
	lea	rsi,[g_ck_src]
	mov	edx,edi
	lea	r10,[g_ck_dst]
	mov	r8d,r9d
	push	r9
	mov	r9d,0
	mov	eax,SYS_copy_file_range
	syscall
	pop	r9
	test	rax,rax
	jle	.failed
	sub	r9d,eax
	jnz	.copying
	; its head names its new place
	pop	rax				; the new place
	mov	qword [g_ck_hdr+RH_ABS],rax
	push	rax
	mov	rdi,rax
	call	cd_segof
	mov	rdi,[rsp]
	cd_pos
	mov	r10,rax
	mov	edi,[g_cd_fd]
	lea	rsi,[g_ck_hdr]
	mov	edx,CD_RH
	mov	eax,SYS_pwrite64
	syscall
	cmp	eax,CD_RH
	jne	.failed
	pop	rax
	pop	rdx
	; the slot points at it, if it still points at the original
	mov	r8,qword [g_ck_hdr+RH_KEY]
	lea	r10,[r12+r14]
	mov	ecx,[rbx+IS_SEQ]
	test	ecx,1
	jnz	.out
	push	rax
	mov	eax,ecx
	lea	ecx,[rax+1]
	lock cmpxchg [rbx+IS_SEQ],ecx
	pop	rax
	jne	.out
	cmp	[rbx+IS_ABS],r10
	jne	.release
	cmp	[rbx+IS_TAG],r8
	jne	.release
	mov	[rbx+IS_ABS],rax
	mov	esi,[rbx+IS_LEN]
	and	esi,CD_LENM
	or	esi,edx
	mov	[rbx+IS_LEN],esi
.release:
	inc	ecx
	mov	[rbx+IS_SEQ],ecx
	jmp	.out
.failed:
	add	rsp,16
	jmp	.out
.no_room:
	test	r15d,r15d
	jnz	.out
	lea	rsi,[g_ck_hdr+RH_KEY]		; (from S, M full: a ghost, back to M when asked)
	call	cd_ghost_add
.out:
	pop	rbx
	ret
