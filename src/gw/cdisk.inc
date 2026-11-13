; `okena { cache_disk /var/cache/okena size=200GiB }`: the second tier of `cache`, on
; disk, one for every worker and every okena process on the machine: what one fills,
; all serve; a reload, an upgrade or a restart starts with it full.
;
; Two files in the directory. okena.dat holds the answers, written one after the
; other (a log); okena.idx is mapped shared by all, and holds where each one is.
; Nothing is locked on the way of a request:
;
; - There are two logs, cut in segments: a small one (S, a tenth) where answers come
;   in, and a main one (M). A writer takes room with one compare-and-swap on a log's
;   head, below its `ready`. A record never crosses a segment. Room is made ahead of
;   the heads by the cache keeper (ckeep.inc), off the way of requests, as S3-FIFO
;   does: of S's oldest segment, what was asked for again moves to M and the rest
;   goes, its key kept as a ghost; of M's, what was asked for again is written again
;   at M's head, and the rest goes. An answer whose key is a ghost comes in to M
;   straight away. One-hit wonders (a crawler) pass through S and never reach M.
;   Once its records are dealt with, a segment holds a generation its old index
;   entries do not name, and nobody needs to look for them.
;
; - A reader pins the segment it reads (a counter of its own, per segment, so no
;   two processes write the same word), then checks that the segment still holds
;   the generation it wants. A segment being reclaimed is first marked so, and is
;   handed over only once nobody pins it: what a client is being sent is never
;   overwritten under it. (Dekker: the reader writes its pin and reads the mark, the
;   reclaimer writes the mark and reads the pins, each with a barrier between.)
;
; - The index is buckets of 8 slots of 32 bytes. A slot is written under a sequence
;   number (odd while it is written, taken with a compare-and-swap) and read twice
;   around it; a full bucket loses its oldest answer, the one going soonest anyway.
;   A slot holds 8 bytes of the key; the record on disk has all 32, and is checked.
;
; Who pins is a slot in a registry, by pid; a worker that died leaves pins behind,
; and the next worker to start (under a lock on okena.lock) clears what the dead
; held. The last one to leave cleanly writes everything out and marks the store
; clean: after a reboot only a clean store is kept (a power cut may have lost pages
; the index points at), and a size that changed makes a new one, put in place by a
; rename, so that processes still on the old one keep it until they go.
;
; Reads of the head and writes of a record are made at once (pread, pwritev): the
; page cache takes them. The body of a hit comes through the ring like a file's.

CD_MARK		:= 0x40000000			; HB_CE: a hit from disk, and its segment
CD_HMAX		:= 8192				; the largest head kept on disk
CD_RH		:= 64				; a record's own head
CD_REG		:= 256				; processes that can pin, at once
CD_IOV		:= 256
CD_VER		:= 5				; (5: the purge sketch)
CD_LOGM		:= 1 shl 62			; a place in M (in S without it)
CD_FREQ		:= 1 shl 30			; IS_LEN: asked for again (0-3), above the length
CD_LENM		:= CD_FREQ - 1

; okena.idx: its head
CH_MAGIC	:= 0				; q
CH_VER		:= 8				; d
CH_SEGSH	:= 12				; d
CH_SIZE		:= 16				; q: bytes of okena.dat
CH_NSEG		:= 24				; d
CH_NSLOT	:= 28				; d
CH_NS		:= 32				; d: segments of S (the rest are M's)
CH_LIVE		:= 48				; q: who is in (low half); bit 32: left clean
CH_BOOT		:= 64				; 40: the boot it was used in
CH_HDR		:= 128				; (what is read before mapping)
CH_LOGS		:= 128				; S, then M: q where the next record goes (ever
						; growing), q room is free below this
CH_KEEPER	:= 160				; d: the pid of the keeper at work, 0 none
CH_WAKE		:= 164				; d: a futex: a writer entered a segment, or found
						; no room: the keeper wakes
CH_SEGS		:= 4096				; q a segment: its generation * 2, + 1 being reclaimed

; a slot of the index
IS_SEQ		:= 0				; d
IS_LEN		:= 4				; d: the record's length, 0 empty
IS_TAG		:= 8				; q: the key's first 8 bytes
IS_ABS		:= 16				; q: where in the log
IS_FRESH	:= 24				; d: seconds (wall clock)
IS_STALE	:= 28				; d
IS_SIZE		:= 32

; a record
RH_MAGIC	:= 0				; d
RH_HLEN		:= 4				; w: the head's length; then w: its purge facts', before it
RH_MLEN		:= 6
RH_BLEN		:= 8				; d
RH_SWR		:= 12				; d: stale-while-revalidate ends, seconds (past it,
						; to the slot's IS_STALE, only for an error)
RH_ABS		:= 16				; q
RH_BORN		:= 24				; q: µs (wall clock) its fetch began
RH_KEY		:= 32				; 32

bss
	align 8
	g_plan_cdpath	dq ?
	g_plan_cdsize	dq ?
	g_plan_cdplen	dd ?
	g_cd_on		dd ?
	g_cd_base	dq ?			; okena.idx, mapped
	g_cd_total	dq ?			; its length
	g_cd_segs	dq ?
	g_cd_reg	dq ?
	g_cd_pins	dq ?
	g_cd_slots	dq ?
	g_cd_seg	dq ?			; a segment's bytes
	g_cd_size	dq ?
	g_cd_rnow	dq ?			; seconds, wall clock
	g_cd_sabs	dq ?			; cd_find: what it found
	g_cd_spos	dq ?			; cd_lookup: where its body is in okena.dat
	g_cd_slen	dd ?
	g_cd_sfresh	dd ?
	g_cd_sstale	dd ?
	g_cd_sidx	dd ?			; its segment
	g_cd_fd		dd ?			; okena.dat
	g_cd_me		dd ?			; this process's registry slot
	g_cd_segsh	dd ?
	g_cd_nseg	dd ?
	g_cd_nslot	dd ?
	g_cd_ns		dd ?			; S's segments, then M's
	g_cd_nm		dd ?
	g_cd_ghost	dq ?			; the ghosts: buckets of 8, a key's first 8 bytes each
	g_cd_sptr	dq ?			; cd_find: its slot
	g_cd_lockfd	dd ?
	g_cd_idxfd	dd ?
	align 8
	g_cd_how	rq 3			; struct open_how
	g_cd_iov	rq 2 * CD_IOV
	g_cd_rec:	rb CD_RH		; a record's head, written
	g_cd_zero:	rb 64
	g_cd_boot:	rb 40
	g_cd_path:	rb 4096
	g_cd_buf:	rb CD_RH + PM_MAX + CD_HMAX
	g_cd_attach	dd ?			; 1: the store's purge ring only (the admin process)
	g_cd_pr		dq ?			; where the purge ring is in okena.idx
end bss

; g_plan_cdpath, then rsi = what follows (NUL-terminated): g_cd_path
cd_path:
	lea	rdi,[g_cd_path]
	push	rsi
	mov	rsi,[g_plan_cdpath]
	mov	ecx,[g_plan_cdplen]
	rep	movsb
	pop	rsi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	ret

; rsi = the name in the directory, edx = flags: eax = descriptor, or -errno
cd_open:
	push	rdx
	call	cd_path
	pop	rdx
	or	edx,O_CLOEXEC
	mov	[g_cd_how],rdx
	xor	eax,eax
	test	edx,O_CREAT
	jz	@f
	mov	eax,0x180
@@:
	mov	[g_cd_how+8],rax
	mov	qword [g_cd_how+16],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_cd_path]
	lea	rdx,[g_cd_how]
	mov	r10d,24
	mov	eax,SYS_openat2
	syscall
	ret

; g_cd_rnow
cd_clock:
	sub	rsp,24
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	mov	[g_cd_rnow],rax
	add	rsp,24
	ret

; a worker, at its start, before it confines itself: the store, if it can be had.
; Without it, answers are kept in memory only, as before.
cd_init:
	cmp	dword [g_plan_cdplen],0
	je	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	; the shape: segments of 1/16 of it, between 64 KiB and 64 MiB; a slot of the
	; index for every 32 KiB, 4096 at least
	mov	rax,[g_plan_cdsize]
	shr	rax,4
	bsr	rcx,rax
	cmp	ecx,16
	jae	@f
	mov	ecx,16
@@:
	cmp	ecx,26
	jbe	@f
	mov	ecx,26
@@:
	mov	[g_cd_segsh],ecx
	mov	eax,1
	shl	rax,cl
	mov	[g_cd_seg],rax
	mov	rax,[g_plan_cdsize]
	shr	rax,cl
	mov	[g_cd_nseg],eax
	shl	rax,cl
	mov	[g_cd_size],rax
	mov	eax,[g_cd_nseg]			; S: a tenth, 4 segments at least
	xor	edx,edx
	mov	ecx,10
	div	ecx
	cmp	eax,4
	jae	@f
	mov	eax,4
@@:
	mov	[g_cd_ns],eax
	mov	ecx,[g_cd_nseg]
	sub	ecx,eax
	mov	[g_cd_nm],ecx
	mov	rax,[g_plan_cdsize]
	shr	rax,15
	cmp	rax,4096
	jae	@f
	mov	eax,4096
@@:
	dec	rax
	bsr	rcx,rax
	inc	ecx
	mov	eax,1
	shl	rax,cl
	mov	[g_cd_nslot],eax
	; okena.idx: head, segments, registry, pins, slots, each on its own pages
	mov	eax,[g_cd_nseg]
	lea	rax,[CH_SEGS+rax*8+4095]
	and	rax,not 4095
	mov	r12,rax				; registry
	lea	rax,[rax+CD_REG*8+4095]
	and	rax,not 4095
	mov	r13,rax				; pins
	mov	ecx,[g_cd_nseg]
	imul	rcx,rcx,CD_REG*4
	lea	rax,[rax+rcx+4095]
	and	rax,not 4095
	mov	r14,rax				; slots
	mov	ecx,[g_cd_nslot]
	shl	rcx,5
	add	rax,rcx
	mov	ecx,[g_cd_nslot]		; and the ghosts, as many
	lea	rax,[rax+rcx*8+4095]
	and	rax,not 4095
	mov	[g_cd_pr],rax			; then the purge ring (purge.inc)
	add	rax,PR_SIZE
	mov	[g_cd_total],rax

	; the boot this is: a store from another is kept only if it was left clean
	lea	rdi,[g_cd_boot]
	xor	eax,eax
	mov	ecx,40
	rep	stosb
	mov	qword [g_cd_how],O_CLOEXEC
	mov	qword [g_cd_how+8],0
	mov	qword [g_cd_how+16],0
	mov	edi,AT_FDCWD
	lea	rsi,[.boot_id]
	lea	rdx,[g_cd_how]
	mov	r10d,24
	mov	eax,SYS_openat2
	syscall
	test	eax,eax
	js	@f
	mov	ebx,eax
	mov	edi,eax
	lea	rsi,[g_cd_boot]
	mov	edx,36
	mov	eax,SYS_read
	syscall
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
@@:
	; one at a time from here
	lea	rsi,[.n_lock]
	mov	edx,O_RDWR or O_CREAT
	call	cd_open
	test	eax,eax
	js	.fail
	mov	[g_cd_lockfd],eax
	mov	edi,eax
	mov	esi,LOCK_EX
	mov	eax,SYS_flock
	syscall
	test	eax,eax
	js	.fail_lock

	; the store there, if it has this shape
	mov	dword [g_cd_idxfd],-1
	lea	rsi,[.n_idx]
	mov	edx,O_RDWR
	call	cd_open
	test	eax,eax
	js	.fresh
	mov	[g_cd_idxfd],eax
	mov	edi,eax
	lea	rsi,[g_cd_buf]
	mov	edx,CH_HDR
	xor	r10d,r10d
	mov	eax,SYS_pread64
	syscall
	cmp	eax,CH_HDR
	jne	.unfit
	lea	rbx,[g_cd_buf]
	mov	rax,'OKENACD1'
	cmp	[rbx+CH_MAGIC],rax
	jne	.unfit
	cmp	dword [rbx+CH_VER],CD_VER
	jne	.unfit
	mov	eax,[g_cd_segsh]
	cmp	[rbx+CH_SEGSH],eax
	jne	.unfit
	mov	eax,[g_cd_nseg]
	cmp	[rbx+CH_NSEG],eax
	jne	.unfit
	mov	eax,[g_cd_nslot]
	cmp	[rbx+CH_NSLOT],eax
	jne	.unfit
	mov	eax,[g_cd_ns]
	cmp	[rbx+CH_NS],eax
	jne	.unfit
	mov	rax,[g_cd_size]
	cmp	[rbx+CH_SIZE],rax
	jne	.unfit
	; (its length: a store cut short would fault when touched)
	sub	rsp,144
	mov	edi,[g_cd_idxfd]
	mov	rsi,rsp
	mov	eax,SYS_fstat
	syscall
	mov	rcx,[rsp+ST_SIZE]
	add	rsp,144
	test	eax,eax
	js	.unfit
	cmp	rcx,[g_cd_total]
	jne	.unfit
	xor	r15d,r15d			; 1: the registry starts over
	lea	rsi,[rbx+CH_BOOT]
	lea	rdi,[g_cd_boot]
	mov	ecx,40
	repe	cmpsb
	je	.map
	; another boot: kept only if it was left clean, and whoever was in is gone
	mov	rax,[rbx+CH_LIVE]
	bt	rax,32
	jnc	.unfit
	mov	r15d,1
	jmp	.map
.unfit:
	mov	edi,[g_cd_idxfd]
	mov	eax,SYS_close
	syscall
	mov	dword [g_cd_idxfd],-1
.fresh:
	; a new one, under other names, put in place whole
	lea	rsi,[.n_datnew]
	mov	edx,O_RDWR or O_CREAT or O_TRUNC
	call	cd_open
	test	eax,eax
	js	.fail_lock
	mov	ebx,eax
	mov	edi,eax
	mov	rsi,[g_cd_size]
	mov	eax,SYS_ftruncate
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	test	eax,eax
	js	.fail_lock
	lea	rsi,[.n_idxnew]
	mov	edx,O_RDWR or O_CREAT or O_TRUNC
	call	cd_open
	test	eax,eax
	js	.fail_lock
	mov	[g_cd_idxfd],eax
	mov	edi,eax
	mov	rsi,[g_cd_total]
	mov	eax,SYS_ftruncate
	syscall
	test	eax,eax
	js	.fail_idx
	call	.mmap
	js	.fail_idx
	mov	rbx,rax
	mov	rax,'OKENACD1'
	mov	[rbx+CH_MAGIC],rax
	mov	dword [rbx+CH_VER],CD_VER
	mov	eax,[g_cd_segsh]
	mov	[rbx+CH_SEGSH],eax
	mov	rax,[g_cd_size]
	mov	[rbx+CH_SIZE],rax
	mov	qword [rbx+CH_LIVE],0
	mov	dword [rbx+CH_KEEPER],0
	mov	eax,[g_cd_nseg]
	mov	[rbx+CH_NSEG],eax
	mov	eax,[g_cd_ns]
	mov	[rbx+CH_NS],eax
	; both logs empty, all of them free
	mov	qword [rbx+CH_LOGS],0
	mov	ecx,[g_cd_segsh]
	mov	eax,[g_cd_ns]
	shl	rax,cl
	mov	[rbx+CH_LOGS+8],rax
	mov	rax,CD_LOGM
	mov	[rbx+CH_LOGS+16],rax
	mov	eax,[g_cd_nm]
	shl	rax,cl
	mov	rdx,CD_LOGM
	or	rax,rdx
	mov	[rbx+CH_LOGS+24],rax
	mov	eax,[g_cd_nslot]
	mov	[rbx+CH_NSLOT],eax
	lea	rdi,[rbx+CH_BOOT]
	lea	rsi,[g_cd_boot]
	mov	ecx,40
	rep	movsb
	; S's segment i holds its generation i, and M's j its j
	lea	rdi,[rbx+CH_SEGS]
	xor	eax,eax
	mov	ecx,[g_cd_ns]
@@:
	lea	rdx,[rax*2]
	mov	[rdi+rax*8],rdx
	inc	eax
	cmp	eax,ecx
	jb	@b
	lea	rdi,[rdi+rcx*8]
	xor	eax,eax
	mov	ecx,[g_cd_nm]
@@:
	lea	rdx,[rax*2]
	mov	[rdi+rax*8],rdx
	inc	eax
	cmp	eax,ecx
	jb	@b
	; okena.dat first: okena.idx names it
	lea	rsi,[.n_datnew]
	call	cd_path
	lea	rdi,[g_cd_buf]
	lea	rsi,[g_cd_path]
	mov	ecx,4096
	rep	movsb
	lea	rsi,[.n_dat]
	call	cd_path
	lea	rdi,[g_cd_buf]
	lea	rsi,[g_cd_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.fail_idx
	lea	rsi,[.n_idxnew]
	call	cd_path
	lea	rdi,[g_cd_buf]
	lea	rsi,[g_cd_path]
	mov	ecx,4096
	rep	movsb
	lea	rsi,[.n_idx]
	call	cd_path
	lea	rdi,[g_cd_buf]
	lea	rsi,[g_cd_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.fail_idx
	call	log_begin			; (by the one that made it: once)
	out_lit 'cache_disk: a new store in '
	mov	rsi,[g_plan_cdpath]
	mov	edx,[g_plan_cdplen]
	call	out_str
	call	log_end
	jmp	.mapped
.map:
	call	.mmap
	js	.fail_idx
	mov	rbx,rax
	test	r15d,r15d
	jz	.mapped
	; a store from before a reboot, left clean: nobody of then is in
	lea	rdi,[rbx+r12]
	mov	rcx,r14
	sub	rcx,r12
	xor	eax,eax
	rep	stosb
	mov	qword [rbx+CH_LIVE],0
	mov	dword [rbx+CH_KEEPER],0
	lea	rdi,[rbx+CH_BOOT]
	lea	rsi,[g_cd_boot]
	mov	ecx,40
	rep	movsb
.mapped:
	mov	[g_cd_base],rbx
	lea	rax,[rbx+CH_SEGS]
	mov	[g_cd_segs],rax
	lea	rax,[rbx+r12]
	mov	[g_cd_reg],rax
	lea	rax,[rbx+r13]
	mov	[g_cd_pins],rax
	lea	rax,[rbx+r14]
	mov	[g_cd_slots],rax
	mov	ecx,[g_cd_nslot]
	shl	rcx,5
	add	rax,rcx
	mov	[g_cd_ghost],rax
	mov	rax,rbx
	add	rax,[g_cd_pr]
	mov	[g_pr_base],rax			; purges: the store's, for all its processes
	cmp	dword [g_cd_attach],0
	je	@f
	mov	edi,[g_cd_idxfd]		; (the admin: that is all it wants)
	mov	eax,SYS_close
	syscall
	jmp	.unlock
@@:
	mov	edi,[g_cd_idxfd]
	mov	eax,SYS_close
	syscall
	lea	rsi,[.n_dat]
	mov	edx,O_RDWR
	call	cd_open
	test	eax,eax
	js	.fail_lock
	mov	[g_cd_fd],eax

	; who is in: the dead are let go of, with their pins
	mov	r12,[g_cd_reg]
	xor	r13d,r13d
.dead:
	mov	edi,[r12+r13*8]
	test	edi,edi
	jz	.next_dead
	xor	esi,esi
	mov	eax,SYS_kill
	syscall
	cmp	eax,-ESRCH
	jne	.next_dead
	mov	edi,r13d
	call	cd_let_go
.next_dead:
	inc	r13d
	cmp	r13d,CD_REG
	jb	.dead
	; and this one comes in
	mov	eax,SYS_getpid
	syscall
	mov	ecx,eax
	xor	r13d,r13d
.claim:
	xor	eax,eax
	lock cmpxchg [r12+r13*8],ecx
	je	.claimed
	inc	r13d
	cmp	r13d,CD_REG
	jb	.claim
	jmp	.full
.claimed:
	mov	[g_cd_me],r13d
	mov	rbx,[g_cd_base]
	mov	rax,[rbx+CH_LIVE]
@@:
	mov	edx,eax
	inc	edx				; one more, and not left clean
	lock cmpxchg [rbx+CH_LIVE],rdx
	jne	@b
	mov	edi,[g_cd_lockfd]
	mov	eax,SYS_close
	syscall
	mov	dword [g_cd_on],1
	jmp	.out
.full:
	call	log_begin
	out_lit 'cache_disk: more than 256 workers on the store: this one keeps answers in memory'
	call	log_end
	jmp	.unlock
.fail_idx:
	push	rax
	mov	edi,[g_cd_idxfd]
	mov	eax,SYS_close
	syscall
	pop	rax
.fail_lock:
	push	rax
	call	log_begin
	out_lit 'cache_disk: cannot use '
	mov	rsi,[g_plan_cdpath]
	mov	edx,[g_plan_cdplen]
	call	out_str
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit '): answers are kept in memory only'
	call	log_end
.unlock:
	mov	edi,[g_cd_lockfd]
	mov	eax,SYS_close
	syscall
	jmp	.out
.fail:
	push	rax
	call	log_begin
	out_lit 'cache_disk: cannot use '
	mov	rsi,[g_plan_cdpath]
	mov	edx,[g_plan_cdplen]
	call	out_str
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit '): answers are kept in memory only'
	call	log_end
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
; okena.idx, mapped shared: rax, SF on a failure
.mmap:
	xor	edi,edi
	mov	rsi,[g_cd_total]
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED
	mov	r8d,[g_cd_idxfd]
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	ret
.boot_id	db '/proc/sys/kernel/random/boot_id',0
.n_lock		db '/okena.lock',0
.n_idx		db '/okena.idx',0
.n_dat		db '/okena.dat',0
.n_idxnew	db '/okena.idx.new',0
.n_datnew	db '/okena.dat.new',0

; edi = a registry slot whose process is gone: its pins and its place
cd_let_go:
	mov	rdx,[g_cd_pins]
	lea	rdx,[rdx+rdi*4]
	mov	ecx,[g_cd_nseg]
@@:
	mov	dword [rdx],0
	add	rdx,CD_REG*4
	dec	ecx
	jnz	@b
	mov	rdx,[g_cd_reg]
	mov	dword [rdx+rdi*8],0
	mov	rdx,[g_cd_base]
	mov	rax,[rdx+CH_LIVE]
.again:
	test	eax,eax
	jz	.done
	lea	rcx,[rax-1]			; (the clean bit stays as it is: none of it)
	lock cmpxchg [rdx+CH_LIVE],rcx
	jne	.again
.done:
	ret

; a worker that drained: out of the store. The last one out writes it all down and
; marks it clean.
cd_leave:
	cmp	dword [g_cd_on],0
	je	.none
	mov	dword [g_cd_on],0
	mov	edi,[g_cd_me]
	mov	rdx,[g_cd_pins]
	lea	rdx,[rdx+rdi*4]
	mov	ecx,[g_cd_nseg]
@@:
	mov	dword [rdx],0
	add	rdx,CD_REG*4
	dec	ecx
	jnz	@b
	mov	rdx,[g_cd_reg]
	mov	dword [rdx+rdi*8],0
	mov	rdx,[g_cd_base]
	mov	rax,[rdx+CH_LIVE]
.again:
	mov	ecx,eax
	test	ecx,ecx
	jz	.none
	dec	ecx				; (a low half only: not clean while one is in)
	lock cmpxchg [rdx+CH_LIVE],rcx
	jne	.again
	test	ecx,ecx
	jnz	.none
	mov	edi,[g_cd_fd]
	mov	eax,SYS_fdatasync
	syscall
	test	eax,eax
	js	.none
	mov	rdi,[g_cd_base]
	mov	rsi,[g_cd_total]
	mov	edx,MS_SYNC
	mov	eax,SYS_msync
	syscall
	test	eax,eax
	js	.none
	; clean, unless someone came in meanwhile
	mov	rdx,[g_cd_base]
	xor	eax,eax
	mov	rcx,1 shl 32
	lock cmpxchg [rdx+CH_LIVE],rcx
	; (and that mark itself on disk)
	mov	rdi,[g_cd_base]
	mov	esi,4096
	mov	edx,MS_SYNC
	mov	eax,SYS_msync
	syscall
.none:
	ret

; rdi = a place in a log: eax = its segment, r8 = the generation it is in. Keeps rdi,
; rsi, r10, r11.
cd_segof:
	mov	r8,rdi
	btr	r8,62				; (CF: in M)
	setc	r9b
	mov	ecx,[g_cd_segsh]
	shr	r8,cl
	mov	rax,r8
	xor	edx,edx
	test	r9b,r9b
	jnz	.m
	mov	ecx,[g_cd_ns]
	div	rcx
	mov	eax,edx
	ret
.m:
	mov	ecx,[g_cd_nm]
	div	rcx
	mov	eax,edx
	add	eax,[g_cd_ns]
	ret

; rdi = a place in a log: pinned, eax = its segment. CF: it no longer holds it.
cd_pin:
	call	cd_segof
	mov	r9,[g_cd_pins]
	mov	r10d,eax
	shl	r10,8				; * CD_REG
	add	r10d,[g_cd_me]
	inc	dword [r9+r10*4]
	mfence
	mov	rcx,[g_cd_segs]
	add	r8,r8
	cmp	[rcx+rax*8],r8
	jne	.gone
	clc
	ret
.gone:
	dec	dword [r9+r10*4]
	stc
	ret

; edi = a segment: unpinned. Keeps all but rax, rdx.
cd_unpin:
	mov	eax,edi
	shl	rax,8
	add	eax,[g_cd_me]
	mov	rdx,[g_cd_pins]
	dec	dword [rdx+rax*4]
	ret

; eax = a segment, rdi = a place in the log: rax = where it is in okena.dat
macro cd_pos
	mov	ecx,[g_cd_segsh]
	shl	rax,cl
	mov	rdx,[g_cd_seg]
	dec	rdx
	and	rdx,rdi
	add	rax,rdx
end macro

; g_ck = a key: its newest slot in g_cd_s*. CF: none.
cd_find:
	mov	r8,qword [g_ck]
	mov	rax,qword [g_ck+8]
	mov	ecx,[g_cd_nslot]
	shr	ecx,3
	dec	ecx
	and	rax,rcx
	shl	rax,8				; 8 slots of 32
	add	rax,[g_cd_slots]
	mov	r9,rax
	mov	dword [g_cd_slen],0
	mov	r11d,8
.slot:
	mov	r10d,8				; looks, while someone writes it
.read:
	mov	eax,[r9+IS_SEQ]
	test	eax,1
	jnz	.busy
	mov	edx,[r9+IS_LEN]
	mov	rsi,[r9+IS_TAG]
	mov	rdi,[r9+IS_ABS]
	mov	rcx,[r9+IS_FRESH]		; (and IS_STALE)
	cmp	eax,[r9+IS_SEQ]
	jne	.busy
	test	edx,edx
	jz	.next
	cmp	rsi,r8
	jne	.next
	cmp	dword [g_cd_slen],0
	je	.take
	cmp	rdi,[g_cd_sabs]
	jbe	.next
.take:
	and	edx,CD_LENM
	mov	[g_cd_slen],edx
	mov	[g_cd_sabs],rdi
	mov	qword [g_cd_sfresh],rcx
	mov	[g_cd_sptr],r9
	jmp	.next
.busy:
	pause
	dec	r10d
	jnz	.read
.next:
	add	r9,IS_SIZE
	dec	r11d
	jnz	.slot
	cmp	dword [g_cd_slen],1		; CF when none
	ret

; g_ck = a key, r15 = record. eax = 0 not on disk; 1 there and fresh; 2 stale but in
; its stale-while-revalidate window; 3 past it, within stale-if-error. When there, it is pinned (g_cd_sidx) and its head is in g_cd_buf,
; checked. Keeps rbx, r12-r15.
cd_lookup:
	cmp	dword [g_cd_on],0
	je	.no
	call	cd_find
	jc	.no
	call	cd_clock
	mov	eax,[g_cd_sstale]
	cmp	[g_cd_rnow],rax
	jae	.no
	mov	rdi,[g_cd_sabs]
	call	cd_pin
	jc	.no
	mov	[g_cd_sidx],eax
	mov	rdi,[g_cd_sabs]
	cd_pos
	mov	r10,rax				; where
	mov	edx,[g_cd_slen]
	cmp	edx,CD_RH + PM_MAX + CD_HMAX
	jbe	@f
	mov	edx,CD_RH + PM_MAX + CD_HMAX
@@:
	push	r10
	mov	edi,[g_cd_fd]
	lea	rsi,[g_cd_buf]
	mov	eax,SYS_pread64
	syscall
	pop	r10
	; what it says it is, it must be
	cmp	eax,CD_RH
	jl	.bad
	lea	rsi,[g_cd_buf]
	cmp	dword [rsi+RH_MAGIC],'OKR1'
	jne	.bad
	mov	rcx,[g_cd_sabs]
	cmp	[rsi+RH_ABS],rcx
	jne	.bad
	movzx	ecx,word [rsi+RH_HLEN]
	cmp	ecx,CD_HMAX
	ja	.bad
	movzx	edx,word [rsi+RH_MLEN]
	cmp	edx,PM_MAX
	ja	.bad
	lea	edx,[rcx+rdx+CD_RH]
	cmp	edx,eax
	ja	.bad
	mov	r8d,[rsi+RH_BLEN]
	add	rdx,r8
	cmp	edx,[g_cd_slen]
	ja	.bad
	lea	rdi,[g_ck]
	add	rsi,RH_KEY
	mov	ecx,4
	repe	cmpsq
	jne	.bad
	lea	rsi,[g_cd_buf]
	movzx	eax,word [rsi+RH_HLEN]
	movzx	ecx,word [rsi+RH_MLEN]
	add	eax,ecx
	lea	rax,[r10+rax+CD_RH]
	mov	[g_cd_spos],rax
	; a purge since it was fetched?
	mov	rdi,[g_cd_buf+RH_BORN]
	pr_maybe
	jnc	.unpurged
	movzx	ecx,word [g_cd_buf+RH_MLEN]
	mov	esi,ecx
	lea	rdi,[g_pm]
	push	rsi
	lea	rsi,[g_cd_buf+CD_RH]
	rep	movsb
	pop	rsi
	mov	rdi,[g_cd_buf+RH_BORN]
	call	pr_check
	jc	.bad
.unpurged:
	; asked for again: up to 3 (once is enough: a slot changed meanwhile keeps its own)
	mov	rcx,[g_cd_sptr]
	mov	eax,[rcx+IS_LEN]
	cmp	eax,3 * CD_FREQ
	jae	@f
	mov	rdx,[g_cd_sabs]
	cmp	[rcx+IS_ABS],rdx
	jne	@f
	lea	edx,[rax+CD_FREQ]
	lock cmpxchg [rcx+IS_LEN],edx
@@:
	mov	eax,1
	mov	ecx,[g_cd_sfresh]
	cmp	[g_cd_rnow],rcx
	jb	@f
	mov	eax,2
	mov	ecx,[g_cd_buf+RH_SWR]
	cmp	[g_cd_rnow],rcx
	jb	@f
	mov	eax,3				; (only should the backend fail)
@@:
	ret
.bad:
	mov	edi,[g_cd_sidx]
	call	cd_unpin
.no:
	xor	eax,eax
	ret

; after cd_lookup found it: r15, ebx: answered from it, as cache_serve does from memory
cd_serve:
	mov	rax,[r15+H_BUF]
	mov	ecx,[g_cd_sidx]
	or	ecx,CD_MARK
	mov	[rax+HB_CE],ecx
	mov	dword [rax+HB_CW],0
	mov	dword [rax+HB_ZCP],0		; (no pipe yet: zc.inc)
	inc	qword [g_st_cd_hits]
	mov	qword [rax+HB_HT0],0
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_CACHED
	mov	dword [rax+S_SERVER],NIL
	mov	qword [r15+H_UPT0],0
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	movzx	eax,word [g_cd_buf+RH_MLEN]
	lea	rsi,[g_cd_buf+CD_RH+rax]
	movzx	ecx,word [g_cd_buf+RH_HLEN]
	rep	movsb
	mov	eax,[g_cd_buf+RH_BLEN]
	call	range_fix			; a Range: a 206 of it
	call	cond_fix			; its validators matched: a 304
	mov	eax,[g_cd_buf+RH_BLEN]
	call	slice_fix			; a slice: the object's head
	mov	rax,[g_c_skip]
	add	[g_cd_spos],rax
	memit_x 'Age: '
	mov	rax,[g_cd_buf+RH_BORN]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	rcx,rax
	mov	rax,[g_cd_rnow]
	sub	rax,rcx
	jns	@f
	xor	eax,eax				; (a clock set back)
@@:
	call	fmt_u64
	call	cache_status_head
	mov	eax,[g_cd_sfresh]
	sub	rax,[g_cd_rnow]
	jg	@f
	mov	byte [rdi],'-'			; (stale, by any amount: never ttl=0)
	inc	rdi
	neg	rax
	jnz	@f
	inc	eax
@@:
	call	fmt_u64
	memit_x '; detail=disk',13,10,13,10
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_UP]
	sub	rdi,rax
	mov	[r15+H_UPLEN],edi
	mov	dword [r15+H_UPOFF],0
	mov	rax,[r15+H_BUF]
	mov	rcx,[g_cd_spos]
	mov	[rax+HB_CPOSB],rcx		; (and HB_CPOS: a place in okena.dat)
	mov	rcx,[g_c_take]
	mov	[rax+HB_CLEFT],ecx
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	jmp	http_resp_head
assert HB_CPOS = HB_CPOSB + 4

; h_recv on the upstream side of a hit from disk: ebx, r15, r8 = its buffer, rdi =
; where, esi = room
cd_recv:
	mov	ecx,[r8+HB_CLEFT]
	cmp	ecx,esi
	cmova	ecx,esi
	test	ecx,ecx
	jz	.end
	sub	[r8+HB_CLEFT],ecx
	mov	r10,[r8+HB_CPOSB]
	add	[r8+HB_CPOSB],rcx
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	push	rdi
	push	rcx
	push	r10
	mov	edi,OP_H_RECV_U
	mov	esi,ebx
	call	sess_sqe
	pop	r10
	pop	rcx
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	edx,[g_cd_fd]
	mov	[rax+SQE_FD],edx
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],ecx
	mov	[rax+SQE_OFF],r10
	ret
.epoll:
	mov	rsi,rdi
	mov	edi,[g_cd_fd]
	mov	edx,ecx
	mov	eax,SYS_pread64
	syscall
	jmp	.done
.end:
	xor	eax,eax
.done:
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue

; ecx = a record's length, esi = the log (0 S, 1 M): rax = its place. CF: no room
; now (the keeper makes it).
cd_reserve:
	push	rbx
	push	r12
	mov	rbx,[g_cd_base]
	shl	esi,4
	lea	rbx,[rbx+rsi+CH_LOGS]		; its head, then its ready
	mov	r12d,ecx
	mov	r11d,8
.again:
	mov	rax,[rbx]
	mov	r8,rax
	mov	rdx,[g_cd_seg]
	dec	rdx
	and	rdx,rax
	add	rdx,r12
	cmp	rdx,[g_cd_seg]
	jbe	@f
	mov	r8,[g_cd_seg]			; (not across a segment: the next one)
	dec	r8
	or	r8,rax
	inc	r8
@@:
	lea	r9,[r8+r12]
	cmp	r9,[rbx+8]
	ja	.full
	lock cmpxchg [rbx],r9
	je	@f
	dec	r11d
	jnz	.again
.full:
	call	cd_wake				; (room, now)
	stc
	jmp	.out
@@:
	mov	rax,r8
	mov	rdx,[g_cd_seg]
	dec	rdx
	test	rax,rdx
	jnz	@f
	push	rax
	call	cd_wake				; a segment begun: the next one made room
	pop	rax
@@:
	clc
.out:
	pop	r12
	pop	rbx
	ret

; rsi = a key: its bucket of ghosts, rdx; rax = its first 8 bytes
macro cd_ghost_bucket
	mov	rdx,[rsi+8]
	mov	ecx,[g_cd_nslot]
	shr	ecx,3
	dec	ecx
	and	rdx,rcx
	shl	rdx,6				; 8 of 8 bytes
	add	rdx,[g_cd_ghost]
	mov	rax,[rsi]
end macro

; rsi = a key: eax = 1 when it was a ghost (it no longer is)
cd_ghost_take:
	cd_ghost_bucket
	xor	ecx,ecx
.look:
	cmp	[rdx+rcx*8],rax
	je	.found
	inc	ecx
	cmp	ecx,8
	jb	.look
	xor	eax,eax
	ret
.found:
	mov	qword [rdx+rcx*8],0
	mov	eax,1
	ret

; rsi = a key: a ghost now. Into an empty place of its bucket, or over one of them
; (the bits below its own pick which).
cd_ghost_add:
	cd_ghost_bucket
	xor	ecx,ecx
.look:
	cmp	qword [rdx+rcx*8],0
	je	.put
	cmp	[rdx+rcx*8],rax
	je	.put
	inc	ecx
	cmp	ecx,8
	jb	.look
	mov	ecx,eax
	and	ecx,7
.put:
	mov	[rdx+rcx*8],rax
	ret

; the keeper woken. Keeps all but rax, rcx, rdx, rsi, rdi, r8-r11.
cd_wake:
	mov	rdi,[g_cd_base]
	add	rdi,CH_WAKE
	lock inc dword [rdi]
	mov	esi,FUTEX_WAKE
	mov	edx,1
	xor	r10d,r10d
	mov	eax,SYS_futex
	syscall
	ret

; r12 = a memory entry just made ready, g_ck its key: a copy on disk, when it fits.
; Keeps rbx, r12-r15.
cd_put:
	cmp	dword [g_cd_on],0
	je	.none
	cmp	dword [r12+CE_HLEN],CD_HMAX
	ja	.none
	cmp	dword [r12+CE_MLEN],PM_MAX
	ja	.none
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	eax,[r12+CE_HLEN]
	add	eax,[r12+CE_MLEN]
	add	eax,[r12+CE_BLEN]
	jc	.out
	lea	rcx,[rax+CD_RH+63]
	and	rcx,not 63
	cmp	rcx,[g_cd_seg]
	ja	.out
	mov	r15,rcx				; its length
	; a ghost (it went from S unasked a while ago, and is back): straight to M
	lea	rsi,[g_ck]
	call	cd_ghost_take
	mov	esi,eax
.log:
	mov	ecx,r15d
	push	rsi
	call	cd_reserve
	pop	rsi
	jnc	@f
	test	esi,esi
	jz	.full
	xor	esi,esi				; (M full now: S)
	mov	ecx,r15d
	call	cd_reserve
	jnc	@f
.full:
	inc	qword [g_st_cd_full]
	jmp	.out
@@:
	mov	r13,rax				; its place in the log
	mov	rdi,rax
	call	cd_pin				; (none takes it while it is written)
	jc	.out
	mov	r14d,eax
	call	cd_clock
	; its head
	lea	rdi,[g_cd_rec]
	mov	dword [rdi+RH_MAGIC],'OKR1'
	mov	eax,[r12+CE_HLEN]
	mov	[rdi+RH_HLEN],ax
	mov	eax,[r12+CE_MLEN]
	mov	[rdi+RH_MLEN],ax
	mov	eax,[r12+CE_BLEN]
	mov	[rdi+RH_BLEN],eax
	mov	eax,[r12+CE_TTL]
	add	eax,dword [g_cd_rnow]
	add	eax,[r12+CE_SWR]
	mov	[rdi+RH_SWR],eax
	mov	[rdi+RH_ABS],r13
	mov	rax,[r12+CE_RB]
	mov	[rdi+RH_BORN],rax
	lea	rsi,[g_ck]
	add	rdi,RH_KEY
	mov	ecx,4
	rep	movsq
	; then the head and the body, from their blocks
	mov	eax,r14d
	mov	rdi,r13
	cd_pos
	mov	rbx,rax				; where in okena.dat
	lea	r8,[g_cd_iov]
	lea	rax,[g_cd_rec]
	mov	[r8],rax
	mov	qword [r8+8],CD_RH
	mov	r9d,1				; iovecs
	mov	r10,CD_RH			; their bytes
	mov	eax,[r12+CE_META]
	mov	ecx,[r12+CE_MLEN]
	call	.chain
	jc	.unpin
	mov	eax,[r12+CE_HEAD]
	mov	ecx,[r12+CE_HLEN]
	call	.chain
	jc	.unpin
	mov	eax,[r12+CE_BODY]
	mov	ecx,[r12+CE_BLEN]
	call	.chain
	jc	.unpin
	mov	rcx,r15
	sub	rcx,r10
	jz	@f
	lea	rax,[g_cd_zero]			; to the next 64
	call	.iov
	jc	.unpin
@@:
	call	.flush
	jc	.unpin
	; in the index
	mov	rdi,r13
	mov	esi,r15d
	mov	eax,[r12+CE_TTL]
	add	rax,[g_cd_rnow]
	mov	edx,eax				; fresh until
	mov	ecx,[r12+CE_SWR]
	cmp	ecx,[r12+CE_SIE]
	cmovb	ecx,[r12+CE_SIE]
	add	ecx,eax				; and of any use until
	call	cd_publish
	inc	qword [g_st_cd_writes]
.unpin:
	mov	edi,r14d
	call	cd_unpin
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
.none:
	ret
; eax = a chain's first block, ecx = its bytes: into the iovecs. CF: a write failed.
.chain:
	push	r12
	mov	r12d,ecx
	mov	r11d,eax
.block:
	test	r12d,r12d
	jz	.chained
	cmp	r11d,NIL
	je	.chained
	mov	ecx,CB_SIZE
	cmp	ecx,r12d
	cmova	ecx,r12d
	sub	r12d,ecx
	mov	eax,r11d
	shl	rax,CB_SHIFT
	add	rax,[g_cb_base]
	call	.iov
	jc	.chain_out
	mov	rdx,[g_cb_nexts]
	mov	r11d,[rdx+r11*4]
	jmp	.block
.chained:
	clc
.chain_out:
	pop	r12
	ret
; rax = bytes, ecx = how many: one more iovec; written when they are full
.iov:
	cmp	r9d,CD_IOV
	jb	@f
	push	rax
	push	rcx
	push	r11
	call	.flush
	pop	r11
	pop	rcx
	pop	rax
	jc	.iov_out
@@:
	mov	edx,r9d
	shl	edx,4
	mov	[r8+rdx],rax
	mov	[r8+rdx+8],rcx
	inc	r9d
	add	r10,rcx
	clc
.iov_out:
	ret
; what the iovecs hold, written at rbx: rbx moves on, r10 counts on. CF: failed.
.flush:
	test	r9d,r9d
	jz	.flushed
	push	r10
	xor	ecx,ecx				; their bytes, this time
	xor	eax,eax
@@:
	mov	edx,eax
	shl	edx,4
	add	rcx,[r8+rdx+8]
	inc	eax
	cmp	eax,r9d
	jb	@b
	push	rcx
	mov	edi,[g_cd_fd]
	mov	rsi,r8
	mov	edx,r9d
	mov	r10,rbx
	mov	eax,SYS_pwritev
	syscall
	pop	rcx
	pop	r10
	lea	r8,[g_cd_iov]
	cmp	rax,rcx
	jne	.flush_bad
	add	rbx,rcx
	xor	r9d,r9d
.flushed:
	clc
	ret
.flush_bad:
	stc
	ret

; rdi = a record's place in the log, esi = its length, edx = fresh until, ecx = stale
; until; g_ck = its key: into the index. A full bucket loses: an entry for the same
; key, else an empty slot, else one whose segment was reclaimed, else the oldest.
cd_publish:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,esi
	mov	r14d,edx
	mov	r15d,ecx
	mov	r11d,8				; tries
.again:
	mov	r8,qword [g_ck]
	mov	rax,qword [g_ck+8]
	mov	ecx,[g_cd_nslot]
	shr	ecx,3
	dec	ecx
	and	rax,rcx
	shl	rax,8
	add	rax,[g_cd_slots]
	mov	r9,rax
	; the best to lose: rbx = it, r10d = how good (3 same key, 2 empty, 1 gone, 0 oldest)
	mov	rbx,rax
	mov	r10d,-1
	mov	rsi,-1				; the oldest place seen
	xor	ecx,ecx
.look:
	mov	eax,[r9+IS_LEN]
	test	eax,eax
	jnz	@f
	mov	edx,2
	jmp	.rate
@@:
	cmp	[r9+IS_TAG],r8
	jne	@f
	mov	edx,3
	jmp	.rate
@@:
	; is its segment still holding it?
	push	rcx
	push	r8
	push	r9
	push	r10
	mov	rdi,[r9+IS_ABS]
	call	cd_segof
	mov	rcx,[g_cd_segs]
	add	r8,r8
	cmp	[rcx+rax*8],r8
	pop	r10
	pop	r9
	pop	r8
	pop	rcx
	je	@f
	mov	edx,1
	jmp	.rate
@@:
	xor	edx,edx
	cmp	r10d,0
	jg	.skip
	mov	rax,[r9+IS_ABS]
	cmp	rax,rsi
	jae	.skip
	mov	rsi,rax
	mov	rbx,r9
	mov	r10d,0
	jmp	.skip
.rate:
	cmp	edx,r10d
	jle	.skip
	mov	r10d,edx
	mov	rbx,r9
.skip:
	add	r9,IS_SIZE
	inc	ecx
	cmp	ecx,8
	jb	.look
	; taken: odd while it is written
	mov	eax,[rbx+IS_SEQ]
	test	eax,1
	jnz	.retry
	lea	edx,[eax+1]
	lock cmpxchg [rbx+IS_SEQ],edx
	jne	.retry
	mov	[rbx+IS_LEN],r13d
	mov	[rbx+IS_TAG],r8
	mov	[rbx+IS_ABS],r12
	mov	[rbx+IS_FRESH],r14d
	mov	[rbx+IS_STALE],r15d
	add	edx,1
	mov	[rbx+IS_SEQ],edx		; (x86 keeps stores in order)
	jmp	.out
.retry:
	pause
	dec	r11d
	jnz	.again
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; `okena { cache_disk PATH size=SIZE }`, rbx = the node
compile_cache_disk:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	plan_bad_cache_disk
	cmp	edx,3800
	ja	plan_bad_cache_disk
	cmp	byte [rcx],'/'
	jne	plan_bad_cache_disk
	mov	[g_plan_cdpath],rcx
	mov	[g_plan_cdplen],edx
	mov	rdi,rbx
	lea	rsi,[.k_size]
	call	node_option
	test	rax,rax
	jz	plan_bad_cache_disk
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_size
	cmp	rax,1 shl 20
	jb	plan_bad_cache_disk
	mov	rcx,1 shl 42
	cmp	rax,rcx
	ja	plan_bad_cache_disk
	mov	[g_plan_cdsize],rax
	ret
cstring .k_size, 'size',0

plan_bad_cache_disk:
	call	log_begin
	out_lit 'cache_disk needs a directory, its whole path, and size= between 1MiB and 4TiB'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
