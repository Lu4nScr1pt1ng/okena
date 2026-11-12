; CPUs this process may use: the affinity mask (taskset, cpusets) and the
; cgroup CPU quota (docker --cpus, Kubernetes limits).
;
; A quota smaller than the mask matters: with 16 CPUs visible and a quota
; of 2, sixteen workers would exhaust the quota early in every period and
; all stall until the next one, the worst tail latency there is.

bss
	g_affinity:	rb 128		; cpu_set_t at startup (1024 CPUs)
	g_cpu_count	dd ?		; CPUs in the mask
	g_cpu_quota	dd ?		; ceil(quota / period), 0 = none
	g_workers	dd ?
end bss

cstring str_cpu_max, '/sys/fs/cgroup/cpu.max',0

; Fill g_affinity, g_cpu_count, g_cpu_quota.
cpu_discover:
	push	rbx
	xor	edi,edi
	mov	esi,128
	lea	rdx,[g_affinity]
	mov	eax,SYS_sched_getaffinity
	syscall
	xor	ecx,ecx
	test	rax,rax
	jle	.counted
	xor	edx,edx
.count:
	popcnt	r8,[g_affinity+rdx*8]
	add	ecx,r8d
	inc	edx
	cmp	edx,16
	jb	.count
.counted:
	test	ecx,ecx
	jnz	@f
	mov	ecx,1
@@:
	mov	[g_cpu_count],ecx
	; cgroup v2: "max 100000" or "<quota> <period>"
	sub	rsp,64
	mov	edi,AT_FDCWD
	lea	rsi,[str_cpu_max]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.no_quota
	mov	ebx,eax
	mov	edi,ebx
	mov	rsi,rsp
	mov	edx,63
	xor	eax,eax
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	test	rax,rax
	jle	.no_quota
	mov	byte [rsp+rax],0
	cmp	byte [rsp],'m'			; "max"
	je	.no_quota
	mov	rdi,rsp
	call	.number
	jc	.no_quota
	mov	r8,rax				; quota
	cmp	byte [rdi],' '
	jne	.no_quota
	inc	rdi
	call	.number
	jc	.no_quota
	test	rax,rax
	jz	.no_quota
	mov	rcx,rax
	mov	rax,r8
	add	rax,rcx
	dec	rax
	xor	edx,edx
	div	rcx				; ceil
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	mov	[g_cpu_quota],eax
.no_quota:
	add	rsp,64
	pop	rbx
	ret
; rdi = text. rax = number, rdi past it, CF when no digit.
.number:
	xor	eax,eax
	xor	ecx,ecx
@@:
	movzx	edx,byte [rdi]
	sub	edx,'0'
	cmp	edx,9
	ja	@f
	imul	rax,rax,10
	add	rax,rdx
	inc	rdi
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.nonum
	clc
	ret
.nonum:
	stc
	ret

; eax = worker count: the configured one, or min(mask, quota).
cpu_worker_count:
	mov	eax,[g_plan_workers]
	test	eax,eax
	jnz	.done
	mov	eax,[g_cpu_count]
	mov	ecx,[g_cpu_quota]
	test	ecx,ecx
	jz	@f
	cmp	ecx,eax
	cmovb	eax,ecx
@@:
	cmp	eax,MAX_WORKERS
	jbe	.done
	mov	eax,MAX_WORKERS
.done:
	ret

PIN_OFF		:= 0
PIN_ON		:= 1
PIN_AUTO	:= 2
PIN_HIGH	:= 50		; auto: busy past this share of a tick, pinned
PIN_LOW		:= 20		; and below this one, free again

bss
	g_plan_pin	dd ?		; `pin_workers`: PIN_*
	g_pin_index	dd ?		; this worker's index
	g_pinned	dd ?		; pinned now
	align 8
	g_util_cpu	dq ?		; its CPU time (ns) at the last tick
	g_util_wall	dq ?		; and the clock's
end bss

CLOCK_PROCESS_CPUTIME_ID := 2
PIN_GAP_US	:= 50		; auto: a wait this long is a pause in the work
PIN_BUSY_US	:= 2000		; and this long without one, a worker pins itself now

bss
	align 8
	g_wait_t0	dq ?		; TSC as the wait for events began
	g_busy_since	dq ?		; TSC of the last pause (a wait of PIN_GAP_US)
	g_busy_cpu	dq ?		; CPU time (ns) when that busy spell was first seen, 0 not yet
	g_busy_tsc	dq ?		; and the TSC then
end bss
PIN_BUSY_SHARE	:= 75		; percent of a busy spell spent running: work, not a busy host

; Around each wait for events (both engines), auto: a worker under a sudden
; load (a flood) pins itself within PIN_BUSY_US instead of at the next tick,
; a second later; one at ease waits often and is left to the tick.
macro pin_wait_begin
	push	rax
	push	rdx
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[g_wait_t0],rax
	pop	rdx
	pop	rax
end macro
macro pin_wait_end
	push	rax
	push	rcx
	push	rdx
	push	r8
	call	pin_after_wait
	pop	r8
	pop	rdx
	pop	rcx
	pop	rax
end macro

; Keeps all but rax, rcx, rdx, r8 (pin_wait_end saves those).
pin_after_wait:
	cmp	dword [g_plan_pin],PIN_AUTO
	jne	.out
	cmp	dword [g_pinned],0
	jne	.out
	mov	rcx,[g_tsc_per_us]
	test	rcx,rcx
	jz	.out
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	rdx,rax
	sub	rdx,[g_wait_t0]			; how long it waited
	imul	r8,rcx,PIN_GAP_US
	cmp	rdx,r8
	jb	@f
	mov	[g_busy_since],rax		; a pause
	mov	qword [g_busy_cpu],0
	ret
@@:
	cmp	qword [g_busy_since],0
	jne	@f
	mov	[g_busy_since],rax		; (the first time)
	ret
@@:
	mov	r8,rax
	sub	rax,[g_busy_since]
	imul	rcx,rcx,PIN_BUSY_US
	cmp	rax,rcx
	jb	.out
	; no pause for PIN_BUSY_US: running, or waiting for a CPU on a busy host
	; (then the events pile up and every wait returns at once)? The CPU it
	; used over the next spell decides.
	push	rsi
	push	rdi
	push	r9
	push	r10
	push	r11
	push	rcx
	sub	rsp,16
	mov	edi,CLOCK_PROCESS_CPUTIME_ID
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	r9,[rsp],1000000000
	add	r9,[rsp+8]			; CPU ns now
	add	rsp,16
	pop	rcx
	cmp	qword [g_busy_cpu],0
	jne	.second
	mov	[g_busy_cpu],r9			; the spell's start: look again later
	mov	[g_busy_tsc],r8
	jmp	.done_check
.second:
	mov	rax,r8
	sub	rax,[g_busy_tsc]		; TSC ticks since
	cmp	rax,rcx
	jb	.done_check			; (not a whole spell yet)
	sub	r9,[g_busy_cpu]			; CPU ns used
	mov	qword [g_busy_cpu],0
	xor	edx,edx
	div	qword [g_tsc_per_us]		; us elapsed
	imul	rax,rax,1000 * PIN_BUSY_SHARE / 100	; ns it should have run
	cmp	r9,rax
	jb	.done_check			; a busy host: free still
	pop	r11
	pop	r10
	pop	r9
	pop	rdi
	pop	rsi
	push	rsi
	push	rdi
	push	r9
	push	r10
	push	r11
	mov	dword [g_pinned],1
	mov	edi,[g_pin_index]
	call	pin_now
	pop	r11
	pop	r10
	pop	r9
	pop	rdi
	pop	rsi
.out:
	ret
.done_check:
	pop	r11
	pop	r10
	pop	r9
	pop	rdi
	pop	rsi
	ret

; Workers and cores. Pinned (`pin_workers on`), a worker keeps its core's
; caches, and two workers never share a core: under load, its tail is the
; best (at 80000 req/s on two cores, p99 73-89 us; free, 466-532). Free
; (`off`), it runs wherever a core is idle: on a host it shares (anything
; else, the kernel's own threads included) a pinned worker waits for
; whatever took its core, milliseconds, where a free one moves (at 10000/s,
; p99.9 54-59 us free, 540-679 pinned). `auto`, the default, is each by turn:
; a worker busy past PIN_HIGH of a tick pins itself, one below PIN_LOW lets go.

; Tick, auto: this worker's share of busy time since the last tick, and its
; affinity to match.
pin_tick:
	cmp	dword [g_plan_pin],PIN_AUTO
	jne	.out
	; the CPU this worker used since the last tick (in the kernel too: with
	; io_uring much of its work is in io_uring_enter) against the clock
	sub	rsp,16
	mov	edi,CLOCK_PROCESS_CPUTIME_ID
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	r8,[rsp],1000000000
	add	r8,[rsp+8]
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	r9,[rsp],1000000000
	add	r9,[rsp+8]
	add	rsp,16
	mov	rcx,r8
	xchg	rcx,[g_util_cpu]
	mov	rdx,r9
	xchg	rdx,[g_util_wall]
	test	rdx,rdx
	jz	.out				; (the first tick: from now on)
	sub	r9,rdx				; elapsed
	jz	.out
	sub	r8,rcx				; busy
	imul	rax,r8,100
	xor	edx,edx
	div	r9				; eax = busy, percent
	cmp	dword [g_pinned],0
	jne	.pinned
	cmp	eax,PIN_HIGH
	jb	.out
	mov	dword [g_pinned],1
	mov	edi,[g_pin_index]
	jmp	pin_now
.pinned:
	cmp	eax,PIN_LOW
	jae	.out
	mov	dword [g_pinned],0
	; free: back to every CPU it was given
	xor	edi,edi
	mov	esi,128
	lea	rdx,[g_affinity]
	mov	eax,SYS_sched_setaffinity
	syscall
.out:
	ret

pin_to_cpu:
	mov	[g_pin_index],edi
	cmp	dword [g_plan_pin],PIN_ON
	jne	pin_free
	mov	dword [g_pinned],1
	; edi = worker index: onto its core now
pin_now:
	sub	rsp,128
	mov	ecx,edi
	; n modulo the number of CPUs in the mask
	mov	eax,ecx
	xor	edx,edx
	div	dword [g_cpu_count]
	mov	ecx,edx
	xor	edx,edx				; bit index
.find:
	cmp	edx,1024
	jae	.done
	bt	[g_affinity],edx
	jnc	.next
	test	ecx,ecx
	jz	.found
	dec	ecx
.next:
	inc	edx
	jmp	.find
.found:
	lea	rdi,[rsp]
	xor	eax,eax
	mov	ecx,16
	push	rdx
	rep	stosq
	pop	rdx
	bts	[rsp],edx
	xor	edi,edi
	mov	esi,128
	mov	rdx,rsp
	mov	eax,SYS_sched_setaffinity
	syscall
.done:
	add	rsp,128
pin_free:
	ret

; rax = seconds on the monotonic clock.
monotonic_seconds:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,24
	ret
