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

; edi = worker index: pin to the n-th CPU of the startup mask.
pin_to_cpu:
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
