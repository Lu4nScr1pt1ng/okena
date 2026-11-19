; The memory guard: in a cgroup with a memory limit (docker --memory, a pod's
; resources.limits.memory), okena keeps away from the OOM killer instead of
; meeting it. The workers look at the cgroup's use (memory.current, one read)
; once a tick and every MG_EVERY new HTTP/2 streams; from MG_HI percent of the
; limit up to when it is back under MG_LO:
;
;   - new HTTP/2 streams are refused (REFUSED_STREAM: safe to send again);
;   - HTTP/2 connections with streams that wait for the client's window or for
;     room are sent GOAWAY (ENHANCE_YOUR_CALM) and closed: a client that asks
;     and never takes the answers holds memory it is not using
;     (CVE-2019-9517, "window stall").
;
; Without a limit (memory.max "max", or no cgroup v2) it does nothing and costs
; nothing.

MG_HI		:= 80			; percent of memory.max: tight from here
MG_LO		:= 70			; and until under this
MG_EVERY	:= 256			; new streams between looks

bss
	align 8
	g_mg_hi		dq ?		; bytes, 0: no limit
	g_mg_lo		dq ?
	g_mg_fd		dd ?		; memory.current, open (the workers inherit it)
	g_mg_tight	dd ?
	g_mg_count	dd ?
end bss

cstring str_mem_max, '/sys/fs/cgroup/memory.max',0
cstring str_mem_cur, '/sys/fs/cgroup/memory.current',0

; the supervisor, at the start: the limit, and memory.current kept open
mg_discover:
	push	rbx
	sub	rsp,64
	mov	qword [g_mg_hi],0
	mov	dword [g_mg_fd],-1
	mov	edi,AT_FDCWD
	lea	rsi,[str_mem_max]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out
	mov	ebx,eax
	mov	edi,ebx
	mov	rsi,rsp
	mov	edx,63
	xor	eax,eax				; read
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	test	rax,rax
	jle	.out
	mov	byte [rsp+rax],0
	mov	rsi,rsp
	call	mg_number			; ("max": none)
	jc	.out
	test	rax,rax
	jz	.out
	mov	rcx,rax
	imul	rax,rcx,MG_HI			; (limits fit: 100 * 2^56)
	xor	edx,edx
	mov	r8d,100
	div	r8
	mov	r9,rax
	imul	rax,rcx,MG_LO
	xor	edx,edx
	div	r8
	mov	r10,rax
	mov	edi,AT_FDCWD
	lea	rsi,[str_mem_cur]
	mov	edx,O_RDONLY			; (kept across the workers' fork)
	push	r9
	push	r10
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	pop	r10
	pop	r9
	test	eax,eax
	js	.out
	mov	[g_mg_fd],eax
	mov	[g_mg_hi],r9
	mov	[g_mg_lo],r10
.out:
	add	rsp,64
	pop	rbx
	ret

; rsi = text: rax = its leading decimal number, CF when none
mg_number:
	xor	eax,eax
	xor	ecx,ecx
.d:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.end
	imul	rax,rax,10
	add	rax,rdx
	inc	rsi
	inc	ecx
	jmp	.d
.end:
	test	ecx,ecx
	jz	.no
	clc
	ret
.no:
	stc
	ret

; tick, and every MG_EVERY new streams: g_mg_tight from the cgroup's use.
; Keeps rbx, rbp, r12-r15.
mg_check:
	cmp	qword [g_mg_hi],0
	je	.out
	sub	rsp,40
	mov	edi,[g_mg_fd]
	mov	rsi,rsp
	mov	edx,31
	xor	r10d,r10d
	mov	eax,SYS_pread64
	syscall
	test	rax,rax
	jle	.done
	mov	byte [rsp+rax],0
	mov	rsi,rsp
	call	mg_number
	jc	.done
	cmp	rax,[g_mg_hi]
	jae	.tight
	cmp	rax,[g_mg_lo]
	jae	.done				; (between: as it was)
	cmp	dword [g_mg_tight],0
	je	.done
	mov	dword [g_mg_tight],0
	call	log_begin
	out_lit 'memory: worker '
	mov	eax,[g_worker_id]
	call	out_u64
	out_lit ': back under the limit, new streams taken again'
	call	log_end
	jmp	.done
.tight:
	cmp	dword [g_mg_tight],0
	jne	.done
	mov	dword [g_mg_tight],1
	call	log_begin
	out_lit 'memory: worker '
	mov	eax,[g_worker_id]
	call	out_u64
	out_lit ': near the cgroup limit; new HTTP/2 streams refused, stalled connections closed'
	call	log_end
.done:
	add	rsp,40
.out:
	ret

; tick: the cgroup looked at; tight, the HTTP/2 connections that hold answers
; their clients do not take are closed
mg_tick:
	call	mg_check
	cmp	dword [g_mg_tight],0
	je	.out
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_sess_hwm]
	jae	.done
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2C
	jz	.skip
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.skip
	c2_regs
	test	dword [r13+C2_FLAGS],C2F_CLOSING or C2F_CLIENT
	jnz	.skip
	cmp	dword [r13+C2_BLKH],0		; streams waiting for window or room
	je	.skip
	mov	edx,H2E_CALM
	call	h2_goaway
	call	h2_pump				; (its GOAWAY out, then closed)
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
.out:
	ret
