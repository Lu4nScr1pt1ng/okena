; Shared helpers: output, numbers, environment, CPU checks.
;
; Calling convention for every routine in this program (SysV-like):
; arguments in rdi, rsi, rdx, rcx, r8; result in rax; rbx, rbp and r12-r15
; are preserved; everything else, including flags, may be clobbered.
;
; Output goes through one buffer per stream. Lines are assembled with
; out_* calls and written with out_flush, so a message is one write(2)
; and lines from different processes do not interleave.

OUT_CAP := 16384

bss
	g_argc		dq ?
	g_argv		dq ?
	g_envp		dq ?
	g_is_worker	dd ?
	g_worker_id	dd ?
	g_out_fd	dd ?
	g_out_len	dd ?
	g_out_buf:	rb OUT_CAP
end bss

cstring str_log_prefix, 'okena: '

; Append a literal to the output buffer.
macro out_lit text&
	local s
	cstring s, text
	lea	rsi,[s]
	mov	edx,s.len
	call	out_str
end macro

; Old name used by the log helpers below.
macro log_lit text&
	out_lit text
end macro

; Select the stream for the next out_* calls (1 = stdout, 2 = stderr).
; Flushes whatever was pending on the previous stream.
out_select:
	cmp	edi,[g_out_fd]
	je	.same
	push	rdi
	call	out_flush
	pop	rdi
	mov	[g_out_fd],edi
.same:
	ret

; rsi = text, edx = length. Flushes when the buffer is full.
out_str:
	push	rbx
	push	r12
	mov	rbx,rsi
	mov	r12d,edx
.again:
	mov	ecx,[g_out_len]
	mov	eax,OUT_CAP
	sub	eax,ecx
	jnz	@f
	call	out_flush
	jmp	.again
@@:
	mov	edx,r12d
	cmp	edx,eax
	jbe	@f
	mov	edx,eax
@@:
	lea	rdi,[g_out_buf+rcx]
	mov	rsi,rbx
	add	ecx,edx
	mov	[g_out_len],ecx
	add	rbx,rdx
	sub	r12d,edx
	mov	ecx,edx
	rep	movsb
	test	r12d,r12d
	jnz	.again
	pop	r12
	pop	rbx
	ret

; dil = one byte.
out_char:
	mov	ecx,[g_out_len]
	cmp	ecx,OUT_CAP
	jb	@f
	push	rdi
	call	out_flush
	pop	rdi
	mov	ecx,[g_out_len]
@@:
	mov	[g_out_buf+rcx],dil
	inc	ecx
	mov	[g_out_len],ecx
	ret

; edi = count of spaces.
out_spaces:
	push	rbx
	mov	ebx,edi
@@:
	test	ebx,ebx
	jz	@f
	mov	edi,' '
	call	out_char
	dec	ebx
	jmp	@b
@@:
	pop	rbx
	ret

; rax = unsigned value.
out_u64:
	sub	rsp,24
	lea	rdi,[rsp+24]
	mov	ecx,10
@@:
	xor	edx,edx
	div	rcx
	add	dl,'0'
	dec	rdi
	mov	[rdi],dl
	test	rax,rax
	jnz	@b
	mov	rsi,rdi
	lea	rdx,[rsp+24]
	sub	rdx,rdi
	call	out_str
	add	rsp,24
	ret

; rsi = NUL-terminated string.
out_cstr:
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	jmp	out_str

; Write the buffer to the selected stream.
out_flush:
	push	rbx
	xor	ebx,ebx
.loop:
	mov	edx,[g_out_len]
	sub	edx,ebx
	jbe	.done
	lea	rsi,[g_out_buf+rbx]
	mov	edi,[g_out_fd]
	mov	eax,SYS_write
	syscall
	cmp	rax,-EINTR
	je	.loop
	test	rax,rax
	jle	.done				; nowhere to report it
	add	ebx,eax
	jmp	.loop
.done:
	mov	dword [g_out_len],0
	pop	rbx
	ret

; Start a log line on stderr: "okena: " or "okena: worker N: ".
log_begin:
	mov	edi,2
	call	out_select
	lea	rsi,[str_log_prefix]
	mov	edx,str_log_prefix.len
	call	out_str
	cmp	dword [g_is_worker],0
	je	.done
	out_lit 'worker '
	mov	eax,[g_worker_id]
	call	out_u64
	out_lit ': '
.done:
	ret

log_str = out_str
log_u64 = out_u64

; rax = signed value.
log_i64:
	test	rax,rax
	jns	out_u64
	push	rax
	out_lit '-'
	pop	rax
	neg	rax
	jmp	out_u64

; End the line and write it.
log_end:
	mov	edi,10
	call	out_char
	jmp	out_flush

; edi = exit status. Does not return.
exit_process:
	push	rdi
	call	out_flush
	pop	rdi
	mov	eax,SYS_exit_group
	syscall
	hlt

; rdi, rsi = NUL-terminated strings. eax = 1 when equal.
cstr_eq:
	xor	ecx,ecx
@@:
	mov	al,[rdi+rcx]
	cmp	al,[rsi+rcx]
	jne	.differ
	inc	rcx
	test	al,al
	jnz	@b
	mov	eax,1
	ret
.differ:
	xor	eax,eax
	ret

; rdi = text, esi = length, rdx = NUL-terminated literal. eax = 1 when equal.
mem_eq_cstr:
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	je	.end
	mov	al,[rdi+rcx]
	cmp	al,[rdx+rcx]
	jne	.differ
	inc	ecx
	jmp	@b
.end:
	cmp	byte [rdx+rcx],0
	jne	.differ
	mov	eax,1
	ret
.differ:
	xor	eax,eax
	ret

; rdi, rsi = buffers, edx = length. eax = 1 when equal.
mem_eq:
	mov	ecx,edx
	repe	cmpsb
	sete	al
	movzx	eax,al
	ret

; rdi, rsi = buffers, edx = length. eax = 1 when equal ignoring ASCII case.
mem_eq_nocase:
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.yes
	movzx	eax,byte [rdi+rcx]
	movzx	r8d,byte [rsi+rcx]
	or	eax,0x20
	or	r8d,0x20
	cmp	eax,r8d
	jne	.no
	inc	ecx
	jmp	.next
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; rdi = "NAME=" prefix, esi = its length. rax = value or 0 when unset.
getenv:
	mov	r8,[g_envp]
.next:
	mov	r9,[r8]
	test	r9,r9
	jz	.none
	add	r8,8
	xor	ecx,ecx
.compare:
	cmp	ecx,esi
	je	.found
	mov	al,[r9+rcx]
	cmp	al,[rdi+rcx]
	jne	.next
	inc	ecx
	jmp	.compare
.found:
	lea	rax,[r9+rsi]
	ret
.none:
	xor	eax,eax
	ret

; The scanners use AVX2 and BMI1/BMI2 (x86-64-v3). Refuse to start on
; anything older instead of faulting on the first request.
cpu_require:
	push	rbx
	mov	eax,1
	cpuid
	and	ecx,(1 shl 27) or (1 shl 28)		; OSXSAVE, AVX
	cmp	ecx,(1 shl 27) or (1 shl 28)
	jne	.unsupported
	xor	ecx,ecx
	xgetbv
	and	eax,6					; XMM and YMM state enabled by the OS
	cmp	eax,6
	jne	.unsupported
	mov	eax,7
	xor	ecx,ecx
	cpuid
	and	ebx,(1 shl 3) or (1 shl 5) or (1 shl 8)	; BMI1, AVX2, BMI2
	cmp	ebx,(1 shl 3) or (1 shl 5) or (1 shl 8)
	jne	.unsupported
	pop	rbx
	ret
.unsupported:
	call	log_begin
	out_lit 'this CPU lacks AVX2/BMI2 (x86-64-v3 is required)'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process
