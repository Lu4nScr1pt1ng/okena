; A request that crashes workers again and again: quarantined.
;
; A worker notes the session it is working on (g_cur_sess, at each event).
; When it dies of a fault (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP), or of
; the watchdog's SIGABRT when it is stuck, a handler on its own stack hashes
; that session's request head (the bytes about to be parsed, H_HEADN of them)
; into its heartbeat line, then lets the signal take it. The supervisor reads
; the hash when it reaps the worker and counts it in a table every worker
; sees; at the second crash on the same head that head is quarantined for
; QZ_SECS: workers answer it 503 before parsing it. The hash is of the whole
; head, so a request merely like it is not touched; the cost when nothing is
; quarantined is one load a request. HTTP/1.x requests (HTTP/2 and 3 decode
; their heads elsewhere).

QZ_N		:= 64
QZ_CRASHES	:= 2
QZ_SECS		:= 600
QZ_LIVE		:= 0			; d: entries quarantined now (a hint: 0, none)
QZ_E		:= 64			; the entries
QZ_FP		:= 0			; q: the head's hash, 0 free
QZ_COUNT	:= 8			; d: crashes on it
QZ_UNTIL	:= 12			; d: monotonic second its quarantine ends
QZ_ESIZE	:= 16
QZ_SIZE		:= QZ_E + QZ_N * QZ_ESIZE
H_HEADN		:= 380			; d: the length of the head being parsed (proxy.inc's H_)
HB_FP_OFF	:= 8			; the hash's place in a heartbeat line

bss
	align 8
	g_qz		dq ?		; shared: the table
	g_cur_sess	dd ?		; this worker: the session of the event at hand
	align 16
	g_qz_stack	rb 65536	; the handler's stack (a fault may be the stack's)
end bss

rodata
	align 8
	sigact_crash	dq on_crash, SA_SIGINFO or SA_RESTORER or SA_ONSTACK or SA_RESETHAND, sigsys_restorer, 0
	qz_signals	db SIGSEGV_, SIGBUS_, SIGILL_, SIGFPE_, SIGTRAP_, SIGABRT_, 0
end rodata

SA_ONSTACK	:= 0x08000000
SA_RESETHAND	:= 0x80000000
SIGILL_		:= 4
SIGTRAP_	:= 5
SIGABRT_	:= 6
SIGBUS_		:= 7
SIGFPE_		:= 8
SIGSEGV_	:= 11
SYS_sigaltstack	:= 131

; supervisor, before the first fork
qz_init:
	xor	edi,edi
	mov	esi,QZ_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	jbe	@f
	xor	eax,eax				; (no table: nothing quarantined)
@@:
	mov	[g_qz],rax
	ret

; a worker, starting: the handlers, on a stack of their own
qz_worker_init:
	mov	dword [g_cur_sess],-1
	sub	rsp,24
	lea	rax,[g_qz_stack]
	mov	[rsp],rax			; stack_t { sp, flags, size }
	mov	dword [rsp+8],0
	mov	qword [rsp+16],65536
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_sigaltstack
	syscall
	add	rsp,24
	push	rbx
	lea	rbx,[qz_signals]
.sig:
	movzx	edi,byte [rbx]
	test	edi,edi
	jz	.done
	lea	rsi,[sigact_crash]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall
	inc	rbx
	jmp	.sig
.done:
	pop	rbx
	ret

; the handler: the head of the session at hand, hashed into the heartbeat
; line; returning, the fault comes again with the default action (reset)
on_crash:
	mov	ebx,[g_cur_sess]
	cmp	ebx,[g_sessions]
	jae	.out
	mov	r15d,ebx
	shl	r15,H_SHIFT
	add	r15,[g_http_base]
	mov	ecx,[r15+H_HEADN]
	test	ecx,ecx
	jz	.out
	cmp	ecx,H_IN_CAP
	ja	.out
	mov	rsi,[r15+H_BUF]
	test	rsi,rsi
	jz	.out
	add	rsi,HB_IN
	call	hash_bytes
	or	rax,1				; (0 is none)
	mov	rcx,[g_hb]
	mov	edx,[g_hb_slot]
	mov	[rcx+rdx+HB_FP_OFF],rax
.out:
	ret

; rdi/esi = a request head about to be parsed: CF when it is quarantined.
; Only called when the table says something is.
qz_hit:
	push	rbx
	mov	ecx,esi
	mov	rsi,rdi
	call	hash_bytes
	or	rax,1
	mov	rbx,rax
	call	monotonic_seconds
	mov	rcx,[g_qz]
	lea	rdx,[rcx+QZ_E]
	lea	r8,[rcx+QZ_SIZE]
.e:
	cmp	rdx,r8
	jae	.no
	cmp	[rdx+QZ_FP],rbx
	jne	.next
	cmp	dword [rdx+QZ_COUNT],QZ_CRASHES
	jb	.no
	cmp	[rdx+QZ_UNTIL],eax
	jbe	.no
	pop	rbx
	stc
	ret
.next:
	add	rdx,QZ_ESIZE
	jmp	.e
.no:
	pop	rbx
	clc
	ret

; supervisor: worker ebx (current generation) died of a signal. Its head's
; hash, if it left one, counted; the second time, quarantined.
qz_crashed:
	push	r12
	push	r13
	call	hb_line
	add	rax,[g_hb]
	xor	r12d,r12d
	xchg	r12,[rax+HB_FP_OFF]		; (the next worker starts clean)
	test	r12,r12
	jz	.out
	mov	rcx,[g_qz]
	test	rcx,rcx
	jz	.out
	; its entry, else a free one, else the one whose quarantine ends first
	lea	rdx,[rcx+QZ_E]
	lea	r8,[rcx+QZ_SIZE]
	xor	r9d,r9d				; a free one
	xor	r10d,r10d			; the oldest
.e:
	cmp	rdx,r8
	jae	.new
	cmp	[rdx+QZ_FP],r12
	je	.found
	cmp	qword [rdx+QZ_FP],0
	jne	@f
	test	r9,r9
	jnz	@f
	mov	r9,rdx
@@:
	test	r10,r10
	jz	.older
	mov	eax,[rdx+QZ_UNTIL]
	cmp	eax,[r10+QZ_UNTIL]
	jae	@f
.older:
	mov	r10,rdx
@@:
	add	rdx,QZ_ESIZE
	jmp	.e
.new:
	mov	rdx,r9
	test	rdx,rdx
	jnz	@f
	mov	rdx,r10
@@:
	mov	dword [rdx+QZ_COUNT],0
	mov	dword [rdx+QZ_UNTIL],0
	mov	[rdx+QZ_FP],r12
.found:
	inc	dword [rdx+QZ_COUNT]
	mov	r13,rdx
	call	log_begin
	out_lit 'worker '
	mov	eax,ebx
	call	out_u64
	out_lit ' died on a request (head '
	mov	rax,r12
	call	out_u64
	out_lit ')'
	cmp	dword [r13+QZ_COUNT],QZ_CRASHES
	jb	.said
	call	monotonic_seconds
	add	eax,QZ_SECS
	mov	[r13+QZ_UNTIL],eax
	out_lit ': twice now, so it is answered 503 for 10 minutes, unparsed'
	call	qz_tick
.said:
	call	log_end
.out:
	pop	r13
	pop	r12
	ret

; supervisor, each second: how many are quarantined now
qz_tick:
	mov	rcx,[g_qz]
	test	rcx,rcx
	jz	.out
	push	rcx
	call	monotonic_seconds
	pop	rcx
	xor	r9d,r9d
	lea	rdx,[rcx+QZ_E]
	lea	r8,[rcx+QZ_SIZE]
.e:
	cmp	rdx,r8
	jae	.counted
	cmp	dword [rdx+QZ_COUNT],QZ_CRASHES
	jb	@f
	cmp	[rdx+QZ_UNTIL],eax
	jbe	@f
	inc	r9d
@@:
	add	rdx,QZ_ESIZE
	jmp	.e
.counted:
	mov	[rcx+QZ_LIVE],r9d
.out:
	ret
