; Tracing (W3C Trace Context, spans out over OTLP): on a listener with
; `tracing`, each request is a server span. Its trace is the client's, when
; it sends a valid `traceparent` (its sampled flag decides, as
; OpenTelemetry's parent-based sampler does), or a new one, kept for
; `sample=` of them. The backend gets `traceparent` with okena's span as its
; parent, sampled or not, so the trace goes on through it either way.
;
; A kept span leaves at the end of its exchange as one line through the
; logger's pipe, like an access log line, and the logger sends it to the
; collector: nothing in a worker waits on it. Its id and its trace's are also
; in the access log line, so logs and traces meet.

TRC_ID		:= 0			; the trace id, 32 hex digits
TRC_SPAN		:= 32			; okena's span id, 16
TRC_PARENT	:= 48			; the client's span id, 16 (TF_PARENT)
TRC_FLAGS	:= 64			; d: TF_*
TRC_T0		:= 72			; q: wall clock ns at the request head
TRC_SIZE		:= 80

TF_ON		:= 1			; the request has a trace
TF_SAMPLED	:= 2			; and it is kept (the flag sent on)
TF_EMIT		:= 4			; its span is still to be sent
TF_PARENT	:= 8			; the client's span is its parent

bss
	align 8
	g_trc_rng	dq ?
end bss


; r15 = record, rcx = its listener, g_hm = the request: its trace, or none.
; Keeps rbx and r12-r15.
trace_begin:
	mov	rdi,[r15+H_BUF]
	mov	dword [rdi+HB_TRC+TRC_FLAGS],0
	cmp	dword [rcx+LS_TRACE],0
	je	.none
	push	rbx
	push	r12
	push	r13
	lea	r12,[rdi+HB_TRC]
	mov	r13d,[rcx+LS_TSAMPLE]
	xor	ebx,ebx
.field:
	lea	r8,[g_hm]
	cmp	ebx,[r8+HM_NHDR]
	jae	.new
	imul	rdi,rbx,HF_SIZE
	lea	rdi,[r8+HM_HDRS+rdi]
	inc	ebx
	push	rdi
	lea	rsi,[hn_traceparent]
	call	hf_is
	pop	rdi
	jnz	.field
	mov	rsi,[rdi+HF_VALUE]
	mov	edx,[rdi+HF_VLEN]
	call	trace_parse
	jc	.new				; not one to go on with: a trace of our own
	jmp	.span
.new:
	call	trace_rand
	lea	rdi,[r12+TRC_ID]
	call	trace_hex16
	call	trace_rand
	push	rax
	lea	rdi,[r12+TRC_ID+16]
	call	trace_hex16
	pop	rax
	; kept for `sample=`: the trace id's low bits, as TraceIdRatio
	mov	dword [r12+TRC_FLAGS],TF_ON
	mov	eax,eax
	imul	rax,rax,1000000
	shr	rax,32
	cmp	eax,r13d
	jae	.span
	or	dword [r12+TRC_FLAGS],TF_SAMPLED or TF_EMIT
.span:
@@:
	call	trace_rand
	test	rax,rax
	jz	@b
	lea	rdi,[r12+TRC_SPAN]
	call	trace_hex16
	call	wall_ns
	mov	[r12+TRC_T0],rax
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; rsi/edx = a traceparent's value, r12 = the trace: it, read. CF when it is
; not one ("VERSION-TRACEID-PARENTID-FLAGS", lowercase hex, ids not all zero;
; a later version may add fields after a '-').
trace_parse:
	cmp	edx,55
	jb	.bad
	je	@f
	cmp	byte [rsi+55],'-'
	jne	.bad
	cmp	word [rsi],'00'
	je	.bad				; version 00 is exactly 55
@@:
	cmp	word [rsi],'ff'
	je	.bad
	cmp	byte [rsi+2],'-'
	jne	.bad
	cmp	byte [rsi+35],'-'
	jne	.bad
	cmp	byte [rsi+52],'-'
	jne	.bad
	push	rsi
	mov	ecx,2
	call	.hex
	lea	rsi,[rsi+3]
	mov	ecx,32
	call	.hex
	lea	rsi,[rsi+33]
	mov	ecx,16
	call	.hex
	lea	rsi,[rsi+17]
	mov	ecx,2
	call	.hex
	pop	rsi
	jc	.bad
	; no id all zero
	lea	rdi,[rsi+3]
	mov	ecx,32
	call	.zero
	je	.bad
	lea	rdi,[rsi+36]
	mov	ecx,16
	call	.zero
	je	.bad
	push	rsi
	lea	rsi,[rsi+3]
	lea	rdi,[r12+TRC_ID]
	mov	ecx,32
	rep	movsb
	mov	rsi,[rsp]
	lea	rsi,[rsi+36]
	lea	rdi,[r12+TRC_PARENT]
	mov	ecx,16
	rep	movsb
	pop	rsi
	mov	dword [r12+TRC_FLAGS],TF_ON or TF_PARENT
	movzx	eax,byte [rsi+54]		; the flags' low digit: bit 0 is sampled
	cmp	al,'a'
	jb	@f
	sub	al,'a' - 10 - '0'
@@:
	test	al,1
	jz	@f
	or	dword [r12+TRC_FLAGS],TF_SAMPLED or TF_EMIT
@@:
	clc
	ret
.bad:
	stc
	ret
; rsi = text, ecx = digits: CF unless all lowercase hex (keeps rsi; sticky CF)
.hex:
	jc	.hex_out
	xor	edx,edx
@@:
	movzx	eax,byte [rsi+rdx]
	sub	al,'0'
	cmp	al,9
	jbe	.digit
	sub	al,'a' - '0'
	cmp	al,5
	ja	.hex_bad
.digit:
	inc	edx
	cmp	edx,ecx
	jb	@b
	clc
.hex_out:
	ret
.hex_bad:
	stc
	ret
; rdi = text, ecx = length: ZF when it is all '0'
.zero:
	mov	al,'0'
	repe	scasb
	ret

; rax = 64 random bits (xorshift64*, seeded once a worker). Keeps all else.
trace_rand:
	mov	rax,[g_trc_rng]
	test	rax,rax
	jnz	@f
	push	rdx
	rdtsc
	shl	rdx,32
	or	rax,rdx
	xor	rax,[g_seed]
	mov	edx,[g_worker_id]
	shl	rdx,48
	xor	rax,rdx
	or	rax,1
	pop	rdx
@@:
	push	rcx
	mov	rcx,rax
	shr	rcx,12
	xor	rax,rcx
	mov	rcx,rax
	shl	rcx,25
	xor	rax,rcx
	mov	rcx,rax
	shr	rcx,27
	xor	rax,rcx
	mov	[g_trc_rng],rax
	mov	rcx,2685821657736338717
	imul	rax,rcx
	pop	rcx
	ret

; rax = value, rdi = out: 16 lowercase hex digits. Keeps rax.
trace_hex16:
	push	rax
	lea	rdi,[rdi+15]
	mov	ecx,16
@@:
	mov	edx,eax
	and	edx,15
	mov	dl,[hex_digits+rdx]
	mov	[rdi],dl
	dec	rdi
	shr	rax,4
	dec	ecx
	jnz	@b
	pop	rax
	ret

; r15 = record, rdi = the upstream head: `traceparent` with okena's span as
; the parent, when the request has a trace. rdi = after it.
trace_emit:
	mov	rax,[r15+H_BUF]
	test	dword [rax+HB_TRC+TRC_FLAGS],TF_ON
	jz	.none
	push	rax
	memit_x 'traceparent: 00-'
	pop	rax
	lea	rsi,[rax+HB_TRC+TRC_ID]
	mov	ecx,32
	rep	movsb
	mov	byte [rdi],'-'
	inc	rdi
	lea	rsi,[rax+HB_TRC+TRC_SPAN]
	mov	ecx,16
	rep	movsb
	mov	dword [rdi],'-00'
	test	dword [rax+HB_TRC+TRC_FLAGS],TF_SAMPLED
	jz	@f
	mov	byte [rdi+2],'1'
@@:
	mov	word [rdi+3],0x0A0D
	add	rdi,5
.none:
	ret

; r15 = record, r14 = a request field: ZF when it is the client's
; traceparent and okena sends its own instead. Keeps rdi.
trace_drops:
	mov	rax,[r15+H_BUF]
	test	dword [rax+HB_TRC+TRC_FLAGS],TF_ON
	jz	.keep
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_traceparent]
	call	hf_is
	pop	rdi
	ret
.keep:
	or	eax,1				; (NZ)
	ret
