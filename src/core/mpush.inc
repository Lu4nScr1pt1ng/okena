; Metrics pushed over OTLP/HTTP (JSON), beside Prometheus' pull:
; `okena { metrics_push otlp://collector:4318 [every=15s] [trust=FILE] }`.
;
; The logger, which already posts logs and spans and waits on collectors so
; that nothing else does, renders /metrics' text every `every=` (as the admin
; process would) and turns it into OTLP metrics: a family of `# TYPE counter`
; or `histogram` gives cumulative monotonic sums (one metric a series name:
; _bucket, _sum and _count apart, `le` an attribute), the rest gauges; labels
; become attributes. Each push replaces one not yet taken (a newer snapshot
; says more than an older one). It goes to /v1/metrics, or the URL's path.

MP_CAP		:= 8 shl 20			; the JSON of one push, at most
MP_HEAD_ROOM	:= 4096

bss
	align 8
	g_mp_next	dq ?			; logger: monotonic ms of the next push
	g_mp_name	dq ?			; the series being written
	g_mp_nlen	dd ?
	g_mp_open	dd ?			; a metric is open
	g_mp_sum	dd ?			; the family is a counter or a histogram
	g_mp_first	dd ?			; no point in the open metric yet
	g_mp_fam	dq ?			; the # TYPE family's name
	g_mp_flen	dd ?
	g_mp_end	dq ?			; where the JSON must stop
end bss

rodata
	mp_mark		db 'metrics '
	mp_v1		db '/v1/metrics'
	mp_v1.len	= $ - mp_v1
end rodata

; rbx = a `metrics_push` node: its destination (the logger's, as "metrics
; URL[ trust=PATH]") and its period. Keeps rbx, r12-r15.
compile_mpush:
	push	r12
	mov	rdx,[rbx+N_ARGS]
	mov	rsi,[rdx+A_VAL]
	mov	ecx,[rdx+A_VLEN]
	cmp	ecx,ALOG_PATH - 1
	jae	.bad
	sub	rsp,64
	mov	rdi,rsp
	call	alog_url
	mov	eax,[rsp+LN_KIND]
	lea	rsp,[rsp+64]
	jc	.bad
	cmp	eax,LKS_OTLP
	jb	.bad
	cmp	eax,LKS_OTLPS
	ja	.bad
	mov	dword [g_plan_mpevery],15
	mov	rdi,rbx
	cstring str_key_every, 'every',0
	lea	rsi,[str_key_every]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	.bad
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jz	.bad
	cmp	eax,86400
	ja	.bad
	mov	[g_plan_mpevery],eax
@@:
	mov	rdi,rbx
	call	alog_dest_node
	lea	eax,[rsi+8]
	cmp	eax,ALOG_PATH - 1
	jae	.bad
	mov	rcx,rsi
	mov	rsi,rdi
	lea	rdi,[g_alog_tmp2]
	mov	rax,qword [mp_mark]
	mov	[rdi],rax
	add	rdi,8
	push	rcx
	rep	movsb
	pop	rsi
	add	esi,8
	lea	rdi,[g_alog_tmp2]
	call	alog_dest_id
	mov	[g_plan_mpush],eax
	pop	r12
	ret
.bad:
	call	log_begin
	out_lit 'metrics_push takes otlp://HOST[:PORT][/PATH] or otlp+https://..., with every=TIME (1s to 1d) and trust=FILE'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------ the logger

; ln_setup, at a destination r14 whose text r12 starts with "metrics ": it
; marked (LN_TRACES 2), its default path /v1/metrics, r12 past the mark.
; ZF when it is one. Keeps all but rax.
mp_dest_mark:
	mov	rax,qword [mp_mark]
	cmp	[r12],rax
	jne	.out
	mov	dword [r14+LN_TRACES],2
	add	r12,8
	xor	eax,eax				; (ZF)
.out:
	ret

; after alog_url: r14's default path /v1/metrics when it is the push's
mp_dest_path:
	cmp	dword [r14+LN_TRACES],2
	jne	.out
	lea	rax,[ln_v1logs]
	cmp	[r14+LN_PATH],rax
	jne	.out
	lea	rax,[mp_v1]
	mov	[r14+LN_PATH],rax
	mov	dword [r14+LN_PLEN],mp_v1.len
.out:
	ret

; the logger's buffers: the batch of r14 (the push's) is MP_CAP, and the admin
; buffer metrics_render writes in. rax = the batch, or 0
mp_buffers:
	xor	edi,edi
	mov	esi,ADMIN_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none
	mov	[g_admin_buf],rax
	xor	edi,edi
	mov	esi,MP_CAP
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	jbe	.out
.none:
	xor	eax,eax
.out:
	ret

; ln_tick, each turn: the push, when it is due. eax = ms until the next one
; (-1: none). Keeps rbx, r12-r15.
mp_tick:
	mov	eax,-1
	cmp	dword [g_plan_mpush],0
	je	.done
	cmp	qword [g_admin_buf],0
	je	.done
	push	r14
	mov	r14d,[g_plan_mpush]
	dec	r14d
	imul	r14,r14,LN_SIZE
	add	r14,[g_ln]
	cmp	dword [r14+LN_TRACES],2
	jne	.never
	cmp	qword [r14+LN_BUF],0
	je	.never
	call	ln_ms
	mov	rcx,[g_mp_next]
	test	rcx,rcx
	jnz	@f
	mov	rcx,rax				; the first: now
@@:
	sub	rcx,rax
	jg	.later
	; due: a snapshot, in place of one not taken
	push	rax
	call	metrics_render			; rsi/edx = the answer, head and text
	lea	rdx,[rsi+rdx]
	mov	rsi,[g_admin_buf]
	add	rsi,256				; (the text: where it began)
	sub	rdx,rsi
	mov	rdi,[r14+LN_BUF]
	call	mp_convert
	mov	rcx,[r14+LN_BUF]
	sub	rdi,rcx
	mov	[r14+LN_BLEN],edi
	mov	dword [r14+LN_BN],1
	pop	rax
	mov	ecx,[g_plan_mpevery]
	imul	rcx,rcx,1000
	add	rcx,rax
	mov	[g_mp_next],rcx
	mov	qword [r14+LN_RETRY],0
	call	ln_post
	mov	ecx,[g_plan_mpevery]
	imul	ecx,ecx,1000
.later:
	mov	eax,ecx
	pop	r14
.done:
	ret
.never:
	pop	r14
	ret

; rsi/edx = Prometheus' text exposition, rdi = out (MP_CAP): the OTLP JSON up
; to the last metric's points (ln_post adds the end, "]}]}]}"). rdi = after.
mp_convert:
	push	rbx
	push	r12
	push	r13
	push	r15
	lea	r13,[rsi+rdx]			; the text's end
	lea	rax,[rdi+MP_CAP-MP_HEAD_ROOM]
	mov	[g_mp_end],rax
	mov	dword [g_mp_open],0
	mov	dword [g_mp_sum],0
	mov	dword [g_mp_flen],0
	mov	r12,rsi
	memit '{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"okena"}}]},"scopeMetrics":[{"scope":{"name":"okena","version":"', OKENA_VERSION, '"},"metrics":['
	; the time of every point
	call	wall_ns
	mov	r15,rax
.line:
	cmp	r12,r13
	jae	.done
	mov	rbx,r12				; its start
@@:
	cmp	r12,r13
	jae	@f
	cmp	byte [r12],10
	je	@f
	inc	r12
	jmp	@b
@@:
	mov	rcx,r12				; rbx..rcx: the line
	inc	r12
	cmp	rbx,rcx
	je	.line
	cmp	byte [rbx],'#'
	jne	.sample
	; # TYPE name kind
	lea	rax,[rbx+7]
	cmp	rax,rcx
	jae	.line
	cmp	dword [rbx],'# TY'
	jne	.line
	cmp	dword [rbx+3],'YPE '
	jne	.line
	lea	rsi,[rbx+7]
	mov	rdx,rsi
@@:
	cmp	rdx,rcx
	jae	.line
	cmp	byte [rdx],' '
	je	@f
	inc	rdx
	jmp	@b
@@:
	mov	[g_mp_fam],rsi
	mov	rax,rdx
	sub	rax,rsi
	mov	[g_mp_flen],eax
	inc	rdx
	mov	dword [g_mp_sum],0
	mov	rax,rcx
	sub	rax,rdx
	cmp	eax,7
	jb	.line
	cmp	dword [rdx],'coun'
	je	.summed
	cmp	dword [rdx],'hist'
	jne	.line
.summed:
	mov	dword [g_mp_sum],1
	jmp	.line
.sample:
	; name[{labels}] value
	mov	rsi,rbx
@@:
	cmp	rsi,rcx
	jae	.line
	cmp	byte [rsi],'{'
	je	@f
	cmp	byte [rsi],' '
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	rdx,rsi
	sub	rdx,rbx				; the series name's length
	jz	.line
	push	rcx
	push	rsi
	call	mp_metric			; rbx/edx: open its metric (or keep it)
	pop	rsi
	pop	rcx
	jc	.full
	; the value: after the labels (a '}' outside quotes) and a space
	mov	r8,rsi				; the labels, if any
	cmp	byte [rsi],'{'
	jne	.value
	xor	r9d,r9d				; in quotes
@@:
	inc	rsi
	cmp	rsi,rcx
	jae	.line
	mov	al,[rsi]
	cmp	al,'\'
	jne	.nq
	inc	rsi
	jmp	@b
.nq:
	cmp	al,'"'
	jne	.nquote
	xor	r9d,1
	jmp	@b
.nquote:
	test	r9d,r9d
	jnz	@b
	cmp	al,'}'
	jne	@b
	inc	rsi
.value:
	cmp	rsi,rcx
	jae	.line
	cmp	byte [rsi],' '
	jne	.line
	inc	rsi
	mov	r9,rsi				; the value: rsi..r10
	mov	r10,rsi
@@:
	cmp	r10,rcx
	jae	@f
	cmp	byte [r10],' '
	je	@f
	movzx	eax,byte [r10]
	cmp	al,'0'
	jb	.sign
	cmp	al,'9'
	jbe	.vok
.sign:
	cmp	al,'.'
	je	.vok
	cmp	al,'-'
	je	.vok
	cmp	al,'+'
	je	.vok
	cmp	al,'e'
	je	.vok
	cmp	al,'E'
	je	.vok
	jmp	.line				; +Inf, NaN: no JSON number
.vok:
	inc	r10
	jmp	@b
@@:
	cmp	r9,r10
	je	.line
	cmp	byte [r9],'+'
	jne	@f
	inc	r9
@@:
	; the point
	cmp	rdi,[g_mp_end]
	jae	.full
	cmp	dword [g_mp_first],0
	jne	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	dword [g_mp_first],0
	memit '{"attributes":['
	cmp	byte [r8],'{'
	jne	.attrs_done
	call	mp_labels			; r8 at '{': the labels as attributes
.attrs_done:
	memit '],"timeUnixNano":"'
	mov	rax,r15
	call	fmt_u64
	memit '","asDouble":'
	mov	rsi,r9
	mov	rcx,r10
	sub	rcx,rsi
	rep	movsb
	mov	byte [rdi],'}'
	inc	rdi
	jmp	.line
.full:
.done:
	cmp	dword [g_mp_open],0
	je	@f
	memit ']}}'
@@:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbx/edx = a series' name: its metric open, a new one when it is not the open
; one. CF when there is no room. Keeps rbx, r8-r15.
mp_metric:
	cmp	dword [g_mp_open],0
	je	.new
	cmp	edx,[g_mp_nlen]
	jne	.close
	push	rdi
	mov	rdi,[g_mp_name]
	mov	rsi,rbx
	mov	ecx,edx
	repe	cmpsb
	pop	rdi
	je	.same
.close:
	memit ']}},'
.new:
	cmp	rdi,[g_mp_end]
	jae	.full
	mov	[g_mp_name],rbx
	mov	[g_mp_nlen],edx
	mov	dword [g_mp_open],1
	mov	dword [g_mp_first],1
	memit '{"name":"'
	mov	rsi,rbx
	mov	ecx,edx
	rep	movsb
	; its family's kind: when its name starts with the family's
	mov	eax,[g_mp_flen]
	test	eax,eax
	jz	.gauge
	cmp	eax,edx
	ja	.gauge
	push	rdi
	mov	rdi,[g_mp_fam]
	mov	rsi,rbx
	mov	ecx,eax
	repe	cmpsb
	pop	rdi
	jne	.gauge
	cmp	dword [g_mp_sum],0
	je	.gauge
	memit '","sum":{"aggregationTemporality":2,"isMonotonic":true,"dataPoints":['
	clc
	ret
.gauge:
	memit '","gauge":{"dataPoints":['
.same:
	clc
	ret
.full:
	stc
	ret

; r8 at a sample's '{': its labels, {"key":"k","value":{"stringValue":"v"}},
; out. Keeps r9-r15.
mp_labels:
	inc	r8
	xor	edx,edx				; one written
.label:
	cmp	byte [r8],'}'
	je	.done
	cmp	byte [r8],','
	jne	@f
	inc	r8
	jmp	.label
@@:
	test	edx,edx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	edx,1
	memit '{"key":"'
@@:
	mov	al,[r8]
	cmp	al,'='
	je	@f
	cmp	al,'}'
	je	.done
	stosb
	inc	r8
	jmp	@b
@@:
	memit '","value":{"stringValue":'
	inc	r8				; at the opening quote
	mov	al,[r8]
	stosb
	inc	r8
.v:
	mov	al,[r8]
	cmp	al,'\'
	jne	@f
	stosb
	inc	r8
	mov	al,[r8]
	stosb
	inc	r8
	jmp	.v
@@:
	stosb
	inc	r8
	cmp	al,'"'
	jne	.v
	mov	word [rdi],'}}'
	add	rdi,2
	jmp	.label
.done:
	ret
