; Access log lines' extra fields (http): user_agent, referer, tls,
; upstream_ms, bytes_in. What they need is kept a session in a side table,
; mapped only when some http listener logs (g_plan_alx) and touched only for
; those sessions; each hook below is one byte compared otherwise.

ALX_UAL		:= 0				; d: User-Agent: its length
ALX_RFL		:= 4				; d: Referer
ALX_TLS		:= 8				; d: 0 none, 12 TLS 1.2, 13 TLS 1.3
ALX_HDLEN	:= 12				; d: the request head's length
ALX_BODY0	:= 16				; q: what H_REMAIN was when the body began (body_size)
ALX_RTSC	:= 24				; q: TSC when the backend's head came, 0 none
ALX_UA		:= 32				; ALX_UA_CAP
ALX_UA_CAP	:= 236
ALX_RF		:= ALX_UA + ALX_UA_CAP		; ALX_RF_CAP
ALX_RF_CAP	:= 244
ALX_SHIFT	:= 9
assert ALX_RF + ALX_RF_CAP <= 1 shl ALX_SHIFT

bss
	align 8
	g_alx_base	dq ?
	g_plan_alx	dd ?			; some http listener has an access log
end bss

cstring hn_user_agent_t, 'user-agent',0
cstring hn_referer_t, 'referer',0

; Worker: the table, when it is needed. eax = 0 or -errno.
alx_worker_init:
	xor	eax,eax
	cmp	dword [g_plan_alx],0
	je	.done
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,ALX_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_alx_base],rax
	xor	eax,eax
.done:
	ret

; ebx = session: rax = its record, ZF when there is none (no access log on
; its listener). Keeps all but rax.
alx_rec:
	cmp	qword [g_alx_base],0
	je	.none
	push	rcx
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_ALOG],0
	pop	rcx
	je	.none
	mov	eax,ebx
	shl	rax,ALX_SHIFT
	add	rax,[g_alx_base]
	ret					; (NZ: rax is not 0)
.none:
	xor	eax,eax
	ret

; ebx = a new http connection: no TLS seen yet. Keeps all but rax.
alx_conn_start:
	call	alx_rec
	jz	.out
	mov	dword [rax+ALX_TLS],0
.out:
	ret

; ebx = session, edx = 0 (TLS 1.2) or 1 (1.3), its handshake done. Keeps all
; but rax.
alx_tls:
	call	alx_rec
	jz	.out
	push	rdx
	add	edx,12
	mov	[rax+ALX_TLS],edx
	pop	rdx
.out:
	ret

; edi = an HTTP/2 stream's session, esi = its connection's: the TLS it came
; over. Keeps all but rax, rcx.
alx_inherit:
	cmp	qword [g_alx_base],0
	je	.out
	mov	eax,esi
	shl	rax,ALX_SHIFT
	add	rax,[g_alx_base]
	mov	ecx,[rax+ALX_TLS]
	mov	eax,edi
	shl	rax,ALX_SHIFT
	add	rax,[g_alx_base]
	mov	[rax+ALX_TLS],ecx
.out:
	ret

; edi = an HTTP/3 stream's session: TLS 1.3, always. Keeps all but rax.
alx_h3:
	cmp	qword [g_alx_base],0
	je	.out
	mov	eax,edi
	shl	rax,ALX_SHIFT
	add	rax,[g_alx_base]
	mov	dword [rax+ALX_TLS],13
.out:
	ret

; ebx = session, r15 = record, g_hm = its request: User-Agent, Referer and
; the head's length kept; the rest starts over. Keeps rbx, r12-r15.
alx_request:
	call	alx_rec
	jz	.out
	push	r12
	push	r13
	mov	r12,rax
	mov	eax,[r15+H_HEADN]
	mov	[r12+ALX_HDLEN],eax
	xor	eax,eax
	mov	[r12+ALX_UAL],eax
	mov	[r12+ALX_RFL],eax
	mov	[r12+ALX_BODY0],rax
	mov	[r12+ALX_RTSC],rax
	xor	r13d,r13d
.field:
	cmp	r13d,[g_hm+HM_NHDR]
	jae	.done
	imul	rdi,r13,HF_SIZE
	lea	rdi,[g_hm+HM_HDRS+rdi]
	inc	r13d
	push	rdi
	lea	rsi,[hn_user_agent_t]
	call	hf_is
	pop	rdi
	jne	@f
	lea	rdx,[r12+ALX_UA]
	lea	rcx,[r12+ALX_UAL]
	mov	r8d,ALX_UA_CAP
	call	.keep
	jmp	.field
@@:
	push	rdi
	lea	rsi,[hn_referer_t]
	call	hf_is
	pop	rdi
	jne	.field
	lea	rdx,[r12+ALX_RF]
	lea	rcx,[r12+ALX_RFL]
	mov	r8d,ALX_RF_CAP
	call	.keep
	jmp	.field
.done:
	pop	r13
	pop	r12
.out:
	ret
; rdi = field, rdx = room (r8d bytes), rcx = its length's place: the first
; such field kept, cut to the room
.keep:
	cmp	dword [rcx],0
	jne	.kept
	mov	esi,[rdi+HF_VLEN]
	cmp	esi,r8d
	jbe	@f
	mov	esi,r8d
@@:
	mov	[rcx],esi
	push	rdi
	mov	rsi,[rdi+HF_VALUE]
	mov	rdi,rdx
	mov	ecx,[rcx]
	rep	movsb
	pop	rdi
.kept:
	ret

; ebx = session, r15 = record: the body's start (after body_size set
; H_REMAIN). Keeps all but rax.
alx_body:
	call	alx_rec
	jz	.out
	push	rcx
	xor	ecx,ecx
	cmp	dword [r15+H_BODY],BK_NONE
	je	@f
	mov	rcx,[r15+H_REMAIN]
@@:
	mov	[rax+ALX_BODY0],rcx
	pop	rcx
.out:
	ret

; ebx = session: the backend's final head is in. Keeps all (eax is the
; status where it is called).
alx_resp_head:
	push	rax
	call	alx_rec
	jz	.out
	push	rdx
	push	rcx
	mov	rcx,rax
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[rcx+ALX_RTSC],rax
	pop	rcx
	pop	rdx
.out:
	pop	rax
	ret

; rdi = the line, ebx = session (r13 its pointer), r15 = record: the extra
; fields, each a ",name":value. Keeps rbx, r12-r15.
alx_fields:
	call	alx_rec
	jz	.out
	push	r12
	mov	r12,rax
	memit ',"user_agent":"'
	lea	rsi,[r12+ALX_UA]
	mov	edx,[r12+ALX_UAL]
	mov	ecx,ALX_UA_CAP * 6
	call	json_text
	memit '","referer":"'
	lea	rsi,[r12+ALX_RF]
	mov	edx,[r12+ALX_RFL]
	mov	ecx,ALX_RF_CAP * 6
	call	json_text
	memit '","tls":'
	mov	eax,[r12+ALX_TLS]
	cmp	eax,13
	je	.t13
	cmp	eax,12
	je	.t12
	memit 'null'
	jmp	.upstream
.t13:
	memit '"1.3"'
	jmp	.upstream
.t12:
	memit '"1.2"'
.upstream:
	memit ',"upstream_ms":'
	mov	rax,[r12+ALX_RTSC]
	mov	rcx,[r15+H_LT0]
	test	rax,rax
	jz	.no_upstream
	test	rcx,rcx
	jz	.no_upstream
	sub	rax,rcx
	jb	.no_upstream
	cmp	qword [g_tsc_per_us],0
	je	.no_upstream
	tsc_us
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,3
	call	fmt_pad
	jmp	.bytes
.no_upstream:
	memit 'null'
.bytes:
	memit ',"bytes_in":'
	mov	eax,[r12+ALX_HDLEN]
	mov	rcx,[r12+ALX_BODY0]		; what of the body came: its start less
	sub	rcx,[r15+H_REMAIN]		; what is still to come (no body: 0, and
	jae	@f				; H_BODY is BK_NONE again once one is read)
	xor	ecx,ecx
@@:
	add	rax,rcx
	call	fmt_u64
	pop	r12
.out:
	ret
