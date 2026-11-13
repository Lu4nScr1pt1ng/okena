; Maintenance: `okena maintenance on [ROUTE]` answers every request (or a
; route's, named by its path as written) with 503, a Retry-After and the
; maintenance page, until `okena maintenance off [ROUTE]`. The state is in
; the admin API's shared page, so a reload keeps it; a restart starts out of
; maintenance. An http listener may say how:
;
;   maintenance file=/srv/maint.html retry=2m allow=10.0.0.0/8 except=/healthz
;
; `allow`: clients (as trusted_proxies has them) still let through, to check
; the work; `except`: paths still served (exact, or a prefix with a trailing
; *), as a balancer's health check. Without a file the page is a short text.

AP_MAINT	:= 16			; d: all of it in maintenance
AP_MNUM		:= 20			; d: routes in maintenance (AP_MPATHS)
AP_MPATHS	:= AP_ENT + AO_N * AO_SIZE	; MAINT_ROUTES of MP_SIZE: length d, text
MP_SIZE		:= 128
MAINT_ROUTES	:= 16
AP_SIZE		:= AP_MPATHS + MAINT_ROUTES * MP_SIZE

MT_PAGE		:= 0			; d: its page (g_eps), 0 the text
MT_RETRY	:= 4			; d: seconds
MT_ACL		:= 8			; d: its allow (g_acls) + 1, 0 none
MT_XN		:= 12			; d: except paths
MT_X		:= 16			; MT_XMAX of MP_SIZE
MT_XMAX		:= 8
MT_SIZE		:= MT_X + MT_XMAX * MP_SIZE
MAX_MAINTS	:= MAX_LISTENERS
MAINT_RETRY	:= 30

bss
	align 8
	g_plan_maints	dd ?
	g_maints	rb MT_SIZE * MAX_MAINTS
end bss

cstring str_key_retry, 'retry',0
cstring str_key_allow, 'allow',0
cstring str_key_except, 'except',0
cstring ep_maint_text, 'Under maintenance: back soon.',10,'request id: {request_id}',10

; The plan, starting: the maintenance text as g_eps[0], in no range
errpage_plan_init:
	mov	ecx,ep_maint_text.len
	lea	rsi,[ep_maint_text]
	lea	rdi,[g_ep_store]
	rep	movsb
	mov	dword [g_ep_used],ep_maint_text.len
	mov	dword [g_eps+EP_LO],0
	mov	dword [g_eps+EP_HI],0
	mov	dword [g_eps+EP_OFF],0
	mov	dword [g_eps+EP_LEN],ep_maint_text.len
	mov	dword [g_eps+EP_SPLIT],ep_maint_text.len
	mov	dword [g_eps+EP_TYPE],2
	mov	dword [g_plan_eps],1
	ret

; rdi = an http listener's node: eax = its `maintenance` + 1, 0 none
compile_maintenance:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ecx,DIR_MAINTENANCE
	call	find_child
	test	rax,rax
	jz	.none
	mov	rbx,rax
	mov	eax,[g_plan_maints]
	cmp	eax,MAX_MAINTS
	jae	.bad
	inc	dword [g_plan_maints]
	mov	r12d,eax
	imul	r13,rax,MT_SIZE
	lea	r13,[g_maints+r13]
	mov	dword [r13+MT_RETRY],MAINT_RETRY
	; its page: an entry of no range of its own
	mov	rdi,rbx
	lea	rsi,[str_key_file]
	call	node_option
	test	rax,rax
	jz	.retry
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	call	errpage_load			; eax = its entry
	mov	[r13+MT_PAGE],eax
.retry:
	mov	rdi,rbx
	lea	rsi,[str_key_retry]
	call	node_option
	test	rax,rax
	jz	.allow
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	.bad
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax				; (a second at least)
@@:
	mov	[r13+MT_RETRY],eax
.allow:
	mov	rdi,rbx
	lea	rsi,[str_key_allow]
	call	node_option
	test	rax,rax
	jz	.except
	mov	r15,rax
	mov	eax,[g_plan_acls]
	cmp	eax,MAX_ACLS
	jae	.bad
	inc	dword [g_plan_acls]
	lea	ecx,[rax+1]
	mov	[r13+MT_ACL],ecx
	imul	r14,rax,ACL_SIZE
	lea	r14,[g_acls+r14]
	mov	rsi,[r15+A_VAL]
	mov	ecx,[r15+A_VLEN]
	xor	r15d,r15d			; (acl_add: an allow)
.cidr:
	; comma-separated
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],','
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.bad
	push	rsi
	push	rcx
	push	rdx
	mov	rdi,rsi
	mov	esi,edx
	call	acl_add
	pop	rdx
	pop	rcx
	pop	rsi
	inc	edx
	add	rsi,rdx
	sub	ecx,edx
	jg	.cidr
.except:
	mov	rdi,rbx
	lea	rsi,[str_key_except]
	call	node_option
	test	rax,rax
	jz	.done
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
.path:
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],','
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.bad
	cmp	edx,MP_SIZE - 4
	jae	.bad
	cmp	byte [rsi],'/'
	jne	.bad
	mov	eax,[r13+MT_XN]
	cmp	eax,MT_XMAX
	jae	.bad
	inc	dword [r13+MT_XN]
	imul	rdi,rax,MP_SIZE
	lea	rdi,[r13+MT_X+rdi]
	mov	[rdi],edx
	add	rdi,4
	push	rsi
	push	rcx
	mov	ecx,edx
	rep	movsb
	pop	rcx
	pop	rsi
	inc	edx
	add	rsi,rdx
	sub	ecx,edx
	jg	.path
.done:
	lea	eax,[r12+1]
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad:
	call	log_begin
	out_lit 'maintenance takes file=PAGE, retry=TIME, allow=CIDR,... and except=/PATH,... (8 at most; /x* a prefix)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------------ serving

; ebx = session, r15 = record, rcx = the route chosen (g_routes): CF when it
; is in maintenance and this request is not let through. Keeps rcx, rdx.
maint_check:
	mov	rax,[g_api_ov]
	mov	r8d,[rax+AP_MAINT]
	or	r8d,[rax+AP_MNUM]
	jnz	.look
	clc					; (the common case: one test)
	ret
.look:
	push	rcx
	push	rdx
	push	r12
	push	r13
	mov	r12,rcx
	mov	r13,rax
	cmp	dword [r13+AP_MAINT],0
	jne	.applies
	; this route's path, as written ("/api/*"), among those in it
	xor	r8d,r8d
.route:
	cmp	r8d,[r13+AP_MNUM]
	jae	.through
	cmp	r8d,MAINT_ROUTES
	jae	.through
	imul	r9,r8,MP_SIZE
	lea	r9,[r13+AP_MPATHS+r9]
	inc	r8d
	mov	ecx,[r12+RT_PLEN]
	mov	eax,ecx
	cmp	dword [r12+RT_PREFIX],1
	jne	@f
	inc	eax				; and its '*'
@@:
	cmp	eax,[r9]
	jne	.route
	mov	rsi,[r12+RT_PATH]
	lea	rdi,[r9+4]
	repe	cmpsb
	jne	.route
	cmp	dword [r12+RT_PREFIX],1
	jne	.applies
	cmp	byte [rdi],'*'
	jne	.route
.applies:
	; the listener's own rules: who and what still goes through
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_MAINT]
	test	eax,eax
	jz	.refused
	dec	eax
	imul	r12,rax,MT_SIZE
	lea	r12,[g_maints+r12]
	; except: the request's path
	lea	r8,[g_hm]
	mov	rsi,[r8+HM_TARGET]
	mov	edx,[r8+HM_PLEN]
	cmp	edx,-1
	jne	@f
	mov	edx,[r8+HM_TLEN]
@@:
	xor	r9d,r9d
.except:
	cmp	r9d,[r12+MT_XN]
	jae	.allow
	imul	rdi,r9,MP_SIZE
	lea	rdi,[r12+MT_X+rdi]
	inc	r9d
	mov	ecx,[rdi]
	add	rdi,4
	cmp	byte [rdi+rcx-1],'*'
	je	.prefix
	cmp	ecx,edx
	jne	.except
	push	rsi
	repe	cmpsb
	pop	rsi
	je	.through
	jmp	.except
.prefix:
	dec	ecx
	cmp	ecx,edx
	ja	.except
	push	rsi
	repe	cmpsb
	pop	rsi
	je	.through
	jmp	.except
.allow:
	mov	eax,[r12+MT_ACL]
	test	eax,eax
	jz	.refused
	dec	eax
	imul	rax,rax,ACL_SIZE
	lea	r13,[g_acls+rax]
	call	http_client_resolve
	lea	rsi,[r15+H_CLIENT]
	mov	ecx,32
	mov	rax,[r13+ACL_V4]
	cmp	dword [r15+H_CKIND],6
	jne	@f
	mov	ecx,128
	mov	rax,[r13+ACL_V6]
@@:
	call	tn_has
	jc	.through
.refused:
	; its page and its Retry-After, for http_error
	mov	dword [g_ep_retry],MAINT_RETRY
	mov	qword [g_ep_force],g_eps	; (the text, g_eps[0])
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_MAINT]
	test	eax,eax
	jz	@f
	dec	eax
	imul	rax,rax,MT_SIZE
	mov	ecx,dword [g_maints+rax+MT_RETRY]
	mov	[g_ep_retry],ecx
	mov	ecx,dword [g_maints+rax+MT_PAGE]
	imul	rcx,rcx,EP_SIZE
	add	rcx,g_eps
	mov	[g_ep_force],rcx
@@:
	stc
	jmp	.out
.through:
	clc
.out:
	pop	r13
	pop	r12
	pop	rdx
	pop	rcx
	ret
