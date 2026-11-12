; `early_hints /a.css /b.js` on a route: a 103 for the client, so that it starts on
; them while the backend works on the page. It is written into UP as if the backend
; had sent it, when the request is on its way, and from there it goes as a backend's
; 103 does: dropped for HTTP/1.0, framed for HTTP/2 and HTTP/3. Once, retries or not.
; GET only: it is for pages.
;
; `headers preset=secure`, on a listener, a host block or a route: the response
; headers everyone means to set. What the route says itself, by `response header` of
; the same name, stands; `preset=none` takes them away where they were inherited.

HI_MAX		:= 4096

; ebx, r15, its request just sent: eax = 1 when there is a 103 in UP
hints_inject:
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_EH],0
	je	.none
	mov	dword [rax+HB_EH],0
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	lea	r8,[g_acts+rax]
	mov	rsi,[r8+RA_EH]
	mov	ecx,[r8+RA_EHLEN]
	mov	[r15+H_UPLEN],ecx
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	rep	movsb
	mov	eax,1
	ret
.none:
	xor	eax,eax
	ret

; g_hm = the request, r15: does this one get them?
hints_request:
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_EH],0
	mov	qword [rax+HB_HOLD],0
	mov	dword [rax+HB_WOKEN],0		; (a turn that came to a request gone before)
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_EHLEN],0
	je	.none
	cmp	dword [g_hm+HM_MLEN],3
	jne	.none
	mov	rax,[g_hm+HM_METHOD]
	mov	eax,[rax]
	and	eax,0xFFFFFF
	cmp	eax,'GET'
	jne	.none
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_EH],1
.none:
	ret

; r12 = a route's node, r13 = the action: its `early_hints`, rendered
compile_hints:
	push	rbx
	push	r14
	push	r15
	mov	rdi,r12
	mov	ecx,DIR_EARLY_HINTS
	call	find_child
	test	rax,rax
	jz	.out
	mov	rbx,rax
	lea	rdi,[g_ar_text]
	mov	esi,HI_MAX
	call	arena_alloc
	mov	r14,rax
	mov	[r13+RA_EH],rax
	mov	rdi,rax
	lea	rsi,[.line]
	mov	ecx,.line_len
	rep	movsb
	mov	r15,[rbx+N_ARGS]
	mov	ebx,[rbx+N_ARGC]
.arg:
	test	ebx,ebx
	jz	.end
	dec	ebx
	mov	rsi,[r15+A_VAL]
	mov	ecx,[r15+A_VLEN]
	add	r15,A_SIZE
	lea	rax,[r14+HI_MAX-300]
	lea	rdx,[rdi+rcx]
	cmp	rdx,rax
	ja	plan_bad_hints
	cmp	byte [rsi],'/'
	jne	plan_bad_hints
	mov	r8,rsi
	mov	r9d,ecx
.ch:
	mov	al,[r8]
	cmp	al,' '
	jbe	plan_bad_hints
	cmp	al,0x7F
	jae	plan_bad_hints
	cmp	al,'>'
	je	plan_bad_hints
	cmp	al,'<'
	je	plan_bad_hints
	inc	r8
	dec	r9d
	jnz	.ch
	mov	r8,rsi
	mov	r9d,ecx
	memit_x 'Link: <'
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	memit_x '>; rel=preload'
	; what it is, by its end
	lea	r8,[r8+r9]
	mov	eax,[r8-4]
	cmp	eax,'.css'
	jne	@f
	memit_x '; as=style'
	jmp	.line_end
@@:
	mov	eax,[r8-3]
	and	eax,0xFFFFFF
	cmp	eax,'.js'
	jne	@f
	memit_x '; as=script'
	jmp	.line_end
@@:
	mov	eax,[r8-4]
	cmp	eax,'.mjs'
	jne	@f
	memit_x '; as=script'
	jmp	.line_end
@@:
	cmp	eax,'.ttf'
	je	.font
	cmp	eax,'.otf'
	je	.font
	cmp	eax,'woff'
	je	.font
	cmp	eax,'off2'
	je	.font
	cmp	eax,'.png'
	je	.image
	cmp	eax,'.jpg'
	je	.image
	cmp	eax,'.svg'
	je	.image
	cmp	eax,'.gif'
	je	.image
	cmp	eax,'webp'
	je	.image
	cmp	eax,'avif'
	je	.image
	jmp	.line_end
.font:
	memit_x '; as=font; crossorigin'
	jmp	.line_end
.image:
	memit_x '; as=image'
.line_end:
	memit_x 13,10
	jmp	.arg
.end:
	memit_x 13,10
	sub	rdi,r14
	mov	[r13+RA_EHLEN],edi
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret
.line	db 'HTTP/1.1 103 Early Hints',13,10
.line_len := $ - .line

; r12 = a route's node, r13 = the action, its response ops being collected: those of
; `headers preset=secure`, its own or inherited, but for what the route sets itself
compile_preset:
	push	rbx
	push	r14
	push	r15
	mov	r14,r12
.up:
	test	r14,r14
	jz	.out
	mov	rdi,r14
	mov	ecx,DIR_HEADERS
	call	find_child
	test	rax,rax
	jnz	.found
	mov	r14,[r14+N_PARENT]
	jmp	.up
.found:
	mov	rdi,rax
	lea	rsi,[.k_preset]
	call	node_option
	test	rax,rax
	jz	plan_bad_hints
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	cmp	esi,4
	jne	@f
	cmp	dword [rdi],'none'
	je	.out
@@:
	lea	rdx,[.secure]
	call	mem_eq_cstr
	test	eax,eax
	jz	plan_bad_hints
	lea	r14,[.table]
.entry:
	movzx	r15d,byte [r14]
	test	r15d,r15d
	jz	.out
	inc	r14
	; does the route set it?
	mov	rbx,[r12+N_CHILD]
.own:
	test	rbx,rbx
	jz	.add
	lea	rax,[dir_table + D_SIZE*DIR_RRESPONSE]
	cmp	[rbx+N_DEF],rax
	jne	.own_next
	mov	rax,[rbx+N_ARGS]
	cmp	[rax+2*A_SIZE+A_VLEN],r15d
	jne	.own_next
	mov	rdi,[rax+2*A_SIZE+A_VAL]
	mov	rsi,r14
	mov	edx,r15d
	call	mem_eq_nocase
	test	eax,eax
	jnz	.skip
.own_next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.own
.add:
	mov	ecx,[g_plan_hdrops]
	too_many	ecx,MAX_HDROPS,str_tm_max_hdrops
	inc	dword [g_plan_hdrops]
	imul	r8,rcx,HD_SIZE
	lea	r8,[g_hdrops+r8]
	mov	dword [r8+HD_KIND],HOP_SET
	mov	dword [r8+HD_PREFIX],0
	mov	dword [r8+HD_VARS],0
	mov	[r8+HD_NAME],r14
	mov	[r8+HD_NLEN],r15d
	lea	rax,[r14+r15]
	movzx	ecx,byte [rax]
	inc	rax
	mov	[r8+HD_VAL],rax
	mov	[r8+HD_VLEN],ecx
.skip:
	add	r14,r15
	movzx	eax,byte [r14]
	lea	r14,[r14+rax+1]
	jmp	.entry
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret
cstring .k_preset, 'preset',0
cstring .secure, 'secure',0
macro hp n*, v*
	db lengthof n, n, lengthof v, v
end macro
.table:
	hp 'strict-transport-security', 'max-age=63072000'
	hp 'x-content-type-options', 'nosniff'
	hp 'x-frame-options', 'SAMEORIGIN'
	hp 'referrer-policy', 'strict-origin-when-cross-origin'
	db 0

plan_bad_hints:
	call	log_begin
	out_lit 'early_hints takes absolute paths; headers takes preset=secure or preset=none'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
