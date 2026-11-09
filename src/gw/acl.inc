; `allow CIDR... | file:PATH` and `deny ...` on a route: by the client as
; trusted_proxies has it, before anything else on the route costs anything. A deny
; wins; with any allow, what is not in one gets a 403 too. Lists from files can run to
; thousands, so each is a binary trie by family: a lookup is one step a bit, at most.

MAX_ACLS	:= 256
ACL_CMAX	:= 64
ACL_V4		:= 0				; q: root
ACL_V6		:= 8				; q
ACL_DENY4	:= 16				; q
ACL_DENY6	:= 24				; q
ACL_ALLOWS	:= 32				; d: it has an allow
ACL_CN		:= 40				; d: countries allowed
ACL_DN		:= 44				; d: denied
ACL_C		:= 48				; w each
ACL_D		:= ACL_C + 2 * ACL_CMAX
ACL_SIZE	:= ACL_D + 2 * ACL_CMAX
TRN_ZERO		:= 0				; q: child, 0 none
TRN_ONE		:= 8				; q
TRN_END		:= 16				; d: a prefix ends here
TRN_SIZE		:= 24

bss
	align 8
	g_acls:		rb ACL_SIZE * MAX_ACLS
	g_plan_acls	dd ?
	g_tr_tmp:	rb TR_SIZE
end bss

; rax = a trie's root, 0 none, rsi = the address, ecx = its bits: CF when in it.
; Keeps rbx, r12-r15, rsi.
tn_has:
	test	rax,rax
	jz	.no
	xor	edx,edx				; the bit
.step:
	cmp	dword [rax+TRN_END],0
	jne	.yes
	cmp	edx,ecx
	jae	.no
	mov	r8d,edx
	shr	r8d,3
	movzx	r8d,byte [rsi+r8]
	mov	r9d,edx
	and	r9d,7
	mov	r10d,7
	sub	r10d,r9d
	bt	r8d,r10d
	mov	r8d,TRN_ZERO
	jnc	@f
	mov	r8d,TRN_ONE
@@:
	mov	rax,[rax+r8]
	inc	edx
	test	rax,rax
	jnz	.step
.no:
	clc
	ret
.yes:
	stc
	ret

; eax = the action's RA_ACL, r15, ebx: CF refused. Keeps rbx, r12-r15, rcx, rdx.
acl_check:
	push	rcx
	push	rdx
	push	r12
	push	r13
	dec	eax
	imul	r12,rax,ACL_SIZE
	lea	r12,[g_acls+r12]
	call	http_client_resolve
	lea	rsi,[r15+H_CLIENT]
	mov	ecx,32
	mov	r11d,[r15+H_CKIND]
	cmp	r11d,6
	jne	@f
	mov	ecx,128
@@:
	mov	rax,[r12+ACL_DENY4]
	cmp	r11d,6
	cmove	rax,[r12+ACL_DENY6]
	push	rcx
	call	tn_has
	pop	rcx
	jc	.refused
	; by country, when there is any to look at
	xor	r13d,r13d
	mov	eax,[r12+ACL_CN]
	or	eax,[r12+ACL_DN]
	jz	.ranges
	push	rcx
	push	rsi
	push	r11
	mov	edx,r11d
	call	geo_country
	pop	r11
	pop	rsi
	pop	rcx
	mov	r13d,eax
	test	eax,eax
	jz	.ranges
	lea	r8,[r12+ACL_D]
	mov	r9d,[r12+ACL_DN]
.deny:
	test	r9d,r9d
	jz	.ranges
	cmp	ax,[r8]
	je	.refused
	add	r8,2
	dec	r9d
	jmp	.deny
.ranges:
	cmp	dword [r12+ACL_ALLOWS],0
	je	.fine
	test	r13d,r13d
	jz	.by_range
	lea	r8,[r12+ACL_C]
	mov	r9d,[r12+ACL_CN]
.allow:
	test	r9d,r9d
	jz	.by_range
	cmp	r13w,[r8]
	je	.fine
	add	r8,2
	dec	r9d
	jmp	.allow
.by_range:
	mov	rax,[r12+ACL_V4]
	cmp	r11d,6
	cmove	rax,[r12+ACL_V6]
	call	tn_has
	jnc	.refused
.fine:
	clc
	jmp	.out
.refused:
	stc
.out:
	pop	r13
	pop	r12
	pop	rdx
	pop	rcx
	ret

; r12 = a route's node, r13 = the action
compile_acl:
	push	rbx
	push	r14
	push	r15
	; any?
	mov	rbx,[r12+N_CHILD]
.any:
	test	rbx,rbx
	jz	.out
	lea	rax,[dir_table + D_SIZE*DIR_ALLOW]
	cmp	[rbx+N_DEF],rax
	je	.some
	lea	rax,[dir_table + D_SIZE*DIR_DENY]
	cmp	[rbx+N_DEF],rax
	je	.some
	mov	rbx,[rbx+N_NEXT]
	jmp	.any
.some:
	mov	eax,[g_plan_acls]
	cmp	eax,MAX_ACLS
	jae	plan_bad_acl
	inc	dword [g_plan_acls]
	lea	ecx,[rax+1]
	mov	[r13+RA_ACL],ecx
	imul	r14,rax,ACL_SIZE
	lea	r14,[g_acls+r14]
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.out
	lea	rax,[dir_table + D_SIZE*DIR_ALLOW]
	xor	r15d,r15d			; 0 allow
	cmp	[rbx+N_DEF],rax
	jne	@f
	mov	dword [r14+ACL_ALLOWS],1
	jmp	.args
@@:
	lea	rax,[dir_table + D_SIZE*DIR_DENY]
	mov	r15d,1
	cmp	[rbx+N_DEF],rax
	jne	.next_line
.args:
	mov	r8d,[rbx+N_ARGC]
	mov	r9,[rbx+N_ARGS]
.arg:
	test	r8d,r8d
	jz	.next_line
	dec	r8d
	push	r8
	push	r9
	mov	rsi,[r9+A_VAL]
	mov	ecx,[r9+A_VLEN]
	cmp	ecx,5
	jbe	.one
	cmp	dword [rsi],'file'
	jne	.one
	cmp	byte [rsi+4],':'
	jne	.one
	add	rsi,5
	sub	ecx,5
	call	acl_file
	jmp	.done_arg
.one:
	; a provider's name: its ranges
	mov	rdi,rsi
	mov	esi,ecx
	push	rdi
	push	rsi
	call	ranges_named
	pop	rcx
	pop	rdi
	jc	@f
	lea	rax,[acl_add]
	call	ranges_each
	jmp	.done_arg
@@:
	mov	rsi,rdi
	cmp	ecx,10
	jb	.range
	mov	rax,[rsi]
	mov	rdx,'country:'
	cmp	rax,rdx
	jne	.range
	add	rsi,8
	sub	ecx,8
	call	acl_countries
	jmp	.done_arg
.range:
	mov	rdi,rsi
	mov	esi,ecx
	call	acl_add
.done_arg:
	pop	r9
	pop	r8
	add	r9,A_SIZE
	jmp	.arg
.next_line:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret

; rsi = BR,PT, ecx = its length, r14 = the acl, r15d = deny
acl_countries:
	cmp	qword [g_geo_base],0
	je	plan_bad_acl
.code:
	cmp	ecx,2
	jb	plan_bad_acl
	movzx	eax,word [rsi]
	lea	r8,[r14+ACL_C]
	lea	r9,[r14+ACL_CN]
	test	r15d,r15d
	jz	@f
	lea	r8,[r14+ACL_D]
	lea	r9,[r14+ACL_DN]
@@:
	mov	edx,[r9]
	cmp	edx,ACL_CMAX
	jae	plan_bad_acl
	mov	[r8+rdx*2],ax
	inc	dword [r9]
	sub	ecx,2
	jz	.out
	cmp	byte [rsi+2],','
	jne	plan_bad_acl
	add	rsi,3
	dec	ecx
	jmp	.code
.out:
	ret

; rsi = a path, ecx = its length, r14 = the acl, r15d = deny: each line a CIDR
acl_file:
	push	rbx
	push	r12
	cmp	ecx,1000
	ja	plan_bad_acl
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_acl
	mov	rbx,rax
	mov	edx,edx
	lea	r12,[rax+rdx]
.line:
	cmp	rbx,r12
	jae	.out
	mov	al,[rbx]
	cmp	al,' '
	je	.blank
	cmp	al,9
	je	.blank
	cmp	al,13
	je	.blank
	cmp	al,10
	je	.blank
	cmp	al,'#'
	je	.comment
	mov	rdi,rbx
.w:
	cmp	rbx,r12
	jae	.w_end
	cmp	byte [rbx],' '
	jbe	.w_end
	inc	rbx
	jmp	.w
.w_end:
	mov	rsi,rbx
	sub	rsi,rdi
	call	acl_add
	jmp	.line
.blank:
	inc	rbx
	jmp	.line
.comment:
	cmp	rbx,r12
	jae	.out
	cmp	byte [rbx],10
	je	.line
	inc	rbx
	jmp	.comment
.out:
	pop	r12
	pop	rbx
	ret

; rdi/esi = a CIDR, r14 = the acl, r15d = deny
acl_add:
	push	rbx
	push	r12
	push	r13
	lea	rdx,[g_tr_tmp]
	call	parse_cidr
	jc	plan_bad_acl
	mov	eax,[g_tr_tmp+TR_KIND]
	lea	rbx,[r14+ACL_V4]
	cmp	eax,6
	jne	@f
	lea	rbx,[r14+ACL_V6]
@@:
	test	r15d,r15d
	jz	@f
	add	rbx,ACL_DENY4 - ACL_V4
@@:
	; rbx = where the next node's address goes
	mov	r12d,[g_tr_tmp+TR_BITS]
	xor	r13d,r13d			; the bit
.step:
	mov	rax,[rbx]
	test	rax,rax
	jnz	.have
	lea	rdi,[g_ar_text]
	mov	esi,TRN_SIZE
	call	arena_alloc
	mov	qword [rax+TRN_ZERO],0
	mov	qword [rax+TRN_ONE],0
	mov	dword [rax+TRN_END],0
	mov	[rbx],rax
.have:
	cmp	r13d,r12d
	jae	.end
	mov	ecx,r13d
	shr	ecx,3
	movzx	edx,byte [g_tr_tmp+TR_IP+rcx]
	mov	ecx,r13d
	and	ecx,7
	mov	r8d,7
	sub	r8d,ecx
	bt	edx,r8d
	lea	rbx,[rax+TRN_ZERO]
	jnc	@f
	lea	rbx,[rax+TRN_ONE]
@@:
	inc	r13d
	jmp	.step
.end:
	mov	dword [rax+TRN_END],1
	pop	r13
	pop	r12
	pop	rbx
	ret

plan_bad_acl:
	call	log_begin
	out_lit 'allow and deny take addresses, ranges, file:PATH with one a line, or country:BR,PT with a `geoip` file'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
