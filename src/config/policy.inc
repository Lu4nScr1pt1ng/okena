; `policy NAME { ... }` and `use NAME`: a set of route directives kept in one place.
;
; Done on the tree, before the checker: a route's `use` gets the policy's directives
; as children of its own, so that each route is checked and compiled with what it
; ends up having, and nothing past this needs to know. What a route writes itself,
; or got from an earlier `use`, overrides a directive of that name, all of them (a
; route's `limit` replaces the policy's). A policy's body is checked as a route's,
; so a mistake shows even when no route uses it.

cstring str_policy, 'policy',0
cstring str_route, 'route',0
cstring str_use, 'use',0

; rdi = a node, rsi = a NUL-terminated name: ZF when it is that directive.
; Keeps rdi, r8-r15.
node_is:
	mov	ecx,[rdi+N_NLEN]
	mov	rdx,[rdi+N_NAME]
.ch:
	test	ecx,ecx
	jz	.end
	mov	al,[rdx]
	cmp	al,[rsi]
	jne	.out
	inc	rdx
	inc	rsi
	dec	ecx
	jmp	.ch
.end:
	cmp	byte [rsi],0
.out:
	ret

; rdi, rsi = nodes: ZF when they have the same name
node_same:
	mov	ecx,[rdi+N_NLEN]
	cmp	ecx,[rsi+N_NLEN]
	jne	.out
	push	rsi
	push	rdi
	mov	rdi,[rdi+N_NAME]
	mov	rsi,[rsi+N_NAME]
	repe	cmpsb
	pop	rdi
	pop	rsi
.out:
	ret

; rdi, rsi = nodes: ZF when their first values are the same
args_same:
	mov	rax,[rdi+N_ARGS]
	mov	rcx,[rsi+N_ARGS]
	mov	edx,[rax+A_VLEN]
	cmp	edx,[rcx+A_VLEN]
	jne	.out
	push	rsi
	push	rdi
	mov	rdi,[rax+A_VAL]
	mov	rsi,[rcx+A_VAL]
	mov	ecx,edx
	repe	cmpsb
	pop	rdi
	pop	rsi
.out:
	ret

policies_expand:
	push	rbx
	push	r12
	; a name is given once
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.def:
	test	rbx,rbx
	jz	.routes
	mov	rdi,rbx
	lea	rsi,[str_policy]
	call	node_is
	jne	.def_next
	cmp	dword [rbx+N_ARGC],1
	jne	.def_next
	mov	r12,[rbx+N_NEXT]
.later:
	test	r12,r12
	jz	.def_next
	mov	rdi,r12
	lea	rsi,[str_policy]
	call	node_is
	jne	.later_next
	cmp	dword [r12+N_ARGC],1
	jne	.later_next
	mov	rdi,rbx
	mov	rsi,r12
	call	args_same
	jne	.later_next
	mov	rdi,r12
	call	policy_error
	out_lit 'this policy is defined twice'
	call	cfg_diag_end
	call	cfg_error_limit
.later_next:
	mov	r12,[r12+N_NEXT]
	jmp	.later
.def_next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.def
.routes:
	mov	rdi,[g_cfg_root]
	call	policy_walk
	pop	r12
	pop	rbx
	ret

; rdi = a node
policy_error:
	mov	rax,rdi
	mov	rdi,[rax+N_NAME]
	mov	esi,[rax+N_NLEN]
	mov	edx,[rax+N_LINE]
	jmp	cfg_error

; rdi = a node: the routes under it
policy_walk:
	push	rbx
	mov	rbx,[rdi+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rdi,rbx
	lea	rsi,[str_route]
	call	node_is
	jne	.other
	mov	rdi,rbx
	call	policy_route
	jmp	.sibling
.other:
	mov	rdi,rbx
	lea	rsi,[str_policy]
	call	node_is
	je	.sibling
	mov	rdi,rbx
	call	policy_walk
.sibling:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	rbx
	ret

; rdi = a route
policy_route:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	r12,rdi
	mov	rbx,[r12+N_CHILD]
.child:
	test	rbx,rbx
	jz	.done
	mov	rdi,rbx
	lea	rsi,[str_use]
	call	node_is
	jne	.next
	cmp	dword [rbx+N_ARGC],1
	jne	.next				; (the checker says)
	; which
	mov	rax,[g_cfg_root]
	mov	r13,[rax+N_CHILD]
.find:
	test	r13,r13
	jz	.unknown
	mov	rdi,r13
	lea	rsi,[str_policy]
	call	node_is
	jne	.find_next
	cmp	dword [r13+N_ARGC],1
	jne	.find_next
	mov	rdi,rbx
	mov	rsi,r13
	call	args_same
	je	.found
.find_next:
	mov	r13,[r13+N_NEXT]
	jmp	.find
.found:
	; what the route has now: it keeps those names
	mov	r14,rbx
@@:
	mov	rax,[r14+N_NEXT]
	test	rax,rax
	jz	@f
	mov	r14,rax
	jmp	@b
@@:
	mov	rbp,r14				; the end, as it grows
	mov	r15,[r13+N_CHILD]
.take:
	test	r15,r15
	jz	.next
	mov	rdi,r15
	lea	rsi,[str_use]
	call	node_is
	jne	.fresh
	mov	rdi,r15
	call	policy_error
	out_lit 'a policy cannot use another'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.take_next
.fresh:
	mov	r8,[r12+N_CHILD]
.own:
	mov	rdi,r15
	mov	rsi,r8
	call	node_same
	je	.take_next
	cmp	r8,r14
	je	.clone
	mov	r8,[r8+N_NEXT]
	jmp	.own
.clone:
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	mov	rdi,rax
	mov	rsi,r15
	mov	ecx,N_SIZE
	rep	movsb
	mov	qword [rax+N_NEXT],0
	mov	[rax+N_PARENT],r12
	mov	[rbp+N_NEXT],rax
	mov	rbp,rax
.take_next:
	mov	r15,[r15+N_NEXT]
	jmp	.take
.unknown:
	mov	rdi,rbx
	call	policy_error
	out_lit 'no policy of that name: define it with `policy NAME { ... }` at the top level'
	call	cfg_diag_end
	call	cfg_error_limit
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.child
.done:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
