; `match header:x-canary=yes method=POST { ... }` inside a route: a narrower case of
; it. Conditions are method, header:NAME, query:NAME, cookie:NAME and client.ip, all
; of them must hold, and the first block that fits in the order written is the one.
; NAME=VALUE is exact, VALUE* a prefix, NAME alone that it is there; client.ip takes
; a CIDR, and is the client as trusted_proxies has it.
;
; A block is a variant of its route: the route's directives with the block's in
; place of those of the same name, compiled as a route and kept out of the route
; tables. So everything a route can do a block can, and what it does not mention
; stays: an `auth` on the route holds inside. `to`, `redirect` and `split` are one
; thing, where the request goes. `limit` is the exception: a block's adds to the
; route's, as replacing it would loosen it unawares.

MC_KIND		:= 0				; d: LK_*
MC_MODE		:= 4				; d: MM_*
MC_NAME		:= 8				; q
MC_NLEN		:= 16				; d
MC_VLEN		:= 20				; d
MC_VAL		:= 24				; q
MC_TR		:= 32				; client.ip: a TR_* record
MC_SIZE		:= 64
assert MC_TR + TR_SIZE <= MC_SIZE
MM_EQ		:= 0
MM_PREFIX	:= 1
MM_THERE	:= 2
MM_REGEX	:= 3				; ~REGEX: its regex in MC_VLEN (regex.inc)
LK_MPATH	:= 8				; `path`: the normalized path

MB_RT		:= 0				; d: its variant, in g_mroutes
MB_CFIRST	:= 4				; d
MB_CN		:= 8				; d
MB_LAST		:= 12				; d: the route has no more
MB_SIZE		:= 16

MAX_MATCH	:= 65536
MAX_MCOND	:= 262144
ROUTE_MATCH_MAX	:= 1024

CV_ACT		:= 0				; d
CV_POOL		:= 4				; d
CV_CFIRST	:= 8				; d
CV_CN		:= 12				; d
CV_SIZE		:= 16

bss
	g_plan_mroutes	dd ?
	g_plan_mconds	dd ?
	g_cmv_n		dd ?
	g_mroutes:	rb RT_SIZE * MAX_MATCH
	g_mblocks:	rb MB_SIZE * MAX_MATCH
	g_mconds:	rb MC_SIZE * MAX_MCOND
	g_cmv:		rb CV_SIZE * ROUTE_MATCH_MAX
end bss

; rcx = a route with blocks, g_hm = the request, r15 = record, ebx = session: rcx =
; the variant that fits, or the route. Keeps rbx, r12-r15.
match_pick:
	push	r12
	push	r13
	push	r14
	mov	r14,rcx
	mov	eax,[rcx+RT_MATCH]
	dec	eax
	shl	rax,4
	lea	r12,[g_mblocks+rax]
.block:
	mov	eax,[r12+MB_CFIRST]
	mov	r13d,[r12+MB_CN]
	imul	rax,rax,MC_SIZE
	lea	rax,[g_mconds+rax]
.cond:
	test	r13d,r13d
	jz	.fits
	dec	r13d
	push	rax
	call	mc_holds
	pop	rax
	test	ecx,ecx
	jz	.next
	add	rax,MC_SIZE
	jmp	.cond
.fits:
	mov	eax,[r12+MB_RT]
	imul	rax,rax,RT_SIZE
	lea	r14,[g_mroutes+rax]
	jmp	.out
.next:
	cmp	dword [r12+MB_LAST],0
	jne	.out
	add	r12,MB_SIZE
	jmp	.block
.out:
	mov	rcx,r14
	pop	r14
	pop	r13
	pop	r12
	ret

; rax = a condition: ecx = 1 when it holds, 0 not. Keeps rbx, r12-r15.
mc_holds:
	push	r12
	mov	r12,rax
	mov	eax,[r12+MC_KIND]
	cmp	eax,LK_METHOD
	je	.method
	cmp	eax,LK_HEADER
	je	.header
	cmp	eax,LK_COOKIE
	je	.cookie
	cmp	eax,LK_QUERY
	je	.query
	cmp	eax,LK_MPATH
	je	.path
	; client.ip
	cmp	dword [g_cr_dry],0
	je	@f
	mov	dword [g_cr_ip],1
	jmp	.no
@@:
	call	http_client_resolve
	cmp	dword [r12+MC_KIND],LK_COUNTRY
	jne	.by_range
	lea	rsi,[r15+H_CLIENT]
	mov	edx,[r15+H_CKIND]
	call	geo_country
	test	eax,eax
	jz	.no
	; BR or BR,PT,AR
	mov	rsi,[r12+MC_VAL]
	mov	ecx,[r12+MC_VLEN]
.code:
	cmp	ecx,2
	jb	.no
	cmp	ax,[rsi]
	je	.yes
	add	rsi,3
	sub	ecx,3
	jg	.code
	jmp	.no
.by_range:
	lea	r8,[r12+MC_TR]
	mov	eax,[r15+H_CKIND]
	cmp	[r8+TR_KIND],eax
	jne	.no
	lea	rsi,[r15+H_CLIENT]
	mov	ecx,[r8+TR_BITS]
	xor	edx,edx
.byte:
	cmp	ecx,8
	jb	.bits
	mov	al,[rsi+rdx]
	cmp	al,[r8+TR_IP+rdx]
	jne	.no
	inc	edx
	sub	ecx,8
	jmp	.byte
.bits:
	test	ecx,ecx
	jz	.yes
	movzx	eax,byte [rsi+rdx]
	xor	al,[r8+TR_IP+rdx]
	neg	ecx
	add	ecx,8
	shr	eax,cl
	test	eax,eax
	jnz	.no
.yes:
	mov	ecx,1
	jmp	.out
.method:
	mov	rsi,[g_hm+HM_METHOD]
	mov	ecx,[g_hm+HM_MLEN]
	jmp	.compare
.path:
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	jmp	.compare
.header:
	mov	rdi,[r12+MC_NAME]
	mov	esi,[r12+MC_NLEN]
	call	limit_find
	jmp	.compare
.cookie:
	lea	rdi,[limit_key.cookie_name]
	mov	esi,6
	call	limit_find
	test	ecx,ecx
	jz	.compare
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+MC_NAME]
	mov	ecx,[r12+MC_NLEN]
	mov	r8b,';'
	call	limit_field
	jmp	.compare
.query:
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	mov	edx,[g_hm+HM_PLEN]
	sub	ecx,edx
	jbe	.no
	add	rsi,rdx
	inc	rsi
	dec	ecx
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+MC_NAME]
	mov	ecx,[r12+MC_NLEN]
	mov	r8b,'&'
	call	limit_field
.compare:
	; rsi, ecx: what the request has, ecx = 0 nothing
	mov	eax,[r12+MC_MODE]
	cmp	eax,MM_REGEX
	jne	.not_rx
	mov	eax,[r12+MC_VLEN]		; (a header not there: an empty one)
	call	rx_match
	mov	ecx,eax
	jmp	.out
.not_rx:
	cmp	eax,MM_THERE
	jne	@f
	test	ecx,ecx
	jz	.no
	jmp	.yes
@@:
	mov	edx,[r12+MC_VLEN]
	cmp	eax,MM_PREFIX
	je	.prefix
	cmp	ecx,edx
	jne	.no
	jmp	.bytes
.prefix:
	cmp	ecx,edx
	jb	.no
.bytes:
	test	edx,edx
	jz	.yes
	mov	rdi,[r12+MC_VAL]
	mov	ecx,edx
	repe	cmpsb
	je	.yes
.no:
	xor	ecx,ecx
.out:
	pop	r12
	ret

; rbx = a route node, r13d = its pool: each of its blocks compiled, into g_cmv.
; Keeps rbx, r12-r15.
compile_matches:
	push	r12
	push	r14
	push	r15
	mov	dword [g_cmv_n],0
	mov	r12,[rbx+N_CHILD]
.next:
	test	r12,r12
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_MATCH]
	cmp	[r12+N_DEF],rax
	jne	.sibling
	cmp	dword [g_cmv_n],ROUTE_MATCH_MAX
	jae	plan_bad_match
	call	match_conditions
	mov	r14d,eax			; first
	mov	r15d,edx			; how many
	call	match_variant
	push	rax
	mov	rdi,rax
	mov	eax,[g_cmv_n]
	imul	rax,rax,CV_SIZE
	lea	rax,[g_cmv+rax]
	mov	[rax+CV_CFIRST],r14d
	mov	[rax+CV_CN],r15d
	mov	r14,rax
	; where it goes, as a route's: compile_routes
	mov	ecx,DIR_TO
	call	match_child
	mov	r15d,r13d			; (unless it says: the route's)
	test	rax,rax
	jz	.no_target
	; (the checker looks at a route's `to`, not at these)
	cmp	dword [rax+N_ARGC],2
	jne	.target
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_SIZE+A_VAL]
	mov	esi,[rax+A_SIZE+A_VLEN]
	call	plan_pool_index
	cmp	eax,-1
	je	plan_bad_match
.target:
	mov	rdi,[rsp]
	call	compile_target
	mov	r15d,eax
.no_target:
	mov	ecx,DIR_REDIRECT
	call	match_child
	test	rax,rax
	jz	@f
	mov	r15d,-1
@@:
	mov	ecx,DIR_RESPOND
	call	match_child
	test	rax,rax
	jz	@f
	mov	r15d,-1
@@:
	mov	ecx,DIR_FILES
	call	match_child
	test	rax,rax
	jz	@f
	mov	r15d,-1
@@:
	pop	rdi
	call	compile_route_action
	mov	[r14+CV_ACT],eax
	mov	ecx,DIR_SPLIT
	call	match_child
	test	rax,rax
	jz	.pooled
	mov	eax,[r14+CV_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_SPLIT]
	dec	eax
	imul	rax,rax,SL_SIZE
	mov	r15d,[g_splits+rax+SL_P]
.pooled:
	mov	[r14+CV_POOL],r15d
	inc	dword [g_cmv_n]
.sibling:
	mov	r12,[r12+N_NEXT]
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r12
	ret

; r12 = a block, ecx = a directive: rax = it among the block's, 0
match_child:
	mov	rdi,r12
	jmp	find_child

; r12 = a block: its conditions. eax = the first, edx = how many.
match_conditions:
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	r14d,[g_plan_mconds]
	xor	r15d,r15d
	; (nothing that would need more than a route can do)
	mov	rbx,[r12+N_CHILD]
.inner:
	test	rbx,rbx
	jz	.args
	lea	rax,[dir_table + D_SIZE*DIR_MATCH]
	cmp	[rbx+N_DEF],rax
	je	plan_bad_match
	lea	rax,[dir_table + D_SIZE*DIR_USE]
	cmp	[rbx+N_DEF],rax
	je	plan_bad_match
	mov	rbx,[rbx+N_NEXT]
	jmp	.inner
.args:
	mov	r13,[r12+N_ARGS]
	cmp	dword [r12+N_ARGC],0
	je	plan_bad_match
.arg:
	cmp	r15d,[r12+N_ARGC]
	jae	.done
	mov	eax,[g_plan_mconds]
	cmp	eax,MAX_MCOND
	jae	plan_bad_match
	inc	dword [g_plan_mconds]
	imul	rax,rax,MC_SIZE
	lea	rbx,[g_mconds+rax]
	mov	rdi,rbx
	mov	ecx,MC_SIZE
	xor	eax,eax
	rep	stosb
	mov	dword [rbx+MC_MODE],MM_THERE
	cmp	dword [r13+A_KIND],ARG_KV
	jne	.bare
	mov	rsi,[r13+A_KEY]
	mov	ecx,[r13+A_KLEN]
	mov	rax,[r13+A_VAL]
	mov	edx,[r13+A_VLEN]
	test	edx,edx
	jz	plan_bad_match
	mov	[rbx+MC_VAL],rax
	mov	[rbx+MC_VLEN],edx
	mov	dword [rbx+MC_MODE],MM_EQ
	cmp	byte [rax],'~'			; ~REGEX
	jne	@f
	cmp	edx,2
	jb	plan_bad_match
	push	rsi
	push	rcx
	lea	rsi,[rax+1]
	lea	ecx,[rdx-1]
	call	rx_compile_or_exit
	mov	[rbx+MC_VLEN],eax
	mov	dword [rbx+MC_MODE],MM_REGEX
	pop	rcx
	pop	rsi
	jmp	.key
@@:
	cmp	byte [rax+rdx-1],'*'
	jne	.key
	dec	dword [rbx+MC_VLEN]
	mov	dword [rbx+MC_MODE],MM_PREFIX
	jmp	.key
.bare:
	mov	rsi,[r13+A_VAL]
	mov	ecx,[r13+A_VLEN]
.key:
	; rsi, ecx: what is looked at
	cmp	ecx,4				; path: the normalized path
	jne	@f
	cmp	dword [rsi],'path'
	jne	@f
	cmp	dword [rbx+MC_MODE],MM_THERE
	je	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_MPATH
	jmp	.taken
@@:
	cmp	ecx,6
	jne	@f
	mov	eax,[rsi]
	cmp	eax,'meth'
	jne	.named
	cmp	word [rsi+4],'od'
	jne	.named
	cmp	dword [rbx+MC_MODE],MM_THERE
	je	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_METHOD
	jmp	.taken
@@:
	cmp	ecx,14
	jne	.not_country
	cmp	dword [rsi],'clie'
	jne	.named
	cmp	dword [rsi+4],'nt.c'
	jne	.named
	cmp	dword [rsi+8],'ount'
	jne	.named
	cmp	word [rsi+12],'ry'
	jne	.named
	cmp	dword [rbx+MC_MODE],MM_EQ
	jne	plan_bad_match
	cmp	qword [g_geo_base],0
	je	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_COUNTRY
	jmp	.taken
.not_country:
	cmp	ecx,9
	jne	.named
	cmp	dword [rsi],'clie'
	jne	.named
	cmp	dword [rsi+4],'nt.i'
	jne	.named
	cmp	byte [rsi+8],'p'
	jne	.named
	cmp	dword [rbx+MC_MODE],MM_EQ
	jne	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_IP
	mov	rdi,[rbx+MC_VAL]
	mov	esi,[rbx+MC_VLEN]
	lea	rdx,[rbx+MC_TR]
	call	parse_cidr
	jc	plan_bad_match
	jmp	.taken
.named:
	cmp	ecx,7
	jbe	.short
	mov	rax,[rsi]
	mov	rdx,'header:'
	shl	rax,8
	shl	rdx,8
	cmp	rax,rdx
	jne	.short
	mov	dword [rbx+MC_KIND],LK_HEADER
	add	rsi,7
	sub	ecx,7
	jmp	.name
.short:
	cmp	ecx,6
	jbe	plan_bad_match
	mov	eax,[rsi]
	mov	dx,[rsi+4]
	cmp	eax,'quer'
	jne	@f
	cmp	dx,'y:'
	jne	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_QUERY
	jmp	.named6
@@:
	cmp	eax,'cook'
	jne	plan_bad_match
	cmp	dx,'ie'
	jne	plan_bad_match
	cmp	byte [rsi+6],':'
	jne	plan_bad_match
	mov	dword [rbx+MC_KIND],LK_COOKIE
	inc	rsi
	dec	ecx
.named6:
	add	rsi,6
	sub	ecx,6
.name:
	test	ecx,ecx
	jz	plan_bad_match
	mov	[rbx+MC_NAME],rsi
	mov	[rbx+MC_NLEN],ecx
.taken:
	add	r13,A_SIZE
	inc	r15d
	jmp	.arg
.done:
	mov	eax,r14d
	mov	edx,r15d
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret

; rbx = a route node, r12 = a block of it: rax = a node with the route's directives
; and the block's. Keeps rbx, r12-r15.
match_variant:
	push	r13
	push	r14
	push	r15
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	mov	r15,rax
	mov	rdi,rax
	mov	rsi,rbx
	mov	ecx,N_SIZE
	rep	movsb
	mov	qword [r15+N_CHILD],0
	mov	qword [r15+N_NEXT],0
	xor	r14d,r14d			; the last one in it
	; the route's, but for what the block replaces
	mov	r13,[rbx+N_CHILD]
.own:
	test	r13,r13
	jz	.block
	lea	rax,[dir_table + D_SIZE*DIR_MATCH]
	cmp	[r13+N_DEF],rax
	je	.own_next
	mov	rdi,r13
	call	match_replaces
	test	eax,eax
	jnz	.own_next
	mov	rsi,r13
	call	.add
.own_next:
	mov	r13,[r13+N_NEXT]
	jmp	.own
.block:
	mov	r13,[r12+N_CHILD]
.mine:
	test	r13,r13
	jz	.done
	mov	rsi,r13
	call	.add
	mov	r13,[r13+N_NEXT]
	jmp	.mine
.done:
	mov	rax,r15
	pop	r15
	pop	r14
	pop	r13
	ret
; rsi = a node: a copy, at the end
.add:
	push	rsi
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	pop	rsi
	mov	rdi,rax
	mov	ecx,N_SIZE
	rep	movsb
	mov	qword [rax+N_NEXT],0
	mov	[rax+N_PARENT],r15
	test	r14,r14
	jz	.first
	mov	[r14+N_NEXT],rax
	jmp	.linked
.first:
	mov	[r15+N_CHILD],rax
.linked:
	mov	r14,rax
	ret

; rdi = a directive of the route, r12 = a block: eax = 1 when the block replaces it
match_replaces:
	push	r13
	mov	r13,rdi
	lea	rax,[dir_table + D_SIZE*DIR_RLIMIT]
	cmp	[r13+N_DEF],rax
	je	.no				; limits add up
	mov	r8,[r12+N_CHILD]
.next:
	test	r8,r8
	jz	.no
	mov	rax,[r8+N_DEF]
	cmp	rax,[r13+N_DEF]
	je	.yes
	push	rax
	call	.goes
	mov	ecx,eax
	pop	rax
	test	ecx,ecx
	jz	.other
	mov	rax,[r13+N_DEF]
	call	.goes
	test	eax,eax
	jnz	.yes
.other:
	mov	r8,[r8+N_NEXT]
	jmp	.next
.yes:
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r13
	ret
; rax = a directive's entry: eax = 1 when it says where the request goes
.goes:
	lea	rcx,[dir_table + D_SIZE*DIR_TO]
	cmp	rax,rcx
	je	.is
	lea	rcx,[dir_table + D_SIZE*DIR_REDIRECT]
	cmp	rax,rcx
	je	.is
	lea	rcx,[dir_table + D_SIZE*DIR_RESPOND]
	cmp	rax,rcx
	je	.is
	lea	rcx,[dir_table + D_SIZE*DIR_SPLIT]
	cmp	rax,rcx
	je	.is
	lea	rcx,[dir_table + D_SIZE*DIR_FILES]
	cmp	rax,rcx
	je	.is
	xor	eax,eax
	ret
.is:
	mov	eax,1
	ret

; rcx = a route entry just made: its blocks, from g_cmv. Keeps all but rax, rdx, rsi,
; rdi, r8.
match_entries:
	cmp	dword [g_cmv_n],0
	je	.none
	push	r12
	push	r13
	xor	r12d,r12d
.next:
	mov	eax,[g_plan_mroutes]
	cmp	eax,MAX_MATCH
	jae	plan_bad_match
	inc	dword [g_plan_mroutes]
	test	r12d,r12d
	jnz	@f
	lea	edx,[rax+1]
	mov	[rcx+RT_MATCH],edx
@@:
	imul	rdx,rax,RT_SIZE
	lea	rdx,[g_mroutes+rdx]
	mov	rsi,[rcx+RT_PATH]
	mov	[rdx+RT_PATH],rsi
	mov	esi,[rcx+RT_PLEN]
	mov	[rdx+RT_PLEN],esi
	mov	esi,[rcx+RT_PREFIX]
	mov	[rdx+RT_PREFIX],esi
	imul	r13,r12,CV_SIZE
	lea	r13,[g_cmv+r13]
	mov	esi,[r13+CV_ACT]
	mov	[rdx+RT_ACT],esi
	mov	esi,[r13+CV_POOL]
	mov	[rdx+RT_POOL],esi
	mov	r8,rax
	shl	r8,4
	lea	r8,[g_mblocks+r8]
	mov	[r8+MB_RT],eax
	mov	esi,[r13+CV_CFIRST]
	mov	[r8+MB_CFIRST],esi
	mov	esi,[r13+CV_CN]
	mov	[r8+MB_CN],esi
	inc	r12d
	cmp	r12d,[g_cmv_n]
	jb	.next
	mov	dword [r8+MB_LAST],1
	pop	r13
	pop	r12
.none:
	ret

plan_bad_match:
	call	log_begin
	out_lit 'match needs conditions: method=, header:NAME[=VALUE], query:NAME[=VALUE], cookie:NAME[=VALUE], client.ip=CIDR, client.country=CC, path=~REGEX (and NAME=~REGEX); pools that exist; no `match` or `use` inside; at most 1024 in a route'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
