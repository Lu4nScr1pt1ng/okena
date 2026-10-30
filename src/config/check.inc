; Configuration checker: structure against the schema, values against
; their types, then the rules that span directives (pools that exist,
; addresses used once, listeners that send traffic somewhere).

bss
	g_chk_listeners	dd ?
	g_chk_pools	dd ?
	g_chk_servers	dd ?
	g_chk_addr:	rb AD_SIZE
	g_chk_addr2:	rb AD_SIZE
end bss

; Walk the whole tree.
cfg_check:
	mov	rdi,[g_cfg_root]
	mov	esi,CTX_TOP
	call	check_children
	cmp	dword [g_cfg_errors],0
	jne	.done
	call	check_semantics
.done:
	ret

; rdi = parent node, esi = context of its block.
check_children:
	push	rbx
	push	r12
	mov	r12d,esi
	mov	rbx,[rdi+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rdi,rbx
	mov	esi,r12d
	call	check_directive
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r12
	pop	rbx
	ret

; rdi = node, esi = context.
check_directive:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	ecx,r13d
	mov	edx,1
	shl	edx,cl
	call	dir_lookup
	test	rax,rax
	jz	.unknown
	mov	rbx,rax
	mov	[r12+N_DEF],rbx
	test	dword [rbx+D_FLAGS],F_UNIQUE
	jz	@f
	mov	rdi,r12
	call	check_unique
@@:
	; `tcp :5432 to 10.0.0.1:5432` on the command line: no braces needed
	cmp	dword [g_cfg_inline],0
	je	.block
	cmp	dword [r12+N_BLOCK],0
	jne	.block
	cmp	dword [rbx+D_CHILD],0
	je	.block
	mov	rdi,r12
	call	inline_split
.block:
	mov	rdi,r12
	mov	rsi,rbx
	call	check_args
	cmp	dword [r12+N_BLOCK],0
	je	.no_block
	mov	esi,[rbx+D_CHILD]
	test	esi,esi
	jz	.keys_block
	mov	rdi,r12
	call	check_children
	jmp	.args
.keys_block:
	test	dword [rbx+D_FLAGS],F_KEYS_BLOCK
	jz	.no_block_allowed
	mov	rdi,r12
	call	check_keys_block
	jmp	.args
.no_block_allowed:
	mov	rdi,[r12+N_BRACE]
	mov	esi,1
	mov	edx,[r12+N_BLINE]
	call	cfg_error
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' does not take a block'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.args
.no_block:
	test	dword [rbx+D_FLAGS],F_BLOCK_REQ
	jz	.args
	cmp	dword [r12+N_BLOCK],0
	jne	.args
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' needs a block'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: write its settings between `{` and `}`'
	call	cfg_note_end
	call	cfg_error_limit
.args:
	jmp	.out
.unknown:
	mov	rdi,r12
	mov	esi,r13d
	call	report_unknown
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = node whose entry is F_UNIQUE. Reports when an earlier sibling has
; the same entry.
check_unique:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	rax,[r12+N_PARENT]
	mov	rbx,[rax+N_CHILD]
.next:
	cmp	rbx,r12
	je	.done
	mov	rax,[rbx+N_DEF]
	cmp	rax,[r12+N_DEF]
	je	.dup
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.dup:
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' is set twice in the same block'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: first set on line '
	mov	eax,[rbx+N_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
.done:
	pop	r12
	pop	rbx
	ret

; Command-line form: the first argument that names a directive of the
; block starts a nested directive with the rest of the arguments.
; rdi = node (no block, its entry has a child context).
inline_split:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	rax,[r12+N_DEF]
	mov	ecx,[rax+D_CHILD]
	mov	r13d,1
	shl	r13d,cl
	xor	r14d,r14d			; index
.scan:
	cmp	r14d,[r12+N_ARGC]
	jae	.done
	imul	rbx,r14,A_SIZE
	add	rbx,[r12+N_ARGS]
	cmp	dword [rbx+A_KIND],ARG_WORD
	jne	.skip
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	mov	edx,r13d
	call	dir_lookup
	test	rax,rax
	jnz	.split
.skip:
	inc	r14d
	jmp	.scan
.split:
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	mov	rcx,[rbx+A_VAL]
	mov	[rax+N_NAME],rcx
	mov	ecx,[rbx+A_VLEN]
	mov	[rax+N_NLEN],ecx
	mov	ecx,[rbx+A_LINE]
	mov	[rax+N_LINE],ecx
	mov	[rax+N_PARENT],r12
	lea	rcx,[rbx+A_SIZE]
	mov	[rax+N_ARGS],rcx
	mov	ecx,[r12+N_ARGC]
	sub	ecx,r14d
	dec	ecx
	mov	[rax+N_ARGC],ecx
	mov	[r12+N_ARGC],r14d
	mov	[r12+N_CHILD],rax
	mov	dword [r12+N_BLOCK],1
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Unknown in this context. rdi = node, esi = context.
report_unknown:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	; exists elsewhere?
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,-1
	call	dir_lookup
	test	rax,rax
	jnz	.misplaced
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	lea	rdx,[future_names]
	call	list_index
	test	rax,rax
	jns	.future
	out_lit 'unknown directive '
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	call	cfg_diag_end
	; HTTPS is a layer, not a listener
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	cstring str_https, 'https',0
	lea	rdx,[str_https]
	call	mem_eq_cstr
	test	eax,eax
	jz	@f
	call	cfg_note
	out_lit 'help: HTTPS is `http` with a TLS layer: `http :443 { tls { cert auto } ... }`'
	call	cfg_note_end
	jmp	.out
@@:
	; suggest among the directives of this context
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	call	suggest_begin
	lea	rbx,[dir_table]
.offer:
	lea	rax,[dir_table_end]
	cmp	rbx,rax
	jae	.offered
	mov	ecx,r13d
	mov	eax,1
	shl	eax,cl
	test	[rbx+D_CTX],eax
	jz	@f
	lea	rdx,[rbx+D_NAME]
	call	suggest_offer
@@:
	add	rbx,D_SIZE
	jmp	.offer
.offered:
	call	suggest_note
	jmp	.out
.misplaced:
	mov	rbx,rax
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' is not allowed in '
	mov	ecx,r13d
	dec	ecx
	lea	rdx,[ctx_names]
	call	list_item
	call	out_str
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: '
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' belongs in '
	bsf	ecx,[rbx+D_CTX]
	dec	ecx
	lea	rdx,[ctx_names]
	call	list_item
	call	out_str
	call	cfg_note_end
	jmp	.out
.future:
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' is not supported by this version of okena yet'
	call	cfg_diag_end
.out:
	call	cfg_error_limit
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = arg. rdi/esi = what a caret should point at for its value.
arg_value_span:
	mov	rax,[rdi+A_VAL]
	cmp	rax,[g_cfg_src]
	jb	.raw
	cmp	rax,[g_cfg_end]
	ja	.raw
	mov	esi,[rdi+A_VLEN]
	mov	rdi,rax
	test	esi,esi
	jnz	@f
	mov	esi,1
@@:
	ret
.raw:
	mov	esi,[rdi+A_RAWLEN]
	mov	rdi,[rdi+A_RAW]
	ret

; Positional arguments and options. rdi = node, rsi = entry.
check_args:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	cmp	qword [r13+D_TYPE1],T_TARGET
	jne	.generic
	mov	rdi,r12
	call	check_target
	jmp	.out
.generic:
	xor	r14d,r14d			; index
	xor	r15d,r15d			; positional count
.next:
	cmp	r14d,[r12+N_ARGC]
	jae	.count
	imul	rbx,r14,A_SIZE
	add	rbx,[r12+N_ARGS]
	cmp	dword [rbx+A_KIND],ARG_KV
	je	.option
	; positional
	movzx	eax,word [r13+D_MAXP]
	cmp	r15d,eax
	jae	.extra
	mov	rsi,[r13+D_TYPE1]
	test	r15d,r15d
	jz	@f
	mov	rsi,[r13+D_TYPEN]
@@:
	mov	rdi,rbx
	call	check_value
	inc	r15d
	jmp	.advance
.extra:
	inc	r15d
	mov	rdi,[rbx+A_RAW]
	mov	esi,[rbx+A_RAWLEN]
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'unexpected argument for '
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	call	cfg_diag_end
	call	usage_note
	call	cfg_error_limit
	jmp	.advance
.option:
	mov	rdi,rbx
	mov	rsi,r12
	mov	rdx,[r13+D_KEYS]
	call	check_option
.advance:
	inc	r14d
	jmp	.next
.count:
	movzx	eax,word [r13+D_MINP]
	cmp	r15d,eax
	jae	.out
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' needs '
	movzx	eax,word [r13+D_MINP]
	cmp	eax,1
	jne	@f
	out_lit 'a value'
	jmp	.counted
@@:
	call	out_u64
	out_lit ' values'
.counted:
	call	cfg_diag_end
	mov	rbx,r13
	call	usage_note
	call	cfg_error_limit
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; "= help: expected ..." for the type of the entry in r13 (first arg).
usage_note:
	mov	rdi,[r13+D_TYPE1]
	jmp	type_help

; rdi = arg (ARG_KV), rsi = node, rdx = options table.
check_option:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	test	r13,r13
	jz	.none
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	mov	rdx,r13
	call	key_lookup
	test	rax,rax
	jz	.unknown
	mov	r14,rax
	; the same key twice?
	mov	rdi,r12
	mov	rsi,rbx
	call	option_repeated
	cmp	qword [r14+K_TYPE],T_FUTURE
	je	.future
	mov	rdi,rbx
	mov	rsi,[r14+K_TYPE]
	call	check_value
	jmp	.out
.future:
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'option '
	mov	rsi,[rbx+A_KEY]
	mov	edx,[rbx+A_KLEN]
	call	cfg_quote
	out_lit ' is not supported by this version of okena yet'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.none:
	mov	rdi,[rbx+A_RAW]
	mov	esi,[rbx+A_RAWLEN]
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	out_lit ' takes no options'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.unknown:
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'unknown option '
	mov	rsi,[rbx+A_KEY]
	mov	edx,[rbx+A_KLEN]
	call	cfg_quote
	out_lit ' for '
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	call	cfg_diag_end
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	call	suggest_begin
	mov	r14,r13
.offer:
	cmp	byte [r14+K_NAME],0
	je	.offered
	lea	rdx,[r14+K_NAME]
	call	suggest_offer
	add	r14,K_SIZE
	jmp	.offer
.offered:
	cmp	qword [g_sug_ptr],0
	jne	.suggest
	call	cfg_note
	out_lit 'help: the options are'
	mov	r14,r13
@@:
	cmp	byte [r14+K_NAME],0
	je	@f
	out_lit ' '
	lea	rsi,[r14+K_NAME]
	call	out_cstr
	add	r14,K_SIZE
	jmp	@b
@@:
	call	cfg_note_end
	jmp	.limit
.suggest:
	call	suggest_note
.limit:
	call	cfg_error_limit
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = node, rsi = an ARG_KV of it. Reports when an earlier argument or a
; block entry has the same key.
option_repeated:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r12+N_ARGS]
.next:
	cmp	rbx,r13
	jae	.done
	cmp	dword [rbx+A_KIND],ARG_KV
	jne	.skip
	mov	eax,[rbx+A_KLEN]
	cmp	eax,[r13+A_KLEN]
	jne	.skip
	mov	rdi,[rbx+A_KEY]
	mov	rsi,[r13+A_KEY]
	mov	edx,eax
	call	mem_eq
	test	eax,eax
	jnz	.dup
.skip:
	add	rbx,A_SIZE
	jmp	.next
.dup:
	mov	rdi,[r13+A_KEY]
	mov	esi,[r13+A_KLEN]
	mov	edx,[r13+A_LINE]
	call	cfg_error
	out_lit 'option '
	mov	rsi,[r13+A_KEY]
	mov	edx,[r13+A_KLEN]
	call	cfg_quote
	out_lit ' is given twice'
	call	cfg_diag_end
	call	cfg_error_limit
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Block form of options: each nested directive is "key value".
; rdi = node.
check_keys_block:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	rax,[r12+N_DEF]
	mov	r13,[rax+D_KEYS]
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	rdx,r13
	call	key_lookup
	test	rax,rax
	jz	.unknown
	mov	r14,rax
	cmp	dword [rbx+N_BLOCK],0
	jne	.shape
	cmp	dword [rbx+N_ARGC],1
	jne	.shape
	mov	rdi,[rbx+N_ARGS]
	cmp	dword [rdi+A_KIND],ARG_KV
	je	.shape
	; also given on the directive's own line?
	mov	rdi,r12
	mov	rsi,rbx
	call	keys_block_repeated
	cmp	qword [r14+K_TYPE],T_FUTURE
	je	.future
	mov	rdi,[rbx+N_ARGS]
	mov	rsi,[r14+K_TYPE]
	call	check_value
	jmp	.advance
.future:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'option '
	mov	rsi,[rbx+N_NAME]
	mov	edx,[rbx+N_NLEN]
	call	cfg_quote
	out_lit ' is not supported by this version of okena yet'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.advance
.shape:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'expected one value for '
	mov	rsi,[rbx+N_NAME]
	mov	edx,[rbx+N_NLEN]
	call	cfg_quote
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.advance
.unknown:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'unknown option '
	mov	rsi,[rbx+N_NAME]
	mov	edx,[rbx+N_NLEN]
	call	cfg_quote
	out_lit ' for '
	mov	rsi,[r12+N_NAME]
	mov	edx,[r12+N_NLEN]
	call	cfg_quote
	call	cfg_diag_end
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	call	suggest_begin
	mov	r14,r13
@@:
	cmp	byte [r14+K_NAME],0
	je	@f
	lea	rdx,[r14+K_NAME]
	call	suggest_offer
	add	r14,K_SIZE
	jmp	@b
@@:
	call	suggest_note
	call	cfg_error_limit
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = node with a keys block, rsi = block entry. Reports when the same
; key is on the directive's line or earlier in the block.
keys_block_repeated:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	; on the line
	mov	rbx,[r12+N_ARGS]
	mov	ecx,[r12+N_ARGC]
	imul	ecx,ecx,A_SIZE
	add	rcx,rbx
	push	rcx
.args:
	cmp	rbx,[rsp]
	jae	.args_done
	cmp	dword [rbx+A_KIND],ARG_KV
	jne	.arg_skip
	mov	eax,[rbx+A_KLEN]
	cmp	eax,[r13+N_NLEN]
	jne	.arg_skip
	mov	rdi,[rbx+A_KEY]
	mov	rsi,[r13+N_NAME]
	mov	edx,eax
	call	mem_eq
	test	eax,eax
	jnz	.dup_pop
.arg_skip:
	add	rbx,A_SIZE
	jmp	.args
.args_done:
	pop	rcx
	; earlier in the block
	mov	rbx,[r12+N_CHILD]
.block:
	cmp	rbx,r13
	je	.done
	mov	eax,[rbx+N_NLEN]
	cmp	eax,[r13+N_NLEN]
	jne	.block_skip
	mov	rdi,[rbx+N_NAME]
	mov	rsi,[r13+N_NAME]
	mov	edx,eax
	call	mem_eq
	test	eax,eax
	jnz	.dup
.block_skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.block
.dup_pop:
	pop	rcx
.dup:
	mov	rdi,[r13+N_NAME]
	mov	esi,[r13+N_NLEN]
	mov	edx,[r13+N_LINE]
	call	cfg_error
	out_lit 'option '
	mov	rsi,[r13+N_NAME]
	mov	edx,[r13+N_NLEN]
	call	cfg_quote
	out_lit ' is given twice'
	call	cfg_diag_end
	call	cfg_error_limit
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; `to pool NAME` or `to ADDR...`. rdi = node.
cstring str_pool_word, 'pool',0

check_target:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	rbx,[r12+N_ARGS]
	cmp	dword [r12+N_ARGC],0
	je	.missing
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	lea	rdx,[str_pool_word]
	call	mem_eq_cstr
	test	eax,eax
	jz	.addresses
	cmp	dword [rbx+A_KIND],ARG_WORD
	jne	.addresses
	cmp	dword [r12+N_ARGC],2
	jne	.pool_shape
	add	rbx,A_SIZE
	mov	rdi,rbx
	mov	esi,T_NAME
	call	check_value
	jmp	.out
.pool_shape:
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	out_lit '`to pool` takes exactly one pool name'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.addresses:
	xor	r13d,r13d
.addr:
	cmp	r13d,[r12+N_ARGC]
	jae	.out
	imul	rdi,r13,A_SIZE
	add	rdi,[r12+N_ARGS]
	cmp	dword [rdi+A_KIND],ARG_KV
	je	.option
	mov	esi,T_BACKEND
	call	check_value
	inc	r13d
	jmp	.addr
.option:
	push	rdi
	mov	rsi,[rdi+A_KEY]
	mov	edx,[rdi+A_KLEN]
	mov	rdi,rsi
	mov	esi,edx
	mov	rdx,[rsp]
	mov	edx,[rdx+A_LINE]
	call	cfg_error
	out_lit '`to` takes addresses or `pool NAME`, not options'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: for weights and health checks, declare a `pool` and use `to pool NAME`'
	call	cfg_note_end
	call	cfg_error_limit
	pop	rdi
	inc	r13d
	jmp	.addr
.missing:
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	out_lit '`to` needs a destination'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `to 10.0.0.11:5432 10.0.0.12:5432` or `to pool NAME`'
	call	cfg_note_end
	call	cfg_error_limit
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- values

; rdi = arg, rsi = type. Reports and returns CF when invalid.
check_value:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	cmp	r12,4096
	jae	.enum
	cmp	r12,T_ANY
	je	.ok
	cmp	r12,T_NAME
	je	.name
	cmp	r12,T_UINT
	je	.uint
	cmp	r12,T_COUNT
	je	.count
	cmp	r12,T_WEIGHT
	je	.weight
	cmp	r12,T_DURATION
	je	.duration
	cmp	r12,T_SIZE
	je	.size
	cmp	r12,T_RATE
	je	.rate
	cmp	r12,T_PERCENT
	je	.percent
	cmp	r12,T_LISTEN
	je	.listen
	cmp	r12,T_BACKEND
	je	.backend
	cmp	r12,T_WORKERS
	je	.workers
	cmp	r12,T_ROUTE
	je	.route
	cmp	r12,T_HOSTNAME
	je	.hostname
	cmp	r12,T_LOGDEST
	je	.logdest
	cmp	r12,T_CIDR
	je	.cidr
	cmp	r12,T_STATUSES
	je	.statuses
	jmp	.ok
.statuses:
	call	parse_statuses
	jc	.bad
	jmp	.ok
.cidr:
	sub	rsp,TR_SIZE
	mov	rdx,rsp
	call	parse_cidr
	lea	rsp,[rsp+TR_SIZE]		; (keeps CF)
	jc	.bad
	jmp	.ok
.logdest:
	lea	rdx,[e_logdest]
	call	list_index
	test	rax,rax
	jns	.ok
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	cmp	byte [rdi],'/'
	jne	.bad
	cmp	esi,ALOG_PATH - 1
	jae	.bad
	jmp	.ok
.hostname:
	; "*.example.com" or a name; matched without case
	cmp	esi,2
	jb	@f
	cmp	word [rdi],'*.'
	jne	@f
	add	rdi,2
	sub	esi,2
@@:
	call	check_hostname
	jc	.bad
	jmp	.ok
.route:
	call	check_route_arg
	jc	.bad
	jmp	.ok
.name:
	call	check_name
	jc	.bad
	jmp	.ok
.uint:
	call	parse_decimal
	jc	.bad
	cmp	rax,0x7FFFFFFF
	ja	.bad
	jmp	.ok
.count:
	call	parse_decimal
	jc	.bad
	test	rax,rax
	jz	.bad
	cmp	rax,100000000
	ja	.bad
	jmp	.ok
.weight:
	call	parse_decimal
	jc	.bad
	test	rax,rax
	jz	.bad
	cmp	rax,1000
	ja	.bad
	jmp	.ok
.duration:
	call	parse_duration
	jc	.bad
	jmp	.ok
.size:
	call	parse_size
	jc	.bad
	jmp	.ok
.rate:
	call	parse_rate
	jc	.bad
	jmp	.ok
.percent:
	call	parse_percent
	jc	.bad
	jmp	.ok
.listen:
	lea	rdx,[g_chk_addr]
	xor	ecx,ecx
	call	parse_address
	jc	.bad_addr
	jmp	.ok
.backend:
	lea	rdx,[g_chk_addr]
	mov	ecx,1
	call	parse_address
	jc	.bad_addr
	jmp	.ok
.workers:
	lea	rdx,[e_auto]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.ok
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	parse_decimal
	jc	.bad
	test	rax,rax
	jz	.bad
	cmp	rax,MAX_WORKERS
	ja	.bad
	jmp	.ok
.enum:
	mov	rdx,r12
	call	list_index
	test	rax,rax
	js	.bad_enum
.ok:
	clc
	jmp	.out
.bad_addr:
	push	rax
	call	value_error_head
	out_lit 'invalid address '
	call	value_quote
	pop	rax
	cmp	eax,ADDR_ERR_PORT
	jne	@f
	out_lit ': the port must be from 1 to 65535'
@@:
	cmp	eax,ADDR_ERR_IP
	jne	@f
	out_lit ': not a valid IP address'
@@:
	cmp	eax,ADDR_ERR_NAME
	jne	@f
	out_lit ': not a valid host name'
@@:
	cmp	eax,ADDR_ERR_ANY
	jne	@f
	out_lit ': a backend needs a host'
@@:
	cmp	eax,ADDR_ERR_PATH
	jne	@f
	out_lit ': a unix socket path must be absolute and at most 107 bytes'
@@:
	call	cfg_diag_end
	mov	rdi,r12
	call	type_help
	jmp	.fail
.bad_enum:
	call	value_error_head
	call	value_quote
	out_lit ' is not one of:'
	mov	rdx,r12
	call	out_list
	call	cfg_diag_end
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	suggest_begin
	mov	rdx,r12
	call	suggest_offer_list
	call	suggest_note
	jmp	.fail
.bad:
	call	value_error_head
	out_lit 'invalid value '
	call	value_quote
	call	cfg_diag_end
	mov	rdi,r12
	call	type_help
.fail:
	call	cfg_error_limit
	stc
.out:
	pop	r12
	pop	rbx
	ret

cstring e_auto, 'auto',0

; rdi/esi = route argument. CF when it is neither a path nor a method.
; Paths: "/" then target characters, at most one "*", only as the last
; segment ("/api/*") or alone after "/" ("/*"). Methods: tchar capitals.
check_route_arg:
	test	esi,esi
	jz	.bad
	cmp	byte [rdi],'/'
	jne	.method
	xor	ecx,ecx
.path:
	cmp	ecx,esi
	jae	.ok
	movzx	eax,byte [rdi+rcx]
	cmp	al,'*'
	je	.star
	cmp	al,'?'
	je	.bad				; queries are not part of a route
	cmp	byte [http_target_ok+rax],0
	je	.bad
	inc	ecx
	jmp	.path
.star:
	lea	eax,[rcx+1]
	cmp	eax,esi
	jne	.bad				; "*" only at the end
	cmp	byte [rdi+rcx-1],'/'
	jne	.bad				; and only as a whole segment
	jmp	.ok
.method:
	xor	ecx,ecx
.mchar:
	movzx	eax,byte [rdi+rcx]
	cmp	al,'A'
	jb	.bad
	cmp	al,'Z'
	ja	.bad
	inc	ecx
	cmp	ecx,esi
	jb	.mchar
.ok:
	clc
	ret
.bad:
	stc
	ret

; rdx = NUL-separated list. Prints " a b c".
out_list:
	push	rbx
	mov	rbx,rdx
.next:
	cmp	byte [rbx],0
	je	.done
	out_lit ' '
	mov	rsi,rbx
	call	out_cstr
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	jmp	.next
.done:
	pop	rbx
	ret

; Diagnostic at the value of the argument in rbx (inside check_value).
value_error_head:
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	jmp	cfg_error

value_quote:
	mov	rsi,[rbx+A_VAL]
	mov	edx,[rbx+A_VLEN]
	jmp	cfg_quote

; rdi = type. Prints "= help: expected ..." for it.
type_help:
	cmp	rdi,4096
	jae	.none
	cmp	rdi,T_ANY
	jbe	.none
	push	rbx
	mov	rbx,rdi
	call	cfg_note
	out_lit 'help: expected '
	cmp	rbx,T_NAME
	jne	@f
	out_lit 'a name: lowercase letters, digits, `-` and `_`, starting with a letter or digit'
	jmp	.end
@@:
	cmp	rbx,T_UINT
	jne	@f
	out_lit 'a whole number'
	jmp	.end
@@:
	cmp	rbx,T_COUNT
	jne	@f
	out_lit 'a whole number from 1 to 100000000'
	jmp	.end
@@:
	cmp	rbx,T_WEIGHT
	jne	@f
	out_lit 'a weight from 1 to 1000'
	jmp	.end
@@:
	cmp	rbx,T_DURATION
	jne	@f
	out_lit 'a duration with its unit: 250ms, 30s, 5m, 1h (units: us ms s m h d)'
	jmp	.end
@@:
	cmp	rbx,T_SIZE
	jne	@f
	out_lit 'a size with its unit: 512B, 16KiB, 4MiB, 1GiB'
	jmp	.end
@@:
	cmp	rbx,T_RATE
	jne	@f
	out_lit 'a rate: 100/s, 5000/m, 10000/h'
	jmp	.end
@@:
	cmp	rbx,T_PERCENT
	jne	@f
	out_lit 'a percentage: 20%, 0.5%'
	jmp	.end
@@:
	cmp	rbx,T_LISTEN
	jne	@f
	out_lit 'a listen address: :443, 10.0.0.1:80, [::1]:8080'
	jmp	.end
@@:
	cmp	rbx,T_BACKEND
	jne	@f
	out_lit 'an address: 10.0.0.11:5432, [2001:db8::1]:443, db.internal:5432, unix:/run/app.sock'
	jmp	.end
@@:
	cmp	rbx,T_WORKERS
	jne	@f
	out_lit '`auto` or a number of workers from 1 to 256'
	jmp	.end
@@:
	cmp	rbx,T_ROUTE
	jne	@f
	out_lit 'a path (/health, /api/*, /*) or a method in capitals (GET, POST)'
	jmp	.end
@@:
	cmp	rbx,T_HOSTNAME
	jne	@f
	out_lit 'a host name (api.example.com) or *.example.com'
	jmp	.end
@@:
	cmp	rbx,T_STATUSES
	jne	@f
	out_lit 'an HTTP status or a range of them: 200, 200..299'
	jmp	.end
@@:
	cmp	rbx,T_CIDR
	jne	@f
	out_lit 'an IP address or a range: 10.0.0.0/8, 192.168.1.10, 2001:db8::/32'
	jmp	.end
@@:
	cmp	rbx,T_LOGDEST
	jne	@f
	out_lit '`stdout`, `stderr`, `off`, or an absolute file path (/var/log/okena/access.log)'
	jmp	.end
@@:
.end:
	call	cfg_note_end
	pop	rbx
.none:
	ret

; ------------------------------------------------------------- semantics

; Rules across directives. Runs only on a tree without structural errors.
check_semantics:
	push	rbx
	push	r12
	push	r13
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.unused
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_TCP]
	cmp	rax,rcx
	je	.listener
	lea	rcx,[dir_table + D_SIZE*DIR_POOL]
	cmp	rax,rcx
	je	.pool
	lea	rcx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	rax,rcx
	je	.http
	jmp	.advance
.http:
	inc	dword [g_chk_listeners]
	mov	rdi,rbx
	call	check_http
	mov	rdi,rbx
	call	check_tls
	jmp	.advance
.listener:
	inc	dword [g_chk_listeners]
	mov	rdi,rbx
	call	check_listener
	mov	rdi,rbx
	call	check_tcp_timeouts
	mov	rdi,rbx
	call	check_tls
	jmp	.advance
.pool:
	inc	dword [g_chk_pools]
	mov	rdi,rbx
	call	check_pool
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.unused:
	call	check_unused_pools
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = listener: a tls block names both its certificate and its key
; (the files themselves are read when the configuration is compiled).
check_tls:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	[g_chk_tls_listener],rdi
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	.done
	mov	rbx,rax
	cmp	dword [rbx+N_ARGC],0
	jne	.passthrough
	mov	rdi,rbx				; sni and default belong to passthrough
	mov	ecx,DIR_SNI
	call	find_child
	test	rax,rax
	jnz	.pt_only
	mov	rdi,rbx
	mov	ecx,DIR_DEFAULT
	call	find_child
	test	rax,rax
	jnz	.pt_only
	mov	rdi,rbx
	mov	ecx,DIR_KEY
	call	find_child
	mov	r15,rax				; the block's key line, or 0
	; the certs: how many, how many without key=, the first of those
	xor	r12d,r12d
	xor	r13d,r13d
	xor	r14d,r14d
	lea	rdx,[dir_table + D_SIZE*DIR_CERT]
	mov	rax,[rbx+N_CHILD]
.cert:
	test	rax,rax
	jz	.counted
	cmp	[rax+N_DEF],rdx
	jne	.next
	inc	r12d
	cmp	dword [rax+N_ARGC],1
	ja	.next				; key=FILE on the line
	inc	r13d
	test	r14,r14
	jnz	.next
	mov	r14,rax
.next:
	mov	rax,[rax+N_NEXT]
	jmp	.cert
.counted:
	test	r12d,r12d
	jz	.missing
	test	r13d,r13d
	jz	.all_keyed
	cmp	r12d,1
	ja	.unkeyed
	test	r15,r15
	jz	.missing
	jmp	.done
.all_keyed:
	test	r15,r15
	jz	.done
	mov	rdi,[r15+N_NAME]
	mov	esi,[r15+N_NLEN]
	mov	edx,[r15+N_LINE]
	call	cfg_error
	out_lit 'every cert here names its key (key=): this key line belongs to none'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.done
.unkeyed:
	mov	rdi,[r14+N_NAME]
	mov	esi,[r14+N_NLEN]
	mov	edx,[r14+N_LINE]
	call	cfg_error
	out_lit 'with several certificates, each names its key'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `cert /etc/okena/example.pem key=/etc/okena/example.key`'
	call	cfg_note_end
	call	cfg_error_limit
	jmp	.done
.passthrough:
	mov	rdi,[g_chk_tls_listener]
	mov	rsi,rbx
	call	check_passthrough
	jmp	.done
.pt_only:
	mov	rdi,[rax+N_NAME]
	mov	esi,[rax+N_NLEN]
	mov	edx,[rax+N_LINE]
	call	cfg_error
	out_lit 'routing on SNI is for `tls passthrough`; this tls block decrypts'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.done
.missing:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'a tls block needs its certificate and its key'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `tls { cert /etc/okena/fullchain.pem; key /etc/okena/key.pem }`'
	call	cfg_note_end
	call	cfg_error_limit
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = tcp listener: `header` and `response` are http timeouts.
check_tcp_timeouts:
	push	rbx
	mov	ecx,DIR_TIMEOUT
	call	find_child
	test	rax,rax
	jz	.done
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_HEADER]
	cmp	[rbx+N_DEF],rax
	je	.http_only
	lea	rax,[dir_table + D_SIZE*DIR_BODY_IDLE]
	cmp	[rbx+N_DEF],rax
	je	.http_only
	lea	rax,[dir_table + D_SIZE*DIR_RESPONSE]
	cmp	[rbx+N_DEF],rax
	jne	.advance
.http_only:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'a tcp listener has no requests to time: this is an `http` timeout'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: a tcp connection has `idle`; `header`, `body_idle` and `response` time HTTP exchanges'
	call	cfg_note_end
	call	cfg_error_limit
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	rbx
	ret

; rdi = node. rax = the first child with entry index ecx, or 0.
find_child:
	imul	ecx,ecx,D_SIZE
	lea	rdx,[dir_table+rcx]
	mov	rax,[rdi+N_CHILD]
.next:
	test	rax,rax
	jz	.done
	cmp	[rax+N_DEF],rdx
	je	.done
	mov	rax,[rax+N_NEXT]
	jmp	.next
.done:
	ret

; rdi = tcp listener node.
check_listener:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	ecx,DIR_TO
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,r12
	call	listener_passthrough
	test	rax,rax
	jnz	.addresses			; its sni lines name the pools
	jmp	.no_target
@@:
	mov	rbx,rax
	mov	r13,[rbx+N_ARGS]
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	lea	rdx,[str_pool_word]
	call	mem_eq_cstr
	test	eax,eax
	jz	.inline_pool
	add	r13,A_SIZE
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	call	pool_find
	test	rax,rax
	jnz	.addresses
	mov	rdi,r13
	call	arg_value_span
	mov	edx,[r13+A_LINE]
	call	cfg_error
	out_lit 'there is no pool named '
	mov	rsi,[r13+A_VAL]
	mov	edx,[r13+A_VLEN]
	call	cfg_quote
	call	cfg_diag_end
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	call	suggest_begin
	call	suggest_pools
	call	suggest_note
	call	cfg_error_limit
	jmp	.addresses
.inline_pool:
	inc	dword [g_chk_pools]
	mov	eax,[rbx+N_ARGC]
	add	[g_chk_servers],eax
	mov	rdi,rbx
	call	check_duplicate_servers_args
	jmp	.addresses
.no_target:
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[r12+N_DEF],rax
	jne	@f
	out_lit 'this route does not send traffic anywhere'
	jmp	.said
@@:
	out_lit 'this listener does not send traffic anywhere'
.said:
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: add `to ADDRESS...` or `to pool NAME` to its block'
	call	cfg_note_end
	call	cfg_error_limit
.addresses:
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[r12+N_DEF],rax
	je	@f				; a route: its listener checks addresses
	mov	rdi,r12
	call	check_listen_addresses
@@:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = node: CF when it is a listener (tcp or http).
is_listener:
	mov	rax,[rdi+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_TCP]
	cmp	rax,rcx
	je	.yes
	lea	rcx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	rax,rcx
	je	.yes
	clc
	ret
.yes:
	stc
	ret

; rdi = http listener: routes, each sending somewhere, none twice in the
; same set (the listener's own, or a host block's); hosts named once.
check_http:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	xor	r13d,r13d			; routes
	mov	rdi,r12
	call	check_route_set
	add	r13d,eax
	mov	rbx,[r12+N_CHILD]
.host:
	test	rbx,rbx
	jz	.hosts_done
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[rbx+N_DEF],rax
	jne	.next_host
	mov	rdi,rbx
	call	check_route_set
	add	r13d,eax
	test	eax,eax
	jnz	@f
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'this host has no `route`'
	call	cfg_diag_end
	call	cfg_error_limit
@@:
	mov	rdi,r12
	mov	rsi,rbx
	call	check_host_unique
.next_host:
	mov	rbx,[rbx+N_NEXT]
	jmp	.host
.hosts_done:
	test	r13d,r13d
	jnz	.addresses
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	out_lit 'this listener has no `route`'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `route /* { to 127.0.0.1:3000 }` sends everything to one backend'
	call	cfg_note_end
	call	cfg_error_limit
.addresses:
	mov	rdi,r12
	call	check_listen_addresses
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = listener or host block: check the routes directly in it.
; eax = how many.
check_route_set:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	xor	r13d,r13d
	mov	rbx,[r12+N_CHILD]
.route:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	inc	r13d
	mov	rdi,rbx
	mov	ecx,DIR_REDIRECT
	call	find_child
	test	rax,rax
	jz	.forwards
	push	rax
	mov	rdi,rbx
	mov	ecx,DIR_TO
	call	find_child
	pop	rdi
	test	rax,rax
	jz	.redirects
	push	rdi
	mov	rdi,[rax+N_NAME]
	mov	esi,[rax+N_NLEN]
	mov	edx,[rax+N_LINE]
	call	cfg_error
	out_lit 'a route either forwards (`to`) or redirects, not both'
	call	cfg_diag_end
	call	cfg_error_limit
	pop	rdi
.redirects:
	call	check_redirect_target
	jmp	.actions
.forwards:
	mov	rdi,rbx
	call	check_listener			; its `to`
.actions:
	mov	rdi,rbx
	mov	ecx,DIR_REWRITE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	check_rewrite
@@:
	mov	rdi,rbx
	call	check_header_ops
	mov	rdi,r12
	mov	rsi,rbx
	call	check_route_unique
	mov	rdi,rbx
	call	check_route_has_path
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.route
.done:
	mov	eax,r13d
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = http listener, rsi = a host block of it: none of its names is
; also named by an earlier host block (names compared without case).
check_host_unique:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	xor	r14d,r14d			; argument of this block
.mine:
	cmp	r14d,[r13+N_ARGC]
	jae	.done
	imul	r15,r14,A_SIZE
	add	r15,[r13+N_ARGS]
	mov	rbx,[r12+N_CHILD]
.other:
	cmp	rbx,r13
	je	.mine_next			; only earlier blocks
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[rbx+N_DEF],rax
	jne	.other_next
	mov	rcx,[rbx+N_ARGS]
	mov	edx,[rbx+N_ARGC]
.theirs:
	test	edx,edx
	jz	.other_next
	mov	eax,[rcx+A_VLEN]
	cmp	eax,[r15+A_VLEN]
	jne	.theirs_next
	push	rcx
	push	rdx
	mov	rdi,[rcx+A_VAL]
	mov	rsi,[r15+A_VAL]
	mov	edx,eax
	call	mem_eq_nocase
	pop	rdx
	pop	rcx
	test	eax,eax
	jnz	.dup
.theirs_next:
	add	rcx,A_SIZE
	dec	edx
	jmp	.theirs
.other_next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.other
.dup:
	mov	rdi,r15
	call	arg_value_span
	mov	edx,[r15+A_LINE]
	call	cfg_error
	out_lit 'host '
	mov	rsi,[r15+A_VAL]
	mov	edx,[r15+A_VLEN]
	call	cfg_quote
	out_lit ' already has a block'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: on line '
	mov	eax,[rbx+N_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
.mine_next:
	inc	r14d
	jmp	.mine
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Methods as bits (0 = any method).
RM_GET		:= 1
RM_HEAD		:= 2
RM_POST		:= 4
RM_PUT		:= 8
RM_DELETE	:= 16
RM_PATCH	:= 32
RM_OPTIONS	:= 64
RM_OTHER	:= 128

enumdef e_logdest, 'stdout', 'stderr', 'off'
enumdef method_names, 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'

; rdi/esi = method name. eax = its bit.
method_bit:
	lea	rdx,[method_names]
	call	list_index
	test	eax,eax
	js	.other
	mov	ecx,eax
	mov	eax,1
	shl	eax,cl
	ret
.other:
	mov	eax,RM_OTHER
	ret

; rdi = route node. eax = the methods it names, 0 when none (any).
route_methods:
	push	rbx
	push	r12
	push	r13
	mov	rbx,[rdi+N_ARGS]
	mov	r12d,[rdi+N_ARGC]
	xor	r13d,r13d
.next:
	test	r12d,r12d
	jz	.done
	mov	rdi,[rbx+A_VAL]
	cmp	byte [rdi],'/'
	je	.skip
	mov	esi,[rbx+A_VLEN]
	call	method_bit
	or	r13d,eax
.skip:
	add	rbx,A_SIZE
	dec	r12d
	jmp	.next
.done:
	mov	eax,r13d
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = route: at least one path among its arguments.
check_route_has_path:
	mov	rcx,[rdi+N_ARGS]
	mov	edx,[rdi+N_ARGC]
.next:
	test	edx,edx
	jz	.none
	mov	rax,[rcx+A_VAL]
	cmp	byte [rax],'/'
	je	.ok
	add	rcx,A_SIZE
	dec	edx
	jmp	.next
.none:
	push	rdi
	mov	rsi,[rdi+N_NAME]
	mov	edx,[rdi+N_NLEN]
	mov	ecx,[rdi+N_LINE]
	mov	rdi,rsi
	mov	esi,edx
	mov	edx,ecx
	call	cfg_error
	out_lit 'a route needs a path: /, /api/*, /*'
	call	cfg_diag_end
	call	cfg_error_limit
	pop	rdi
.ok:
	ret

; rdi = http listener, rsi = a route of it: no earlier route of the
; listener has one of its paths with an overlapping method set.
check_route_unique:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	mov	rdi,r13
	call	route_methods
	mov	r15d,eax			; this route's methods (0 = all)
	mov	rbx,[r12+N_CHILD]
.other:
	cmp	rbx,r13
	je	.done
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	rdi,rbx
	call	route_methods
	; overlap: either is "all", or they share a method
	test	eax,eax
	jz	.paths
	test	r15d,r15d
	jz	.paths
	test	eax,r15d
	jz	.next
.paths:
	; a path of this route among the other's paths?
	xor	r14d,r14d
.mine:
	cmp	r14d,[r13+N_ARGC]
	jae	.next
	imul	rsi,r14,A_SIZE
	add	rsi,[r13+N_ARGS]
	mov	rax,[rsi+A_VAL]
	cmp	byte [rax],'/'
	jne	.mine_next
	mov	rcx,[rbx+N_ARGS]
	mov	edx,[rbx+N_ARGC]
.theirs:
	test	edx,edx
	jz	.mine_next
	push	rcx
	push	rdx
	push	rsi
	mov	rdi,rcx
	call	same_arg_value
	pop	rsi
	pop	rdx
	pop	rcx
	jc	.dup
	add	rcx,A_SIZE
	dec	edx
	jmp	.theirs
.mine_next:
	inc	r14d
	jmp	.mine
.dup:
	mov	r14,rsi
	mov	rdi,rsi
	call	arg_value_span
	mov	edx,[r14+A_LINE]
	call	cfg_error
	out_lit 'route '
	mov	rsi,[r14+A_VAL]
	mov	edx,[r14+A_VLEN]
	call	cfg_quote
	out_lit ' is already defined for these methods'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: on line '
	mov	eax,[rbx+N_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
	jmp	.done
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.other
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Each listen address must be unique across all listeners, and ":port"
; conflicts with any address on the same port. rdi = listener node.
check_listen_addresses:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	xor	r13d,r13d			; arg index
.next:
	cmp	r13d,[r12+N_ARGC]
	jae	.done
	imul	rbx,r13,A_SIZE
	add	rbx,[r12+N_ARGS]
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	lea	rdx,[g_chk_addr]
	xor	ecx,ecx
	call	parse_address
	; compare with every listen address before this one
	mov	rax,[g_cfg_root]
	mov	r14,[rax+N_CHILD]
.other:
	test	r14,r14
	jz	.advance
	push	rdi
	mov	rdi,r14
	call	is_listener
	pop	rdi
	jnc	.other_next
	xor	r15d,r15d
.other_arg:
	cmp	r14,r12
	jne	@f
	cmp	r15d,r13d
	jae	.advance			; reached ourselves
@@:
	cmp	r15d,[r14+N_ARGC]
	jae	.other_next
	imul	rdi,r15,A_SIZE
	add	rdi,[r14+N_ARGS]
	push	rdi
	mov	esi,[rdi+A_VLEN]
	mov	rdi,[rdi+A_VAL]
	lea	rdx,[g_chk_addr2]
	xor	ecx,ecx
	call	parse_address
	pop	rdi
	call	listen_conflict
	jc	.conflict
	inc	r15d
	jmp	.other_arg
.other_next:
	mov	r14,[r14+N_NEXT]
	jmp	.other
.conflict:
	push	rdi
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'address '
	mov	rsi,[rbx+A_VAL]
	mov	edx,[rbx+A_VLEN]
	call	cfg_quote
	out_lit ' is already used'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: by '
	mov	rdi,[rsp]
	mov	rsi,[rdi+A_VAL]
	mov	edx,[rdi+A_VLEN]
	call	cfg_quote
	out_lit ' on line '
	pop	rdi
	mov	eax,[rdi+A_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
.advance:
	inc	r13d
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_chk_addr vs g_chk_addr2. CF when they would bind the same socket.
listen_conflict:
	mov	eax,[g_chk_addr+AD_PORT]
	cmp	eax,[g_chk_addr2+AD_PORT]
	jne	.no
	mov	eax,[g_chk_addr+AD_KIND]
	mov	ecx,[g_chk_addr2+AD_KIND]
	cmp	eax,ADDR_ANY
	je	.yes
	cmp	ecx,ADDR_ANY
	je	.yes
	cmp	eax,ecx
	jne	.no
	mov	rax,[g_chk_addr+AD_IP]
	cmp	rax,[g_chk_addr2+AD_IP]
	jne	.no
	mov	rax,[g_chk_addr+AD_IP+8]
	cmp	rax,[g_chk_addr2+AD_IP+8]
	jne	.no
.yes:
	stc
	ret
.no:
	clc
	ret

; rdi/esi = pool name. rax = pool node or 0.
pool_find:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.none
	lea	rax,[dir_table + D_SIZE*DIR_POOL]
	cmp	[rbx+N_DEF],rax
	jne	.skip
	mov	rax,[rbx+N_ARGS]
	cmp	[rax+A_VLEN],r13d
	jne	.skip
	mov	rdi,[rax+A_VAL]
	mov	rsi,r12
	mov	edx,r13d
	call	mem_eq
	test	eax,eax
	jnz	.found
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.found:
	mov	rax,rbx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Offer every pool name to the suggester.
suggest_pools:
	push	rbx
	sub	rsp,72
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_POOL]
	cmp	[rbx+N_DEF],rax
	jne	.skip
	; copy the name to a NUL-terminated buffer
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,64
	ja	.skip
	mov	rsi,[rax+A_VAL]
	mov	rdi,rsp
	rep	movsb
	mov	byte [rdi],0
	mov	rdx,rsp
	call	suggest_offer
	; suggest_offer keeps the pointer: point into the source instead
	cmp	[g_sug_ptr],rsp
	jne	.skip
	mov	rax,[rbx+N_ARGS]
	mov	rax,[rax+A_VAL]
	mov	[g_sug_ptr],rax
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	add	rsp,72
	pop	rbx
	ret

; rdi = pool node: a unique name, at least one server, no server twice.
check_pool:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	; name defined earlier?
	mov	rax,[r12+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	pool_find
	cmp	rax,r12
	je	.unique
	mov	rbx,rax
	mov	rax,[r12+N_ARGS]
	mov	rdi,rax
	call	arg_value_span
	mov	rax,[r12+N_ARGS]
	mov	edx,[rax+A_LINE]
	call	cfg_error
	out_lit 'pool '
	mov	rax,[r12+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	cfg_quote
	out_lit ' is defined twice'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: first defined on line '
	mov	eax,[rbx+N_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
.unique:
	xor	r13d,r13d			; servers
	mov	rbx,[r12+N_CHILD]
.server:
	test	rbx,rbx
	jz	.counted
	lea	rax,[dir_table + D_SIZE*DIR_SERVER]
	cmp	[rbx+N_DEF],rax
	jne	@f
	inc	r13d
	mov	rdi,r12
	mov	rsi,rbx
	call	check_duplicate_server
@@:
	mov	rbx,[rbx+N_NEXT]
	jmp	.server
.counted:
	mov	rdi,r12
	mov	ecx,DIR_HEALTH
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	check_health
@@:
	add	[g_chk_servers],r13d
	test	r13d,r13d
	jnz	.out
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	out_lit 'this pool has no `server`'
	call	cfg_diag_end
	call	cfg_error_limit
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = health node. `health tcp` takes nothing more; `health http`
; takes a path, after GET or HEAD if a method is given.
check_health:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	rbx,[r12+N_ARGS]
	call	positional_count
	mov	ecx,eax
	mov	rdi,[rbx+A_VAL]
	cmp	byte [rdi],'t'			; tcp
	jne	.http
	cmp	ecx,1
	je	.out
	lea	rdi,[rbx+A_SIZE]
	call	arg_value_span
	mov	edx,[rbx+A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'a tcp check only connects: it has no method or path'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `health http /healthz` checks an HTTP answer'
	call	cfg_note_end
	call	cfg_error_limit
	jmp	.out
.http:
	cmp	ecx,1
	je	.no_path
	cmp	ecx,3
	jne	.path
	; a method first: GET or HEAD
	lea	rax,[rbx+A_SIZE]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_health_methods]
	call	list_index
	test	eax,eax
	jns	.path
	lea	rdi,[rbx+A_SIZE]
	call	arg_value_span
	mov	edx,[rbx+A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'a health check asks with GET or HEAD'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.path:
	mov	rdi,r12
	call	positional_count
	lea	ecx,[rax-1]
	imul	rax,rcx,A_SIZE
	lea	rax,[rbx+rax]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	cmp	byte [rdi],'/'
	jne	.bad_path
	cmp	esi,1024
	ja	.bad_path
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	.out
	movzx	edx,byte [rdi+rcx]
	cmp	byte [http_target_ok+rdx],0
	je	.bad_path
	inc	ecx
	jmp	@b
.bad_path:
	mov	rdi,rax
	push	rax
	call	arg_value_span
	pop	rax
	mov	edx,[rax+A_LINE]
	call	cfg_error
	out_lit 'a health check path is a request target: /healthz, /status?full=1 (at most 1024 bytes)'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.no_path:
	mov	rdi,[r12+N_NAME]
	mov	esi,[r12+N_NLEN]
	mov	edx,[r12+N_LINE]
	call	cfg_error
	out_lit 'an http check needs a path'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `health http /healthz every=2s expect=200..299`'
	call	cfg_note_end
	call	cfg_error_limit
.out:
	pop	r12
	pop	rbx
	ret

enumdef e_health_methods, 'GET', 'HEAD'

; rdi = rewrite node: `rewrite path FROM/{*} -> TO`, FROM a path ending
; with {*}, TO a path with at most one {*}.
check_rewrite:
	push	rbx
	mov	rbx,[rdi+N_ARGS]
	mov	rax,[rbx+2*A_SIZE+A_VAL]
	cmp	dword [rbx+2*A_SIZE+A_VLEN],2
	jne	.bad
	cmp	word [rax],'->'
	jne	.bad
	; FROM
	mov	rdi,[rbx+A_SIZE+A_VAL]
	mov	esi,[rbx+A_SIZE+A_VLEN]
	cmp	esi,4
	jb	.bad
	cmp	byte [rdi],'/'
	jne	.bad
	cmp	byte [rdi+rsi-3],'{'
	jne	.bad
	cmp	word [rdi+rsi-2],'*}'
	jne	.bad
	sub	esi,3
	call	.printable_no_star
	jc	.bad
	; TO
	mov	rdi,[rbx+3*A_SIZE+A_VAL]
	mov	esi,[rbx+3*A_SIZE+A_VLEN]
	cmp	byte [rdi],'/'
	jne	.bad
	cmp	esi,1024
	ja	.bad
	xor	ecx,ecx
	xor	edx,edx
.to:
	cmp	ecx,esi
	jae	.done
	movzx	eax,byte [rdi+rcx]
	cmp	al,0x21
	jb	.bad
	cmp	al,0x7E
	ja	.bad
	cmp	al,'?'
	je	.bad				; the query is the request's
	cmp	al,'{'
	jne	.to_next
	lea	eax,[rcx+3]
	cmp	eax,esi
	ja	.to_next
	cmp	word [rdi+rcx+1],'*}'
	jne	.to_next
	inc	edx
	cmp	edx,1
	ja	.bad
.to_next:
	inc	ecx
	jmp	.to
.bad:
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'a rewrite is `rewrite path /from/{*} -> /to/{*}` (paths, the source ending with {*})'
	call	cfg_diag_end
	call	cfg_error_limit
.done:
	pop	rbx
	ret
; rdi/esi: printable, no '{' or '?'. CF otherwise.
.printable_no_star:
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	@f
	movzx	eax,byte [rdi+rcx]
	cmp	al,0x21
	jb	.np
	cmp	al,0x7E
	ja	.np
	cmp	al,'{'
	je	.np
	cmp	al,'?'
	je	.np
	inc	ecx
	jmp	@b
@@:
	clc
	ret
.np:
	stc
	ret

; rdi = redirect node: its target is a path or an http(s) URL, printable,
; with at most one {*}.
check_redirect_target:
	push	rbx
	mov	rbx,[rdi+N_ARGS]
	add	rbx,A_SIZE			; the target
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	cmp	esi,1024
	ja	.bad
	cmp	byte [rdi],'/'
	je	.chars
	cmp	esi,8
	jb	.bad
	mov	rax,'https://'
	cmp	[rdi],rax
	je	.chars
	mov	eax,[rdi]
	cmp	eax,'http'
	jne	.bad
	cmp	word [rdi+4],':/'
	jne	.bad
	cmp	byte [rdi+6],'/'
	jne	.bad
.chars:
	xor	ecx,ecx
	xor	edx,edx				; {*} seen
.char:
	cmp	ecx,esi
	jae	.done
	movzx	eax,byte [rdi+rcx]
	cmp	al,0x21
	jb	.bad
	cmp	al,0x7E
	ja	.bad
	cmp	al,'{'
	jne	.next
	lea	eax,[rcx+3]
	cmp	eax,esi
	ja	.next
	cmp	word [rdi+rcx+1],'*}'
	jne	.next
	inc	edx
	cmp	edx,1
	ja	.bad
.next:
	inc	ecx
	jmp	.char
.bad:
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'a redirect goes to a path or an http(s) URL, printable, with {*} at most once'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `redirect 301 /new/{*}` or `redirect 308 https://example.com{*}`'
	call	cfg_note_end
	call	cfg_error_limit
.done:
	pop	rbx
	ret

; rdi = route: its `header` and `response header` lines. set/add take a
; name and a value, drop a name (or a prefix: x-internal-*). Names are
; lower-case tokens and never one okena owns (framing, hop-by-hop,
; forwarding); values carry no CR, LF or NUL.
check_header_ops:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	rbx,[r12+N_CHILD]
.node:
	test	rbx,rbx
	jz	.done
	xor	r13d,r13d			; first argument of the operation
	lea	rax,[dir_table + D_SIZE*DIR_RHEADER]
	cmp	[rbx+N_DEF],rax
	je	.op
	lea	rax,[dir_table + D_SIZE*DIR_RRESPONSE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	inc	r13d				; after "header"
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_SIZE+A_VAL]		; the operation must be there
	cmp	dword [rbx+N_ARGC],3
	jb	.shape
.op:
	imul	r14,r13,A_SIZE
	add	r14,[rbx+N_ARGS]		; operation
	mov	rdi,[r14+A_VAL]
	mov	esi,[r14+A_VLEN]
	lea	rdx,[e_header_ops]
	call	list_index
	test	eax,eax
	js	.bad_op
	mov	ecx,[rbx+N_ARGC]
	sub	ecx,r13d			; operation, name, [value]
	cmp	eax,2
	je	.drop
	cmp	ecx,3
	jne	.shape
	; the value
	mov	rdi,[r14+2*A_SIZE+A_VAL]
	mov	esi,[r14+2*A_SIZE+A_VLEN]
	cmp	esi,1024
	ja	.bad_value
	call	check_header_vars
	jc	.bad_var
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	.name
	mov	al,[rdi+rcx]
	cmp	al,13
	je	.bad_value
	cmp	al,10
	je	.bad_value
	test	al,al
	jz	.bad_value
	inc	ecx
	jmp	@b
.drop:
	cmp	ecx,2
	jne	.shape
.name:
	mov	rdi,[r14+A_SIZE+A_VAL]
	mov	esi,[r14+A_SIZE+A_VLEN]
	xor	ecx,ecx
.nchar:
	cmp	ecx,esi
	jae	.owned
	movzx	eax,byte [rdi+rcx]
	cmp	al,'*'
	jne	@f
	lea	edx,[rcx+1]
	cmp	edx,esi
	jne	.bad_name			; only a trailing *
	mov	rax,[r14+A_VAL]
	cmp	byte [rax],'d'
	jne	.bad_name			; and only for drop
	inc	ecx
	jmp	.nchar
@@:
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	jbe	.bad_name			; lower case
@@:
	cmp	byte [http_tchar+rax],0
	je	.bad_name
	inc	ecx
	jmp	.nchar
.owned:
	test	esi,esi
	jz	.bad_name
	lea	rdx,[e_owned_headers]
	call	list_index
	test	eax,eax
	jns	.owned_name
	jmp	.next
.shape:
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	edx,[rbx+N_LINE]
	call	cfg_error
	out_lit 'set and add take a name and a value, drop a name'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `header set x-env prod`, `header drop x-internal-*`, `response header set cache-control no-store`'
	call	cfg_note_end
	call	cfg_error_limit
	jmp	.next
.bad_op:
	mov	rdi,r14
	call	arg_value_span
	mov	edx,[r14+A_LINE]
	call	cfg_error
	out_lit 'a header operation is set, add or drop'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.next
.bad_name:
	lea	rdi,[r14+A_SIZE]
	call	arg_value_span
	mov	edx,[r14+A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'a header name is a lower-case token (x-env); drop may end it with *'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.next
.owned_name:
	lea	rdi,[r14+A_SIZE]
	call	arg_value_span
	mov	edx,[r14+A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'okena writes this header itself (framing, connection or forwarding): it cannot be changed here'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.next
.bad_var:
	lea	rdi,[r14+2*A_SIZE]
	call	arg_value_span
	mov	edx,[r14+2*A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'unknown variable: the ones a header value can use are ${client.ip} ${request.id} ${time.us} ${time.s}'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.next
.bad_value:
	lea	rdi,[r14+2*A_SIZE]
	call	arg_value_span
	mov	edx,[r14+2*A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'a header value is at most 1024 bytes, without CR, LF or NUL'
	call	cfg_diag_end
	call	cfg_error_limit
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.node
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = a header value: CF when a ${...} in it is not a known
; variable (or is not closed). Keeps rdi, rsi.
check_header_vars:
	xor	ecx,ecx
.scan:
	lea	eax,[rcx+1]
	cmp	eax,esi
	jae	.ok
	cmp	word [rdi+rcx],'${'
	je	.var
	inc	ecx
	jmp	.scan
.var:
	add	ecx,2
	mov	edx,ecx				; name start
@@:
	cmp	ecx,esi
	jae	.bad				; not closed
	cmp	byte [rdi+rcx],'}'
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rdi
	push	rsi
	push	rcx
	lea	rax,[rdi+rdx]
	mov	esi,ecx
	sub	esi,edx
	mov	rdi,rax
	lea	rdx,[e_header_vars]
	call	list_index
	pop	rcx
	pop	rsi
	pop	rdi
	test	eax,eax
	js	.bad
	inc	ecx
	jmp	.scan
.ok:
	clc
	ret
.bad:
	stc
	ret

enumdef e_header_vars, 'client.ip', 'request.id', 'time.us', 'time.s'

enumdef e_owned_headers, 'host', 'content-length', 'transfer-encoding', 'connection', 'keep-alive', \
	'upgrade', 'te', 'trailer', 'proxy-connection', 'expect', 'x-forwarded-for', \
	'x-forwarded-proto', 'x-forwarded-host', 'forwarded', 'x-request-id'

; rdi = node. eax = its arguments that are not key=value (they come first).
positional_count:
	mov	rdx,[rdi+N_ARGS]
	mov	ecx,[rdi+N_ARGC]
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	@f
	cmp	dword [rdx+A_KIND],ARG_KV
	je	@f
	inc	eax
	add	rdx,A_SIZE
	jmp	@b
@@:
	ret

; rdi/esi = "200" or "200..299". eax = low, edx = high (100 .. 599, low
; <= high). CF on error.
parse_statuses:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	xor	ebx,ebx
@@:
	cmp	ebx,r13d
	jae	@f
	cmp	byte [r12+rbx],'.'
	je	@f
	inc	ebx
	jmp	@b
@@:
	mov	rdi,r12
	mov	esi,ebx
	call	parse_decimal
	jc	.bad
	cmp	rax,100
	jb	.bad
	cmp	rax,599
	ja	.bad
	mov	r8d,eax
	mov	edx,eax
	cmp	ebx,r13d
	je	.ok
	lea	eax,[rbx+2]
	cmp	eax,r13d
	jae	.bad
	cmp	byte [r12+rbx+1],'.'
	jne	.bad
	lea	rdi,[r12+rbx+2]
	mov	esi,r13d
	sub	esi,ebx
	sub	esi,2
	push	r8
	call	parse_decimal
	pop	r8
	jc	.bad
	cmp	rax,599
	ja	.bad
	cmp	eax,r8d
	jb	.bad
	mov	edx,eax
.ok:
	mov	eax,r8d
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = pool, rsi = server node. Reports when an earlier server has the
; same address text.
check_duplicate_server:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r12+N_CHILD]
.next:
	cmp	rbx,r13
	je	.done
	lea	rax,[dir_table + D_SIZE*DIR_SERVER]
	cmp	[rbx+N_DEF],rax
	jne	.skip
	mov	rdi,[rbx+N_ARGS]
	mov	rsi,[r13+N_ARGS]
	call	same_arg_value
	jc	.dup
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.dup:
	mov	rdi,[r13+N_ARGS]
	call	arg_value_span
	mov	rax,[r13+N_ARGS]
	mov	edx,[rax+A_LINE]
	call	cfg_error
	out_lit 'server '
	mov	rax,[r13+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	cfg_quote
	out_lit ' is listed twice in this pool'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'note: first listed on line '
	mov	eax,[rbx+N_LINE]
	call	out_u64
	call	cfg_note_end
	call	cfg_error_limit
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; `to a b a`: rdi = `to` node.
check_duplicate_servers_args:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,1
.outer:
	cmp	r13d,[r12+N_ARGC]
	jae	.done
	xor	ebx,ebx
.inner:
	cmp	ebx,r13d
	jae	.advance
	imul	rdi,rbx,A_SIZE
	add	rdi,[r12+N_ARGS]
	imul	rsi,r13,A_SIZE
	add	rsi,[r12+N_ARGS]
	call	same_arg_value
	jc	.dup
	inc	ebx
	jmp	.inner
.dup:
	imul	rdi,r13,A_SIZE
	add	rdi,[r12+N_ARGS]
	push	rdi
	call	arg_value_span
	mov	rax,[rsp]
	mov	edx,[rax+A_LINE]
	call	cfg_error
	out_lit 'address '
	mov	rax,[rsp]
	mov	rsi,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	cfg_quote
	out_lit ' is listed twice'
	call	cfg_diag_end
	call	cfg_error_limit
	pop	rdi
.advance:
	inc	r13d
	jmp	.outer
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi, rsi = args. CF when their values are the same text.
same_arg_value:
	mov	eax,[rdi+A_VLEN]
	cmp	eax,[rsi+A_VLEN]
	jne	.no
	mov	rdi,[rdi+A_VAL]
	mov	rsi,[rsi+A_VAL]
	mov	edx,eax
	call	mem_eq
	test	eax,eax
	jz	.no
	stc
	ret
.no:
	clc
	ret

; Warn about pools no listener uses.
check_unused_pools:
	push	rbx
	push	r12
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_POOL]
	cmp	[rbx+N_DEF],rax
	jne	.skip
	mov	rdi,rbx
	call	pool_used
	jc	.skip
	mov	r12,[rbx+N_ARGS]
	mov	rdi,r12
	call	arg_value_span
	mov	edx,[r12+A_LINE]
	call	cfg_warning
	out_lit 'pool '
	mov	rsi,[r12+A_VAL]
	mov	edx,[r12+A_VLEN]
	call	cfg_quote
	out_lit ' is not used by any listener'
	call	cfg_diag_end
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r12
	pop	rbx
	ret

; rdi = pool node. CF when some `to pool NAME` names it.
pool_used:
	push	rbx
	push	r12
	push	r13
	mov	r12,[rdi+N_ARGS]
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.next:
	test	rbx,rbx
	jz	.no
	lea	rax,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[rbx+N_DEF],rax
	je	.http
	lea	rax,[dir_table + D_SIZE*DIR_TCP]
	cmp	[rbx+N_DEF],rax
	jne	.skip
	mov	rdi,rbx
	call	.uses
	jc	.yes
	mov	rdi,rbx
	call	.uses_pt
	jc	.yes
	jmp	.skip
.http:
	mov	r13,[rbx+N_CHILD]
.route:
	test	r13,r13
	jz	.skip
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[r13+N_DEF],rax
	je	.host
	mov	rdi,r13
	push	r13
	call	.uses
	pop	r13
	jc	.yes
.route_next:
	mov	r13,[r13+N_NEXT]
	jmp	.route
.host:
	; the routes of a host block
	push	r13
	mov	r13,[r13+N_CHILD]
.host_route:
	test	r13,r13
	jz	.host_done
	mov	rdi,r13
	push	r13
	call	.uses
	pop	r13
	jc	.host_yes
	mov	r13,[r13+N_NEXT]
	jmp	.host_route
.host_yes:
	pop	r13
	jmp	.yes
.host_done:
	pop	r13
	jmp	.route_next
; rdi = tcp listener: CF when its tls passthrough sends to this pool (r12)
.uses_pt:
	call	listener_passthrough
	test	rax,rax
	jz	.not
	mov	r13,[rax+N_CHILD]
.pt_line:
	test	r13,r13
	jz	.not
	cmp	dword [r13+N_ARGC],3
	jb	.pt_next			; default reject
	mov	ecx,[r13+N_ARGC]		; ... to pool POOL: the last
	dec	ecx
	imul	rcx,rcx,A_SIZE
	mov	rdi,[r13+N_ARGS]
	add	rdi,rcx
	mov	rsi,r12
	push	r13
	call	same_arg_value
	pop	r13
	jc	.pt_yes
.pt_next:
	mov	r13,[r13+N_NEXT]
	jmp	.pt_line
.pt_yes:
	stc
	ret
; rdi = node with a `to`: CF when it is `to pool` + this pool (r12)
.uses:
	mov	ecx,DIR_TO
	call	find_child
	test	rax,rax
	jz	.not
	cmp	dword [rax+N_ARGC],2
	jne	.not
	mov	r13,[rax+N_ARGS]
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	lea	rdx,[str_pool_word]
	call	mem_eq_cstr
	test	eax,eax
	jz	.not
	lea	rdi,[r13+A_SIZE]
	mov	rsi,r12
	jmp	same_arg_value
.not:
	clc
	ret
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.yes:
	stc
	jmp	.out
.no:
	clc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

bss
	g_chk_tls_listener	dq ?
end bss

; rdi = listener node: rax = its `tls passthrough` block, or 0.
listener_passthrough:
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	.no
	cmp	dword [rax+N_ARGC],0
	jne	.yes
.no:
	xor	eax,eax
.yes:
	ret

cstring str_to_word, 'to',0
cstring str_reject_word, 'reject',0

; rdi = listener node, rsi = its `tls passthrough` block.
check_passthrough:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	rbx,rsi
	lea	rax,[dir_table + D_SIZE*DIR_TCP]
	cmp	[r12+N_DEF],rax
	je	@f
	mov	rdi,rbx
	lea	rsi,[str_pt_http]
	call	.at_node
	jmp	.done
@@:
	mov	rdi,r12				; the pools come from sni: no `to`
	mov	ecx,DIR_TO
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	lea	rsi,[str_pt_to]
	call	.at_node
@@:
	mov	rdi,rbx
	mov	ecx,DIR_CERT
	call	find_child
	test	rax,rax
	jnz	.has_cert
	mov	rdi,rbx
	mov	ecx,DIR_KEY
	call	find_child
	test	rax,rax
	jz	.lines
.has_cert:
	mov	rdi,rax
	lea	rsi,[str_pt_cert]
	call	.at_node
.lines:
	xor	r15d,r15d			; sni lines
	mov	r13,[rbx+N_CHILD]
.line:
	test	r13,r13
	jz	.lines_done
	lea	rax,[dir_table + D_SIZE*DIR_SNI]
	cmp	[r13+N_DEF],rax
	jne	.default_line
	inc	r15d
	mov	ecx,[r13+N_ARGC]		; NAME... to pool POOL
	sub	ecx,3
	imul	rcx,rcx,A_SIZE
	add	rcx,[r13+N_ARGS]
	mov	r14,rcx
	call	.to_pool
	jmp	.next_line
.default_line:
	lea	rax,[dir_table + D_SIZE*DIR_DEFAULT]
	cmp	[r13+N_DEF],rax
	jne	.next_line
	mov	r14,[r13+N_ARGS]
	cmp	dword [r13+N_ARGC],1
	jne	.default_to
	mov	rdi,[r14+A_VAL]
	mov	esi,[r14+A_VLEN]
	lea	rdx,[str_reject_word]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.next_line
	mov	rdi,r13
	lea	rsi,[str_pt_default]
	call	.at_node
	jmp	.next_line
.default_to:
	cmp	dword [r13+N_ARGC],3
	jne	.bad_default
	call	.to_pool
	jmp	.next_line
.bad_default:
	mov	rdi,r13
	lea	rsi,[str_pt_default]
	call	.at_node
.next_line:
	mov	r13,[r13+N_NEXT]
	jmp	.line
.lines_done:
	test	r15d,r15d
	jnz	.done
	mov	rdi,rbx
	lea	rsi,[str_pt_none]
	call	.at_node
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r13 = the line, r14 = its "to": "to pool POOL", the pool defined.
.to_pool:
	mov	rdi,[r14+A_VAL]
	mov	esi,[r14+A_VLEN]
	lea	rdx,[str_to_word]
	call	mem_eq_cstr
	test	eax,eax
	jz	.form
	mov	rdi,[r14+A_SIZE+A_VAL]
	mov	esi,[r14+A_SIZE+A_VLEN]
	lea	rdx,[str_pool_word]
	call	mem_eq_cstr
	test	eax,eax
	jz	.form
	mov	rdi,[r14+2*A_SIZE+A_VAL]
	mov	esi,[r14+2*A_SIZE+A_VLEN]
	call	pool_find
	test	rax,rax
	jnz	.pool_ok
	lea	rdi,[r14+2*A_SIZE]
	call	arg_value_span
	mov	edx,[r14+2*A_SIZE+A_LINE]
	call	cfg_error
	out_lit 'there is no pool named '
	mov	rsi,[r14+2*A_SIZE+A_VAL]
	mov	edx,[r14+2*A_SIZE+A_VLEN]
	call	cfg_quote
	call	cfg_diag_end
	call	cfg_error_limit
.pool_ok:
	ret
.form:
	mov	rdi,r13
	lea	rsi,[str_pt_form]
; rdi = node, rsi = message (C string): an error there.
.at_node:
	push	rsi
	mov	rax,rdi
	mov	rdi,[rax+N_NAME]
	mov	esi,[rax+N_NLEN]
	mov	edx,[rax+N_LINE]
	call	cfg_error
	pop	rsi
	call	out_cstr
	call	cfg_diag_end
	call	cfg_error_limit
	ret

cstring str_pt_http, 'tls passthrough routes TCP connections: it belongs in a tcp listener',0
cstring str_pt_to, 'a tls passthrough listener sends each connection where its sni lines say: no `to` here',0
cstring str_pt_cert, 'tls passthrough does not decrypt: no certificate or key here',0
cstring str_pt_form, 'write it as: sni NAME... to pool POOL',0
cstring str_pt_default, 'write it as: default reject, or default to pool POOL',0
cstring str_pt_none, 'tls passthrough needs at least one `sni NAME... to pool POOL` line',0
