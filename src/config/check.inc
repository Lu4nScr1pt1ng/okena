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
	jmp	.advance
.listener:
	inc	dword [g_chk_listeners]
	mov	rdi,rbx
	call	check_listener
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
	jz	.no_target
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

; rdi = http listener: routes, each sending somewhere, none twice.
check_http:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	xor	r13d,r13d			; routes
	mov	rbx,[r12+N_CHILD]
.route:
	test	rbx,rbx
	jz	.routes_done
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	inc	r13d
	mov	rdi,rbx
	call	check_listener			; its `to`
	mov	rdi,r12
	mov	rsi,rbx
	call	check_route_unique
	mov	rdi,rbx
	call	check_route_has_path
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.route
.routes_done:
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
	pop	r13
	pop	r12
	pop	rbx
	ret

; Methods as bits (0 = any method).
RM_GET		= 1
RM_HEAD		= 2
RM_POST		= 4
RM_PUT		= 8
RM_DELETE	= 16
RM_PATCH	= 32
RM_OPTIONS	= 64
RM_OTHER	= 128

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
	jmp	.skip
.http:
	mov	r13,[rbx+N_CHILD]
.route:
	test	r13,r13
	jz	.skip
	mov	rdi,r13
	push	r13
	call	.uses
	pop	r13
	jc	.yes
	mov	r13,[r13+N_NEXT]
	jmp	.route
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
