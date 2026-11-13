; `addon NAME { ... }` and a route's `addon NAME`: checked, then compiled into the
; plan's addon table (g_addons) and each route's mask of them (RA_ADDONS).
;
;   addon waf {
;       run /usr/local/bin/coraza-okena -rules /etc/crs   ; okena starts it, and again
;       phases request_headers
;       timeout 50ms                 ; a call's time (default 200ms)
;       on_error allow               ; or deny (the default): 503
;       concurrency 1024             ; calls waiting at once, the whole instance
;       breaker errors=5 open=1s     ; failures in a row that open the circuit, and for how long
;   }
;   route /api/* { addon waf; to pool api }
;
; A route that names several asks them in the order they are defined.

MAX_ADDONS	:= 32
AD_DEF_TIMEOUT	:= 200000			; µs
AD_DEF_CONC	:= 1024
AD_DEF_BREAK	:= 5
AD_DEF_OPEN	:= 1000000			; µs

; plan entry
ADE_NAME		:= 0				; q
ADE_NLEN		:= 8				; d
ADE_ARGC		:= 12				; d: `run`'s words
ADE_ARGS		:= 16				; q: and they (A_SIZE each; while compiling only)
ADE_TIMEOUT	:= 24				; q: µs
ADE_ONERR	:= 32				; d: 1 allow, 0 deny
ADE_CONC		:= 36				; d
ADE_PHASES	:= 40				; d: ADP_*
ADE_SLOT		:= 44				; d: its process (the supervisor's g_adrt)
ADE_BREAK	:= 48				; d
ADE_OPEN		:= 56				; q: µs
ADE_HASH		:= 64				; q: what makes it the same process across a reload
ADE_SIZE		:= 72

RA_ADDONS	:= 140				; d: a route's addons, bit i for g_addons[i]

bss
	g_chk_addons	dd ?
	align 8
	g_plan_addons	dd ?
	align 8
	g_addons:	rb ADE_SIZE * MAX_ADDONS
end bss

cstring str_ad_run, 'run',0
cstring str_ad_errors, 'errors',0
cstring str_ad_open, 'open',0

; ------------------------------------------------------------------ checks

; rdi = an `addon` block: what it must have
check_addon:
	push	rbx
	push	r12
	mov	r12,rdi
	inc	dword [g_chk_addons]
	cmp	dword [g_chk_addons],MAX_ADDONS
	jbe	@f
	mov	rdi,r12
	lea	rsi,[str_ad_many]
	call	check_passthrough.at_node
@@:
	mov	rdi,r12
	mov	ecx,DIR_ADRUN
	call	find_child
	test	rax,rax
	jnz	.run
	mov	rdi,r12
	lea	rsi,[str_ad_norun]
	call	check_passthrough.at_node
	jmp	.names
.run:
	mov	rbx,[rax+N_ARGS]
	mov	rcx,[rbx+A_VAL]
	cmp	dword [rbx+A_VLEN],0
	je	.relative
	cmp	byte [rcx],'/'
	je	.names
.relative:
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'run takes the program by its absolute path (okena does not search PATH)'
	call	cfg_diag_end
	call	cfg_error_limit
.names:
	; one block a name
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.other:
	cmp	rbx,r12
	je	.out				; (only those before it)
	lea	rcx,[dir_table + D_SIZE*DIR_ADDON]
	cmp	[rbx+N_DEF],rcx
	jne	.next
	mov	rdi,[rbx+N_ARGS]
	mov	rsi,[r12+N_ARGS]
	mov	ecx,[rdi+A_VLEN]
	cmp	ecx,[rsi+A_VLEN]
	jne	.next
	mov	rdi,[rdi+A_VAL]
	mov	rsi,[rsi+A_VAL]
	repe	cmpsb
	jne	.next
	mov	rbx,[r12+N_ARGS]
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'there is already an addon named '
	mov	rsi,[rbx+A_VAL]
	mov	edx,[rbx+A_VLEN]
	call	cfg_quote
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.next:
	mov	rbx,[rbx+N_NEXT]
	test	rbx,rbx
	jnz	.other
.out:
	pop	r12
	pop	rbx
	ret

cstring str_ad_norun, 'an addon needs `run PROGRAM [ARGUMENTS]`: okena starts it and keeps it running',0
cstring str_ad_many, 'too many addons: 32 at most',0

; every route's `addon NAME` names one
check_addon_refs:
	mov	rax,[g_cfg_root]
	mov	rdi,[rax+N_CHILD]
	; rdi = a list of siblings: each node, and below it
.walk:
	test	rdi,rdi
	jz	.done
	push	rdi
	lea	rcx,[dir_table + D_SIZE*DIR_RADDON]
	cmp	[rdi+N_DEF],rcx
	jne	@f
	call	.ref
@@:
	mov	rdi,[rsp]
	mov	rdi,[rdi+N_CHILD]
	call	.walk
	pop	rdi
	mov	rdi,[rdi+N_NEXT]
	jmp	.walk
.done:
	ret
; rdi = `addon NAME` in a route
.ref:
	push	rbx
	mov	rbx,[rdi+N_ARGS]
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	addon_node_find
	test	rax,rax
	jnz	.found
	mov	rdi,rbx
	call	arg_value_span
	mov	edx,[rbx+A_LINE]
	call	cfg_error
	out_lit 'there is no addon named '
	mov	rsi,[rbx+A_VAL]
	mov	edx,[rbx+A_VLEN]
	call	cfg_quote
	call	cfg_diag_end
	call	cfg_error_limit
.found:
	pop	rbx
	ret

; rdi/esi = a name: rax = the top-level `addon` block of that name, or 0
addon_node_find:
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
	lea	rcx,[dir_table + D_SIZE*DIR_ADDON]
	cmp	[rbx+N_DEF],rcx
	jne	.skip
	mov	rax,[rbx+N_ARGS]
	cmp	[rax+A_VLEN],r13d
	jne	.skip
	mov	rsi,[rax+A_VAL]
	mov	rdi,r12
	mov	ecx,r13d
	repe	cmpsb
	jne	.skip
	mov	rax,rbx
	jmp	.out
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; --------------------------------------------------------------- compiling

; rdi = an `addon` block: into g_addons
compile_addon:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	ecx,[g_plan_addons]
	too_many ecx,MAX_ADDONS,str_tm_addons
	inc	dword [g_plan_addons]
	imul	r13,rcx,ADE_SIZE
	lea	r13,[g_addons+r13]
	mov	rax,[r12+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[r13+ADE_NAME],rcx
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,AD_NAME_MAX
	jbe	@f
	mov	ecx,AD_NAME_MAX
@@:
	mov	[r13+ADE_NLEN],ecx
	mov	qword [r13+ADE_TIMEOUT],AD_DEF_TIMEOUT
	mov	dword [r13+ADE_ONERR],0
	mov	dword [r13+ADE_CONC],AD_DEF_CONC
	mov	dword [r13+ADE_PHASES],ADP_REQ_HEADERS
	mov	dword [r13+ADE_SLOT],-1
	mov	dword [r13+ADE_BREAK],AD_DEF_BREAK
	mov	qword [r13+ADE_OPEN],AD_DEF_OPEN
	mov	rdi,r12
	mov	ecx,DIR_ADRUN
	call	find_child
	mov	ecx,[rax+N_ARGC]
	mov	[r13+ADE_ARGC],ecx
	mov	rcx,[rax+N_ARGS]
	mov	[r13+ADE_ARGS],rcx
	mov	rdi,r12
	mov	ecx,DIR_ADTIMEOUT
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_duration
	jc	plan_bad_addon
	test	rax,rax
	jz	plan_bad_addon
	mov	[r13+ADE_TIMEOUT],rax
@@:
	mov	rdi,r12
	mov	ecx,DIR_ADONERR
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_ad_onerr]
	call	list_index
	cmp	eax,1
	sete	al
	movzx	eax,al
	mov	[r13+ADE_ONERR],eax		; (allow is the second)
@@:
	mov	rdi,r12
	mov	ecx,DIR_ADCONC
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_decimal
	test	rax,rax
	jz	plan_bad_addon
	mov	[r13+ADE_CONC],eax
@@:
	mov	rdi,r12
	mov	ecx,DIR_ADBREAKER
	call	find_child
	test	rax,rax
	jz	.hash
	mov	rbx,rax
	mov	rdi,rbx
	lea	rsi,[str_ad_errors]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	test	rax,rax
	jz	plan_bad_addon
	mov	[r13+ADE_BREAK],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_ad_open]
	call	node_option
	test	rax,rax
	jz	.hash
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	plan_bad_addon
	test	rax,rax
	jz	plan_bad_addon
	mov	[r13+ADE_OPEN],rax
.hash:
	; the process: its name and its run line (FNV-1a, each word with its length)
	mov	rax,0xCBF29CE484222325
	mov	rsi,[r13+ADE_NAME]
	mov	ecx,[r13+ADE_NLEN]
	call	.mix
	mov	rbx,[r13+ADE_ARGS]
	mov	r8d,[r13+ADE_ARGC]
.word:
	test	r8d,r8d
	jz	.hashed
	mov	rsi,[rbx+A_VAL]
	mov	ecx,[rbx+A_VLEN]
	call	.mix
	add	rbx,A_SIZE
	dec	r8d
	jmp	.word
.hashed:
	mov	[r13+ADE_HASH],rax
	pop	r13
	pop	r12
	pop	rbx
	ret
; rax = the hash, rsi/ecx = bytes: and their length after them
.mix:
	mov	rdx,0x100000001B3
.byte:
	test	ecx,ecx
	jz	.len
	movzx	r9d,byte [rsi]
	xor	rax,r9
	imul	rax,rdx
	inc	rsi
	dec	ecx
	jmp	.byte
.len:
	xor	rax,0x5A
	imul	rax,rdx
	ret

cstring str_tm_addons, 'addons',0

plan_bad_addon:
	call	log_begin
	out_lit 'addon: timeout, concurrency and breaker errors= and open= take positive values'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; r12 = the route's node, r13 = its action: the addons it names, in RA_ADDONS
compile_route_addons:
	push	rbx
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	lea	rcx,[dir_table + D_SIZE*DIR_RADDON]
	cmp	[rbx+N_DEF],rcx
	jne	.skip
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	addon_index
	cmp	eax,-1
	je	.skip				; (the checker said so)
	bts	dword [r13+RA_ADDONS],eax
.skip:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	rbx
	ret

; rdi/esi = a name: eax = its index in g_addons, or -1. Keeps rbx, r12-r15.
addon_index:
	xor	eax,eax
.next:
	cmp	eax,[g_plan_addons]
	jae	.none
	imul	rcx,rax,ADE_SIZE
	lea	rcx,[g_addons+rcx]
	cmp	esi,[rcx+ADE_NLEN]
	jne	.skip
	push	rdi
	push	rsi
	push	rax
	mov	rdx,rsi
	mov	rsi,[rcx+ADE_NAME]
	mov	ecx,edx
	repe	cmpsb
	pop	rax
	pop	rsi
	pop	rdi
	je	.out
.skip:
	inc	eax
	jmp	.next
.none:
	mov	eax,-1
.out:
	ret
