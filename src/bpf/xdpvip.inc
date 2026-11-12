; `tcp VIP:PORT { mode xdp; to pool P }` (and `udp`): a VIP of the XDP
; balancer (xdp_lb.inc), compiled into g_plan_xvips, not a listener: no socket,
; no accept; the packets are turned round in the driver. `okena { xdp IFACE... }`
; names the interfaces the program goes on. IPv4 or IPv6, the reals either;
; `mode xdp encap=gue [port=6080]`: GUE (UDP) to the reals, not IP in IP.

XV_ADDR		:= 0		; 16 bytes: the VIP (IPv4 in the first 4), network order
XV_FAMILY	:= 16		; d: 4, 6
XV_PORT		:= 20		; d: host order
XV_PROTO	:= 24		; d: 6 TCP, 17 UDP
XV_POOL		:= 28		; d
XV_FLAGS	:= 32		; d: XVV_FLAGS (xdp_lb.inc)
XV_SIZE		:= 40
XVIP_MAX	:= 64
XIF_MAX		:= 8
XV_GUE_PORT	:= 6080		; (Katran's GUE_DPORT)

bss
	align 8
	g_plan_xvips:	rb XVIP_MAX * XV_SIZE
	g_plan_nxvip	dd ?
	g_plan_nxif	dd ?
	g_plan_xif:	rb XIF_MAX * 16	; the interfaces, NUL-ended (IFNAMSIZ)
	g_plan_xdrop	dd ?		; `drop`: its ranges, in blocks (compile_xdp_drop)
	align 8
	g_plan_xdrop_fam dd ?, ?	; of them IPv4, IPv6 (each at most XC_DROP_N)
	g_plan_xdrop_head dq ?
	g_plan_xdrop_tail dq ?
	g_plan_syn_ivl	dq ?		; `syn_rate`: ns between a source's SYNs, 0 none
	g_plan_syn_tau	dq ?		; and how far ahead it may be (its burst)
end bss

cstring str_key_encap, 'encap',0

; rdi = a tcp/udp node with `mode xdp`: its addresses as VIPs of its pool
compile_xvip:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,16
	mov	r12,rdi
	; nothing but `mode` and `to` applies here: the kernel never sees these
	; connections (TLS, limits, timeouts, PROXY headers have nobody to act)
	mov	rbx,[r12+N_CHILD]
.child:
	test	rbx,rbx
	jz	.children_ok
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_MODE]
	cmp	rax,rcx
	je	.child_ok
	lea	rcx,[dir_table + D_SIZE*DIR_TO]
	cmp	rax,rcx
	jne	.extra
.child_ok:
	mov	rbx,[rbx+N_NEXT]
	jmp	.child
.children_ok:
	mov	rdi,r12
	call	compile_target
	mov	r14d,eax			; the pool
	; encap=ipip|gue port=N: the flags every address of it gets
	mov	rdi,r12
	mov	ecx,DIR_MODE
	call	find_child
	mov	[rsp],rax			; (the mode node, for its options)
	xor	r15d,r15d			; IP in IP
	mov	rdi,rax
	lea	rsi,[str_key_encap]
	call	node_option
	test	rax,rax
	jz	.encap_set
	mov	[rsp+8],rax
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[.s_ipip]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.encap_set
	mov	rax,[rsp+8]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[.s_gue]
	call	mem_eq_cstr
	test	eax,eax
	jz	.bad_encap
	mov	r15d,XV_GUE_PORT
	mov	rdi,[rsp]
	lea	rsi,[str_key_port]
	call	node_option
	test	rax,rax
	jz	.gue_port
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	jc	.bad_port
	test	rax,rax
	jz	.bad_port
	cmp	rax,65535
	ja	.bad_port
	mov	r15d,eax
.gue_port:
	mov	eax,r15d			; network order, in the high half
	xchg	al,ah
	shl	eax,16
	or	eax,XVF_GUE
	mov	r15d,eax
	jmp	.encapped
.encap_set:	; IP in IP: no port to name
	mov	rdi,[rsp]
	lea	rsi,[str_key_port]
	call	node_option
	test	rax,rax
	jnz	.port_ipip
.encapped:
	mov	r13d,6
	lea	rax,[dir_table + D_SIZE*DIR_UDP]
	cmp	[r12+N_DEF],rax
	jne	@f
	mov	r13d,17
@@:
	xor	ebx,ebx				; argument
.arg:
	cmp	ebx,[r12+N_ARGC]
	jae	.out
	cmp	dword [g_plan_nxvip],XVIP_MAX
	jae	.too_many
	imul	rax,rbx,A_SIZE
	add	rax,[r12+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	mov	eax,[g_plan_nxvip]
	imul	rax,rax,XV_SIZE
	lea	rdi,[g_plan_xvips+rax]
	mov	ecx,4
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_V4
	je	@f
	mov	ecx,6
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_V6
	jne	.not_ip
@@:
	mov	[rdi+XV_FAMILY],ecx
	mov	rax,qword [g_cmp_addr+AD_IP]	; (IPv4: the rest is zero)
	mov	[rdi+XV_ADDR],rax
	mov	rax,qword [g_cmp_addr+AD_IP+8]
	mov	[rdi+XV_ADDR+8],rax
	cmp	ecx,4
	jne	@f
	mov	dword [rdi+XV_ADDR+4],0
	mov	qword [rdi+XV_ADDR+8],0
@@:
	mov	ecx,[g_cmp_addr+AD_PORT]
	mov	[rdi+XV_PORT],ecx
	mov	[rdi+XV_PROTO],r13d
	mov	[rdi+XV_POOL],r14d
	mov	[rdi+XV_FLAGS],r15d
	inc	dword [g_plan_nxvip]
	inc	ebx
	jmp	.arg
.out:
	add	rsp,16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
	cstring .s_ipip, 'ipip',0
	cstring .s_gue, 'gue',0
.bad_encap:
	call	log_begin
	out_lit '`mode xdp encap=`: ipip (the default) or gue'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad_port:
	call	log_begin
	out_lit '`mode xdp port=`: the GUE port the reals listen on, 1 to 65535'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.port_ipip:
	call	log_begin
	out_lit '`mode xdp port=` is the GUE port: with `encap=gue`'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.extra:
	call	log_begin
	out_lit 'a listener with `mode xdp` takes `to` and nothing else: its packets are turned round in the driver, the kernel never holds those connections'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.not_ip:
	call	log_begin
	out_lit '`mode xdp` takes IP addresses with a port'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.too_many:
	call	log_begin
	out_lit '`mode xdp`: 64 VIPs at most'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = a `drop` line in `okena`: its ranges, as `deny` reads them but no
; country (a packet has none), onto the plan's drop list: blocks of
; XD_CAP ranges (TR_*: gw/acl.inc's, read by parse_cidr) in the text arena,
; so a reload's list is apart from the running one's. The kernel's LPM
; tries are what looks them up: no trie here (a million ranges are 24 MB).
XD_NEXT		:= 0		; q: the next block
XD_N		:= 8		; d: ranges in this one
XD_E		:= 16		; XD_CAP of TR_SIZE
XD_CAP		:= 8192
compile_xdp_drop:
	push	rbx
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r8d,[rbx+N_ARGC]
	mov	r9,[rbx+N_ARGS]
.arg:
	test	r8d,r8d
	jz	.args_ok
	dec	r8d
	cmp	dword [r9+A_VLEN],8
	jb	@f
	mov	rax,[r9+A_VAL]
	mov	rax,[rax]
	mov	rdx,'country:'
	cmp	rax,rdx
	je	.country
@@:
	add	r9,A_SIZE
	jmp	.arg
.args_ok:
	lea	rax,[xdrop_add]
	mov	[g_acl_sink],rax
	call	acl_args
	mov	qword [g_acl_sink],0
	pop	r15
	pop	r14
	pop	rbx
	ret
.country:
	call	log_begin
	out_lit '`drop` takes addresses, ranges, file:PATH or a provider; a packet has no country (`deny country:` on a route has it)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi/esi = a range (g_acl_sink while `drop` is read): onto the list
xdrop_add:
	lea	rdx,[g_tr_tmp]
	call	parse_cidr
	jc	plan_bad_acl
	mov	rax,[g_plan_xdrop_tail]
	test	rax,rax
	jz	.block
	cmp	dword [rax+XD_N],XD_CAP
	jb	.room
.block:
	push	rax
	lea	rdi,[g_ar_text]
	mov	esi,XD_E + XD_CAP * TR_SIZE
	call	arena_alloc
	pop	rcx
	mov	qword [rax+XD_NEXT],0
	mov	dword [rax+XD_N],0
	test	rcx,rcx
	jz	.first
	mov	[rcx+XD_NEXT],rax
	jmp	.linked
.first:
	mov	[g_plan_xdrop_head],rax
.linked:
	mov	[g_plan_xdrop_tail],rax
.room:
	mov	ecx,[rax+XD_N]
	inc	dword [rax+XD_N]
	imul	rcx,rcx,TR_SIZE
	lea	rdi,[rax+XD_E+rcx]
	lea	rsi,[g_tr_tmp]
	mov	ecx,TR_SIZE
	rep	movsb
	inc	dword [g_plan_xdrop]
	xor	eax,eax
	cmp	dword [g_tr_tmp+TR_KIND],6
	sete	al
	inc	dword [g_plan_xdrop_fam+rax*4]
	cmp	dword [g_plan_xdrop_fam+rax*4],XC_DROP_N
	ja	.too_many
	ret
.too_many:
	call	log_begin
	out_lit '`drop`: 1048576 ranges of a family at most (the size of the kernel table)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = `syn_rate N/s [burst=B]` in `okena`: g_plan_syn_ivl, g_plan_syn_tau
compile_xdp_syn_rate:
	push	rbx
	mov	rbx,rdi
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_rate			; rax a period of rdx seconds
	jc	.bad
	mov	rcx,rax				; ns between two: period * 1e9 / count
	imul	rax,rdx,1000000000
	xor	edx,edx
	div	rcx
	test	rax,rax
	jz	.bad
	mov	[g_plan_syn_ivl],rax
	mov	rax,rcx				; burst: the count, unless burst=
	mov	rdi,rbx
	push	rax
	lea	rsi,[str_key_burst]
	call	node_option
	test	rax,rax
	pop	rcx
	jz	.burst
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rcx,rax
.burst:
	dec	rcx				; B back to back: B - 1 intervals ahead
	mov	rax,[g_plan_syn_ivl]
	mul	rcx
	mov	[g_plan_syn_tau],rax
	pop	rbx
	ret
.bad:
	call	log_begin
	out_lit '`syn_rate` takes a rate (100/s, 6000/m) and burst=N'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = the `xdp` node in `okena`: its interfaces
compile_xdp_ifaces:
	push	rbx
	push	r12
	mov	r12,rdi
	xor	ebx,ebx
.arg:
	cmp	ebx,[r12+N_ARGC]
	jae	.out
	cmp	ebx,XIF_MAX
	jae	.out
	imul	rax,rbx,A_SIZE
	add	rax,[r12+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,15
	ja	.long
	mov	rdi,rbx
	shl	rdi,4
	lea	rdi,[g_plan_xif+rdi]
	rep	movsb
	mov	byte [rdi],0
	inc	ebx
	mov	[g_plan_nxif],ebx
	jmp	.arg
.out:
	pop	r12
	pop	rbx
	ret
.long:
	call	log_begin
	out_lit '`xdp`: an interface name is 15 bytes at most'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
