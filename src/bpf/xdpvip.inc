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
