; `tcp VIP:PORT { mode xdp; to pool P }` (and `udp`): a VIP of the XDP
; balancer (xdp_lb.inc), compiled into g_plan_xvips, not a listener: no socket,
; no accept; the packets are turned round in the driver. `okena { xdp IFACE... }`
; names the interfaces the program goes on. IPv4 for now.

XV_ADDR		:= 0		; d: the VIP, network order
XV_PORT		:= 4		; d: host order
XV_PROTO	:= 8		; d: 6 TCP, 17 UDP
XV_POOL		:= 12		; d
XV_SIZE		:= 16
XVIP_MAX	:= 64
XIF_MAX		:= 8

bss
	align 8
	g_plan_xvips:	rb XVIP_MAX * XV_SIZE
	g_plan_nxvip	dd ?
	g_plan_nxif	dd ?
	g_plan_xif:	rb XIF_MAX * 16	; the interfaces, NUL-ended (IFNAMSIZ)
end bss

; rdi = a tcp/udp node with `mode xdp`: its addresses as VIPs of its pool
compile_xvip:
	push	rbx
	push	r12
	push	r13
	push	r14
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
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_V4
	jne	.not_v4
	mov	eax,[g_plan_nxvip]
	imul	rax,rax,XV_SIZE
	lea	rdi,[g_plan_xvips+rax]
	mov	ecx,[g_cmp_addr+AD_IP]
	mov	[rdi+XV_ADDR],ecx
	mov	ecx,[g_cmp_addr+AD_PORT]
	mov	[rdi+XV_PORT],ecx
	mov	[rdi+XV_PROTO],r13d
	mov	[rdi+XV_POOL],r14d
	inc	dword [g_plan_nxvip]
	inc	ebx
	jmp	.arg
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.extra:
	call	log_begin
	out_lit 'a listener with `mode xdp` takes `to` and nothing else: its packets are turned round in the driver, the kernel never holds those connections'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.not_v4:
	call	log_begin
	out_lit '`mode xdp` takes an IPv4 address and a port (IPv6: not yet)'
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
