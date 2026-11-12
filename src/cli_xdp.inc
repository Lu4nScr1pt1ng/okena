; `okena xdp IFACE [SECONDS]`: the eBPF toolchain end to end, on an interface:
; a program assembled here (no clang, no libbpf) loaded through the verifier,
; attached to IFACE's XDP hook (in the driver; generic when the driver has
; none), counting what comes in, per CPU, and letting it pass. Prints the
; packets of each second. Needs CAP_BPF and CAP_NET_ADMIN (root).

XC_MAP_COUNT	:= 0			; per-CPU array of one u64

rodata
	align 8
; the counter, then XDP_PASS
xc_prog:
	e_st32	BR10, -4, 0			; key 0 on the stack
	e_ldmap	BR1, XC_MAP_COUNT
	e_mov	BR2, BR10
	e_addi	BR2, -4
	e_call	BPF_FUNC_map_lookup_elem
	e_jeqi	BR0, 0, .pass
	e_ldx64	BR1, BR0, 0			; (per CPU: no atomics)
	e_addi	BR1, 1
	e_stx64	BR0, 0, BR1
.pass:
	e_movi	BR0, XDP_PASS
	e_exit
xc_prog_len = $ - xc_prog
end rodata

bss
	align 8
	g_xc_insns:	rb 4096
	g_xc_vals:	rb 8 * 1024		; a per-CPU value: 8 bytes a CPU
	g_xc_key	dd ?
	g_xc_secs	dd ?
	g_xc_link	dd ?
end bss

cli_xdp:
	mov	rax,[g_argv]
	mov	r12,[rax+16]			; the interface
	test	r12,r12
	jz	.usage
	mov	dword [g_xc_secs],10
	mov	rsi,[rax+24]
	test	rsi,rsi
	jz	@f
	xor	eax,eax
.digits:
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.secs
	imul	eax,eax,10
	add	eax,ecx
	inc	rsi
	jmp	.digits
.secs:
	test	eax,eax
	jz	@f
	mov	[g_xc_secs],eax
@@:
	call	eb_ncpu
	mov	edi,BPF_MAP_TYPE_PERCPU_ARRAY
	mov	esi,4
	mov	edx,8
	mov	ecx,1
	mov	r8d,XC_MAP_COUNT
	xor	r9d,r9d
	call	eb_map_create
	test	eax,eax
	js	.no_map
	lea	rdi,[g_xc_insns]
	lea	rsi,[xc_prog]
	mov	edx,xc_prog_len
	call	eb_prog_load_xdp
	test	eax,eax
	js	.no_prog
	mov	r13d,eax
	mov	rsi,r12
	call	eb_ifindex
	test	eax,eax
	js	.no_if
	mov	r14d,eax
	mov	edi,r13d			; in the driver, else generic
	mov	esi,r14d
	mov	edx,XDP_FLAGS_DRV_MODE
	call	eb_xdp_attach
	lea	r15,[.drv]
	test	eax,eax
	jns	.attached
	mov	edi,r13d
	mov	esi,r14d
	mov	edx,XDP_FLAGS_SKB_MODE
	call	eb_xdp_attach
	lea	r15,[.skb]
	test	eax,eax
	js	.no_attach
.attached:
	mov	[g_xc_link],eax
	out_lit 'okena xdp: attached to '
	mov	rsi,r12
	call	out_cstr
	out_lit ' ('
	mov	rsi,r15
	call	out_cstr
	out_lit '), '
	mov	eax,[g_eb_ncpu]
	call	out_u64
	out_lit ' CPUs, counting'
	mov	edi,10
	call	out_char
	call	out_flush
	cstring .drv, 'in the driver',0
	cstring .skb, 'generic: the driver has no XDP',0
	xor	ebx,ebx				; the total so far
.second:
	sub	rsp,16
	mov	qword [rsp],1
	mov	qword [rsp+8],0
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	mov	edi,[g_eb_mapfd+XC_MAP_COUNT*4]
	lea	rsi,[g_xc_key]
	lea	rdx,[g_xc_vals]
	call	eb_map_lookup
	test	eax,eax
	js	.no_read
	xor	eax,eax
	xor	ecx,ecx
@@:
	add	rax,[g_xc_vals+rcx*8]
	inc	ecx
	cmp	ecx,[g_eb_ncpu]
	jb	@b
	push	rax
	sub	rax,rbx
	call	out_u64
	out_lit ' packets/s'
	mov	edi,10
	call	out_char
	call	out_flush
	pop	rbx
	dec	dword [g_xc_secs]
	jnz	.second
	xor	edi,edi
	jmp	exit_process			; (the link goes with the process)
.usage:
	mov	edi,2
	call	out_select
	out_lit 'usage: okena xdp IFACE [SECONDS]'
	mov	edi,10
	call	out_char
	mov	edi,2
	jmp	exit_process
.no_map:
	lea	rsi,[.s_map]
	jmp	.fail
.no_prog:
	push	rax
	mov	edi,2
	call	out_select
	out_lit 'okena xdp: the verifier refused the program (errno '
	pop	rax
	neg	eax
	call	out_u64
	out_lit '):'
	mov	edi,10
	call	out_char
	lea	rsi,[g_eb_log]
	call	out_cstr
	mov	edi,1
	jmp	exit_process
.no_if:
	lea	rsi,[.s_if]
	jmp	.fail
.no_attach:
	lea	rsi,[.s_attach]
	jmp	.fail
.no_read:
	lea	rsi,[.s_read]
.fail:
	push	rax
	push	rsi
	mov	edi,2
	call	out_select
	out_lit 'okena xdp: '
	pop	rsi
	call	out_cstr
	out_lit ' (errno '
	pop	rax
	neg	eax
	call	out_u64
	out_lit '; CAP_BPF and CAP_NET_ADMIN are needed)'
	mov	edi,10
	call	out_char
	mov	edi,1
	jmp	exit_process
	cstring .s_map, 'no map could be made',0
	cstring .s_if, 'no such interface',0
	cstring .s_attach, 'the program could not be attached',0
	cstring .s_read, 'the counter could not be read',0
