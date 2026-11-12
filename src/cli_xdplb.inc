; `okena xdplb IFACE SRC VIP PORT REAL... [-- SECONDS]`: the XDP balancer on
; IFACE, by hand, for the lab: TCP to VIP:PORT spread over the REALs (IPv4
; addresses), wrapped in IPIP from SRC. The ring is filled here slot by slot
; in turn; the control plane proper fills it from a pool's maglev table.
; Prints, each second, what went to the reals, the new flows, the drops.

XB_LRU_N	:= 1 shl 20		; flows remembered

bss
	align 8
	g_xb_insns:	rb 8192
	g_xb_vals:	rb 8 * 1024
	g_xb_key	dd ?
	g_xb_ip		dd ?
	g_xb_val	dd ?
	g_xb_vip:	rb 8
	g_xb_nreal	dd ?
	g_xb_secs	dd ?
	g_xb_last:	rq XS_N
end bss

; rsi = dotted IPv4 (NUL-ended): eax = it, network order. CF: not one.
xb_ip4:
	xor	edx,edx				; the address, filled from the top byte
	xor	ecx,ecx				; octets
.octet:
	xor	eax,eax
	xor	r8d,r8d				; digits
.d:
	movzx	r9d,byte [rsi]
	sub	r9d,'0'
	cmp	r9d,9
	ja	.end
	imul	eax,eax,10
	add	eax,r9d
	inc	rsi
	inc	r8d
	jmp	.d
.end:
	test	r8d,r8d
	jz	.bad
	cmp	eax,255
	ja	.bad
	mov	byte [g_xb_ip+rcx],al
	inc	ecx
	movzx	r9d,byte [rsi]
	cmp	ecx,4
	je	.last
	cmp	r9d,'.'
	jne	.bad
	inc	rsi
	jmp	.octet
.last:
	test	r9d,r9d
	jnz	.bad
	mov	eax,[g_xb_ip]
	clc
	ret
.bad:
	stc
	ret

; rsi = decimal: eax. CF: not one.
xb_uint:
	xor	eax,eax
	xor	ecx,ecx
@@:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	@f
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	inc	ecx
	jmp	@b
@@:
	cmp	ecx,1
	ret					; (CF: no digits)

cli_xdplb:
	mov	rbx,[g_argv]
	cmp	qword [g_argc],7
	jb	.usage
	mov	dword [g_xb_secs],10
	call	eb_ncpu
	; the maps, in the program's order
	irp <num,type,ks,vs,n,fl>, XL_VIPS,BPF_MAP_TYPE_HASH,8,4,64,0, \
		XL_RING,BPF_MAP_TYPE_ARRAY,4,4,MAGLEV_M,0, \
		XL_REALS,BPF_MAP_TYPE_ARRAY,4,4,256,0, \
		XL_LRU,BPF_MAP_TYPE_LRU_HASH,16,4,XB_LRU_N,BPF_F_NO_COMMON_LRU, \
		XL_STATS,BPF_MAP_TYPE_PERCPU_ARRAY,4,8,XS_N,0, \
		XL_CTL,BPF_MAP_TYPE_ARRAY,4,4,1,0
		mov	edi,type
		mov	esi,ks
		mov	edx,vs
		mov	ecx,n
		mov	r8d,num
		mov	r9d,fl
		call	eb_map_create
		test	eax,eax
		js	.no_map
	end irp
	; the outer source
	mov	rsi,[rbx+24]
	call	xb_ip4
	jc	.usage
	mov	[g_xb_val],eax
	mov	dword [g_xb_key],0
	mov	edi,[g_eb_mapfd+XL_CTL*4]
	lea	rsi,[g_xb_key]
	lea	rdx,[g_xb_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.no_fill
	; the VIP: address, port, TCP
	mov	rsi,[rbx+32]
	call	xb_ip4
	jc	.usage
	mov	[g_xb_vip],eax
	mov	rsi,[rbx+40]
	call	xb_uint
	jc	.usage
	xchg	al,ah
	mov	[g_xb_vip+4],ax
	mov	byte [g_xb_vip+6],6
	mov	byte [g_xb_vip+7],0
	mov	dword [g_xb_val],0		; VIP number 0
	mov	edi,[g_eb_mapfd+XL_VIPS*4]
	lea	rsi,[g_xb_vip]
	lea	rdx,[g_xb_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.no_fill
	; the reals (numbers 1..n: 0 stays "none"), then the ring in turn
	mov	dword [g_xb_nreal],0
	mov	r12d,6				; argv index
.real:
	cmp	r12,[g_argc]
	jae	.reals
	mov	rsi,[rbx+r12*8]
	cmp	word [rsi],'--'
	jne	@f
	mov	rsi,[rbx+r12*8+8]
	test	rsi,rsi
	jz	.reals
	call	xb_uint
	jc	.usage
	mov	[g_xb_secs],eax
	jmp	.reals
@@:
	call	xb_ip4
	jc	.usage
	mov	[g_xb_val],eax
	inc	dword [g_xb_nreal]
	mov	eax,[g_xb_nreal]
	mov	[g_xb_key],eax
	mov	edi,[g_eb_mapfd+XL_REALS*4]
	lea	rsi,[g_xb_key]
	lea	rdx,[g_xb_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.no_fill
	inc	r12d
	jmp	.real
.reals:
	cmp	dword [g_xb_nreal],0
	je	.usage
	xor	r13d,r13d			; slot
.slot:
	mov	eax,r13d
	xor	edx,edx
	div	dword [g_xb_nreal]
	inc	edx
	mov	[g_xb_val],edx
	mov	[g_xb_key],r13d
	mov	edi,[g_eb_mapfd+XL_RING*4]
	lea	rsi,[g_xb_key]
	lea	rdx,[g_xb_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.no_fill
	inc	r13d
	cmp	r13d,MAGLEV_M
	jb	.slot
	; the program
	lea	rdi,[g_xb_insns]
	lea	rsi,[xl_prog]
	mov	edx,xl_prog_len
	call	eb_prog_load_xdp
	test	eax,eax
	js	cli_xdp.no_prog
	mov	r13d,eax
	mov	rsi,[rbx+16]
	call	eb_ifindex
	test	eax,eax
	js	cli_xdp.no_if
	mov	r14d,eax
	mov	edi,r13d
	mov	esi,r14d
	mov	edx,XDP_FLAGS_DRV_MODE
	call	eb_xdp_attach
	lea	r15,[cli_xdp.drv]
	test	eax,eax
	jns	.attached
	mov	edi,r13d
	mov	esi,r14d
	mov	edx,XDP_FLAGS_SKB_MODE
	call	eb_xdp_attach
	lea	r15,[cli_xdp.skb]
	test	eax,eax
	js	cli_xdp.no_attach
.attached:
	out_lit 'okena xdplb: on '
	mov	rsi,[rbx+16]
	call	out_cstr
	out_lit ' ('
	mov	rsi,r15
	call	out_cstr
	out_lit '), '
	mov	eax,[g_xb_nreal]
	call	out_u64
	out_lit ' reals'
	mov	edi,10
	call	out_char
	call	out_flush
.second:
	sub	rsp,16
	mov	qword [rsp],1
	mov	qword [rsp+8],0
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	irp <idx,label>, XS_TX,'to reals/s ', XS_MISS,'new flows/s ', XS_DROP,'dropped/s'
		mov	dword [g_xb_key],idx
		mov	edi,[g_eb_mapfd+XL_STATS*4]
		lea	rsi,[g_xb_key]
		lea	rdx,[g_xb_vals]
		call	eb_map_lookup
		xor	eax,eax
		xor	ecx,ecx
	@@:
		add	rax,[g_xb_vals+rcx*8]
		inc	ecx
		cmp	ecx,[g_eb_ncpu]
		jb	@b
		mov	rcx,rax
		sub	rax,[g_xb_last+idx*8]
		mov	[g_xb_last+idx*8],rcx
		call	out_u64
		out_lit ' ', label
	end irp
	mov	edi,10
	call	out_char
	call	out_flush
	dec	dword [g_xb_secs]
	jnz	.second
	xor	edi,edi
	jmp	exit_process
.usage:
	mov	edi,2
	call	out_select
	out_lit 'usage: okena xdplb IFACE SRC VIP PORT REAL... [-- SECONDS]'
	mov	edi,10
	call	out_char
	mov	edi,2
	jmp	exit_process
.no_map:
	lea	rsi,[cli_xdp.s_map]
	jmp	cli_xdp.fail
.no_fill:
	cstring .s_fill, 'a map could not be filled',0
	lea	rsi,[.s_fill]
	jmp	cli_xdp.fail
