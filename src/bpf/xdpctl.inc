; The XDP balancer's control plane.
;
; The supervisor, before it confines itself (bpf() can make maps and load
; programs only then): xdp_setup makes the maps (as large as a reload can
; need: XVIP_MAX VIPs, every server), loads xdp_lb, attaches it to each
; `okena { xdp IFACE }`, the outer header's source from the first one's
; address. The links stay open in the supervisor for its whole life. Without
; CAP_BPF / CAP_NET_ADMIN it says why and goes on without the VIPs.
;
; okena-xdp (spawn_xdpctl, again after a reload): the VIPs into VIPS, each
; pool's maglev table made once (hash_build: the table user space uses, the
; same on every instance), then every XC_TICK_MS the health table read; on
; a change the reals (an address, 0 down) and every VIP's ring written whole
; in one batch update. A slot whose server is down is drawn again from the
; slot, as hash_pick draws a key again: everywhere the same. Its filter
; lets bpf() touch maps and nothing else.

XC_TICK_MS	:= 100
XC_LRU_N	:= 1 shl 20		; flows remembered

bss
	align 8
	g_xdp_on	dd ?		; set up (maps, program, links)
	g_xdp_pid	dd ?
	g_xdp_prog	dd ?
	g_xdp_nlink	dd ?
	g_xdp_link	rd XIF_MAX
	g_xdp_insns:	rb 8192
	g_xdp_ifr:	rb 40
	; okena-xdp
	g_xc_tab	rq XVIP_MAX	; each VIP's pool's maglev table
	g_xc_sig	dq ?		; the servers' states last written
	g_xc_keys	dq ?		; a batch: MAGLEV_M keys and values
	g_xc_vals	dq ?
	g_xc_k		dd ?
	g_xc_v		dd ?
	g_xc_vk:	rb 8
	g_xc_vk2:	rb 8
end bss

rodata
	xdpctl_name	db 'okena-xdp',0
	align 8
	ts_xc_tick	dq 0, XC_TICK_MS * 1000000
end rodata

; Supervisor, before seccomp_supervisor
xdp_setup:
	cmp	dword [g_plan_nxvip],0
	je	.none
	push	rbx
	push	r12
	cmp	dword [g_plan_nxif],0
	je	.no_iface
	call	eb_ncpu
	irp <num,type,ks,vs,n,fl>, XL_VIPS,BPF_MAP_TYPE_HASH,8,4,XVIP_MAX,0, \
		XL_RING,BPF_MAP_TYPE_ARRAY,4,4,XVIP_MAX*MAGLEV_M,0, \
		XL_REALS,BPF_MAP_TYPE_ARRAY,4,4,MAX_SERVERS+1,0, \
		XL_LRU,BPF_MAP_TYPE_LRU_HASH,16,4,XC_LRU_N,BPF_F_NO_COMMON_LRU, \
		XL_STATS,BPF_MAP_TYPE_PERCPU_ARRAY,4,8,XS_N,0, \
		XL_CTL,BPF_MAP_TYPE_ARRAY,4,4,2,0, \
		XL_NH,BPF_MAP_TYPE_PERCPU_ARRAY,4,NH_L,XL_NH_N,0
		mov	edi,type
		mov	esi,ks
		mov	edx,vs
		mov	ecx,n
		mov	r8d,num
		mov	r9d,fl
		call	eb_map_create
		test	eax,eax
		js	.failed_map
	end irp
	; the outer header's source: the first interface's IPv4 address
	lea	rsi,[g_plan_xif]
	lea	rdi,[g_xdp_ifr]
	mov	ecx,16
	rep	movsb
	mov	edi,AF_INET
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.failed_addr
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SIOCGIFADDR_
	lea	rdx,[g_xdp_ifr]
	mov	eax,SYS_ioctl_
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	test	eax,eax
	js	.failed_addr
	mov	eax,[g_xdp_ifr+16+4]		; (struct sockaddr_in in the ifreq)
	mov	[g_xc_v],eax
	mov	dword [g_xc_k],0
	mov	edi,[g_eb_mapfd+XL_CTL*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_v]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.failed_addr
	mov	dword [g_xc_k],1		; the new flows remembered a time step
	mov	dword [g_xc_v],XL_FLOOD_N
	mov	edi,[g_eb_mapfd+XL_CTL*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_v]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	js	.failed_map
	; the program
	lea	rdi,[g_xdp_insns]
	lea	rsi,[xl_prog]
	mov	edx,xl_prog_len
	call	eb_prog_load_xdp
	test	eax,eax
	js	.failed_prog
	mov	[g_xdp_prog],eax
	; on each interface: in the driver, else generic
	xor	r12d,r12d
.iface:
	cmp	r12d,[g_plan_nxif]
	jae	.attached
	mov	rsi,r12
	shl	rsi,4
	lea	rsi,[g_plan_xif+rsi]
	call	eb_ifindex
	test	eax,eax
	js	.failed_if
	mov	ebx,eax
	mov	edi,[g_xdp_prog]
	mov	esi,ebx
	mov	edx,XDP_FLAGS_DRV_MODE
	call	eb_xdp_attach
	lea	rcx,[cli_xdp.drv]
	test	eax,eax
	jns	@f
	mov	edi,[g_xdp_prog]
	mov	esi,ebx
	mov	edx,XDP_FLAGS_SKB_MODE
	call	eb_xdp_attach
	lea	rcx,[cli_xdp.skb]
	test	eax,eax
	js	.failed_if
@@:
	mov	edx,[g_xdp_nlink]
	mov	[g_xdp_link+rdx*4],eax
	inc	dword [g_xdp_nlink]
	push	rcx
	call	log_begin
	out_lit 'xdp: on '
	mov	rsi,r12
	shl	rsi,4
	lea	rsi,[g_plan_xif+rsi]
	call	out_cstr
	out_lit ' ('
	pop	rsi
	call	out_cstr
	out_lit ')'
	call	log_end
	inc	r12d
	jmp	.iface
.attached:
	mov	dword [g_xdp_on],1
	call	log_begin
	out_lit 'xdp: '
	mov	eax,[g_plan_nxvip]
	call	out_u64
	out_lit ' VIPs balanced in the driver'
	call	log_end
	jmp	.out
.no_iface:
	call	log_begin
	out_lit '`mode xdp` needs the interfaces it goes on: okena { xdp IFACE }'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.failed_map:
	lea	rsi,[.s_map]
	jmp	.failed
.failed_addr:
	lea	rsi,[.s_addr]
	jmp	.failed
.failed_prog:
	push	rax
	call	log_begin
	out_lit 'xdp: the verifier refused the balancer: '
	lea	rsi,[g_eb_log]
	call	out_cstr
	call	log_end
	pop	rax
	lea	rsi,[.s_prog]
	jmp	.failed
.failed_if:
	lea	rsi,[.s_if]
.failed:
	push	rax
	push	rsi
	call	log_begin
	out_lit 'xdp: '
	pop	rsi
	call	out_cstr
	out_lit ' (errno '
	pop	rax
	neg	eax
	call	out_u64
	out_lit '; CAP_BPF and CAP_NET_ADMIN are needed): the `mode xdp` VIPs are not served'
	call	log_end
.out:
	pop	r12
	pop	rbx
.none:
	ret
	cstring .s_map, 'no map could be made',0
	cstring .s_addr, 'the first interface has no IPv4 address for the outer header',0
	cstring .s_prog, 'no program loaded',0
	cstring .s_if, 'an interface it could not go on',0

; Supervisor: start okena-xdp when the balancer is set up
spawn_xdpctl:
	cmp	dword [g_xdp_on],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	xdpctl_main
	js	.none
	mov	[g_xdp_pid],eax
.none:
	ret

; Never returns.
xdpctl_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[xdpctl_name]
	mov	eax,SYS_prctl
	syscall
	; the batch's arrays and each VIP's pool's maglev table, before the filter
	xor	edi,edi
	mov	esi,MAGLEV_M * 8
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal
	mov	[g_xc_keys],rax
	add	rax,MAGLEV_M * 4
	mov	[g_xc_vals],rax
	call	groups_refresh			; (names to addresses, as workers do)
	xor	ebx,ebx
.table:
	cmp	ebx,[g_plan_nxvip]
	jae	.tables
	imul	rax,rbx,XV_SIZE
	mov	r12d,[g_plan_xvips+rax+XV_POOL]
	imul	r13,r12,PL_SIZE
	mov	rax,[g_pools+r13+PL_HTAB]
	test	rax,rax
	jnz	.have
	xor	edi,edi
	mov	esi,HT_BYTES
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal
	mov	[g_pools+r13+PL_HTAB],rax
	mov	edi,r12d
	call	hash_build			; (maglev, whatever the pool's balance)
	mov	rax,[g_pools+r13+PL_HTAB]
.have:
	mov	[g_xc_tab+rbx*8],rax
	inc	ebx
	jmp	.table
.tables:
	call	helper_close_sockets
	call	ll_confine_none			; (Landlock: no file at all)
	seccomp_for filter_xdpctl
	call	xc_vips
	mov	qword [g_xc_sig],-1
.loop:
	call	xc_tick
	lea	rdi,[ts_xc_tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.loop
.fatal:
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; the VIPs: those of the plan in, any other out
xc_vips:
	push	rbx
	; out: every key not in the plan (a reload may have dropped some)
	lea	rsi,[g_xc_vk]			; (from the first)
	mov	qword [rsi],0
	xor	ebx,ebx
.next_key:
	mov	edi,[g_eb_mapfd+XL_VIPS*4]
	lea	rsi,[g_xc_vk]
	lea	rdx,[g_xc_vk2]
	test	ebx,ebx
	jnz	@f
	xor	esi,esi				; NULL: the first key
@@:
	call	xc_next_key
	test	eax,eax
	jnz	.in
	mov	rax,[g_xc_vk2]
	mov	[g_xc_vk],rax
	inc	ebx
	call	xc_vip_planned
	jnc	.next_key
	mov	edi,[g_eb_mapfd+XL_VIPS*4]	; (deleting is safe while walking)
	lea	rsi,[g_xc_vk]
	call	xc_delete
	jmp	.next_key
.in:
	xor	ebx,ebx
.vip:
	cmp	ebx,[g_plan_nxvip]
	jae	.out
	call	xc_vip_key
	mov	[g_xc_v],ebx
	mov	edi,[g_eb_mapfd+XL_VIPS*4]
	lea	rsi,[g_xc_vk]
	lea	rdx,[g_xc_v]
	xor	ecx,ecx
	call	eb_map_update
	inc	ebx
	jmp	.vip
.out:
	pop	rbx
	ret

; ebx = a VIP of the plan: g_xc_vk = its key (address, port big endian, protocol)
xc_vip_key:
	imul	rax,rbx,XV_SIZE
	lea	rax,[g_plan_xvips+rax]
	mov	ecx,[rax+XV_ADDR]
	mov	dword [g_xc_vk],ecx
	mov	ecx,[rax+XV_PORT]
	xchg	cl,ch
	mov	word [g_xc_vk+4],cx
	mov	ecx,[rax+XV_PROTO]
	mov	byte [g_xc_vk+6],cl
	mov	byte [g_xc_vk+7],0
	ret

; g_xc_vk2 = a key in VIPS: CF when no VIP of the plan has it
xc_vip_planned:
	push	rbx
	push	qword [g_xc_vk]
	xor	ebx,ebx
.v:
	cmp	ebx,[g_plan_nxvip]
	jae	.no
	call	xc_vip_key
	mov	rax,[g_xc_vk]
	cmp	rax,[g_xc_vk2]
	je	.yes
	inc	ebx
	jmp	.v
.yes:
	pop	qword [g_xc_vk]
	pop	rbx
	clc
	ret
.no:
	pop	qword [g_xc_vk]
	pop	rbx
	stc
	ret

xc_next_key	:= eb_map_next_key
xc_delete	:= eb_map_delete

; once a tick: the servers' states; on a change, reals and rings rewritten
xc_tick:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	; the signature: a hash of every state that counts
	xor	r12d,r12d
	mov	r13,0x9E3779B97F4A7C15
	xor	ebx,ebx
.sig:
	cmp	ebx,[g_plan_servers]
	jae	.signed
	call	xc_up
	movzx	eax,al
	add	r12,rax
	add	r12,rbx
	imul	r12,r13
	inc	ebx
	jmp	.sig
.signed:
	cmp	r12,[g_xc_sig]
	je	.out
	mov	[g_xc_sig],r12
	; the reals: an address while up, 0 down
	xor	ebx,ebx
.real:
	cmp	ebx,[g_plan_servers]
	jae	.rings
	imul	rax,rbx,SV_SIZE
	xor	ecx,ecx
	cmp	word [g_servers+rax+SV_SA],AF_INET
	jne	@f
	call	xc_up
	test	al,al
	jz	@f
	imul	rax,rbx,SV_SIZE
	mov	ecx,[g_servers+rax+SV_SA+4]
@@:
	mov	[g_xc_v],ecx
	lea	eax,[rbx+1]
	mov	[g_xc_k],eax
	mov	edi,[g_eb_mapfd+XL_REALS*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_v]
	xor	ecx,ecx
	call	eb_map_update
	inc	ebx
	jmp	.real
.rings:
	xor	r14d,r14d			; VIP
.vip:
	cmp	r14d,[g_plan_nxvip]
	jae	.out
	mov	r15,[g_xc_tab+r14*8]
	xor	ebx,ebx				; slot
.slot:
	cmp	ebx,MAGLEV_M
	jae	.write
	movzx	eax,word [r15+HT_DATA+rbx*2]
	test	eax,eax
	jz	.none
	push	rbx
	lea	ebx,[rax-1]
	call	xc_up
	pop	rbx
	test	al,al
	jnz	.put
	; down: drawn again from the slot, as hash_pick does from a key
	mov	r13d,HASH_REDRAWS
	mov	eax,ebx
.redraw:
	mov	rdx,0x9E3779B97F4A7C15
	add	rax,rdx
	call	hash_mix
	push	rax
	xor	edx,edx
	mov	ecx,MAGLEV_M
	div	rcx
	movzx	eax,word [r15+HT_DATA+rdx*2]
	push	rbx
	lea	ebx,[rax-1]
	mov	r12d,eax
	call	xc_up
	pop	rbx
	test	al,al
	pop	rax
	jnz	.redrawn
	dec	r13d
	jnz	.redraw
.none:
	xor	eax,eax				; nobody: dropped
	jmp	.store
.redrawn:
	mov	eax,r12d
	jmp	.store
.put:
	movzx	eax,word [r15+HT_DATA+rbx*2]
.store:
	mov	rdx,[g_xc_vals]
	mov	[rdx+rbx*4],eax
	mov	eax,r14d
	imul	eax,eax,MAGLEV_M
	add	eax,ebx
	mov	rdx,[g_xc_keys]
	mov	[rdx+rbx*4],eax
	inc	ebx
	jmp	.slot
.write:
	mov	edi,[g_eb_mapfd+XL_RING*4]
	mov	rsi,[g_xc_keys]
	mov	rdx,[g_xc_vals]
	mov	ecx,MAGLEV_M
	call	xc_update_batch
	inc	r14d
	jmp	.vip
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = a server: al = 1 up (the health table says so, or nobody checks)
xc_up:
	mov	al,1
	cmp	dword [g_plan_health],0
	je	.out
	mov	rdx,[g_health_tbl]
	test	rdx,rdx
	jz	.out
	cmp	dword [rdx+rbx*8],HC_UP
	sete	al
.out:
	ret

xc_update_batch	:= eb_map_update_batch
