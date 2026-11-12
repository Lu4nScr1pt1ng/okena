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
XC_DROP_N	:= 1 shl 20		; `drop` prefixes, each family
XC_SYNS_N	:= 1 shl 20		; sources `syn_rate` follows
XC_STALE_N	:= 65536		; drop list keys gone, deleted a pass at a time

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
	align 8
	g_xc_val:	rb 24		; a value: CTL's, a VIP's, a real's
	g_xc_vk:	rb 24		; VIP keys (8 bytes IPv4, 20 IPv6)
	g_xc_vk2:	rb 24
	g_xc_inet6:	rb 16384	; /proc/net/if_inet6
	align 8
	g_xc_lkey:	rb 24
	g_xc_lkey2:	rb 24
	g_xc_gen	dd ?
	g_xc_stale	dq ?		; XC_STALE_N keys of 24 bytes
end bss

rodata
	xdpctl_name	db 'okena-xdp',0
	align 8
	ts_xc_tick	dq 0, XC_TICK_MS * 1000000
end rodata

; Supervisor, before seccomp_supervisor
xdp_setup:
	cmp	dword [g_plan_nxif],0		; on the `xdp` interfaces, whatever is
	jne	@f				; asked yet (a reload may bring VIPs, `drop`)
	mov	eax,[g_plan_nxvip]
	or	eax,[g_plan_xdrop]
	or	rax,[g_plan_syn_ivl]
	jz	.none
	push	rbx
	push	r12
	jmp	.no_iface
@@:
	push	rbx
	push	r12
	call	eb_ncpu
	irp <num,type,ks,vs,n,fl>, XL_VIPS4,BPF_MAP_TYPE_HASH,8,XVV_L,XVIP_MAX,0, \
		XL_RING,BPF_MAP_TYPE_ARRAY,4,4,XVIP_MAX*MAGLEV_M,0, \
		XL_REALS,BPF_MAP_TYPE_ARRAY,4,XR_L,MAX_SERVERS+1,0, \
		XL_LRU4,BPF_MAP_TYPE_LRU_HASH,16,4,XC_LRU_N,BPF_F_NO_COMMON_LRU, \
		XL_STATS,BPF_MAP_TYPE_PERCPU_ARRAY,4,8,XS_N,0, \
		XL_CTL,BPF_MAP_TYPE_ARRAY,4,CTL_L,CTL_N,0, \
		XL_NH,BPF_MAP_TYPE_PERCPU_ARRAY,4,NH_L,XL_NH_N,0, \
		XL_VIPS6,BPF_MAP_TYPE_HASH,20,XVV_L,XVIP_MAX,0, \
		XL_LRU6,BPF_MAP_TYPE_LRU_HASH,40,4,XC_LRU_N,BPF_F_NO_COMMON_LRU, \
		XL_DROP4,BPF_MAP_TYPE_LPM_TRIE,8,4,XC_DROP_N,BPF_F_NO_PREALLOC, \
		XL_DROP6,BPF_MAP_TYPE_LPM_TRIE,20,4,XC_DROP_N,BPF_F_NO_PREALLOC, \
		XL_SYNS,BPF_MAP_TYPE_LRU_HASH,8,8,XC_SYNS_N,0
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
	; the outer headers' sources: the first interface's IPv4 address, its
	; IPv6 one (global); one of them at least
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
	mov	r12,rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	lea	rdi,[g_xc_val]
	xor	eax,eax
	mov	ecx,3
	rep	stosq
	test	r12,r12
	js	@f				; (no IPv4 address)
	mov	eax,[g_xdp_ifr+16+4]		; (struct sockaddr_in in the ifreq)
	mov	dword [g_xc_val],eax
@@:
	mov	dword [g_xc_k],CTL_SRC4
	call	xdp_ctl_put
	js	.failed_map
	mov	ebx,[g_xc_val]			; (0: none)
	lea	rdi,[g_xc_val]
	xor	eax,eax
	mov	ecx,3
	rep	stosq
	call	xdp_src6			; g_xc_val = it, or ::
	mov	rax,qword [g_xc_val]
	or	rax,qword [g_xc_val+8]
	or	rbx,rax
	jz	.failed_addr
	mov	dword [g_xc_k],CTL_SRC6
	call	xdp_ctl_put
	js	.failed_map
	lea	rdi,[g_xc_val]
	xor	eax,eax
	mov	ecx,3
	rep	stosq
	mov	dword [g_xc_val],XL_FLOOD_N	; the new flows remembered a time step
	mov	dword [g_xc_k],CTL_FLOOD
	call	xdp_ctl_put
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
	call	xdp_check_forwarding
	call	log_begin
	out_lit 'xdp: '
	mov	eax,[g_plan_nxvip]
	call	out_u64
	out_lit ' VIPs balanced in the driver'
	cmp	dword [g_plan_xdrop],0
	je	@f
	out_lit '; `drop` before anything'
@@:
	cmp	qword [g_plan_syn_ivl],0
	je	@f
	out_lit '; SYNs a source at most `syn_rate`'
@@:
	call	log_end
	jmp	.out
.no_iface:
	call	log_begin
	out_lit '`mode xdp`, `drop` and `syn_rate` need the interfaces they go on: okena { xdp IFACE }'
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
	cstring .s_addr, 'the first interface has no IP address (IPv4, or global IPv6) for the outer header',0
	cstring .s_prog, 'no program loaded',0
	cstring .s_if, 'an interface it could not go on',0

; bpf_fib_lookup gives a next hop only on an interface that forwards: for
; each `xdp` interface and each family the VIPs' reals use, say so when it
; does not (without a next hop every packet to those reals is dropped).
; Turning it on is the operator's: on IPv6 it also stops the interface
; taking router advertisements, unless accept_ra=2.
xdp_check_forwarding:
	push	rbx
	push	r12
	push	r13
	; the families of the reals: bit 0 IPv4, bit 1 IPv6
	xor	r13d,r13d
	xor	ebx,ebx
.vip:
	cmp	ebx,[g_plan_nxvip]
	jae	.families
	imul	rax,rbx,XV_SIZE
	mov	eax,[g_plan_xvips+rax+XV_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_FIRST]
	mov	edx,[g_pools+rax+PL_COUNT]
	add	edx,ecx
.server:
	cmp	ecx,edx
	jae	.next_vip
	imul	rax,rcx,SV_SIZE
	cmp	word [g_servers+rax+SV_SA],AF_INET
	jne	@f
	or	r13d,1
@@:
	cmp	word [g_servers+rax+SV_SA],AF_INET6
	jne	@f
	or	r13d,2
@@:
	inc	ecx
	jmp	.server
.next_vip:
	inc	ebx
	jmp	.vip
.families:
	xor	r12d,r12d			; the interface
.iface:
	cmp	r12d,[g_plan_nxif]
	jae	.out
	mov	ebx,4
.family:
	mov	eax,1
	cmp	ebx,4
	je	@f
	mov	eax,2
@@:
	test	r13d,eax
	jz	.next_family
	; /proc/sys/net/ipv4/conf/IFACE/forwarding
	lea	rdi,[g_xc_inet6]
	lea	rsi,[.p1]
	call	.cat
	mov	byte [rdi-1],bl			; (the 4 of the template: 4 or 6)
	add	byte [rdi-1],'0'
	lea	rsi,[.p2]
	call	.cat
	mov	rsi,r12
	shl	rsi,4
	lea	rsi,[g_plan_xif+rsi]
	call	.cat
	lea	rsi,[.p3]
	call	.cat
	mov	byte [rdi],0
	mov	edi,-100			; AT_FDCWD
	lea	rsi,[g_xc_inet6]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.next_family
	push	rax
	mov	edi,eax
	lea	rsi,[g_xc_inet6+512]
	mov	edx,1
	xor	eax,eax				; SYS_read
	syscall
	pop	rdi
	push	rax
	mov	eax,SYS_close
	syscall
	pop	rax
	cmp	rax,1
	jne	.next_family
	cmp	byte [g_xc_inet6+512],'0'
	jne	.next_family
	call	log_begin
	out_lit 'xdp: '
	mov	rsi,r12
	shl	rsi,4
	lea	rsi,[g_plan_xif+rsi]
	call	out_cstr
	out_lit ' does not forward IPv'
	mov	eax,ebx
	call	out_u64
	out_lit ': the kernel gives no next hop, packets to IPv'
	mov	eax,ebx
	call	out_u64
	out_lit ' reals are dropped (sysctl net.ipv'
	mov	eax,ebx
	call	out_u64
	out_lit '.conf.'
	mov	rsi,r12
	shl	rsi,4
	lea	rsi,[g_plan_xif+rsi]
	call	out_cstr
	out_lit '.forwarding=1'
	cmp	ebx,6
	jne	@f
	out_lit '; accept_ra=2 if the host takes its routes from router advertisements'
@@:
	out_lit ')'
	call	log_end
.next_family:
	add	ebx,2
	cmp	ebx,6
	jbe	.family
	inc	r12d
	jmp	.iface
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi = a string (NUL-ended) copied to rdi; rdi past it
.cat:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	.cat
@@:
	ret
	cstring .p1, '/proc/sys/net/ipv4',0
	cstring .p2, '/conf/',0
	cstring .p3, '/forwarding',0

; g_xc_val -> CTL[g_xc_k]. SF: failed.
xdp_ctl_put:
	mov	edi,[g_eb_mapfd+XL_CTL*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	ret

; g_xc_val = the first interface's first global IPv6 address that is in
; use (not tentative, deprecated or failed), from /proc/net/if_inet6:
; "20010db8000000000000000000000001 02 40 00 80 eth0", one a line: the
; address, ifindex, prefix, scope (00 global), flags, the name. Left as
; it is when there is none.
xdp_src6:
	push	rbx
	push	r12
	push	r13
	mov	edi,-100			; AT_FDCWD
	lea	rsi,[.path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out
	mov	ebx,eax
	xor	r12d,r12d			; read so far
.read:
	mov	edi,ebx
	lea	rsi,[g_xc_inet6+r12]
	mov	edx,16384 - 1
	sub	edx,r12d
	jz	.read_all
	mov	eax,SYS_read
	syscall
	test	rax,rax
	jle	.read_all
	add	r12d,eax
	jmp	.read
.read_all:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	byte [g_xc_inet6+r12],0
	lea	r13,[g_xc_inet6]		; the line
.line:
	cmp	byte [r13],0
	je	.out
	; the name: the last field, the line's end
	mov	rsi,r13
@@:
	movzx	eax,byte [rsi]
	test	eax,eax
	jz	@f
	cmp	eax,10
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	r12,rsi				; the line's end
	mov	rdi,rsi
@@:
	cmp	rdi,r13
	je	.next
	cmp	byte [rdi-1],' '
	je	@f
	dec	rdi
	jmp	@b
@@:	; rdi..r12: the name; compare with the interface's
	lea	rsi,[g_plan_xif]
	mov	rcx,r12
	sub	rcx,rdi
	cmp	byte [rsi+rcx],0
	jne	.next
	repe	cmpsb
	jne	.next
	; 32 hex digits, " ", ifindex, " ", prefix, " ", scope, " ", flags
	cmp	byte [r13+32],' '
	jne	.next
	lea	rsi,[r13+33]
	call	.skip_field			; ifindex
	call	.skip_field			; prefix
	cmp	word [rsi],'00'			; global
	jne	.next
	cmp	byte [rsi+2],' '
	jne	.next
	add	rsi,3
	call	.hex_byte			; the flags
	jc	.next
	test	al,0x08 or 0x20 or 0x40		; dadfailed, deprecated, tentative
	jnz	.next
	xor	ecx,ecx
@@:
	lea	rsi,[r13+rcx*2]
	call	.hex_byte
	jc	.next
	mov	[g_xc_val+rcx],al
	inc	ecx
	cmp	ecx,16
	jb	@b
	jmp	.out
.next:
	lea	r13,[r12+1]
	cmp	byte [r12],0
	jne	.line
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi = a field and its spaces: rsi past them
.skip_field:
	cmp	byte [rsi],' '
	je	@f
	cmp	byte [rsi],10
	jbe	@f
	inc	rsi
	jmp	.skip_field
@@:
	cmp	byte [rsi],' '
	jne	@f
	inc	rsi
	jmp	@b
@@:
	ret
; rsi = two hex digits: al. CF: not hex
.hex_byte:
	push	rcx
	xor	eax,eax
	mov	ecx,2
.digit:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	jbe	@f
	sub	edx,'a' - '0' - 10
	cmp	edx,10
	jb	.bad
	cmp	edx,15
	ja	.bad
@@:
	shl	eax,4
	or	eax,edx
	inc	rsi
	dec	ecx
	jnz	.digit
	pop	rcx
	clc
	ret
.bad:
	pop	rcx
	stc
	ret
	cstring .path, '/proc/net/if_inet6',0

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
	xor	edi,edi				; the drop lists' keys gone, a pass's
	mov	esi,XC_STALE_N * 24
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal
	mov	[g_xc_stale],rax
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
	call	xc_filters
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

; the VIPs: those of the plan in, any other out (both families)
xc_vips:
	push	rbx
	push	r12
	mov	r12d,4
.family:
	; out: every key not in the plan (a reload may have dropped some)
	xor	ebx,ebx
.next_key:
	call	xc_vips_fd
	lea	rsi,[g_xc_vk]
	lea	rdx,[g_xc_vk2]
	test	ebx,ebx
	jnz	@f
	xor	esi,esi				; NULL: the first key
@@:
	call	xc_next_key
	test	eax,eax
	jnz	.in
	lea	rsi,[g_xc_vk2]
	lea	rdi,[g_xc_vk]
	mov	ecx,24
	rep	movsb
	inc	ebx
	call	xc_vip_planned
	jnc	.next_key
	call	xc_vips_fd			; (deleting is safe while walking)
	lea	rsi,[g_xc_vk]
	call	xc_delete
	jmp	.next_key
.in:
	cmp	r12d,6
	je	@f
	mov	r12d,6
	jmp	.family
@@:
	xor	ebx,ebx
.vip:
	cmp	ebx,[g_plan_nxvip]
	jae	.out
	xor	r9d,r9d				; its key, then its address's (ping)
.key:
	call	xc_vip_key			; (edi = its map)
	imul	rax,rbx,XV_SIZE
	mov	[g_xc_val+XVV_NUM],ebx
	mov	eax,[g_plan_xvips+rax+XV_FLAGS]
	mov	[g_xc_val+XVV_FLAGS],eax
	push	r9
	lea	rsi,[g_xc_vk]
	lea	rdx,[g_xc_val]
	xor	ecx,ecx
	call	eb_map_update
	pop	r9
	inc	r9d
	cmp	r9d,1
	je	.key
	inc	ebx
	jmp	.vip
.out:
	pop	r12
	pop	rbx
	ret

; r12d = 4 / 6: edi = that family's VIPS map
xc_vips_fd:
	mov	edi,[g_eb_mapfd+XL_VIPS4*4]
	cmp	r12d,6
	jne	@f
	mov	edi,[g_eb_mapfd+XL_VIPS6*4]
@@:
	ret

; ebx = a VIP of the plan: g_xc_vk = its key (the address, port big endian,
; protocol, 0: 8 bytes IPv4, 20 IPv6), edi = its family's map, edx = the
; key's length, r8d = its family. r9d = 1: its address's key instead (port
; 0, ICMP's protocol: the program answers echo requests to it). Keeps rbx,
; r9, r12.
xc_vip_key:
	imul	rax,rbx,XV_SIZE
	lea	rax,[g_plan_xvips+rax]
	lea	rdi,[g_xc_vk]
	xor	ecx,ecx
	mov	[rdi],rcx
	mov	[rdi+8],rcx
	mov	[rdi+16],rcx
	mov	r8d,[rax+XV_FAMILY]
	mov	edx,4				; the address's length
	cmp	r8d,6
	jne	@f
	mov	edx,16
@@:
	push	rsi
	lea	rsi,[rax+XV_ADDR]
	mov	ecx,edx
	rep	movsb				; rdi: past it
	pop	rsi
	mov	ecx,[rax+XV_PORT]
	xchg	cl,ch
	mov	[rdi],cx
	mov	ecx,[rax+XV_PROTO]
	mov	[rdi+2],cl
	test	r9d,r9d
	jz	@f
	mov	word [rdi],0
	mov	byte [rdi+2],1			; ICMP
	cmp	r8d,6
	jne	@f
	mov	byte [rdi+2],58			; ICMPv6
@@:
	add	edx,4
	mov	edi,[g_eb_mapfd+XL_VIPS4*4]
	cmp	r8d,6
	jne	@f
	mov	edi,[g_eb_mapfd+XL_VIPS6*4]
@@:
	ret

; g_xc_vk2 = a key in r12d's family's VIPS: CF when no VIP of the plan has it
xc_vip_planned:
	push	rbx
	sub	rsp,32
	lea	rsi,[g_xc_vk]			; (kept: the walk goes on from it)
	mov	rdi,rsp
	mov	ecx,24
	rep	movsb
	xor	ebx,ebx
.v:
	cmp	ebx,[g_plan_nxvip]
	jae	.no
	xor	r9d,r9d				; its key, its address's
.key:
	call	xc_vip_key
	cmp	r8d,r12d
	jne	.other
	lea	rsi,[g_xc_vk]
	lea	rdi,[g_xc_vk2]
	mov	ecx,edx
	repe	cmpsb
	je	.yes
	inc	r9d
	cmp	r9d,1
	je	.key
.other:
	inc	ebx
	jmp	.v
.yes:
	clc
	jmp	.back
.no:
	stc
.back:
	pushf
	lea	rsi,[rsp+8]
	lea	rdi,[g_xc_vk]
	mov	ecx,24
	rep	movsb
	popf
	add	rsp,32
	pop	rbx
	ret

; The pre-filter, as the plan has it: `drop`'s ranges into DROP4 / DROP6
; with a new generation, then CTL_FILTER and CTL_SYN, then the prefixes of
; the generation before taken out (a reload never leaves a moment with a
; source let through that both lists drop)
xc_filters:
	push	rbx
	push	r12
	; the generation: the last one's, plus one
	mov	dword [g_xc_k],CTL_GEN
	mov	edi,[g_eb_mapfd+XL_CTL*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_val]
	call	eb_map_lookup
	mov	eax,[g_xc_val]
	inc	eax
	mov	[g_xc_gen],eax
	xor	r12d,r12d			; FF_*
	mov	rbx,[g_plan_xdrop_head]
.block:
	test	rbx,rbx
	jz	.lists
	xor	ecx,ecx
.range:
	cmp	ecx,[rbx+XD_N]
	jae	.next_block
	push	rcx
	imul	rsi,rcx,TR_SIZE
	lea	rsi,[rbx+XD_E+rsi]
	call	xc_drop_put			; (eax = FF_DROP4 / FF_DROP6, 0 failed)
	or	r12d,eax
	pop	rcx
	inc	ecx
	jmp	.range
.next_block:
	mov	rbx,[rbx+XD_NEXT]
	jmp	.block
.lists:
	mov	rax,[g_plan_syn_ivl]
	test	rax,rax
	jz	.flags
	or	r12d,FF_SYN
	call	xc_val_clear
	mov	rax,[g_plan_syn_ivl]
	mov	qword [g_xc_val],rax
	mov	rax,[g_plan_syn_tau]
	mov	qword [g_xc_val+8],rax
	mov	dword [g_xc_k],CTL_SYN
	call	xdp_ctl_put
.flags:
	call	xc_val_clear
	mov	[g_xc_val],r12d
	mov	dword [g_xc_k],CTL_FILTER
	call	xdp_ctl_put
	call	xc_val_clear
	mov	eax,[g_xc_gen]
	mov	[g_xc_val],eax
	mov	dword [g_xc_k],CTL_GEN
	call	xdp_ctl_put
	mov	r8d,XL_DROP4
	call	xc_prune
	mov	r8d,XL_DROP6
	call	xc_prune
	pop	r12
	pop	rbx
	ret

xc_val_clear:
	mov	qword [g_xc_val],0
	mov	qword [g_xc_val+8],0
	mov	qword [g_xc_val+16],0
	ret

; rsi = a range (TR_*): into DROP4 / DROP6 as {prefix length, the address,
; its bits past the prefix 0}, with g_xc_gen. eax = its FF_DROP*, 0 failed.
xc_drop_put:
	push	rbx
	mov	ebx,[rsi+TR_BITS]
	mov	[g_xc_lkey],ebx
	xor	ecx,ecx
.byte:
	mov	al,[rsi+TR_IP+rcx]
	mov	edx,ecx
	shl	edx,3
	mov	r8d,ebx
	sub	r8d,edx				; its bits in this byte
	jle	.zero
	cmp	r8d,8
	jae	.whole
	push	rcx
	mov	ecx,8
	sub	ecx,r8d
	mov	dl,0xFF
	shl	dl,cl
	pop	rcx
	and	al,dl
	jmp	.whole
.zero:
	xor	eax,eax
.whole:
	mov	[g_xc_lkey+4+rcx],al
	inc	ecx
	cmp	ecx,16
	jb	.byte
	mov	ebx,FF_DROP4
	mov	edi,[g_eb_mapfd+XL_DROP4*4]
	cmp	dword [rsi+TR_KIND],6
	jne	@f
	mov	ebx,FF_DROP6
	mov	edi,[g_eb_mapfd+XL_DROP6*4]
@@:
	push	rdi
	call	xc_val_clear
	pop	rdi
	mov	eax,[g_xc_gen]
	mov	[g_xc_val],eax
	lea	rsi,[g_xc_lkey]
	lea	rdx,[g_xc_val]
	xor	ecx,ecx
	call	eb_map_update
	test	eax,eax
	mov	eax,ebx
	jns	@f
	xor	eax,eax
@@:
	pop	rbx
	ret

; r8d = an LPM map: its keys of another generation than g_xc_gen out
xc_prune:
	push	rbx
	push	r12
	push	r13
	mov	r13d,r8d
.pass:
	xor	ebx,ebx				; keys gone in this pass
	xor	r12d,r12d			; 0: from the first key
.next:
	mov	edi,[g_eb_mapfd+r13*4]
	lea	rsi,[g_xc_lkey]
	lea	rdx,[g_xc_lkey2]
	test	r12d,r12d
	jnz	@f
	xor	esi,esi
@@:
	call	xc_next_key
	test	eax,eax
	jnz	.delete
	mov	r12d,1
	mov	rax,qword [g_xc_lkey2]
	mov	qword [g_xc_lkey],rax
	mov	rax,qword [g_xc_lkey2+8]
	mov	qword [g_xc_lkey+8],rax
	mov	rax,qword [g_xc_lkey2+16]
	mov	qword [g_xc_lkey+16],rax
	mov	edi,[g_eb_mapfd+r13*4]
	lea	rsi,[g_xc_lkey]
	lea	rdx,[g_xc_val]
	call	eb_map_lookup
	test	eax,eax
	js	.next
	mov	eax,[g_xc_val]
	cmp	eax,[g_xc_gen]
	je	.next
	imul	rdi,rbx,24			; (deleted after the walk: an LPM
	add	rdi,[g_xc_stale]		; trie's walk starts over from a key
	lea	rsi,[g_xc_lkey]			; that is gone)
	mov	ecx,24
	rep	movsb
	inc	ebx
	cmp	ebx,XC_STALE_N
	jb	.next
.delete:
	xor	r12d,r12d
.del:
	cmp	r12d,ebx
	jae	.deleted
	imul	rsi,r12,24
	add	rsi,[g_xc_stale]
	mov	edi,[g_eb_mapfd+r13*4]
	call	xc_delete
	inc	r12d
	jmp	.del
.deleted:
	cmp	ebx,XC_STALE_N			; a full pass: more may be left
	je	.pass
	pop	r13
	pop	r12
	pop	rbx
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
	; the reals: an address and its family while up, nothing down
	xor	ebx,ebx
.real:
	cmp	ebx,[g_plan_servers]
	jae	.rings
	lea	rdi,[g_xc_val]
	xor	eax,eax
	mov	ecx,3
	rep	stosq
	call	xc_up
	test	al,al
	jz	.put_real
	imul	rax,rbx,SV_SIZE
	lea	rax,[g_servers+rax+SV_SA]
	cmp	word [rax],AF_INET
	jne	@f
	mov	ecx,[rax+4]			; sockaddr_in
	mov	[g_xc_val+XR_ADDR],ecx
	mov	dword [g_xc_val+XR_FAMILY],4
	jmp	.put_real
@@:
	cmp	word [rax],AF_INET6
	jne	.put_real
	mov	rcx,[rax+8]			; sockaddr_in6
	mov	[g_xc_val+XR_ADDR],rcx
	mov	rcx,[rax+16]
	mov	[g_xc_val+XR_ADDR+8],rcx
	mov	dword [g_xc_val+XR_FAMILY],6
.put_real:
	lea	eax,[rbx+1]
	mov	[g_xc_k],eax
	mov	edi,[g_eb_mapfd+XL_REALS*4]
	lea	rsi,[g_xc_k]
	lea	rdx,[g_xc_val]
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
