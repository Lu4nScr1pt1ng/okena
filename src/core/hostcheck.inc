; `okena check --host [FILE]`: what of the host would hold okena back, each
; line `ok` or `warn` with what to do. With FILE, measured against what it
; asks for (its connections, its ports, kTLS, UDP). Exit 1 when anything
; warns, so that a deploy script can stop on it.

bss
	g_hc_warns	dd ?
	g_hc_conns	dq ?		; the configuration's connections, all listeners
	g_hc_cfg	dd ?		; a configuration was given
	g_hc_udp	dd ?		; it has udp or http3 listeners
	g_hc_ktls	dd ?		; and kTLS is needed (ktls on, tls on tcp)
end bss

cstring hc_ct_count, '/proc/sys/net/netfilter/nf_conntrack_count',0
cstring hc_ct_max, '/proc/sys/net/netfilter/nf_conntrack_max',0
cstring hc_somaxconn, '/proc/sys/net/core/somaxconn',0
cstring hc_synback, '/proc/sys/net/ipv4/tcp_max_syn_backlog',0
cstring hc_ports, '/proc/sys/net/ipv4/ip_local_port_range',0
cstring hc_rmem, '/proc/sys/net/core/rmem_max',0
cstring hc_uring, '/proc/sys/kernel/io_uring_disabled',0
cstring hc_tls_mod, '/sys/module/tls',0

; rdi = a /proc file: rax = its first number, rdx = its second (0 none). CF
; when it cannot be read.
hc_nums:
	sub	rsp,136
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.none
	push	rax
	mov	edi,eax
	lea	rsi,[rsp+8]
	mov	edx,127
	xor	eax,eax				; SYS_read
	syscall
	mov	r8,rax
	pop	rdi
	push	r8
	mov	eax,SYS_close
	syscall
	pop	r8
	test	r8,r8
	jle	.none
	lea	rsi,[rsp]
	lea	r9,[rsp+r8]
	call	.number
	push	rax
	call	.number
	mov	rdx,rax
	pop	rax
	add	rsp,136
	clc
	ret
.none:
	add	rsp,136
	stc
	ret
; rsi .. r9: the next number (skipping what is not a digit), rax; 0 none
.number:
	xor	eax,eax
@@:
	cmp	rsi,r9
	jae	.got
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	jbe	@f
	inc	rsi
	jmp	@b
@@:
	cmp	rsi,r9
	jae	.got
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.got
	imul	rax,rax,10
	add	rax,rcx
	inc	rsi
	jmp	@b
.got:
	ret

hc_ok:
	mov	edi,1
	call	out_select
	out_lit 'ok    '
	ret

hc_warn:
	inc	dword [g_hc_warns]
	mov	edi,1
	call	out_select
	out_lit 'warn  '
	ret

hc_end:
	mov	edi,10
	jmp	out_char

; the configuration's TCP ports, for the NOTRACK rule: "80, 443"
hc_ports_list:
	push	rbx
	push	r12
	xor	ebx,ebx
	xor	r12d,r12d			; how many said
.l:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	je	.next
	test	r12d,r12d
	jz	@f
	out_lit ', '
	imul	rax,rbx,LS_SIZE
@@:
	mov	eax,[g_listeners+rax+LS_PORT]
	call	out_u64
	inc	r12d
.next:
	inc	ebx
	jmp	.l
.done:
	test	r12d,r12d
	jnz	@f
	out_lit '80, 443'
@@:
	pop	r12
	pop	rbx
	ret

cli_check_host:
	cmp	qword [g_argc],3
	jbe	.host
	mov	edi,3				; a configuration: what it needs
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	mov	dword [g_hc_cfg],1
	xor	ecx,ecx
.ls:
	cmp	ecx,[g_plan_listeners]
	jae	.host
	imul	rax,rcx,LS_SIZE
	mov	edx,[g_listeners+rax+LS_MAXCONN]
	add	[g_hc_conns],rdx
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	@f
	mov	dword [g_hc_udp],1
@@:
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3
	jz	@f
	mov	dword [g_hc_udp],1
@@:
	test	dword [g_listeners+rax+LS_FLAGS],LSF_KTLS
	jnz	.k
	cmp	dword [g_listeners+rax+LS_KIND],LK_TCP
	jne	@f
	cmp	dword [g_listeners+rax+LS_TLS],0
	je	@f
.k:
	mov	dword [g_hc_ktls],1
@@:
	inc	ecx
	jmp	.ls
.host:
	call	hc_conntrack
	call	hc_backlog
	call	hc_portrange
	call	hc_nofile
	call	hc_udpbuf
	call	hc_ktls
	call	hc_iouring
	mov	edi,1
	call	out_select
	xor	edi,edi
	cmp	dword [g_hc_warns],0
	je	@f
	mov	edi,1
@@:
	jmp	exit_process

; conntrack: a full table drops new connections, whatever okena does
hc_conntrack:
	lea	rdi,[hc_ct_max]
	call	hc_nums
	jc	.none
	push	rax
	lea	rdi,[hc_ct_count]
	call	hc_nums
	pop	rcx				; max
	jc	.none
	; full past 3/4, or smaller than twice what okena may hold (a client's
	; connection and a backend's)
	mov	r8,rax
	imul	r9,rax,4
	imul	r10,rcx,3
	cmp	r9,r10
	jae	.warn
	mov	rdx,[g_hc_conns]
	add	rdx,rdx
	cmp	rdx,rcx
	ja	.warn
	test	r8,r8
	jnz	.tracked
	push	rcx
	push	r8
	call	hc_ok
	out_lit 'conntrack: '
	pop	rax
	call	out_u64
	out_lit ' of '
	pop	rax
	call	out_u64
	out_lit ' entries in use'
	jmp	hc_end
.tracked:
	; entries in this namespace: a stateful firewall (firewalld, iptables or
	; nft rules with `ct`, Docker's NAT) runs on every packet okena sends and
	; receives. Measured on loopback, HTTP/1.1 through okena on two workers,
	; this host's firewalld: 160k requests a second, 232k in a namespace
	; without rules (nft chains, interface name matches, conntrack: a quarter
	; of the workers' CPU). Room in the table is not the cost; the rules are.
	push	rcx
	push	r8
	call	hc_warn
	out_lit 'packet filter: conntrack holds '
	pop	rax
	call	out_u64
	out_lit ' of '
	pop	rax
	call	out_u64
	out_lit ' entries, so a stateful firewall runs on every packet of okena',27h,'s traffic (measured with firewalld on loopback: a third fewer requests a second than without rules). On a host that only balances, keep the rules for its ports few and stateless (`notrack` in a raw chain for tcp dport { '
	call	hc_ports_list
	out_lit ' } and the same for output, tcp sport), or filter in front of it'
	jmp	hc_end
.warn:
	push	rcx
	push	r8
	call	hc_warn
	out_lit 'conntrack: '
	pop	rax
	call	out_u64
	out_lit ' of '
	pop	rax
	call	out_u64
	out_lit ' entries in use'
	cmp	dword [g_hc_cfg],0
	je	@f
	out_lit ' (the configuration may hold '
	mov	rax,[g_hc_conns]
	add	rax,rax
	call	out_u64
	out_lit ')'
@@:
	out_lit '; a full table drops new connections. Leave okena',27h,'s ports out of it: nft add table inet raw; nft add chain inet raw pre { type filter hook prerouting priority raw \; }; nft add rule inet raw pre tcp dport { '
	call	hc_ports_list
	out_lit ' } notrack (and the same for output, tcp sport), or raise net.netfilter.nf_conntrack_max'
	jmp	hc_end
.none:
	call	hc_ok
	out_lit 'conntrack: not loaded, no table to fill'
	jmp	hc_end

; the kernel caps a listen backlog at somaxconn
hc_backlog:
	lea	rdi,[hc_somaxconn]
	call	hc_nums
	jc	.syn
	cmp	rax,LISTEN_BACKLOG
	jae	.ok
	push	rax
	call	hc_warn
	out_lit 'net.core.somaxconn is '
	pop	rax
	call	out_u64
	out_lit ': connections waiting for accept past it are dropped in a burst (okena asks for '
	mov	eax,LISTEN_BACKLOG
	call	out_u64
	out_lit '); sysctl -w net.core.somaxconn='
	mov	eax,LISTEN_BACKLOG
	call	out_u64
	call	hc_end
	jmp	.syn
.ok:
	push	rax
	call	hc_ok
	out_lit 'net.core.somaxconn '
	pop	rax
	call	out_u64
	call	hc_end
.syn:
	lea	rdi,[hc_synback]
	call	hc_nums
	jc	.out
	cmp	rax,LISTEN_BACKLOG
	jae	.synok
	push	rax
	call	hc_warn
	out_lit 'net.ipv4.tcp_max_syn_backlog is '
	pop	rax
	call	out_u64
	out_lit ': a SYN flood fills it sooner (syncookies take over); sysctl -w net.ipv4.tcp_max_syn_backlog='
	mov	eax,LISTEN_BACKLOG
	call	out_u64
	jmp	hc_end
.synok:
	push	rax
	call	hc_ok
	out_lit 'net.ipv4.tcp_max_syn_backlog '
	pop	rax
	call	out_u64
	jmp	hc_end
.out:
	ret

; ports for connections to backends, per destination
hc_portrange:
	lea	rdi,[hc_ports]
	call	hc_nums
	jc	.out
	push	rax
	push	rdx
	sub	rdx,rax
	inc	rdx
	cmp	rdx,20000
	jb	.warn
	call	hc_ok
	jmp	.say
.warn:
	call	hc_warn
.say:
	out_lit 'net.ipv4.ip_local_port_range '
	mov	rax,[rsp+8]
	call	out_u64
	out_lit '-'
	mov	rax,[rsp]
	call	out_u64
	out_lit ': '
	pop	rax
	pop	rcx
	sub	rax,rcx
	inc	rax
	push	rax
	call	out_u64
	out_lit ' ports to each backend address'
	pop	rax
	cmp	rax,20000
	jae	hc_end
	out_lit '; few for a busy proxy: sysctl -w net.ipv4.ip_local_port_range="1024 65535", or a pool',27h,'s `source` with more addresses'
	jmp	hc_end
.out:
	ret

; descriptors: a client's and a backend's for each connection
hc_nofile:
	sub	rsp,24
	xor	edi,edi
	mov	esi,RLIMIT_NOFILE
	xor	edx,edx
	mov	r10,rsp
	mov	eax,SYS_prlimit64
	syscall
	mov	rax,[rsp+8]			; the hard limit: okena takes it all
	add	rsp,24
	push	rax
	mov	rcx,[g_hc_conns]
	add	rcx,rcx
	add	rcx,1024
	cmp	dword [g_hc_cfg],0
	je	.ok
	cmp	rax,rcx
	jb	.warn
.ok:
	call	hc_ok
	out_lit 'open files: '
	pop	rax
	call	out_u64
	out_lit ' (the hard limit, which okena raises itself to)'
	jmp	hc_end
.warn:
	call	hc_warn
	out_lit 'open files: '
	pop	rax
	call	out_u64
	out_lit ', under the '
	mov	rax,[g_hc_conns]
	add	rax,rax
	call	out_u64
	out_lit ' the configuration may hold (a client',27h,'s and a backend',27h,'s each); LimitNOFILE= in its unit, or `ulimit -Hn`'
	jmp	hc_end

; UDP: a burst past the socket buffer is lost
hc_udpbuf:
	cmp	dword [g_hc_udp],0
	je	.out
	lea	rdi,[hc_rmem]
	call	hc_nums
	jc	.out
	cmp	rax,4 shl 20
	jae	.ok
	push	rax
	call	hc_warn
	out_lit 'net.core.rmem_max is '
	pop	rax
	call	out_u64
	out_lit ': udp and HTTP/3 listeners lose bursts past it unless okena has CAP_NET_ADMIN (SO_RCVBUFFORCE); sysctl -w net.core.rmem_max=8388608'
	jmp	hc_end
.ok:
	push	rax
	call	hc_ok
	out_lit 'net.core.rmem_max '
	pop	rax
	call	out_u64
	jmp	hc_end
.out:
	ret

; kTLS: the kernel's tls module
hc_ktls:
	mov	edi,AT_FDCWD
	lea	rsi,[hc_tls_mod]
	mov	edx,O_RDONLY or O_DIRECTORY_ or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.none
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	call	hc_ok
	out_lit 'kTLS: the tls module is loaded'
	jmp	hc_end
.none:
	cmp	dword [g_hc_ktls],0
	jne	.warn
	call	hc_ok
	out_lit 'kTLS: the tls module is not loaded (okena seals the records itself; `modprobe tls` for `ktls on`)'
	jmp	hc_end
.warn:
	call	hc_warn
	out_lit 'kTLS: the tls module is not loaded, and the configuration needs it (`ktls on`, or tls on a tcp listener); modprobe tls, and tls in /etc/modules-load.d'
	jmp	hc_end

; io_uring: disabled by sysctl, okena runs on epoll
hc_iouring:
	lea	rdi,[hc_uring]
	call	hc_nums
	jc	.ok
	test	rax,rax
	jz	.ok
	push	rax
	call	hc_ok
	out_lit 'io_uring: kernel.io_uring_disabled is '
	pop	rax
	call	out_u64
	out_lit ', okena runs on epoll (about as fast for most traffic); 0 lets it use io_uring'
	jmp	hc_end
.ok:
	call	hc_ok
	out_lit 'io_uring: available'
	jmp	hc_end
