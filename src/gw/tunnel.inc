; Forward proxy: `tunnel [ports=443,8443] [private=on]` on a route lets
; HTTP/1.1 CONNECT requests open a TCP tunnel to the host and port they name.
;
; A CONNECT is routed as a request for "/" on its target's host (its Host
; must be that target), so host blocks are the list of destinations a client
; may reach, and the route's allow/deny, auth, limits and logs apply as to any
; request. Its port must be one of `ports=` (443 by default). Its name is
; looked up by okena-resolve (/etc/hosts, then the servers of resolv.conf: the
; blocking resolver of net/resolve.inc, in a process of its own); the request
; is held 2 ms at a time until the answer is in a table shared with it (kept
; for the name's TTL, a failure 10 s), 5 s at most. Addresses that are the
; host's own or nobody's (loopback, link-local such as cloud metadata at
; 169.254.169.254, unspecified, multicast) are always refused, private ones
; (RFC 1918, ULA, CGNAT) unless `private=on`: a name cannot be pointed at
; them to reach inside.
;
; The connection: the address goes into one of TUN_SLOTS server slots of a
; hidden pool, "(tunnel)", which the connect is forced to (slots are never
; picked by the balancer: not active); once connected the client gets "200
; Connection established" and the session is the tunnel WebSocket upgrades
; use (bytes either side sent early go first, then the L4 relay).

TNL_NP		:= 0				; d: ports listed (0: 443 only)
TNL_PRIV		:= 4				; d: private=on
TNL_PORTS	:= 8				; 16 words
TNL_SIZE		:= 48
TNL_MAXP		:= 16
MAX_TUNS	:= 1024
TUN_SLOTS	:= 64				; connects under way at once, per worker
TUN_TEXT	:= 264				; a slot's "host:port", for logs

; the table shared with okena-resolve (as bcrypt.inc's)
TRS_LOCK		:= 0
TRS_HEAD		:= 4
TRS_TAIL		:= 8
TRS_WAKE		:= 12
TRS_GEN		:= 16
TRS_RING		:= 64
TRS_RN		:= 256
TRQ_LEN		:= 0				; d
TRQ_GEN		:= 4				; d
TRQ_KEY		:= 8				; 32
TRQ_NAME		:= 40				; 256
TRQ_SIZE		:= 296
TRS_CACHE	:= TRS_RING + TRS_RN * TRQ_SIZE
TRS_N		:= 4096
TRS_PROBE	:= 16
TRE_KEY		:= 0				; 32
TRE_STATE	:= 32				; d: TS_*
TRE_T		:= 36				; d: seconds (monotonic) it was asked or answered
TRE_TTL		:= 40				; d: seconds an answer holds
TRE_GEN		:= 44				; d
TRE_N		:= 48				; d: addresses
TRE_FAM		:= 52				; 8 bytes: 4 or 6
TRE_ADDR		:= 64				; 8 * 16
TRE_SIZE		:= 192
TRS_SIZE		:= TRS_CACHE + TRS_N * TRE_SIZE
TRST_OK		:= 1
TRST_BAD		:= 2
TRST_ASKED	:= 3
TRS_BAD_S	:= 10
TRS_ASK_S	:= 5
TRS_HOLD_US	:= 2000
TRS_WAIT_MS	:= 5000
TUS_GEN		:= 0				; d: the session's generation then
TUS_SLOT		:= 4				; d: its slot + 1 while connecting, 0 none
TUS_SIZE		:= 8

bss
	align 8
	g_tr_shm	dq ?			; the shared table, 0 none
	g_tr_gen	dd ?
	g_tr_pid	dd ?
	g_tun_base	dq ?			; a worker's: per session (TUS_*)
	g_tun_auth	dq ?			; this pass: the CONNECT's target
	g_tun_alen	dd ?
	g_hm_conn	dd ?			; this pass's request is a CONNECT
	g_tun_ent	dq ?			; tun_request: the route's tunnel
	g_tun_key:	rb 32
	g_tun_ad:	rb AD_SIZE
	g_tun_name:	rb 256
	g_tunq:		rb TRQ_SIZE		; okena-resolve: the question it answers
	align 8
	g_tun_busy	rq TUN_SLOTS		; ms until a slot is free again, 0 free
	g_tun_text	rb TUN_SLOTS * TUN_TEXT
end bss

rodata
	tun_name	db '(tunnel)'
	tun_slot_txt	db 'tunnel'
	tr_name		db 'okena-resolve',0
	align 8
	ts_tr_wait	dq 1, 0
	tun_200		db 'HTTP/1.1 200 Connection established',13,10,13,10
	tun_200.len	= $ - tun_200
end rodata

macro tr_lock
	local spin, got
spin:
	mov	eax,1
	xchg	eax,[r10+TRS_LOCK]
	test	eax,eax
	jz	got
	pause
	jmp	spin
got:
end macro

; ------------------------------------------------------------ compiling

; r12 = a route node, r13 = its action: `tunnel`, into RA_TUN; the first one
; makes the hidden pool. Keeps rbx, r12-r15.
tun_compile:
	mov	rdi,r12
	mov	ecx,DIR_TUNNEL
	call	find_child
	test	rax,rax
	jz	.out
	push	rbx
	push	r14
	mov	rbx,rax
	mov	ecx,[g_plan_tuns]
	cmp	ecx,MAX_TUNS
	jae	plan_bad_tunnel
	inc	dword [g_plan_tuns]
	lea	eax,[rcx+1]
	mov	[r13+RA_TUN],eax
	imul	r14,rcx,TNL_SIZE
	lea	r14,[g_tuns+r14]
	; ports=443,8443
	mov	rdi,rbx
	lea	rsi,[str_key_ports]
	call	node_option
	test	rax,rax
	jz	.private
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	lea	rdx,[rsi+rcx]			; the end
.port:
	cmp	rsi,rdx
	jae	.private
	xor	eax,eax
	xor	r8d,r8d				; digits
.digit:
	cmp	rsi,rdx
	jae	.port_end
	movzx	ecx,byte [rsi]
	cmp	cl,','
	je	.port_end
	sub	ecx,'0'
	cmp	ecx,9
	ja	plan_bad_tunnel
	imul	eax,eax,10
	add	eax,ecx
	cmp	eax,65535
	ja	plan_bad_tunnel
	inc	rsi
	inc	r8d
	jmp	.digit
.port_end:
	test	r8d,r8d
	jz	plan_bad_tunnel
	test	eax,eax
	jz	plan_bad_tunnel
	mov	ecx,[r14+TNL_NP]
	cmp	ecx,TNL_MAXP
	jae	plan_bad_tunnel
	mov	[r14+TNL_PORTS+rcx*2],ax
	inc	dword [r14+TNL_NP]
	inc	rsi				; (past the comma)
	jmp	.port
.private:
	mov	rdi,rbx
	lea	rsi,[str_key_private]
	call	node_option
	test	rax,rax
	jz	.pool
	mov	rax,[rax+A_VAL]
	cmp	word [rax],'on'
	jne	.pool
	mov	dword [r14+TNL_PRIV],1
.pool:
	cmp	dword [g_plan_tunpool],0
	jne	.done
	; the hidden pool and its slots
	lea	rdi,[tun_name]
	mov	esi,8
	call	pool_new
	mov	r14,rax
	lea	rcx,[g_pools]
	sub	rax,rcx
	xor	edx,edx
	mov	ecx,PL_SIZE
	div	rcx
	inc	eax
	mov	[g_plan_tunpool],eax
	mov	edx,TUN_SLOTS
.slot:
	mov	ecx,[g_plan_servers]
	too_many	ecx,MAX_SERVERS,str_tm_max_servers
	inc	dword [g_plan_servers]
	inc	dword [r14+PL_COUNT]
	imul	rax,rcx,SV_SIZE
	lea	rax,[g_servers+rax]
	mov	dword [rax+SV_WEIGHT],1
	mov	dword [rax+SV_ACTIVE],0		; (never the balancer's: forced only)
	mov	dword [rax+SV_FAMILY],AF_INET
	lea	rcx,[tun_slot_txt]
	mov	[rax+SV_TEXT],rcx
	mov	dword [rax+SV_TLEN],6
	dec	edx
	jnz	.slot
	inc	dword [r14+PL_PRIMARY]
.done:
	pop	r14
	pop	rbx
.out:
	ret

plan_bad_tunnel:
	call	log_begin
	out_lit 'tunnel: ports= is a list of up to 16 ports (443,8443), private= is on or off; at most 1024 tunnel routes'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_ports, 'ports',0
cstring str_proxy_authorization, 'proxy-authorization'
cstring str_key_private, 'private',0

; ------------------------------------------------------------ the supervisor

; before the workers fork: the table shared with okena-resolve
tr_init:
	cmp	dword [g_plan_tunpool],0
	je	.out
	cmp	qword [g_tr_shm],0
	jne	.gen
	xor	edi,edi
	mov	esi,TRS_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_tr_shm],rax
.gen:
	inc	dword [g_tr_gen]
	mov	rax,[g_tr_shm]
	mov	ecx,[g_tr_gen]
	mov	[rax+TRS_GEN],ecx
.out:
	ret

spawn_resolve:
	cmp	dword [g_plan_tunpool],0
	je	.none
	cmp	qword [g_tr_shm],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	resolve_main
	js	.none
	mov	[g_tr_pid],eax
.none:
	ret

; a reload: okena-resolve again, with the new plan (what was asked before
; is not believed by the new generation)
tr_reload:
	mov	edi,[g_tr_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_tr_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	tr_init
	jmp	spawn_resolve

; ------------------------------------------------------------ the workers

tun_worker_init:
	cmp	dword [g_plan_tunpool],0
	je	.none
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,3				; TUS_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none
	mov	[g_tun_base],rax
.none:
	xor	eax,eax
	ret

; After parsing (g_hm): a CONNECT is noted (g_hm_conn), its target kept and
; "/" routed in its place. CF: refused (edi = the status). Keeps rbx,
; r12-r15.
tun_parsed:
	mov	dword [g_hm_conn],0
	cmp	dword [g_hm+HM_MLEN],7
	jne	.no
	mov	rax,[g_hm+HM_METHOD]
	cmp	dword [rax],'CONN'
	jne	.no
	cmp	dword [rax+3],'NECT'
	jne	.no
	mov	edi,405
	cmp	dword [g_plan_tunpool],0
	je	.refused			; no tunnels here at all
	cmp	qword [g_tun_base],0
	je	.refused
	mov	edi,400
	cmp	qword [g_hm+HM_LENGTH],0	; (a body: a tunnel has none)
	jg	.refused
	test	dword [g_hm+HM_FLAGS],HMF_CHUNKED
	jnz	.refused
	mov	rax,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	cmp	byte [rax],'/'
	je	.refused
	cmp	ecx,255 + 6
	ja	.refused
	mov	[g_tun_auth],rax
	mov	[g_tun_alen],ecx
	; its Host: that target, or none
	push	rax
	push	rcx
	lea	rdi,[.host]
	mov	esi,4
	call	limit_find
	mov	rdi,rsi
	mov	edx,ecx
	pop	rcx
	pop	rsi
	test	edx,edx
	jz	.hosted
	cmp	edx,ecx
	je	.same_len
	; the target without its port, as some clients write Host
	jae	.bad_host
	cmp	byte [rsi+rdx],':'
	jne	.bad_host
.same_len:
	push	rsi
	push	rcx
	call	mem_eq_nocase			; (rdi, rsi, edx)
	pop	rcx
	pop	rsi
	test	eax,eax
	jz	.bad_host
.hosted:
	lea	rax,[.slash]
	mov	[g_hm+HM_TARGET],rax
	mov	dword [g_hm+HM_TLEN],1
	mov	dword [g_hm+HM_PLEN],1
	mov	dword [g_hm_conn],1
.no:
	clc
	ret
.bad_host:
	mov	edi,400
.refused:
	stc
	ret
.host	db 'host'
.slash	db '/'

; ebx = session, r15 = record, rdx = its action's offset in g_acts: the
; CONNECT's tunnel, or a refusal. Returns only to wait (held for its name).
tun_request:
	mov	eax,[g_acts+rdx+RA_TUN]
	dec	eax
	imul	rax,rax,TNL_SIZE
	lea	rax,[g_tuns+rax]
	mov	[g_tun_ent],rax
	; host:port, [v6]:port
	mov	rdi,[g_tun_auth]
	mov	esi,[g_tun_alen]
	lea	rdx,[g_tun_ad]
	mov	ecx,1
	call	parse_address
	mov	edi,400
	jc	http_error
	mov	eax,[g_tun_ad+AD_KIND]
	cmp	eax,ADDR_UNIX
	je	http_error
	; its port, one listed (443 by default)
	mov	eax,[g_tun_ad+AD_PORT]
	mov	rcx,[g_tun_ent]
	mov	edx,[rcx+TNL_NP]
	test	edx,edx
	jnz	.ports
	cmp	eax,443
	je	.port_ok
	jmp	.forbidden
.ports:
	dec	edx
	movzx	r8d,word [rcx+TNL_PORTS+rdx*2]
	cmp	eax,r8d
	je	.port_ok
	test	edx,edx
	jnz	.ports
.forbidden:
	refused REF_FORBID
	mov	edi,403
	jmp	http_error
.port_ok:
	cmp	dword [g_tun_ad+AD_KIND],ADDR_NAME
	jne	.address
	call	tun_resolve			; eax: 1 an answer (g_tun_ad), 2 held, 3 no such name, 4 none to be had
	cmp	eax,2
	jne	@f
	ret
@@:
	cmp	eax,1
	je	.address
	mov	edi,502
	cmp	eax,3
	je	http_error
	mov	edi,504
	jmp	http_error
.address:
	call	tun_address_ok
	jc	.forbidden
	; a slot, the address in it
	call	tun_slot
	cmp	eax,NIL
	jne	@f
	mov	edi,503
	jmp	http_error
@@:
	push	rax
	imul	rdi,rax,SV_SIZE
	lea	rdi,[g_servers+rdi]
	push	rdi
	add	rdi,SV_SA
	lea	rsi,[g_tun_ad]
	call	sockaddr_build
	pop	rdi
	mov	[rdi+SV_SALEN],eax
	mov	[rdi+SV_FAMILY],edx
	; its text: the target, for the logs
	mov	eax,[g_plan_tunpool]
	dec	eax
	imul	rax,rax,PL_SIZE
	mov	ecx,[rsp]
	sub	ecx,[g_pools+rax+PL_FIRST]
	imul	rcx,rcx,TUN_TEXT
	lea	r8,[g_tun_text+rcx]
	mov	[rdi+SV_TEXT],r8
	mov	ecx,[g_tun_alen]
	cmp	ecx,TUN_TEXT
	jbe	@f
	mov	ecx,TUN_TEXT
@@:
	mov	[rdi+SV_TLEN],ecx
	push	rdi
	mov	rdi,r8
	mov	rsi,[g_tun_auth]
	rep	movsb
	pop	rdi
	pop	rax				; the server
	; this session connects to it, and only to it
	mov	rcx,[g_tun_base]
	mov	edx,ebx
	lea	rcx,[rcx+rdx*8]
	push	rax
	call	session_ptr
	mov	edx,[rax+S_GEN]
	mov	[rcx+TUS_GEN],edx
	mov	edx,[rsp]
	mov	r8d,[g_plan_tunpool]
	dec	r8d
	imul	r8,r8,PL_SIZE
	sub	edx,[g_pools+r8+PL_FIRST]
	inc	edx
	mov	[rcx+TUS_SLOT],edx
	mov	edx,[g_plan_tunpool]
	dec	edx
	mov	[rax+S_POOL],edx
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	pop	rax
	mov	[g_force_server],eax
	call	tun_held_done
	h_rec
	mov	dword [r15+H_STATUS],200
	or	dword [r15+H_FLAGS],HX_NOPOOL
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect

; g_tun_ad: CF when its address may not be reached (the host's own,
; nobody's, or a private one the tunnel does not allow). Keeps rbx, r12-r15.
tun_address_ok:
	mov	rcx,[g_tun_ent]
	mov	r9d,[rcx+TNL_PRIV]
	cmp	dword [g_tun_ad+AD_KIND],ADDR_V4
	jne	.v6
	mov	eax,dword [g_tun_ad+AD_IP]
	bswap	eax
.v4:
	mov	edx,eax
	shr	edx,24
	test	edx,edx
	jz	.no				; 0/8
	cmp	edx,127
	je	.no				; loopback
	cmp	edx,224
	jae	.no				; multicast, reserved, broadcast
	mov	edx,eax
	shr	edx,16
	cmp	edx,0xA9FE
	je	.no				; 169.254/16: link-local, cloud metadata
	test	r9d,r9d
	jnz	.yes
	mov	edx,eax
	shr	edx,24
	cmp	edx,10
	je	.no				; 10/8
	mov	edx,eax
	shr	edx,20
	cmp	edx,0xAC1
	je	.no				; 172.16/12
	mov	edx,eax
	shr	edx,16
	cmp	edx,0xC0A8
	je	.no				; 192.168/16
	mov	edx,eax
	shr	edx,22
	cmp	edx,(100 shl 2) or 1
	je	.no				; 100.64/10
.yes:
	clc
	ret
.no:
	stc
	ret
.v6:
	mov	rax,qword [g_tun_ad+AD_IP]
	mov	rdx,qword [g_tun_ad+AD_IP+8]
	mov	r8,rax
	or	r8,rdx
	jz	.no				; ::
	test	rax,rax
	jnz	.not_low
	mov	r8,0x0100000000000000		; ::1 (network order: the last byte)
	cmp	rdx,r8
	je	.no
	mov	r8d,edx				; ::ffff:a.b.c.d: as IPv4
	cmp	r8d,0xFFFF0000
	jne	.not_low
	mov	rax,rdx
	shr	rax,32
	mov	eax,eax
	bswap	eax
	jmp	.v4
.not_low:
	movzx	edx,byte [g_tun_ad+AD_IP]
	cmp	edx,0xFF
	je	.no				; multicast
	movzx	r8d,byte [g_tun_ad+AD_IP+1]
	cmp	edx,0xFE
	jne	@f
	and	r8d,0xC0
	cmp	r8d,0x80
	je	.no				; fe80::/10
@@:
	test	r9d,r9d
	jnz	.yes
	and	edx,0xFE
	cmp	edx,0xFC
	je	.no				; fc00::/7
	clc
	ret

; eax = a free slot's server (reserved for the connect's time), NIL none.
; Keeps rbx, r12-r15.
tun_slot:
	mov	rax,[g_now_ms]
	xor	ecx,ecx
.s:
	cmp	ecx,TUN_SLOTS
	jae	.none
	cmp	[g_tun_busy+rcx*8],rax
	jb	.take
	inc	ecx
	jmp	.s
.take:
	mov	edx,[g_plan_tunpool]
	dec	edx
	imul	rdx,rdx,PL_SIZE
	mov	r8d,[g_pools+rdx+PL_TIMEOUT]	; its connect time, and a margin
	imul	r8,r8,1000
	add	r8,2000
	add	r8,rax
	mov	[g_tun_busy+rcx*8],r8
	mov	eax,[g_pools+rdx+PL_FIRST]
	add	eax,ecx
	ret
.none:
	mov	eax,NIL
	ret

; ebx = session: the slot its connect held, given back (connected or failed).
; CF when it was a tunnel's. Keeps all but rax, rcx, rdx, flags.
tun_release:
	mov	rax,[g_tun_base]
	test	rax,rax
	jz	.no
	mov	ecx,ebx
	lea	rcx,[rax+rcx*8]
	mov	edx,[rcx+TUS_SLOT]
	test	edx,edx
	jz	.no
	mov	dword [rcx+TUS_SLOT],0
	push	rcx
	call	session_ptr
	pop	rcx
	mov	eax,[rax+S_GEN]
	cmp	eax,[rcx+TUS_GEN]
	jne	.no				; another connection's, long gone
	dec	edx
	mov	qword [g_tun_busy+rdx*8],0
	stc
	ret
.no:
	clc
	ret

; ebx = session, connected: a tunnel's? Then the client hears 200 and the
; session becomes the tunnel (http_tunnel_up). Returns when it is not one.
tun_connected:
	call	tun_release
	jc	@f
	ret
@@:
	add	rsp,8				; (does not return)
	h_rec
	cmp	dword [r15+H_RIDLEN],0		; (its id, for the log)
	jne	@f
	call	rid_new
@@:
	mov	eax,[r15+H_UPOFF]
	mov	[r15+H_UPLEN],eax		; (nothing came from the target yet)
	mov	dword [r15+H_STATE],HS_TUNNEL_UP
	or	dword [r15+H_FLAGS],HX_STARTED
	lea	rdi,[tun_200]
	mov	esi,tun_200.len
	mov	ecx,SIDE_CLIENT
	jmp	h_send

; r15: a held exchange is decided: what holding marked, undone
tun_held_done:
	mov	rax,[r15+H_BUF]
	mov	ecx,dword [r15+H_LT0]
	cmp	[rax+HB_FGEN],ecx
	jne	.out
	mov	dword [rax+HB_FGEN],0
	and	dword [r15+H_FLAGS],not HX_FAULTED
.out:
	ret

; g_tun_ad's name: its address into g_tun_ad. eax = 1 there, 2 held (asked,
; or not answered yet), 3 no such name, 4 not to be had (no okena-resolve,
; a full ring, too long). Keeps rbx, r12-r15.
tun_resolve:
	mov	r10,[g_tr_shm]
	test	r10,r10
	jz	.fail4
	; its key: the name in lower case
	mov	ecx,[g_tun_ad+AD_NLEN]
	test	ecx,ecx
	jz	.fail4
	cmp	ecx,253
	ja	.fail4
	mov	rsi,[g_tun_ad+AD_NAME]
	lea	rdi,[g_tun_name]
	push	rcx
@@:
	lodsb
	lea	edx,[rax-'A']
	cmp	dl,25
	ja	.lc
	or	al,0x20
.lc:
	stosb
	dec	ecx
	jnz	@b
	pop	rdx
	push	rdx
	lea	rsi,[g_tun_name]
	lea	rdi,[g_tun_key]
	call	sha256
	pop	r11				; (its length, kept)
	mov	r10,[g_tr_shm]
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rax,[g_now_ms]
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	mov	r13d,eax			; seconds now
	tr_lock
	mov	eax,dword [g_tun_key]
	and	eax,TRS_N - 1
	mov	r14d,eax
	xor	r12,r12				; a place for it
	mov	r15d,-1
	xor	ecx,ecx
.probe:
	lea	eax,[r14+rcx]
	and	eax,TRS_N - 1
	imul	rax,rax,TRE_SIZE
	lea	rdi,[r10+TRS_CACHE+rax]
	mov	eax,[rdi+TRE_STATE]
	test	eax,eax
	jz	.free
	mov	edx,[g_tr_gen]
	cmp	[rdi+TRE_GEN],edx
	jne	.stale
	push	rcx
	push	rdi
	lea	rsi,[g_tun_key]
	mov	ecx,32
	repe	cmpsb
	pop	rdi
	pop	rcx
	jne	.other
	mov	edx,r13d
	sub	edx,[rdi+TRE_T]
	mov	eax,[rdi+TRE_STATE]
	cmp	eax,TRST_OK
	jne	@f
	cmp	edx,[rdi+TRE_TTL]
	jb	.answer
	jmp	.again
@@:
	cmp	eax,TRST_BAD
	jne	@f
	cmp	edx,TRS_BAD_S
	jb	.unlock_bad
	jmp	.again
@@:
	cmp	edx,TRS_ASK_S
	jb	.unlock_hold
.again:
	mov	r12,rdi
	jmp	.ask
.other:
	mov	edx,r13d
	sub	edx,[rdi+TRE_T]
	cmp	dword [rdi+TRE_STATE],TRST_ASKED
	je	.next
	cmp	r15d,-1
	je	.older
	cmp	edx,r15d
	jbe	.next
.older:
	test	r12,r12
	jz	@f
	cmp	dword [r12+TRE_STATE],0
	je	.next
@@:
	mov	r12,rdi
	mov	r15d,edx
	jmp	.next
.stale:
	mov	r15d,-2
.free:
	test	r12,r12
	jz	@f
	cmp	dword [r12+TRE_STATE],0
	je	.next
@@:
	mov	r12,rdi
.next:
	inc	ecx
	cmp	ecx,TRS_PROBE
	jb	.probe
	test	r12,r12
	jz	.unlock_fail
.ask:
	mov	eax,[r10+TRS_HEAD]
	sub	eax,[r10+TRS_TAIL]
	cmp	eax,TRS_RN
	jae	.unlock_fail
	mov	eax,[r10+TRS_HEAD]
	and	eax,TRS_RN - 1
	imul	rax,rax,TRQ_SIZE
	lea	rdi,[r10+TRS_RING+rax]
	mov	[rdi+TRQ_LEN],r11d
	mov	eax,[g_tr_gen]
	mov	[rdi+TRQ_GEN],eax
	push	rdi
	lea	rdi,[rdi+TRQ_KEY]
	lea	rsi,[g_tun_key]
	mov	ecx,32
	rep	movsb
	pop	rdi
	lea	rdi,[rdi+TRQ_NAME]
	lea	rsi,[g_tun_name]
	mov	ecx,r11d
	rep	movsb
	inc	dword [r10+TRS_HEAD]
	mov	rdi,r12
	lea	rsi,[g_tun_key]
	mov	ecx,32
	rep	movsb
	mov	dword [r12+TRE_STATE],TRST_ASKED
	mov	[r12+TRE_T],r13d
	mov	eax,[g_tr_gen]
	mov	[r12+TRE_GEN],eax
	inc	dword [r10+TRS_WAKE]
	mov	dword [r10+TRS_LOCK],0
	lea	rdi,[r10+TRS_WAKE]
	mov	esi,FUTEX_WAKE_
	mov	edx,1
	xor	r10d,r10d
	mov	eax,SYS_futex
	syscall
	jmp	.hold
.answer:
	; the first address of the answer, its family
	mov	rax,[rdi+TRE_ADDR]
	mov	[g_tun_ad+AD_IP],rax
	mov	rax,[rdi+TRE_ADDR+8]
	mov	[g_tun_ad+AD_IP+8],rax
	mov	dword [g_tun_ad+AD_KIND],ADDR_V6
	cmp	byte [rdi+TRE_FAM],4
	jne	@f
	mov	dword [g_tun_ad+AD_KIND],ADDR_V4
@@:
	mov	dword [r10+TRS_LOCK],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	mov	eax,1
	ret
.unlock_bad:
	mov	dword [r10+TRS_LOCK],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	call	tun_held_done
	mov	eax,3
	ret
.unlock_fail:
	mov	dword [r10+TRS_LOCK],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	jmp	.fail4
.unlock_hold:
	mov	dword [r10+TRS_LOCK],0
.hold:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	; held 2 ms at a time, 5 s in all
	mov	rax,[r15+H_BUF]
	mov	ecx,dword [r15+H_LT0]
	cmp	[rax+HB_FGEN],ecx
	je	@f
	mov	[rax+HB_FGEN],ecx
	mov	rcx,[g_now_ms]
	add	rcx,TRS_WAIT_MS
	mov	[rax+HB_FDUE],rcx
@@:
	mov	rcx,[g_now_ms]
	cmp	rcx,[rax+HB_FDUE]
	ja	.fail4
	cmp	dword [g_fd_n],FD_MAX
	jae	.fail4
	mov	eax,TRS_HOLD_US
	call	fault_hold
	mov	eax,2
	ret
.fail4:
	call	tun_held_done
	mov	eax,4
	ret


; ------------------------------------------------------------ okena-resolve

; Never returns.
resolve_main:
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
	lea	rsi,[tr_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	call	priv_drop
	call	ll_confine_reader		; (/etc/hosts, /etc/resolv.conf)
	seccomp_for filter_resolve
	mov	r15,[g_tr_shm]
.loop:
	mov	r10,r15
	tr_lock
	mov	eax,[r15+TRS_TAIL]
	cmp	eax,[r15+TRS_HEAD]
	jne	.take
	mov	edx,[r15+TRS_WAKE]
	mov	dword [r15+TRS_LOCK],0
	lea	rdi,[r15+TRS_WAKE]
	mov	esi,FUTEX_WAIT_
	lea	r10,[ts_tr_wait]
	mov	eax,SYS_futex
	syscall
	jmp	.loop
.take:
	and	eax,TRS_RN - 1
	imul	rax,rax,TRQ_SIZE
	lea	rsi,[r15+TRS_RING+rax]
	lea	rdi,[g_tunq]
	mov	ecx,TRQ_SIZE
	rep	movsb
	inc	dword [r15+TRS_TAIL]
	mov	dword [r15+TRS_LOCK],0
	xor	r14d,r14d			; the state: 0 none (another generation's)
	mov	eax,[g_tunq+TRQ_GEN]
	cmp	eax,[g_tr_gen]
	jne	.answered
	lea	rdi,[g_tunq+TRQ_NAME]
	mov	esi,[g_tunq+TRQ_LEN]
	call	rs_lookup
	mov	r14d,TRST_BAD
	cmp	eax,RS_OK
	jne	.answered
	cmp	dword [g_rs_result+RR_COUNT],0
	je	.answered
	mov	r14d,TRST_OK
.answered:
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	r13,[rsp]
	add	rsp,16
	mov	r10,r15
	tr_lock
	mov	eax,dword [g_tunq+TRQ_KEY]
	and	eax,TRS_N - 1
	mov	r12d,eax
	xor	ecx,ecx
.find:
	lea	eax,[r12+rcx]
	and	eax,TRS_N - 1
	imul	rax,rax,TRE_SIZE
	lea	rdi,[r15+TRS_CACHE+rax]
	cmp	dword [rdi+TRE_STATE],TRST_ASKED
	jne	.find_next
	mov	eax,[g_tunq+TRQ_GEN]
	cmp	[rdi+TRE_GEN],eax
	jne	.find_next
	push	rcx
	push	rdi
	lea	rsi,[g_tunq+TRQ_KEY]
	mov	ecx,32
	repe	cmpsb
	pop	rdi
	pop	rcx
	jne	.find_next
	mov	[rdi+TRE_T],r13d
	cmp	r14d,TRST_OK
	jne	.state
	mov	eax,[g_rs_result+RR_TTL]
	cmp	eax,1
	adc	eax,0
	mov	[rdi+TRE_TTL],eax
	mov	eax,[g_rs_result+RR_COUNT]
	mov	[rdi+TRE_N],eax
	push	rdi
	lea	rsi,[g_rs_result+RR_FAMILY]
	lea	rdi,[rdi+TRE_FAM]
	mov	ecx,8
	rep	movsb
	mov	rdi,[rsp]
	lea	rsi,[g_rs_result+RR_ADDRS]
	lea	rdi,[rdi+TRE_ADDR]
	mov	ecx,8 * 16
	rep	movsb
	pop	rdi
.state:
	mov	[rdi+TRE_STATE],r14d		; (0: the place is free again)
	jmp	.found
.find_next:
	inc	ecx
	cmp	ecx,TRS_PROBE
	jb	.find
.found:
	mov	dword [r15+TRS_LOCK],0
	jmp	.loop
