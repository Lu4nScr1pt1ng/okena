; Rate limits for a fleet: `okena { fleet_limits bind=ADDR peers=ADDR,ADDR...
; key=FILE [interval=50ms] }` and `limit ... fleet=on` on a route.
;
; Each instance keeps its own buckets (limit.inc's GCRA, its batches) and
; tells the others what its clients took: so a limit of 1000/s is 1000/s for
; the whole fleet, however the balancer in front spreads the clients, a client
; going over it on one instance is refused on all of them within an interval,
; and nothing waits on the network to answer a request.
;
; A worker that takes a batch of tokens of such a limit (or gives back what it
; did not use) writes one line, (the key's hash, the limit's id, tokens), to a
; ring of its own in memory shared with okena-fleet: one store a batch, never
; one a request, and a full ring drops the line (the fleet then sees a little
; less than was taken). okena-fleet, every `interval`, empties the rings, adds
; them up by key and sends them to each peer in UDP datagrams sealed with
; HMAC-SHA256 under `key=`; what it receives, sealed with that key, from
; another instance and not seen before, it takes from its own buckets as if
; its clients had asked. The keys hash under a seed made from `key=` (the same
; client is the same key on every instance) and a limit is known by its
; route and its own words (the same configuration: the same ids).
;
; Over the whole fleet a key may get, besides its limit, what the others take
; in one interval before they hear of it: at 50 ms, a twentieth of a second's
; rate an instance.

FLR_N		:= 4096				; lines a ring
FLR_HEAD	:= 0				; q: written by the worker
FLR_TAIL	:= 64				; q: by okena-fleet (its own cache line)
FLR_ENT		:= 128
FLE_KEY		:= 0				; q
FLE_FID		:= 8				; q
FLE_TOK		:= 16				; d, signed
FLE_SIZE	:= 32
FLR_SIZE	:= FLR_ENT + FLR_N * FLE_SIZE
FL_RINGS	:= 2 * MAX_WORKERS		; by worker, for each of two generations
FL_PEERS	:= 16
FL_AGG		:= 16384			; keys an interval (more: sent as they come)
FL_PER_DG	:= 48				; lines a datagram
FL_HDR		:= 40				; magic 4, version 4, sender 8, seq 8, time 8, count 4, pad 4
FL_DG_MAX	:= FL_HDR + FL_PER_DG * 24 + 32
FL_SENDERS	:= 64

bss
	align 8
	g_plan_fl	dd ?			; fleet_limits said
	g_fl_ivms	dd ?			; its interval, ms
	g_fl_bindlen	dd ?
	g_fl_np		dd ?
	g_fl_keylen	dd ?
	g_fl_bind:	rb 32
	g_fl_peer:	rb 32 * FL_PEERS	; sockaddr, then its length at +28
	g_fl_key:	rb 64
	; runtime
	g_fl_rings	dq ?			; shared: FL_RINGS rings
	g_fl_pid	dd ?
	g_fl_fd		dd ?
	g_fl_sender	dq ?
	g_fl_seq	dq ?
	g_fl_next	dq ?			; ms: the next send
	g_fl_aggn	dd ?
	g_fl_agg:	rb FL_AGG * 24		; key, fid, tokens (d) + pad
	g_fl_hash:	rd FL_AGG * 2		; open addressing: index + 1
	g_fl_dg:	rb FL_DG_MAX + 64
	g_fl_in:	rb 2048
	g_fl_mac:	rb 32
	g_fl_from	rq FL_SENDERS		; senders heard: id, last seq
	g_fl_fseq	rq FL_SENDERS
	g_fl_fnext	dd ?
end bss

cstring fl_name, 'okena-fleet',0
cstring fl_seed_text, 'okena fleet rate limit seed'

; ------------------------------------------------------------ the plan

; rbx = the fleet_limits node (okena block)
compile_fleet_limits:
	push	r12
	mov	dword [g_plan_fl],1
	mov	dword [g_fl_ivms],50
	mov	rdi,rbx
	cstring .k_bind, 'bind',0
	lea	rsi,[.k_bind]
	call	node_option
	test	rax,rax
	jz	plan_bad_fleet
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	jc	plan_bad_fleet
	lea	rdi,[g_fl_bind]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	[g_fl_bindlen],eax
	; peers=A,B,...
	mov	rdi,rbx
	cstring .k_peers, 'peers',0
	lea	rsi,[.k_peers]
	call	node_option
	test	rax,rax
	jz	plan_bad_fleet
	mov	r12,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	lea	r8,[r12+rcx]			; the end
.peer:
	cmp	r12,r8
	jae	.peers_done
	mov	rdi,r12
@@:
	cmp	r12,r8
	jae	@f
	cmp	byte [r12],','
	je	@f
	inc	r12
	jmp	@b
@@:
	mov	rsi,r12
	sub	rsi,rdi
	inc	r12				; past the comma
	test	esi,esi
	jz	.peer
	mov	eax,[g_fl_np]
	cmp	eax,FL_PEERS
	jae	plan_bad_fleet
	push	r8
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	pop	r8
	jc	plan_bad_fleet
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_V4
	je	@f
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_V6
	jne	plan_bad_fleet			; (a peer has an address: not ":port")
@@:
	mov	eax,[g_fl_np]
	shl	eax,5
	lea	rdi,[g_fl_peer+rax]
	push	rdi
	lea	rsi,[g_cmp_addr]
	push	r8
	call	sockaddr_build
	pop	r8
	pop	rdi
	mov	[rdi+28],eax
	inc	dword [g_fl_np]
	jmp	.peer
.peers_done:
	cmp	dword [g_fl_np],0
	je	plan_bad_fleet
	; key=FILE: its first line, 16 to 64 bytes
	mov	rdi,rbx
	cstring .k_key, 'key',0
	lea	rsi,[.k_key]
	call	node_option
	test	rax,rax
	jz	plan_bad_fleet
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_fleet
	mov	rsi,[rax+A_VAL]
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_fleet
	xor	ecx,ecx
@@:
	cmp	rcx,rdx
	jae	@f
	cmp	byte [rax+rcx],10
	je	@f
	cmp	byte [rax+rcx],13
	je	@f
	inc	ecx
	jmp	@b
@@:
	cmp	ecx,16
	jb	plan_bad_fleet
	cmp	ecx,64
	ja	plan_bad_fleet
	mov	[g_fl_keylen],ecx
	mov	rsi,rax
	lea	rdi,[g_fl_key]
	rep	movsb
	; interval=
	mov	rdi,rbx
	cstring .k_iv, 'interval',0
	lea	rsi,[.k_iv]
	call	node_option
	test	rax,rax
	jz	.out
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	cmp	eax,5
	jb	plan_bad_fleet
	cmp	eax,10000
	ja	plan_bad_fleet
	mov	[g_fl_ivms],eax
.out:
	pop	r12
	ret

plan_bad_fleet:
	call	log_begin
	out_lit 'fleet_limits takes bind=ADDR:PORT (UDP), peers=ADDR:PORT,... (the other instances, 16 at most), key=FILE (its first line, 16 to 64 bytes, the same on every instance) and interval= (5ms to 10s, 50ms when not said)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rbx = a `limit` node, r12 = its entry: its id, the same on every instance
; with the same configuration: a hash of its words and of those of the
; blocks around it (route, host), not of the listener's addresses.
fleet_limit_id:
	push	rbx
	mov	rax,0xCBF29CE484222325		; FNV-1a
.node:
	test	rbx,rbx
	jz	.done
	cmp	qword [rbx+N_DEF],0
	je	.done
	lea	rcx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[rbx+N_DEF],rcx
	je	.done				; (not the listener's addresses: each instance has its own)
	mov	rsi,[rbx+N_NAME]
	mov	ecx,[rbx+N_NLEN]
	call	.bytes
	mov	r8,[rbx+N_ARGS]
	mov	r9d,[rbx+N_ARGC]
.arg:
	test	r9d,r9d
	jz	.up
	dec	r9d
	mov	rsi,[r8+A_VAL]
	mov	ecx,[r8+A_VLEN]
	call	.bytes
	xor	rax,0xFF			; (between words)
	mov	rdx,0x100000001B3
	imul	rax,rdx
	add	r8,A_SIZE
	jmp	.arg
.up:
	mov	rbx,[rbx+N_PARENT]
	jmp	.node
.done:
	or	rax,1				; (never 0)
	mov	[r12+LM_FID],rax
	pop	rbx
	ret
.bytes:
	mov	rdx,0x100000001B3
@@:
	test	ecx,ecx
	jz	@f
	movzx	r10d,byte [rsi]
	xor	rax,r10
	imul	rax,rdx
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	ret

; Supervisor, at start and on each reload: with fleet_limits, the keys' seed
; from its key (the same client, the same key, on every instance).
fleet_seed:
	cmp	dword [g_plan_fl],0
	je	.out
	lea	rdi,[g_fl_mac]
	lea	rsi,[g_fl_key]
	mov	edx,[g_fl_keylen]
	lea	rcx,[fl_seed_text]
	mov	r8d,fl_seed_text.len
	call	hmac_sha256
	mov	rax,qword [g_fl_mac]
	mov	[g_lim_seed],rax
	mov	rax,qword [g_fl_mac+8]
	mov	[g_lim_seed+8],rax
.out:
	ret

; Supervisor, once: the rings (shared, touched only as used).
fleet_rings_init:
	cmp	qword [g_fl_rings],0
	jne	.out
	xor	edi,edi
	mov	esi,FLR_SIZE * FL_RINGS
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_fl_rings],rax
.out:
	ret

; ------------------------------------------------------------ workers

; r12 = a limit, rdi = a key's hash, edx = tokens taken: one line on this
; worker's ring, when the limit is the fleet's. Keeps all but rax.
fleet_note:
	cmp	dword [r12+LM_FLEET],0
	je	fleet_note_fid.out
	push	rsi
	mov	rsi,[r12+LM_FID]
	call	fleet_note_fid
	pop	rsi
	ret
; rdi = a key's hash, rsi = its limit's id, edx = tokens (negative: given
; back). Keeps all but rax.
fleet_note_fid:
	cmp	qword [g_fl_rings],0
	je	.out
	push	rcx
	push	rsi
	push	rsi
	mov	eax,[g_gen]
	and	eax,1
	imul	eax,eax,MAX_WORKERS
	add	eax,[g_worker_id]
	imul	rax,rax,FLR_SIZE
	add	rax,[g_fl_rings]
	mov	rcx,[rax+FLR_HEAD]
	mov	rsi,rcx
	sub	rsi,[rax+FLR_TAIL]
	cmp	rsi,FLR_N
	jae	.full				; (okena-fleet behind: this one is lost)
	mov	esi,ecx
	and	esi,FLR_N - 1
	shl	rsi,5				; FLE_SIZE
	lea	rsi,[rax+FLR_ENT+rsi]
	mov	[rsi+FLE_KEY],rdi
	push	rdx
	mov	rdx,[rsp+8]			; (the fid)
	mov	[rsi+FLE_FID],rdx
	pop	rdx
	mov	[rsi+FLE_TOK],edx
	inc	rcx
	mov	[rax+FLR_HEAD],rcx		; (x86: the line is stored before it shows)
.full:
	pop	rsi
	pop	rsi
	pop	rcx
.out:
	ret

; rax = the wall clock, ns (okena-fleet: the system's, no TSC assumed)
fl_wall_ns:
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000000
	add	rax,[rsp+8]
	add	rsp,16
	ret

; ------------------------------------------------------------ okena-fleet

; Supervisor: start it when some limit is the fleet's.
spawn_fleet:
	cmp	dword [g_plan_fl],0
	je	.none
	cmp	qword [g_fl_rings],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	fleet_main
	js	.none
	mov	[g_fl_pid],eax
.none:
	ret

; Never returns.
fleet_main:
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
	lea	rsi,[fl_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	; its socket, before the filter: nothing it opens later
	movzx	edi,word [g_fl_bind]
	mov	esi,SOCK_DGRAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.idle
	mov	[g_fl_fd],eax
	cmp	word [g_fl_bind],AF_INET6
	jne	@f
	sub	rsp,16				; (":port": both families)
	mov	dword [rsp],0
	mov	edi,[g_fl_fd]
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,16
@@:
	mov	edi,[g_fl_fd]
	lea	rsi,[g_fl_bind]
	mov	edx,[g_fl_bindlen]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.unbound
	lea	rdi,[g_fl_sender]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	call	priv_drop
	call	ll_confine_none
	seccomp_for filter_fleet
	call	fl_now_ms
	add	eax,[g_fl_ivms]
	mov	[g_fl_next],rax
.loop:
	call	fl_now_ms
	mov	rdx,[g_fl_next]
	sub	rdx,rax
	jg	@f
	call	fl_send_all
	call	fl_now_ms
	mov	ecx,[g_fl_ivms]
	add	rax,rcx
	mov	[g_fl_next],rax
	mov	edx,[g_fl_ivms]
@@:
	sub	rsp,16				; wait for a datagram, up to the next send
	mov	eax,[g_fl_fd]
	mov	[rsp],eax
	mov	dword [rsp+4],POLLIN
	mov	rdi,rsp
	mov	esi,1
	mov	eax,SYS_poll
	syscall
	add	rsp,16
	call	fl_receive_all
	jmp	.loop
.unbound:
	call	log_begin
	out_lit 'okena-fleet: its address cannot be bound (in use?): limits are this instance',39,'s alone'
	call	log_end
.idle:
	sub	rsp,16
	mov	qword [rsp],3600
	mov	qword [rsp+8],0
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	jmp	.idle

; rax = monotonic ms
fl_now_ms:
	call	qs_clock
	mov	rax,[g_qnow]
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	ret

; The rings, added up by key, to every peer.
fl_send_all:
	push	rbx
	push	r12
	push	r13
	push	r14
	; clear what the last interval used
	xor	ecx,ecx
.clear:
	cmp	ecx,[g_fl_aggn]
	jae	.cleared
	imul	rax,rcx,24
	mov	rdx,[g_fl_agg+rax]		; its key: its slot
	mov	r8,[g_fl_agg+rax+8]
	call	fl_slot_of			; r9 = slot index (where it sits)
	mov	dword [g_fl_hash+r9*4],0
	inc	ecx
	jmp	.clear
.cleared:
	mov	dword [g_fl_aggn],0
	xor	r12d,r12d			; ring
.ring:
	cmp	r12d,FL_RINGS
	jae	.drained
	imul	r13,r12,FLR_SIZE
	add	r13,[g_fl_rings]
	mov	r14,[r13+FLR_TAIL]
.line:
	cmp	r14,[r13+FLR_HEAD]
	jae	.ring_done
	mov	eax,r14d
	and	eax,FLR_N - 1
	shl	rax,5
	lea	rbx,[r13+FLR_ENT+rax]
	mov	rdx,[rbx+FLE_KEY]
	mov	r8,[rbx+FLE_FID]
	mov	r10d,[rbx+FLE_TOK]
	call	fl_add
	inc	r14
	jmp	.line
.ring_done:
	mov	[r13+FLR_TAIL],r14
	inc	r12d
	jmp	.ring
.drained:
	; in datagrams of FL_PER_DG lines
	xor	r12d,r12d
.dgram:
	cmp	r12d,[g_fl_aggn]
	jae	.out
	mov	r13d,[g_fl_aggn]
	sub	r13d,r12d
	cmp	r13d,FL_PER_DG
	jbe	@f
	mov	r13d,FL_PER_DG
@@:
	lea	rdi,[g_fl_dg]
	mov	dword [rdi],'OKFL'
	mov	dword [rdi+4],1
	mov	rax,[g_fl_sender]
	mov	[rdi+8],rax
	inc	qword [g_fl_seq]
	mov	rax,[g_fl_seq]
	mov	[rdi+16],rax
	push	rdi
	call	fl_wall_ns
	pop	rdi
	mov	[rdi+24],rax
	mov	[rdi+32],r13d
	mov	dword [rdi+36],0
	add	rdi,FL_HDR
	xor	ecx,ecx
.put:
	cmp	ecx,r13d
	jae	.sealed
	lea	eax,[r12+rcx]
	imul	rax,rax,24
	mov	rdx,[g_fl_agg+rax]
	mov	[rdi],rdx
	mov	rdx,[g_fl_agg+rax+8]
	mov	[rdi+8],rdx
	mov	edx,[g_fl_agg+rax+16]
	mov	[rdi+16],edx
	mov	dword [rdi+20],0
	add	rdi,24
	inc	ecx
	jmp	.put
.sealed:
	lea	rax,[g_fl_dg]
	mov	r8,rdi
	sub	r8,rax				; what is sealed
	push	r8
	push	rdi
	lea	rsi,[g_fl_key]
	mov	edx,[g_fl_keylen]
	mov	rcx,rax
	call	hmac_sha256			; (rdi: the MAC after the lines)
	pop	rdi
	pop	r8
	lea	r14,[r8+32]			; the datagram's length
	xor	ebx,ebx
.peer:
	cmp	ebx,[g_fl_np]
	jae	.sent
	mov	eax,ebx
	shl	eax,5
	lea	r8,[g_fl_peer+rax]
	mov	r9d,[r8+28]
	mov	edi,[g_fl_fd]
	lea	rsi,[g_fl_dg]
	mov	rdx,r14
	mov	r10d,MSG_DONTWAIT
	mov	eax,SYS_sendto
	syscall
	inc	ebx
	jmp	.peer
.sent:
	add	r12d,r13d
	jmp	.dgram
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdx = key, r8 = fid: r9 = its slot in g_fl_hash (where it is, or the free
; one it would take). Keeps all but rax, r9, r11.
fl_slot_of:
	mov	rax,rdx
	xor	rax,r8
	mov	r11,0x9E3779B97F4A7C15
	imul	rax,r11
	shr	rax,49				; 15 bits
	mov	r9d,eax
.probe:
	and	r9d,FL_AGG * 2 - 1
	mov	eax,[g_fl_hash+r9*4]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,24
	cmp	[g_fl_agg+rax],rdx
	jne	.next
	cmp	[g_fl_agg+rax+8],r8
	je	.out
.next:
	inc	r9d
	jmp	.probe
.out:
	ret

; rdx = key, r8 = fid, r10d = tokens: added to the interval's sum. Keeps rbx,
; r12-r15.
fl_add:
	call	fl_slot_of
	mov	eax,[g_fl_hash+r9*4]
	test	eax,eax
	jz	.new
	dec	eax
	imul	rax,rax,24
	add	[g_fl_agg+rax+16],r10d
	ret
.new:
	mov	eax,[g_fl_aggn]
	cmp	eax,FL_AGG
	jae	.full				; (more keys than this an interval: dropped)
	inc	dword [g_fl_aggn]
	lea	ecx,[rax+1]
	mov	[g_fl_hash+r9*4],ecx
	imul	rax,rax,24
	mov	[g_fl_agg+rax],rdx
	mov	[g_fl_agg+rax+8],r8
	mov	[g_fl_agg+rax+16],r10d
.full:
	ret

; Datagrams that came: each one checked, then its lines taken from our
; buckets.
fl_receive_all:
	push	rbx
	push	r12
	push	r13
	push	r14
.next:
	mov	edi,[g_fl_fd]
	lea	rsi,[g_fl_in]
	mov	edx,2048
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	test	rax,rax
	jle	.out
	cmp	eax,FL_HDR + 32
	jb	.next
	mov	r12d,eax
	cmp	dword [g_fl_in],'OKFL'
	jne	.next
	cmp	dword [g_fl_in+4],1
	jne	.next
	mov	ecx,[g_fl_in+32]		; its lines: what its length says
	cmp	ecx,FL_PER_DG
	ja	.next
	imul	eax,ecx,24
	add	eax,FL_HDR + 32
	cmp	eax,r12d
	jne	.next
	mov	rax,[g_fl_in+8]
	cmp	rax,[g_fl_sender]
	je	.next				; (our own, through a peer list that names us)
	; sealed with our key?
	lea	rdi,[g_fl_mac]
	lea	rsi,[g_fl_key]
	mov	edx,[g_fl_keylen]
	lea	rcx,[g_fl_in]
	lea	r8d,[r12-32]
	call	hmac_sha256
	lea	rdi,[g_fl_mac]
	lea	rsi,[g_fl_in+r12-32]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.next
	; recent (30 s either way) and not heard before from this sender
	call	fl_wall_ns
	sub	rax,[g_fl_in+24]
	mov	rcx,rax
	neg	rcx
	cmovs	rcx,rax				; |now - its time|
	mov	rax,30000000000
	cmp	rcx,rax
	ja	.next
	call	fl_fresh
	jc	.next
	; its lines
	mov	r13d,[g_fl_in+32]
	lea	r14,[g_fl_in+FL_HDR]
.line:
	test	r13d,r13d
	jz	.next
	dec	r13d
	mov	rdi,[r14]			; key
	mov	rsi,[r14+8]			; fid
	movsxd	rdx,dword [r14+16]		; tokens
	add	r14,24
	call	fl_take
	jmp	.line
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_fl_in: CF when its sender's seq is not past the last one heard. Keeps
; rbx, r12-r15.
fl_fresh:
	mov	rax,[g_fl_in+8]
	mov	rdx,[g_fl_in+16]
	xor	ecx,ecx
.find:
	cmp	ecx,FL_SENDERS
	jae	.new
	cmp	[g_fl_from+rcx*8],rax
	je	.known
	inc	ecx
	jmp	.find
.known:
	cmp	rdx,[g_fl_fseq+rcx*8]
	jbe	.old
	mov	[g_fl_fseq+rcx*8],rdx
	clc
	ret
.old:
	stc
	ret
.new:
	mov	ecx,[g_fl_fnext]		; (a slot in turn: senders past 64 push out)
	inc	dword [g_fl_fnext]
	and	ecx,FL_SENDERS - 1
	mov	[g_fl_from+rcx*8],rax
	mov	[g_fl_fseq+rcx*8],rdx
	clc
	ret

; rdi = key, rsi = fid, rdx = tokens another instance took: the same taken
; from ours. Keeps rbx, r14, r15.
fl_take:
	push	r12
	push	r13
	push	r14
	mov	r13,rdi
	mov	r9,rdx
	xor	ecx,ecx
.limit:
	cmp	ecx,[g_plan_limits]
	jae	.out				; (a limit this configuration has not)
	imul	r12,rcx,LM_SIZE
	lea	r12,[g_limits+r12]
	inc	ecx
	cmp	dword [r12+LM_FLEET],0
	je	.limit
	cmp	[r12+LM_FID],rsi
	jne	.limit
	push	r9
	call	qs_clock
	imul	r14,[g_qnow],1000
	call	limit_bucket			; r8
	pop	r9
	mov	r10,r9
	imul	r10,[r12+LM_T]			; ns of the rate
.again:
	mov	rax,[r8+LB_TAT]
	mov	rcx,rax
	cmp	rcx,r14
	cmovb	rcx,r14
	add	rcx,r10
	lock cmpxchg [r8+LB_TAT],rcx
	jne	.again
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
