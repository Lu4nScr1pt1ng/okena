; `balance maglev`, `balance ring-hash` and `balance source-hash`: a key
; picks the server, the same one for the same key in every worker, after a
; reload, and on every okena with the same servers.
;
;   balance maglev key=source          the client's address (the default)
;   balance ring-hash key=header:x-user  (http: also cookie:NAME and path)
;   balance source-hash                maglev on the client's address
;
; maglev (Eisenbud et al., NSDI 2016) fills a table of a prime size (65521,
; as Envoy's), from each server's own permutation: a server
; that goes or comes moves about its own share of keys, the shares are even,
; and a lookup is one division. ring-hash is the ketama ring: 160 points per
; unit of weight, a binary search, and the fewest moves; it is what caches
; want. Both take the weights in the file, and are built by each worker
; from the servers' addresses, so all workers agree, and again when a name
; resolves to other addresses.
;
; A server that is down, drained or ejected keeps its place: its keys are
; drawn again from the key itself, so that they go to the same other servers
; everywhere, and every other key stays where it was. Requests with no key
; (no such header, a stream protocol asked for a header) are drawn at
; random, as are retries, which must go elsewhere anyway.

HK_SOURCE	:= 0
HK_HEADER	:= 1
HK_COOKIE	:= 2
HK_PATH		:= 3

HT_M		:= 0			; d: maglev: entries; ring: points
HT_SIG		:= 8			; q: the servers it was built for
HT_DATA		:= 64
MAGLEV_M	:= 65521		; prime: a hundred entries a server for 655 of them
HT_BYTES	:= HT_DATA + 65536 * 8
RING_POINTS	:= 160
RING_MAX	:= 65536
HASH_REDRAWS	:= 16
HASH_WALK	:= 64

bss
	align 8
	g_pick_hash	dq ?
	g_pick_hashed	dd ?		; server_pick takes g_pick_hash, once
	g_ht_n		dd ?
	g_ht_srv	rd MAX_SERVERS	; building: the servers
	g_ht_w		rd MAX_SERVERS
	g_ht_cur	rd MAX_SERVERS
	g_ht_skip	rd MAX_SERVERS
	g_ht_credit	rd MAX_SERVERS
end bss


; rsi/ecx = bytes: rax = their hash (FNV-1a, then a full mix). Keeps rdx? No.
hash_bytes:
	mov	rax,0xCBF29CE484222325
	mov	rdx,0x100000001B3
	test	ecx,ecx
	jz	hash_mix
@@:
	movzx	r8d,byte [rsi]
	xor	rax,r8
	imul	rax,rdx
	inc	rsi
	dec	ecx
	jnz	@b
; rax: mixed (murmur3's finalizer). Keeps all but rax, rdx.
hash_mix:
	mov	rdx,rax
	shr	rdx,33
	xor	rax,rdx
	mov	rdx,0xFF51AFD7ED558CCD
	imul	rax,rdx
	mov	rdx,rax
	shr	rdx,33
	xor	rax,rdx
	mov	rdx,0xC4CEB9FE1A85EC53
	imul	rax,rdx
	mov	rdx,rax
	shr	rdx,33
	xor	rax,rdx
	ret

; rdi = 16 bytes of an address, eax = 4 or 6: the key for the next pick
pick_key_ip:
	mov	rsi,rdi
	mov	ecx,4
	cmp	eax,4
	je	@f
	mov	ecx,16
@@:
	call	hash_bytes
	mov	[g_pick_hash],rax
	mov	dword [g_pick_hashed],1
	ret

; edi = pool: CF when its balance hashes on the client's address
pool_hashes_source:
	imul	rax,rdi,PL_SIZE
	cmp	dword [g_pools+rax+PL_BALANCE],BAL_MAGLEV
	jb	.no
	cmp	dword [g_pools+rax+PL_HKEY],HK_SOURCE
	jne	.no
	stc
	ret
.no:
	clc
	ret

; a tcp session's first connect: ebx = it, r12 = its record
pick_key_l4:
	cmp	dword [g_pick_hashed],0
	jne	.none				; http said which (trusted proxies apply)
	cmp	dword [r12+S_TRIES],1
	jne	.none
	test	dword [r12+S_FLAGS],SF_PEER
	jz	.none
	mov	edi,[r12+S_POOL]
	call	pool_hashes_source
	jnc	.none
	call	peer_ptr
	mov	rsi,rax
	sub	rsp,16
	mov	rdi,rsp
	call	peer_normalize
	mov	rdi,rsp
	call	pick_key_ip
	add	rsp,16
.none:
	ret

; an http request's connect: ebx = session, r15 = record, r12 = its session
; record. The key, if the head parsed last is this request's.
pick_key_http:
	test	dword [r15+H_FLAGS],HX_AVOID or HX_MIRROR
	jnz	.none
	mov	eax,[r12+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	r8,[g_pools+rax]
	cmp	dword [r8+PL_BALANCE],BAL_MAGLEV
	jb	.none
	mov	rax,[g_hm+HM_TARGET]
	mov	rcx,[r15+H_BUF]
	cmp	rax,rcx
	jb	.none
	add	rcx,H_IN_CAP
	cmp	rax,rcx
	jae	.none				; another request's
	push	r12
	mov	r12,r8
	mov	eax,[r12+PL_HKEY]
	cmp	eax,HK_HEADER
	je	.header
	cmp	eax,HK_COOKIE
	je	.cookie
	cmp	eax,HK_PATH
	je	.path
	call	http_client_resolve
	pop	r12
	lea	rdi,[r15+H_CLIENT]
	mov	eax,[r15+H_CKIND]
	jmp	pick_key_ip
.header:
	mov	rdi,[r12+PL_HNAME]
	mov	esi,[r12+PL_HNLEN]
	call	limit_find
	jmp	.value
.cookie:
	lea	rdi,[.cookie_name]
	mov	esi,6
	call	limit_find
	test	ecx,ecx
	jz	.value
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+PL_HNAME]
	mov	ecx,[r12+PL_HNLEN]
	mov	r8b,';'
	call	limit_field
	jmp	.value
.path:
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_PLEN]
.value:
	pop	r12
	test	ecx,ecx
	jz	.none				; none: drawn at random
	call	hash_bytes
	mov	[g_pick_hash],rax
	mov	dword [g_pick_hashed],1
.none:
	ret
.cookie_name	db 'cookie'

; ------------------------------------------------------------ the tables

; a worker, starting: the tables of the pools that hash
hash_tables_init:
	push	rbx
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_plan_pools]
	jae	.done
	imul	rax,rbx,PL_SIZE
	mov	qword [g_pools+rax+PL_HTAB],0
	cmp	dword [g_pools+rax+PL_BALANCE],BAL_MAGLEV
	jb	.next
	xor	edi,edi
	mov	esi,HT_BYTES
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal
	imul	rcx,rbx,PL_SIZE
	mov	[g_pools+rcx+PL_HTAB],rax
	mov	edi,ebx
	call	hash_build
.next:
	inc	ebx
	jmp	.pool
.done:
	pop	rbx
	ret
.fatal:
	mov	edi,EXIT_FATAL
	jmp	exit_process

; a worker, once a second: a name that resolves to other addresses
hash_tick:
	push	rbx
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_plan_pools]
	jae	.done
	imul	rax,rbx,PL_SIZE
	mov	rdx,[g_pools+rax+PL_HTAB]
	test	rdx,rdx
	jz	.next
	push	rdx
	mov	edi,ebx
	call	hash_signature
	pop	rdx
	cmp	rax,[rdx+HT_SIG]
	je	.next
	mov	edi,ebx
	call	hash_build
.next:
	inc	ebx
	jmp	.pool
.done:
	pop	rbx
	ret

; edi = pool: rax = what its table depends on (which slots hold which
; addresses, and the weights)
hash_signature:
	imul	rax,rdi,PL_SIZE
	lea	r9,[g_pools+rax]
	mov	r10d,[r9+PL_FIRST]
	mov	r11d,r10d
	add	r11d,[r9+PL_COUNT]
	xor	r8d,r8d
.server:
	cmp	r10d,r11d
	jae	.out
	imul	rax,r10,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.skip
	lea	rsi,[g_servers+rax+SV_SA]
	mov	ecx,[g_servers+rax+SV_SALEN]
	push	r8
	call	hash_bytes
	pop	r8
	imul	rcx,r10,SV_SIZE
	mov	ecx,[g_servers+rcx+SV_WEIGHT]
	add	rax,rcx
	add	r8,rax
	rol	r8,7
.skip:
	inc	r10d
	jmp	.server
.out:
	mov	rax,r8
	ret

; edi = pool: its table, from its servers of now
hash_build:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	r15d,edi
	call	hash_signature
	imul	rcx,r15,PL_SIZE
	lea	rbx,[g_pools+rcx]
	mov	r12,[rbx+PL_HTAB]
	mov	[r12+HT_SIG],rax
	mov	dword [r12+HT_M],0
	; the servers: primaries with an address, and their weights
	xor	r13d,r13d			; how many
	xor	r14d,r14d			; the largest weight
	mov	ecx,[rbx+PL_FIRST]
	mov	edx,ecx
	add	edx,[rbx+PL_COUNT]
.collect:
	cmp	ecx,edx
	jae	.collected
	imul	rax,rcx,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	@f
	cmp	dword [g_servers+rax+SV_BACKUP],0
	jne	@f
	mov	[g_ht_srv+r13*4],ecx
	mov	eax,[g_servers+rax+SV_WEIGHT]
	test	eax,eax
	jnz	.weighed
	inc	eax
.weighed:
	mov	[g_ht_w+r13*4],eax
	cmp	eax,r14d
	cmova	r14d,eax
	inc	r13d
@@:
	inc	ecx
	jmp	.collect
.collected:
	mov	[g_ht_n],r13d
	test	r13d,r13d
	jz	.out
	cmp	dword [rbx+PL_BALANCE],BAL_RING
	je	.ring
	; ---- maglev: one size whatever the servers, or a change in how many
	; would move every key
	mov	ebp,MAGLEV_M
	mov	[r12+HT_M],ebp
	; empty, and each server's permutation
	lea	rdi,[r12+HT_DATA]
	mov	ecx,ebp
	xor	eax,eax
	rep	stosw
	xor	ecx,ecx
.perm:
	cmp	ecx,r13d
	jae	.fill
	push	rcx
	mov	eax,[g_ht_srv+rcx*4]
	imul	rax,rax,SV_SIZE
	lea	rsi,[g_servers+rax+SV_SA]
	mov	ecx,[g_servers+rax+SV_SALEN]
	call	hash_bytes
	pop	rcx
	push	rax
	xor	edx,edx
	div	rbp
	mov	[g_ht_cur+rcx*4],edx		; offset
	pop	rax
	mov	rdx,0x9E3779B97F4A7C15
	xor	rax,rdx
	call	hash_mix
	lea	r8,[rbp-1]
	xor	edx,edx
	div	r8
	inc	edx
	mov	[g_ht_skip+rcx*4],edx		; skip, in 1 .. M-1
	inc	ecx
	jmp	.perm
.fill:
	xor	r8d,r8d				; entries filled
	lea	rdi,[g_ht_credit]
	mov	ecx,r13d
	xor	eax,eax
	rep	stosd
.round:
	xor	ecx,ecx
.turn:
	cmp	ecx,r13d
	jae	.round
	; weighted: each round adds a server's weight to its credit, and a turn
	; costs the largest weight (the largest takes one every round)
	mov	eax,[g_ht_credit+rcx*4]
	add	eax,[g_ht_w+rcx*4]
	cmp	eax,r14d
	jae	@f
	mov	[g_ht_credit+rcx*4],eax
	jmp	.no_turn
@@:
	sub	eax,r14d
	mov	[g_ht_credit+rcx*4],eax
.seek:
	mov	eax,[g_ht_cur+rcx*4]
	mov	edx,eax
	add	edx,[g_ht_skip+rcx*4]
	cmp	edx,ebp
	jb	@f
	sub	edx,ebp
@@:
	mov	[g_ht_cur+rcx*4],edx
	cmp	word [r12+HT_DATA+rax*2],0
	jne	.seek
	mov	edx,[g_ht_srv+rcx*4]
	inc	edx
	mov	[r12+HT_DATA+rax*2],dx
	inc	r8d
	cmp	r8d,ebp
	jae	.out
.no_turn:
	inc	ecx
	jmp	.turn
	; ---- the ring: points, sorted
.ring:
	xor	eax,eax				; all the points wanted
	xor	ecx,ecx
@@:
	cmp	ecx,r13d
	jae	@f
	add	eax,[g_ht_w+rcx*4]
	inc	ecx
	jmp	@b
@@:
	imul	eax,eax,RING_POINTS
	mov	r14d,eax			; (no larger than RING_MAX: scaled)
	xor	r8d,r8d				; points
	xor	ecx,ecx
.server_points:
	cmp	ecx,r13d
	jae	.sort
	mov	eax,[g_ht_w+rcx*4]
	imul	eax,eax,RING_POINTS
	cmp	r14d,RING_MAX
	jbe	@f
	imul	rax,rax,RING_MAX
	xor	edx,edx
	div	r14
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	mov	r9d,eax				; this server's
	push	rcx
	push	r8
	push	r9
	mov	eax,[g_ht_srv+rcx*4]
	imul	rax,rax,SV_SIZE
	lea	rsi,[g_servers+rax+SV_SA]
	mov	ecx,[g_servers+rax+SV_SALEN]
	call	hash_bytes
	pop	r9
	pop	r8
	pop	rcx
	mov	r10,rax
	xor	r11d,r11d
.point:
	cmp	r11d,r9d
	jae	.points_done
	cmp	r8d,RING_MAX
	jae	.points_done
	mov	rax,r11
	mov	rdx,0x9E3779B97F4A7C15
	imul	rax,rdx
	add	rax,r10
	call	hash_mix
	shr	rax,32
	shl	rax,32
	mov	edx,[g_ht_srv+rcx*4]
	inc	edx
	or	rax,rdx
	mov	[r12+HT_DATA+r8*8],rax
	inc	r8d
	inc	r11d
	jmp	.point
.points_done:
	inc	ecx
	jmp	.server_points
.sort:
	mov	[r12+HT_M],r8d
	lea	rdi,[r12+HT_DATA]
	mov	esi,r8d
	call	sort_q
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = qwords, esi = how many: in ascending order (heapsort: no memory, no
; worst case)
sort_q:
	cmp	esi,2
	jb	.done
	push	rbx
	push	r12
	mov	r12d,esi
	mov	ebx,esi
	shr	ebx,1
.heapify:
	dec	ebx
	js	.heaped
	mov	ecx,ebx
	mov	edx,r12d
	call	.sift
	jmp	.heapify
.heaped:
	mov	ebx,r12d
.pop:
	dec	ebx
	jz	.sorted
	mov	rax,[rdi]
	mov	rcx,[rdi+rbx*8]
	mov	[rdi],rcx
	mov	[rdi+rbx*8],rax
	xor	ecx,ecx
	mov	edx,ebx
	call	.sift
	jmp	.pop
.sorted:
	pop	r12
	pop	rbx
.done:
	ret
; ecx = root, edx = end: down the heap
.sift:
	lea	eax,[rcx+rcx+1]
	cmp	eax,edx
	jae	.sifted
	lea	r8d,[rax+1]
	cmp	r8d,edx
	jae	@f
	mov	r9,[rdi+r8*8]
	cmp	r9,[rdi+rax*8]
	jbe	@f
	mov	eax,r8d
@@:
	mov	r9,[rdi+rax*8]
	cmp	r9,[rdi+rcx*8]
	jbe	.sifted
	mov	r10,[rdi+rcx*8]
	mov	[rdi+rcx*8],r9
	mov	[rdi+rax*8],r10
	mov	ecx,eax
	jmp	.sift
.sifted:
	ret

; ------------------------------------------------------------ picking

; rbx = pool, ebp = a server to avoid or NIL, g_pick_hash: eax = the server
; its key gives, or NIL when none of the ones it gives may be chosen
hash_pick:
	push	r12
	push	r13
	push	r14
	mov	r12,[rbx+PL_HTAB]
	test	r12,r12
	jz	.none
	mov	r13d,[r12+HT_M]
	test	r13d,r13d
	jz	.none
	mov	r14,[g_pick_hash]
	cmp	dword [rbx+PL_BALANCE],BAL_RING
	je	.ring
	mov	ecx,HASH_REDRAWS
.draw:
	push	rcx
	mov	rax,r14
	xor	edx,edx
	div	r13
	movzx	edi,word [r12+HT_DATA+rdx*2]
	dec	edi
	call	.usable
	pop	rcx
	jc	.found
	; drawn again from the key: everywhere the same
	mov	rax,r14
	mov	rdx,0x9E3779B97F4A7C15
	add	rax,rdx
	call	hash_mix
	mov	r14,rax
	dec	ecx
	jnz	.draw
	jmp	.none
.ring:
	; the first point at or past the key's
	mov	r8,r14
	shr	r8,32
	shl	r8,32
	xor	ecx,ecx				; lo
	mov	edx,r13d			; hi
.search:
	cmp	ecx,edx
	jae	.searched
	lea	eax,[rcx+rdx]
	shr	eax,1
	cmp	[r12+HT_DATA+rax*8],r8
	jae	.left
	lea	ecx,[rax+1]
	jmp	.search
.left:
	mov	edx,eax
	jmp	.search
.searched:
	mov	r8d,HASH_WALK
.walk:
	cmp	ecx,r13d
	jb	@f
	xor	ecx,ecx				; round the ring
@@:
	push	rcx
	push	r8
	mov	edi,[r12+HT_DATA+rcx*8]
	dec	edi
	call	.usable
	pop	r8
	pop	rcx
	jc	.found
	inc	ecx
	dec	r8d
	jnz	.walk
.none:
	mov	eax,NIL
	jmp	.out
.found:
	mov	eax,edi
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
; edi = server: CF when it may have this request. Keeps rdi.
.usable:
	cmp	edi,ebp
	je	.not
	push	rdi
	xor	esi,esi
	call	server_eligible
	pop	rdi
	ret
.not:
	clc
	ret
