; `cache 30s stale-while-revalidate=5m vary=accept-encoding max=1MiB shared=on` on a
; route: answers kept in memory, in each worker (`okena { cache_memory 64MiB }`, for
; each). Nothing is shared, so nothing is locked and a worker that dies takes only
; its own copy along; the price is that each worker fills on its own.
;
; Memory is blocks of CB_SIZE from a free list, an object a chain of them, so a
; response of unknown length costs what it turns out to be, and nothing fragments.
; When there are none left the object used longest ago goes, unless someone is
; reading it: a session pins what it serves.
;
; A hit is a backend that is not there. The head kept goes into UP and through
; http_resp_head like any answer, and the body comes through h_recv on the upstream
; side (SF_CACHED), so CORS, `response` rules, HTTP/2 and HTTP/3 need nothing else.
;
; A miss for something already being fetched waits, looking every CW_POLL µs, up to
; CW_MAX times: a popular object that expires costs the backend one request. The
; first one holds an entry in CE_FILL, and what it relays goes in as it passes.
; An answer that turns out not to be kept leaves a CE_PASS for CP_SECS, so that
; requests do not line up for what will never be cached.
;
; Stale within `stale-while-revalidate`: served at once, and a session with no
; client (SF_CREF) fetches it again. Past that it is a miss.
;
; What is not kept, whatever the route says: anything but GET; status other than
; 200, 301, 308, 404, 410; Cache-Control no-store, private, no-cache; Set-Cookie;
; Vary: * or a field not in vary=; a body whose end cannot be told from a cut
; connection (no length, not chunked); bigger than max=. Unless shared=on, nor is a
; request with Cookie or Authorization, or that proved who it is, served or kept: an
; answer for one person must not reach another. s-maxage and max-age say for how
; long, over what the route says; must-revalidate and proxy-revalidate leave no
; stale window.

SF_CACHED	:= 4194304			; S_FLAGS: its answer comes from the cache
SF_CFILL	:= 8388608			; what it relays goes into an entry
SF_CREF		:= 16777216			; a copy that fetches a stale entry again

FD_CACHE	:= 0x20000000			; FD_SESS: it waits for an entry being filled

CB_SIZE		:= 4096
CB_SHIFT	:= 12
CW_POLL		:= 1000				; µs
CW_MAX		:= 5000
CP_SECS		:= 1
CA_VMAX		:= 4
CACHE_MEM_DEF	:= 64 shl 20

CE_FREE		:= 0
CE_FILL		:= 1
CE_READY	:= 2
CE_PASS		:= 3

CE_KEY		:= 0				; 32
CE_STATE	:= 32				; d
CE_PIN		:= 36				; d: sessions reading it
CE_NEXT		:= 40				; d: in its bucket
CE_LPREV	:= 44				; d: used longest ago, or sooner
CE_LNEXT	:= 48				; d
CE_DEAD		:= 52				; d: out of the index: freed with its last pin
CE_HEAD		:= 56				; d: the head's blocks: first
CE_HTAIL	:= 60				; d: last
CE_HLEN		:= 64				; d
CE_BODY		:= 68				; d: the body's
CE_BTAIL	:= 72				; d
CE_BLEN		:= 76				; d
CE_FRESH	:= 80				; q: µs it is good until
CE_STALE	:= 88				; q: and may be served until
CE_BORN		:= 96				; q: µs
CE_WANT		:= 104				; q: the length said, -1 not said
CE_MAX		:= 112				; d: what the route allows
CE_TTL		:= 116				; d: seconds
CE_SWR		:= 120				; d
CE_SIZE		:= 128

; `cache` of a route (plan)
CA_TTL		:= 0				; d: seconds
CA_SWR		:= 4				; d
CA_MAX		:= 8				; d: bytes
CA_SHARED	:= 12				; d
CA_VN		:= 16				; d
CA_V		:= 24				; (name q, length q) * CA_VMAX
CA_SIZE		:= CA_V + 16 * CA_VMAX
MAX_CACHES	:= 256

bss
	align 8
	g_caches:	rb CA_SIZE * MAX_CACHES
	g_plan_caches	dd ?
	g_plan_cmem	dq ?			; bytes, each worker
	g_cb_base	dq ?			; the blocks
	g_cb_nexts	dq ?			; dword each: the next in its chain
	g_ce_base	dq ?			; entries
	g_ch		dq ?			; buckets
	g_ch_mask	dd ?
	g_cb_free	dd ?
	g_ce_free	dd ?
	g_ce_old	dd ?			; used longest ago
	g_ce_new	dd ?
	g_cf_r		dd ?			; ce_find: ready, filling, pass
	g_cf_f		dd ?
	g_cf_p		dd ?
	g_ck_sha:	rb SHA256_CTX_SIZE
	g_ck:		rb 32
	g_c_pool	dd ?			; the route's pool, for a refetch
end bss

; a worker, at its start
cache_init:
	cmp	dword [g_plan_caches],0
	je	.none
	push	rbx
	push	r12
	push	r13
	mov	rax,[g_plan_cmem]
	test	rax,rax
	jnz	@f
	mov	eax,CACHE_MEM_DEF
@@:
	shr	rax,CB_SHIFT
	mov	r12,rax				; blocks
	mov	r13,rax
	shr	r13,1				; entries
	cmp	r13,64
	jae	@f
	mov	r13d,64
@@:
	bsr	rcx,r13
	inc	ecx
	mov	eax,1
	shl	rax,cl				; buckets
	lea	ecx,[rax-1]
	mov	[g_ch_mask],ecx
	; [blocks][nexts][entries][buckets]
	mov	rbx,rax
	mov	rsi,r12
	shl	rsi,CB_SHIFT
	lea	rax,[r12*4+4095]
	and	rax,not 4095
	add	rsi,rax
	mov	rax,r13
	imul	rax,rax,CE_SIZE
	add	rsi,rax
	lea	rsi,[rsi+rbx*4]
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	js	.out
	mov	[g_cb_base],rax
	mov	rcx,r12
	shl	rcx,CB_SHIFT
	add	rax,rcx
	mov	[g_cb_nexts],rax
	lea	rcx,[r12*4+4095]
	and	rcx,not 4095
	add	rax,rcx
	mov	[g_ce_base],rax
	mov	rcx,r13
	imul	rcx,rcx,CE_SIZE
	add	rax,rcx
	mov	[g_ch],rax
	; free lists; buckets all empty
	mov	rdi,rax
	mov	rcx,rbx
	mov	eax,NIL
	rep	stosd
	mov	rdi,[g_cb_nexts]
	mov	eax,1
	mov	rcx,r12
@@:
	stosd
	inc	eax
	dec	rcx
	jnz	@b
	mov	dword [rdi-4],NIL
	mov	dword [g_cb_free],0
	mov	rdi,[g_ce_base]
	mov	eax,1
	mov	rcx,r13
@@:
	mov	[rdi+CE_NEXT],eax
	add	rdi,CE_SIZE
	inc	eax
	dec	rcx
	jnz	@b
	mov	dword [rdi-CE_SIZE+CE_NEXT],NIL
	mov	dword [g_ce_free],0
	mov	dword [g_ce_old],NIL
	mov	dword [g_ce_new],NIL
	call	cd_init				; and on disk, if it is to be
.out:
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; eax = entry: rax = it. Keeps everything else.
macro ce_ptr
	shl	rax,7				; CE_SIZE
	add	rax,[g_ce_base]
end macro
assert CE_SIZE = 128

; edi = entry: into the list, as the one used last
ce_lru_add:
	mov	eax,edi
	ce_ptr
	mov	ecx,[g_ce_new]
	mov	[rax+CE_LPREV],ecx
	mov	dword [rax+CE_LNEXT],NIL
	mov	[g_ce_new],edi
	cmp	ecx,NIL
	jne	@f
	mov	[g_ce_old],edi
	ret
@@:
	mov	eax,ecx
	ce_ptr
	mov	[rax+CE_LNEXT],edi
	ret

; edi = entry: out of the list
ce_lru_del:
	mov	eax,edi
	ce_ptr
	mov	ecx,[rax+CE_LPREV]
	mov	edx,[rax+CE_LNEXT]
	cmp	ecx,NIL
	jne	@f
	mov	[g_ce_old],edx
	jmp	.next
@@:
	mov	eax,ecx
	ce_ptr
	mov	[rax+CE_LNEXT],edx
.next:
	cmp	edx,NIL
	jne	@f
	mov	[g_ce_new],ecx
	ret
@@:
	mov	eax,edx
	ce_ptr
	mov	[rax+CE_LPREV],ecx
	ret

; rsi = a key: its bucket's place
macro ch_slot
	mov	eax,[rsi]
	and	eax,[g_ch_mask]
	mov	rdx,[g_ch]
	lea	rdx,[rdx+rax*4]
end macro

; edi = entry: into the index, under its key
ce_link:
	mov	eax,edi
	ce_ptr
	mov	r8,rax
	mov	rsi,r8				; (CE_KEY = 0)
	ch_slot
	mov	eax,[rdx]
	mov	[r8+CE_NEXT],eax
	mov	[rdx],edi
	ret

; edi = entry: out of the index
ce_unlink:
	mov	eax,edi
	ce_ptr
	mov	r8,rax
	mov	rsi,r8
	ch_slot
.walk:
	mov	eax,[rdx]
	cmp	eax,NIL
	je	.out
	cmp	eax,edi
	je	.found
	ce_ptr
	lea	rdx,[rax+CE_NEXT]
	jmp	.walk
.found:
	mov	eax,[r8+CE_NEXT]
	mov	[rdx],eax
.out:
	ret

; edi = chain's first block: all of it free
cb_free_chain:
	mov	eax,edi
.next:
	cmp	eax,NIL
	je	.out
	mov	rdx,[g_cb_nexts]
	mov	ecx,[rdx+rax*4]
	mov	r8d,[g_cb_free]
	mov	[rdx+rax*4],r8d
	mov	[g_cb_free],eax
	mov	eax,ecx
	jmp	.next
.out:
	ret

; edi = entry, out of the index and the list: gone
ce_free:
	push	rbx
	mov	ebx,edi
	mov	eax,edi
	ce_ptr
	push	rax
	mov	edi,[rax+CE_HEAD]
	call	cb_free_chain
	mov	rax,[rsp]
	mov	edi,[rax+CE_BODY]
	call	cb_free_chain
	pop	rax
	mov	dword [rax+CE_STATE],CE_FREE
	mov	ecx,[g_ce_free]
	mov	[rax+CE_NEXT],ecx
	mov	[g_ce_free],ebx
	pop	rbx
	ret

; edi = entry in the index and the list: out, and gone when nobody reads it
ce_kill:
	push	rbx
	mov	ebx,edi
	call	ce_unlink
	mov	edi,ebx
	call	ce_lru_del
	mov	eax,ebx
	ce_ptr
	cmp	dword [rax+CE_PIN],0
	je	@f
	mov	dword [rax+CE_DEAD],1
	pop	rbx
	ret
@@:
	mov	edi,ebx
	call	ce_free
	pop	rbx
	ret

; room: the entry used longest ago that nobody reads goes. CF: all are being read.
ce_evict:
	mov	eax,[g_ce_old]
.next:
	cmp	eax,NIL
	je	.none
	mov	ecx,eax
	ce_ptr
	cmp	dword [rax+CE_PIN],0
	je	.found
	mov	eax,[rax+CE_LNEXT]
	jmp	.next
.found:
	mov	edi,ecx
	call	ce_kill
	clc
	ret
.none:
	stc
	ret

; eax = a block. CF: no room.
cb_alloc:
.again:
	mov	eax,[g_cb_free]
	cmp	eax,NIL
	je	.evict
	mov	rdx,[g_cb_nexts]
	mov	ecx,[rdx+rax*4]
	mov	[g_cb_free],ecx
	mov	dword [rdx+rax*4],NIL
	clc
	ret
.evict:
	call	ce_evict
	jnc	.again
	ret

; eax = an entry, CE_FILL's fields cleared, CF: no room.
ce_alloc:
.again:
	mov	eax,[g_ce_free]
	cmp	eax,NIL
	je	.evict
	mov	r8d,eax
	ce_ptr
	mov	ecx,[rax+CE_NEXT]
	mov	[g_ce_free],ecx
	mov	rdi,rax
	xor	eax,eax
	mov	ecx,CE_SIZE
	rep	stosb
	sub	rdi,CE_SIZE
	mov	eax,NIL
	mov	[rdi+CE_HEAD],eax
	mov	[rdi+CE_HTAIL],eax
	mov	[rdi+CE_BODY],eax
	mov	[rdi+CE_BTAIL],eax
	mov	eax,r8d
	clc
	ret
.evict:
	call	ce_evict
	jnc	.again
	ret

; r9 = the entry's (first, last, length) field, rsi = bytes, ecx = how many: added.
; CF: no room.
cw_put:
	push	rbx
	push	r12
	mov	rbx,rsi
	mov	r12d,ecx
.more:
	test	r12d,r12d
	jz	.done
	mov	eax,[r9+8]
	and	eax,CB_SIZE - 1			; what the last block has
	jnz	.room
	push	r9
	call	cb_alloc
	pop	r9
	jc	.out
	cmp	dword [r9],NIL
	jne	@f
	mov	[r9],eax
	jmp	.linked
@@:
	mov	ecx,[r9+4]
	mov	rdx,[g_cb_nexts]
	mov	[rdx+rcx*4],eax
.linked:
	mov	[r9+4],eax
	xor	eax,eax
.room:
	mov	ecx,CB_SIZE
	sub	ecx,eax
	cmp	ecx,r12d
	cmova	ecx,r12d
	mov	edx,[r9+4]
	shl	rdx,CB_SHIFT
	add	rdx,[g_cb_base]
	lea	rdi,[rdx+rax]
	mov	rsi,rbx
	add	[r9+8],ecx
	add	rbx,rcx
	sub	r12d,ecx
	rep	movsb
	jmp	.more
.done:
	clc
.out:
	pop	r12
	pop	rbx
	ret

; g_ck = a key: g_cf_r, g_cf_f, g_cf_p, its entries, NIL for none
ce_find:
	mov	eax,NIL
	mov	[g_cf_r],eax
	mov	[g_cf_f],eax
	mov	[g_cf_p],eax
	lea	rsi,[g_ck]
	ch_slot
	mov	r8d,[rdx]
.walk:
	cmp	r8d,NIL
	je	.out
	mov	eax,r8d
	ce_ptr
	mov	r9,rax
	lea	rsi,[g_ck]
	mov	rdi,r9
	mov	ecx,4
	repe	cmpsq
	jne	.next
	mov	eax,[r9+CE_STATE]
	cmp	eax,CE_READY
	jne	@f
	mov	[g_cf_r],r8d
	jmp	.next
@@:
	cmp	eax,CE_FILL
	jne	@f
	mov	[g_cf_f],r8d
	jmp	.next
@@:
	mov	[g_cf_p],r8d
.next:
	mov	r8d,[r9+CE_NEXT]
	jmp	.walk
.out:
	ret

; r12 = the route's `cache`: g_ck for this request, in g_hm. Keeps rbx, r12-r15.
ck_make:
	push	rbx
	push	r13
	lea	rdi,[g_ck_sha]
	call	sha256_init
	lea	rdi,[.host]
	mov	esi,4
	call	limit_find
	mov	edx,ecx
	call	.field
	mov	rsi,[g_hm+HM_TARGET]
	mov	edx,[g_hm+HM_TLEN]
	call	.field
	mov	ebx,[r12+CA_VN]
	lea	r13,[r12+CA_V]
.vary:
	test	ebx,ebx
	jz	.done
	dec	ebx
	mov	rdi,[r13]
	mov	esi,[r13+8]
	add	r13,16
	call	limit_find
	mov	edx,ecx
	call	.field
	jmp	.vary
.done:
	lea	rdi,[g_ck_sha]
	lea	rsi,[g_ck]
	call	sha256_final
	pop	r13
	pop	rbx
	ret
; a field and its length: two fields must not pass for two others
.field:
	push	rsi
	push	rdx
	mov	[g_ck],edx
	lea	rsi,[g_ck]
	mov	edx,4
	lea	rdi,[g_ck_sha]
	call	sha256_update
	pop	rdx
	pop	rsi
	lea	rdi,[g_ck_sha]
	jmp	sha256_update
.host	db 'host'

; ZF when the request has no such field. Keeps r12-r15.
macro has_field name
	local n, e
	jmp	e
	n db name
	e:
	lea	rdi,[n]
	mov	esi,e - n
	call	limit_find
	test	ecx,ecx
end macro

; r15 = record, g_hm = the request, H_ACT its action. eax = 1 it is taken care of:
; served, or waiting; 0 it goes on to the backend, with SF_CFILL if it is to fill.
; Keeps rbx, r12-r15.
cache_check:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.pass0
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CACHE]
	test	eax,eax
	jnz	.routed
.pass0:
	xor	eax,eax
	ret
.routed:
	push	r12
	push	r13
	dec	eax
	imul	r12,rax,CA_SIZE
	lea	r12,[g_caches+r12]
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_CPASS],0
	je	@f
	mov	dword [rax+HB_CPASS],0
	jmp	.origin
@@:
	test	dword [r15+H_FLAGS],HX_NOBODY
	jz	.origin
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jnz	.origin
	; GET, or HEAD, which reads what GET kept and fills nothing
	xor	r13d,r13d			; 1: it may read, not fill
	test	dword [r15+H_FLAGS],HX_HEAD
	jz	@f
	inc	r13d
	jmp	.method
@@:
	cmp	dword [g_hm+HM_MLEN],3
	jne	.origin
	mov	rax,[g_hm+HM_METHOD]
	mov	eax,[rax]
	and	eax,0xFFFFFF
	cmp	eax,'GET'
	jne	.origin
.method:
	has_field 'range'
	jnz	.origin				; (not a whole object: the backend's)
	cmp	dword [r12+CA_SHARED],0
	jne	.conditional
	has_field 'authorization'
	jnz	.origin
	has_field 'cookie'
	jnz	.origin
	; (the route, not HB_AUTHL: that holds, on a route with no auth, what the last
	; request on this session's buffers left; and a yes may come with no name)
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_AUTH],0
	jne	.origin
.conditional:
	; a conditional request reads what is kept, but its answer may be a 304
	has_field 'if-none-match'
	jz	@f
	mov	r13d,1
@@:
	has_field 'if-modified-since'
	jz	@f
	mov	r13d,1
@@:
	call	ck_make
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_CK]
	lea	rsi,[g_ck]
	mov	ecx,32
	rep	movsb
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_CW],0
	call	qs_clock
	call	ce_find
	mov	eax,[g_cf_r]
	cmp	eax,NIL
	je	.no_entry
	ce_ptr
	mov	rcx,[g_qnow]
	cmp	rcx,[rax+CE_FRESH]
	jb	.serve
	cmp	rcx,[rax+CE_STALE]
	jae	.too_old
	; stale, and allowed: a fresh one on disk is better; else this one now, and
	; someone goes for a new one
	call	cd_lookup
	cmp	eax,1
	je	.disk
	test	eax,eax
	jz	@f
	mov	edi,[g_cd_sidx]
	call	cd_unpin
@@:
	call	cache_refresh
	jmp	.serve
.too_old:
	mov	edi,[g_cf_r]
	call	ce_kill
	mov	dword [g_cf_r],NIL
.no_entry:
	; not in this worker's memory: on disk, filled by any of them?
	call	cd_lookup
	test	eax,eax
	jz	.no_disk
	cmp	eax,2
	jne	.disk
	call	cache_refresh
.disk:
	call	cd_serve
	jmp	.taken
.no_disk:
	cmp	dword [g_cf_f],NIL
	jne	.wait
	mov	eax,[g_cf_p]
	cmp	eax,NIL
	je	.miss
	ce_ptr
	mov	rcx,[g_qnow]
	cmp	rcx,[rax+CE_FRESH]
	jb	.origin
	mov	edi,[g_cf_p]
	call	ce_kill
.miss:
	test	r13d,r13d
	jnz	.origin
	call	cache_begin
	jmp	.origin
.wait:
	test	r13d,r13d
	jnz	.origin
	cmp	dword [g_fd_n],FD_MAX
	jae	.origin
	call	cache_hold
	jmp	.taken
.serve:
	mov	edi,[g_cf_r]
	call	cache_serve
.taken:
	mov	eax,1
	jmp	.out
.origin:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	ret

; ebx = session, r15 = record: looks again, in a moment
cache_hold:
	mov	rax,[r15+H_BUF]
	inc	dword [rax+HB_CW]
	mov	eax,CW_POLL
	call	fault_hold
	or	dword [g_fd+rcx+FD_SESS],FD_CACHE
	ret

; time to look again: ebx = session, r15 = record
cache_poll:
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.none
	lea	rdi,[g_ck]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_CK]
	mov	ecx,32
	rep	movsb
	call	qs_clock
	call	ce_find
	mov	eax,[g_cf_r]
	cmp	eax,NIL
	je	.no_entry
	ce_ptr
	mov	rcx,[g_qnow]
	cmp	rcx,[rax+CE_STALE]
	jae	.no_entry
	mov	edi,[g_cf_r]
	jmp	cache_serve
.no_entry:
	cmp	dword [g_cf_f],NIL
	je	.again				; (who filled gave up: this one tries)
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_CW],CW_MAX
	jae	.late
	cmp	dword [g_fd_n],FD_MAX
	jae	.late
	jmp	cache_hold
.late:
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_CPASS],1
.again:
	cmp	dword [g_cf_p],NIL
	je	@f
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_CPASS],1
@@:
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.none:
	ret

; g_ck = the key, r12 = the route's `cache`, r15 = record, ebx = session: an entry to
; fill. No entry to be had: no matter, it just is not kept.
cache_begin:
	call	ce_alloc
	jc	.out
	mov	r8d,eax
	ce_ptr
	mov	dword [rax+CE_STATE],CE_FILL
	mov	rdi,rax
	lea	rsi,[g_ck]
	mov	ecx,32
	rep	movsb
	sub	rdi,32
	mov	eax,[r12+CA_MAX]
	mov	[rdi+CE_MAX],eax
	mov	eax,[r12+CA_TTL]
	mov	[rdi+CE_TTL],eax
	mov	eax,[r12+CA_SWR]
	mov	[rdi+CE_SWR],eax
	push	r8
	mov	edi,r8d
	call	ce_link
	pop	r8
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_CE],r8d
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_CFILL
.out:
	ret

; a stale entry was just found, r12 = the route's `cache`: a copy fetches it again,
; unless one is at it or was refused a moment ago
cache_refresh:
	cmp	dword [g_cf_f],NIL
	jne	.none
	cmp	dword [g_cf_p],NIL
	jne	.pass
.go:
	cmp	dword [g_mir_n],MIR_MAX
	jae	.none
	mov	eax,[g_fd_n]
	cmp	eax,FD_MAX
	jae	.none
	mov	edi,[g_c_pool]			; (no backend is chosen yet: the route's pool)
	cmp	edi,[g_plan_pools]
	jae	.none				; (`split`: none of its own)
	mov	esi,SF_CREF
	xor	edx,edx
	mov	r9d,[r15+H_INOFF]
	mov	r10d,r9d
	call	mirror_new
.none:
	ret
.pass:
	mov	eax,[g_cf_p]
	ce_ptr
	mov	rcx,[g_qnow]
	cmp	rcx,[rax+CE_FRESH]
	jb	.none
	mov	edi,[g_cf_p]
	call	ce_kill
	mov	dword [g_cf_p],NIL
	jmp	.go

; a copy that fetches again, its head parsed: ebx, r15, g_hm: it fills. Keeps r13.
cache_refetch:
	push	r12
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CACHE]
	test	eax,eax
	jz	.out
	dec	eax
	imul	r12,rax,CA_SIZE
	lea	r12,[g_caches+r12]
	call	ck_make
	call	ce_find
	cmp	dword [g_cf_f],NIL
	jne	.out
	call	cache_begin
.out:
	pop	r12
	ret

; edi = a ready entry: this request is answered from it. r15, ebx. g_ck, g_qnow.
cache_serve:
	push	r12
	push	r13
	mov	r12d,edi
	mov	eax,edi
	ce_ptr
	mov	r13,rax
	inc	dword [r13+CE_PIN]
	mov	edi,r12d
	call	ce_lru_del
	mov	edi,r12d
	call	ce_lru_add
	mov	rax,[r15+H_BUF]
	mov	[rax+HB_CE],r12d
	mov	qword [rax+HB_HT0],0
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_CACHED
	mov	dword [rax+S_SERVER],NIL
	mov	qword [r15+H_UPT0],0
	; the head, and how old it is
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	mov	eax,[r13+CE_HEAD]
	mov	ecx,[r13+CE_HLEN]
.head:
	test	ecx,ecx
	jz	.head_done
	mov	r8d,ecx
	cmp	r8d,CB_SIZE
	jbe	@f
	mov	r8d,CB_SIZE
@@:
	mov	rdx,rax
	shl	rdx,CB_SHIFT
	add	rdx,[g_cb_base]
	mov	rsi,rdx
	sub	ecx,r8d
	xchg	ecx,r8d
	rep	movsb
	mov	ecx,r8d
	mov	rdx,[g_cb_nexts]
	mov	eax,[rdx+rax*4]
	jmp	.head
.head_done:
	memit_x 'Age: '
	mov	rax,[g_qnow]
	sub	rax,[r13+CE_BORN]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	call	fmt_u64
	memit_x 13,10,'Cache-Status: okena; hit; ttl='
	mov	rax,[r13+CE_FRESH]
	sub	rax,[g_qnow]
	jns	@f
	mov	byte [rdi],'-'			; (stale, by any amount: never ttl=0)
	inc	rdi
	neg	rax
	add	rax,999999
@@:
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	call	fmt_u64
	memit_x 13,10,13,10
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_UP]
	sub	rdi,rax
	mov	[r15+H_UPLEN],edi
	mov	dword [r15+H_UPOFF],0
	mov	rax,[r15+H_BUF]
	mov	ecx,[r13+CE_BODY]
	mov	[rax+HB_CPOSB],ecx
	mov	dword [rax+HB_CPOS],0
	mov	ecx,[r13+CE_BLEN]
	mov	[rax+HB_CLEFT],ecx
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	pop	r13
	pop	r12
	jmp	http_resp_head

; h_recv on the upstream side of a hit: ebx = session, rdi = buffer, esi = room
cache_recv:
	h_rec
	mov	r8,[r15+H_BUF]
	mov	eax,[r8+HB_CE]
	cmp	eax,NIL
	je	@f
	test	eax,CD_MARK
	jnz	cd_recv				; from disk
@@:
	mov	ecx,[r8+HB_CLEFT]
	cmp	ecx,esi
	cmova	ecx,esi
	mov	r9d,ecx				; how much
	mov	r10d,ecx
	sub	[r8+HB_CLEFT],ecx
.more:
	test	r10d,r10d
	jz	.done
	mov	eax,[r8+HB_CPOSB]
	mov	edx,[r8+HB_CPOS]
	mov	ecx,CB_SIZE
	sub	ecx,edx
	cmp	ecx,r10d
	cmova	ecx,r10d
	sub	r10d,ecx
	mov	rsi,rax
	shl	rsi,CB_SHIFT
	add	rsi,[g_cb_base]
	add	rsi,rdx
	add	edx,ecx
	rep	movsb
	cmp	edx,CB_SIZE
	jne	@f
	mov	rcx,[g_cb_nexts]
	mov	eax,[rcx+rax*4]
	mov	[r8+HB_CPOSB],eax
	xor	edx,edx
@@:
	mov	[r8+HB_CPOS],edx
	jmp	.more
.done:
	mov	eax,r9d
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue

; g_hm = an answer's head: ebx, r15: a session that fills looks at it. Keeps all
; but rax, rcx, rdx, rsi, rdi, r8-r11.
cache_head:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_CFILL
	jz	.none
	push	r12
	push	r13
	push	r14
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_CE]
	mov	r14d,eax
	ce_ptr
	mov	r12,rax
	mov	eax,[g_hm+HM_STATUS]
	cmp	eax,200
	je	.status
	cmp	eax,301
	je	.status
	cmp	eax,308
	je	.status
	cmp	eax,404
	je	.status
	cmp	eax,410
	jne	.no
.status:
	mov	eax,[r15+H_RBODY]
	cmp	eax,BK_CHUNKED
	je	.chunked
	cmp	eax,BK_LENGTH
	jne	.no
	mov	rax,[r15+H_RREMAIN]
	mov	[r12+CE_WANT],rax
	mov	ecx,[r12+CE_MAX]
	cmp	rax,rcx
	ja	.no
	jmp	.fields
.chunked:
	mov	qword [r12+CE_WANT],-1
.fields:
	call	cache_fields
	jc	.no
	cmp	dword [r12+CE_TTL],0
	je	.no
	jmp	.out
.no:
	call	cache_no
.out:
	pop	r14
	pop	r13
	pop	r12
.none:
	ret

; ebx, r15: what it was filling will not do: nobody waits for it for a while
cache_no:
	push	r12
	call	session_ptr
	and	dword [rax+S_FLAGS],not SF_CFILL
	mov	rax,[r15+H_BUF]
	mov	r12d,[rax+HB_CE]
	mov	eax,r12d
	ce_ptr
	push	rax
	mov	edi,[rax+CE_HEAD]
	call	cb_free_chain
	mov	rax,[rsp]
	mov	edi,[rax+CE_BODY]
	call	cb_free_chain
	call	qs_clock
	pop	rax
	mov	ecx,NIL
	mov	[rax+CE_HEAD],ecx
	mov	[rax+CE_BODY],ecx
	mov	dword [rax+CE_STATE],CE_PASS
	mov	rcx,[g_qnow]
	add	rcx,CP_SECS * 1000000
	mov	[rax+CE_FRESH],rcx
	mov	edi,r12d
	call	ce_lru_add
	pop	r12
	ret

; r12 = the entry, g_hm = the head: the head kept, Cache-Control read. CF: not kept.
cache_fields:
	push	rbx
	push	r13
	push	r14
	mov	r14d,[r12+CE_SWR]
	; the status line
	sub	rsp,48
	mov	rdi,rsp
	memit_x 'HTTP/1.1 '
	mov	eax,[g_hm+HM_STATUS]
	call	fmt_u64
	memit_x ' OK',13,10
	mov	rcx,rdi
	sub	rcx,rsp
	mov	rsi,rsp
	lea	r9,[r12+CE_HEAD]
	; (first, last, length: CE_HEAD, CE_HTAIL, CE_HLEN)
	call	cw_put
	lea	rsp,[rsp+48]
	jc	.no
	xor	ebx,ebx
.field:
	cmp	ebx,[g_hm+HM_NHDR]
	jae	.done
	imul	r13,rbx,HF_SIZE
	lea	r13,[g_hm+HM_HDRS+r13]
	inc	ebx
	mov	rdi,[r13+HF_NAME]
	mov	ecx,[r13+HF_NLEN]
	cmp	ecx,10
	jne	@f
	lea	rsi,[.n_setc]
	mov	edx,ecx
	call	.same
	jnz	.no
@@:
	mov	ecx,[r13+HF_NLEN]
	cmp	ecx,13
	jne	@f
	mov	rdi,[r13+HF_NAME]
	lea	rsi,[.n_cc]
	mov	edx,ecx
	call	.same
	jz	@f
	call	cache_control
	jc	.no
	jmp	.keep
@@:
	cmp	dword [r13+HF_NLEN],4
	jne	.not_vary
	mov	rdi,[r13+HF_NAME]
	lea	rsi,[.n_vary]
	mov	edx,4
	call	.same
	jz	.not_age
	call	cache_vary
	jc	.no
	jmp	.keep
.not_age:
.not_vary:
	; what a hit says for itself, or says again
	mov	rdi,[r13+HF_NAME]
	mov	esi,[r13+HF_NLEN]
	lea	rdx,[.dropped]
	call	name_in
	jnz	.field
.keep:
	mov	rsi,[r13+HF_NAME]
	mov	ecx,[r13+HF_NLEN]
	lea	r9,[r12+CE_HEAD]
	call	cw_put
	jc	.no
	lea	rsi,[.sep]
	mov	ecx,2
	lea	r9,[r12+CE_HEAD]
	call	cw_put
	jc	.no
	mov	rsi,[r13+HF_VALUE]
	mov	ecx,[r13+HF_VLEN]
	lea	r9,[r12+CE_HEAD]
	call	cw_put
	jc	.no
	lea	rsi,[.eol]
	mov	ecx,2
	lea	r9,[r12+CE_HEAD]
	call	cw_put
	jc	.no
	jmp	.field
.done:
	mov	[r12+CE_SWR],r14d
	cmp	dword [r12+CE_HLEN],H_UP_CAP - 256
	ja	.no
	clc
	jmp	.out
.no:
	stc
.out:
	pop	r14
	pop	r13
	pop	rbx
	ret
; ZF clear when they are the same
.same:
	call	mem_eq_nocase
	test	eax,eax
	ret
.dropped db 3,'age',14,'content-length',17,'transfer-encoding',10,'connection'
	db 10,'keep-alive',12,'cache-status',0
.n_setc	db 'set-cookie'
.n_cc	db 'cache-control'
.n_vary	db 'vary'
.sep	db ': '
.eol	db 13,10

; rdi = a name, esi = its length, rdx = a list (length, name, ..., 0): ZF clear when
; it is in it, in any case. Keeps r12-r15, rbx.
name_in:
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	r14,rdx
.next:
	movzx	eax,byte [r14]
	test	eax,eax
	jz	.out				; (ZF)
	cmp	eax,r13d
	jne	.other
	mov	rdi,r12
	lea	rsi,[r14+1]
	mov	edx,eax
	call	mem_eq_nocase
	test	eax,eax
	jnz	.out
	movzx	eax,byte [r14]
.other:
	lea	r14,[r14+rax+1]
	jmp	.next
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; r13 = a Cache-Control field, r12 = the entry, r14d = the stale window: CF not to
; be kept; CE_TTL, r14d as it says. s-maxage over max-age, wherever they stand.
cache_control:
	push	rbx
	push	r15
	mov	rsi,[r13+HF_VALUE]
	mov	eax,[r13+HF_VLEN]
	lea	r15,[rsi+rax]
	mov	rbx,-1				; s-maxage seen
.token:
	cmp	rsi,r15
	jae	.done
	cmp	byte [rsi],' '
	je	.skip
	cmp	byte [rsi],9
	je	.skip
	cmp	byte [rsi],','
	jne	.word
.skip:
	inc	rsi
	jmp	.token
.word:
	mov	r8,rsi				; the token, up to = or ,
.w:
	cmp	rsi,r15
	jae	.w_end
	mov	al,[rsi]
	cmp	al,','
	je	.w_end
	cmp	al,'='
	je	.w_end
	cmp	al,' '
	je	.w_end
	inc	rsi
	jmp	.w
.w_end:
	mov	rcx,rsi
	sub	rcx,r8
	push	rsi
	push	rcx
	push	r8
	mov	rdi,r8
	mov	esi,ecx
	lea	rdx,[.refused]
	call	name_in
	mov	rax,[rsp]
	mov	rdi,rax
	mov	esi,[rsp+8]
	mov	r9d,0
	setnz	r9b
	lea	rdx,[.strict]
	push	r9
	call	name_in
	pop	r9
	pop	r8
	pop	rcx
	pop	rsi
	jz	@f
	xor	r14d,r14d			; no stale window
@@:
	test	r9d,r9d
	jnz	.refuse
	cmp	ecx,7
	jne	.not_max
	push	rsi
	push	rcx
	push	r8
	mov	rdi,r8
	lea	rsi,[.n_max]
	mov	edx,7
	call	mem_eq_nocase
	pop	r8
	pop	rcx
	pop	rsi
	test	eax,eax
	jz	.not_max
	call	.seconds
	jc	.refuse
	cmp	rbx,-1
	jne	.value_end			; (s-maxage said)
	mov	[r12+CE_TTL],eax
	jmp	.value_end
.not_max:
	cmp	ecx,8
	jne	.value_end
	push	rsi
	push	rcx
	push	r8
	mov	rdi,r8
	lea	rsi,[.n_smax]
	mov	edx,8
	call	mem_eq_nocase
	pop	r8
	pop	rcx
	pop	rsi
	test	eax,eax
	jz	.value_end
	call	.seconds
	jc	.refuse
	mov	rbx,rax
	mov	[r12+CE_TTL],eax
.value_end:
	; past a value, quoted ones too
.ve:
	cmp	rsi,r15
	jae	.done
	mov	al,[rsi]
	cmp	al,'"'
	jne	@f
.q:
	inc	rsi
	cmp	rsi,r15
	jae	.done
	cmp	byte [rsi],'"'
	jne	.q
	inc	rsi
	jmp	.ve
@@:
	cmp	al,','
	je	.token
	inc	rsi
	jmp	.ve
.done:
	clc
	jmp	.out
.refuse:
	stc
.out:
	pop	r15
	pop	rbx
	ret
; rsi at "=123": rax = it, rsi past it. CF: not a number
.seconds:
	cmp	rsi,r15
	jae	.nan
	cmp	byte [rsi],'='
	jne	.nan
	inc	rsi
	xor	eax,eax
	xor	ecx,ecx
.d:
	cmp	rsi,r15
	jae	.d_end
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.d_end
	imul	rax,rax,10
	add	rax,rdx
	cmp	rax,1 shl 30
	ja	.nan
	inc	ecx
	inc	rsi
	jmp	.d
.d_end:
	test	ecx,ecx
	jz	.nan
	clc
	ret
.nan:
	stc
	ret
.refused db 8,'no-store',7,'private',8,'no-cache',0
.strict	db 15,'must-revalidate',16,'proxy-revalidate',0
.n_max	db 'max-age'
.n_smax	db 's-maxage'

; r13 = a Vary field, r12 = the entry, r15 = record: CF unless all it names are in
; the route's vary=: it would have to be in the key.
cache_vary:
	push	rbx
	push	r14
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CACHE]
	dec	eax
	imul	r14,rax,CA_SIZE
	lea	r14,[g_caches+r14]
	mov	rsi,[r13+HF_VALUE]
	mov	eax,[r13+HF_VLEN]
	lea	r8,[rsi+rax]
.name:
	cmp	rsi,r8
	jae	.yes
	cmp	byte [rsi],' '
	je	.sp
	cmp	byte [rsi],','
	jne	.w
.sp:
	inc	rsi
	jmp	.name
.w:
	mov	r9,rsi
@@:
	cmp	rsi,r8
	jae	@f
	cmp	byte [rsi],','
	je	@f
	cmp	byte [rsi],' '
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	r10,rsi
	sub	r10,r9
	mov	ebx,[r14+CA_VN]
	lea	rcx,[r14+CA_V]
.listed:
	test	ebx,ebx
	jz	.no				; (`*` is here too)
	dec	ebx
	cmp	[rcx+8],r10
	jne	.other
	push	rsi
	push	rcx
	push	r8
	push	r9
	push	r10
	mov	rdi,r9
	mov	rsi,[rcx]
	mov	edx,r10d
	call	mem_eq_nocase
	pop	r10
	pop	r9
	pop	r8
	pop	rcx
	pop	rsi
	test	eax,eax
	jnz	.name
.other:
	add	rcx,16
	jmp	.listed
.yes:
	clc
	jmp	.out
.no:
	stc
.out:
	pop	r14
	pop	rbx
	ret

; rsi = body bytes passing, ecx = how many, ebx, r15. Keeps all.
cache_tee:
	push	rax
	call	session_ptr
	mov	eax,[rax+S_FLAGS]
	test	eax,SF_IDEMF
	jz	@f
	call	idem_tee
@@:
	test	eax,SF_CFILL
	pop	rax
	jz	.none
	push	rax
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_CE]
	ce_ptr
	mov	r8d,[rax+CE_BLEN]
	add	r8d,ecx
	cmp	r8d,[rax+CE_MAX]
	ja	.no
	mov	r10,rax
	lea	r9,[rax+CE_BODY]
	call	cw_put
	jc	.no
	; the whole of what it said? (chunked: at its last chunk, http_resp_pump)
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_CE]
	ce_ptr
	mov	rcx,[rax+CE_WANT]
	mov	edx,[rax+CE_BLEN]
	cmp	rcx,rdx
	jne	.out
	call	cache_commit
	jmp	.out
.no:
	call	cache_no
.out:
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
.none:
	ret

; the exchange is over: ebx, r15. What it read goes back, what it filled is kept.
cache_finish:
	call	session_ptr
	mov	ecx,[rax+S_FLAGS]
	test	ecx,SF_IDEMS
	jz	@f
	and	dword [rax+S_FLAGS],not SF_IDEMS
	and	dword [r15+H_FLAGS],not HX_UPKEEP
@@:
	test	ecx,SF_IDEMF
	jz	@f
	call	idem_commit
	call	session_ptr
	mov	ecx,[rax+S_FLAGS]
@@:
	test	ecx,SF_ZIP
	jz	@f
	call	zip_done
	call	session_ptr
	mov	ecx,[rax+S_FLAGS]
@@:
	test	ecx,SF_CACHED or SF_CFILL or SF_FILE
	jz	.none
	test	ecx,SF_FILE
	jnz	file_done
	test	ecx,SF_CACHED
	jz	cache_commit
	and	dword [rax+S_FLAGS],not SF_CACHED
	and	dword [r15+H_FLAGS],not HX_UPKEEP
	jmp	cache_unpin
.none:
	ret

; all of the body has passed, ebx, r15: what it filled is kept, whatever becomes of
; its client: one that reads the last byte and leaves, ahead of the send's completion,
; must not cost the entry. Keeps rbx, r12-r15.
cache_commit:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_CFILL
	jz	.none
	and	dword [rax+S_FLAGS],not SF_CFILL
	push	r12
	push	r13
	mov	rax,[r15+H_BUF]
	mov	r13d,[rax+HB_CE]
	mov	eax,r13d
	ce_ptr
	mov	r12,rax
	; all of what it said it was
	mov	rax,[r12+CE_WANT]
	cmp	rax,-1
	je	@f
	mov	ecx,[r12+CE_BLEN]
	cmp	rax,rcx
	jne	.drop
@@:
	; its length, for the head
	sub	rsp,48
	mov	rdi,rsp
	memit_x 'Content-Length: '
	mov	eax,[r12+CE_BLEN]
	call	fmt_u64
	memit_x 13,10
	mov	rcx,rdi
	sub	rcx,rsp
	mov	rsi,rsp
	lea	r9,[r12+CE_HEAD]
	call	cw_put
	lea	rsp,[rsp+48]
	jc	.drop
	call	qs_clock
	mov	rax,[g_qnow]
	mov	[r12+CE_BORN],rax
	mov	ecx,[r12+CE_TTL]
	imul	rcx,rcx,1000000
	add	rax,rcx
	mov	[r12+CE_FRESH],rax
	mov	ecx,[r12+CE_SWR]
	imul	rcx,rcx,1000000
	add	rax,rcx
	mov	[r12+CE_STALE],rax
	; it takes the place of whatever was under this key
	lea	rdi,[g_ck]
	mov	rsi,r12
	mov	ecx,32
	rep	movsb
	call	ce_find
	mov	edi,[g_cf_r]
	cmp	edi,NIL
	je	@f
	call	ce_kill
@@:
	mov	edi,[g_cf_p]
	cmp	edi,NIL
	je	@f
	call	ce_kill
@@:
	mov	dword [r12+CE_STATE],CE_READY
	mov	edi,r13d
	call	ce_lru_add
	call	cd_put				; and a copy on disk
	pop	r13
	pop	r12
.none:
	ret
.drop:
	; (cache_no looks at the flag and the entry only)
	pop	r13
	pop	r12
	jmp	cache_no

; ebx, r15: its pin goes; the last one of an entry already gone frees it
cache_unpin:
	mov	rax,[r15+H_BUF]
	mov	edi,[rax+HB_CE]
	cmp	edi,NIL
	je	.out				; (okena's own head, no entry)
	test	edi,CD_MARK
	jnz	.disk
	mov	eax,edi
	ce_ptr
	dec	dword [rax+CE_PIN]
	jnz	.out
	cmp	dword [rax+CE_DEAD],0
	je	.out
	jmp	ce_free
.out:
	ret
.disk:
	and	edi,CD_MARK - 1
	jmp	cd_unpin

; a session is closing, ebx = it, r12 = it: nothing of the cache stays with it. Keeps
; all.
cache_gone:
	test	dword [r12+S_FLAGS],SF_CACHED or SF_CFILL or SF_FILE or SF_ZIP or SF_IDEMF
	jz	.none
	push	rax
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r15
	h_rec
	call	zc_gone				; a pipe it held
	test	dword [r12+S_FLAGS],SF_IDEMF
	jz	@f
	call	idem_gone
	test	dword [r12+S_FLAGS],SF_CACHED or SF_CFILL or SF_FILE or SF_ZIP
	jz	.out
@@:
	test	dword [r12+S_FLAGS],SF_ZIP
	jz	@f
	call	zip_done
	test	dword [r12+S_FLAGS],SF_CACHED or SF_CFILL or SF_FILE
	jz	.out
@@:
	test	dword [r12+S_FLAGS],SF_FILE
	jz	@f
	call	file_done
	jmp	.out
@@:
	test	dword [r12+S_FLAGS],SF_CACHED
	jz	.filling
	and	dword [r12+S_FLAGS],not SF_CACHED
	call	cache_unpin
	jmp	.out
.filling:
	; nobody will finish it; those who wait try for themselves
	and	dword [r12+S_FLAGS],not SF_CFILL
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_CE]
	push	rbx
	mov	ebx,eax
	mov	edi,eax
	call	ce_unlink
	mov	edi,ebx
	call	ce_free
	pop	rbx
.out:
	pop	r15
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
.none:
	ret

; r12 = the route's action, rbx = its `cache` node
compile_cache:
	push	r13
	push	r14
	mov	eax,[g_plan_caches]
	cmp	eax,MAX_CACHES
	jae	plan_bad_cache
	inc	dword [g_plan_caches]
	mov	[r12+RA_CACHE],eax
	inc	dword [r12+RA_CACHE]
	imul	r13,rax,CA_SIZE
	lea	r13,[g_caches+r13]
	mov	rdi,rbx
	call	node_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jz	plan_bad_cache
	mov	[r13+CA_TTL],eax
	mov	dword [r13+CA_MAX],1 shl 20
	mov	rdi,rbx
	lea	rsi,[.k_swr]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	[r13+CA_SWR],eax
@@:
	mov	rdi,rbx
	lea	rsi,[.k_max]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_size
	test	rax,rax
	jz	plan_bad_cache
	cmp	rax,1 shl 30
	ja	plan_bad_cache
	mov	[r13+CA_MAX],eax
@@:
	mov	rdi,rbx
	lea	rsi,[.k_shared]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[str_word_on]
	call	mem_eq_cstr
	mov	[r13+CA_SHARED],eax
@@:
	mov	rdi,rbx
	lea	rsi,[.k_vary]
	call	node_option
	test	rax,rax
	jz	.done
	mov	r8,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	lea	r9,[r8+rcx]
.name:
	mov	rcx,r8
@@:
	cmp	rcx,r9
	jae	@f
	cmp	byte [rcx],','
	je	@f
	inc	rcx
	jmp	@b
@@:
	mov	rdx,rcx
	sub	rdx,r8
	jz	plan_bad_cache
	mov	eax,[r13+CA_VN]
	cmp	eax,CA_VMAX
	jae	plan_bad_cache
	inc	dword [r13+CA_VN]
	shl	rax,4
	mov	[r13+CA_V+rax],r8
	mov	[r13+CA_V+rax+8],rdx
	lea	r8,[rcx+1]
	cmp	rcx,r9
	jb	.name
.done:
	pop	r14
	pop	r13
	ret
cstring .k_swr, 'stale-while-revalidate',0
cstring .k_max, 'max',0
cstring .k_shared, 'shared',0
cstring .k_vary, 'vary',0

plan_bad_cache:
	call	log_begin
	out_lit 'cache needs a time above a second; stale-while-revalidate= a time, max= a size up to 1GiB, vary= up to 4 fields, and at most 256 routes have one'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
