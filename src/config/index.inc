; A name index for checking and compiling a configuration: (kind, scope,
; bytes) -> value, one open-addressing table, so that finding a pool by its
; name, or whether a route's path or a host name came before, costs the same
; with ten entries as with a hundred thousand. Without it these were walks of
; the whole tree for each entry: a large configuration took seconds.
;
; A kind with NI_NOCASE compares and hashes ASCII letters without case (as
; mem_eq_nocase does). Several entries may share a key (routes with other
; methods): ni_find gives the first, ni_next the one after. Clearing costs
; what was put in, not the table's size. Past NI_FILL entries nothing more
; is added and ni_full is set; such a configuration is larger than any plan
; holds, and the callers fall back to their walks.

NI_BITS		:= 20
NI_CAP		:= 1 shl NI_BITS
NI_FILL		:= NI_CAP / 2
NI_MIN		:= 1024

NI_KEY		:= 0		; q: the bytes, 0 = empty slot
NI_SCOPE	:= 8		; q
NI_VAL		:= 16		; q
NI_LEN		:= 24		; d
NI_KIND		:= 28		; d
NI_SIZE		:= 32

NI_NOCASE	:= 0x100

NI_ROUTE	:= 1				; scope: the route set's node; value: the route
NI_HOST		:= 2 or NI_NOCASE		; scope: the listener; value: the host block
NI_POOL		:= 3				; value: the pool's node (the first of its name)
NI_USED		:= 4				; a pool named somewhere (check_unused_pools)
NI_PPOOL	:= 5				; compiling: value: the pool's index
NI_INLINE	:= 6				; compiling: scope: how many addresses; key: the first
NI_KIDN		:= 7				; scope: a node; key: an N_DEF; value: its children of it
NI_KIDDONE	:= 8				; scope: a node whose children are in NI_KIDS
NI_KIDS		:= 9				; | k shl NI_KSHIFT: its k-th child of that N_DEF
NI_KSHIFT	:= 12

KIDS_WALK	:= 32		; children walked before a node is indexed

bss
	align 8
	g_ni_tab:	rb NI_SIZE * NI_CAP
	g_ni_used	rd NI_FILL		; slots in use, to clear them
	g_ni_n		dd ?
	g_ni_mask	dd ?		; slots in use less one: sized for the tree (ni_reset)
	g_ni_full	dd ?
	g_ni_pools	dd ?		; 1 when NI_POOL holds every pool of the tree
	g_ni_qkind	dd ?		; the key of the last ni_find
	g_ni_qlen	dd ?
	g_ni_qkey	dq ?
	g_ni_qscope	dq ?
	g_ni_kids	dd ?		; 1 once the checker has set every node's N_DEF
	g_kid_mode	dd ?		; kids_next: 0 walking siblings, 1 in the index
	g_kid_cur	dq ?		; the child (walking) or its entry (index)
	g_kid_node	dq ?		; (index) the parent
	g_kid_k		dd ?		; (index) which of them
	g_kid_def	dq ?		; the directive asked for
end bss

; A new tree: nothing of the old one stays, and its N_DEF are not set yet.
ni_new_tree:
	mov	dword [g_ni_kids],0

ni_reset:
	xor	ecx,ecx
.next:
	cmp	ecx,[g_ni_n]
	jae	.done
	mov	eax,[g_ni_used+rcx*4]
	shl	rax,5
	mov	qword [g_ni_tab+rax+NI_KEY],0
	inc	ecx
	jmp	.next
.done:
	mov	dword [g_ni_n],0
	mov	dword [g_ni_full],0
	mov	dword [g_ni_pools],0
	; as many slots as the tree could fill, twice over: its pages are touched
	; at random, so a table larger than that would be resident all the same
	mov	rax,[g_ar_nodes+AR_NEXT]
	sub	rax,[g_ar_nodes+AR_BASE]
	xor	edx,edx
	mov	ecx,N_SIZE
	div	rcx
	lea	r8,[rax*2+rax]			; children, their counts, the node itself
	mov	rax,[g_ar_args+AR_NEXT]
	sub	rax,[g_ar_args+AR_BASE]
	xor	edx,edx
	mov	ecx,A_SIZE
	div	rcx
	add	r8,rax				; names and paths
	shl	r8,2				; at most half full, rounded up
	mov	eax,NI_MIN
@@:
	cmp	rax,r8
	jae	@f
	cmp	eax,NI_CAP
	jae	@f
	shl	eax,1
	jmp	@b
@@:
	dec	eax
	mov	[g_ni_mask],eax
	ret

; The tree is compiled: the index's pages go back to the kernel (the
; supervisor would keep them, and every worker after it). A later lookup
; that needs the index builds it again.
ni_release:
	call	ni_reset
	lea	rdi,[g_ni_tab]
	mov	esi,NI_SIZE * NI_CAP
	call	pages_release
	lea	rdi,[g_ni_used]
	mov	esi,4 * NI_FILL
	jmp	pages_release

; rdi = start, rsi = length: the whole pages inside go back to the kernel
; (they read as zero again).
pages_release:
	lea	rax,[rdi+rsi]
	add	rdi,4095
	and	rdi,not 4095
	and	rax,not 4095
	sub	rax,rdi
	jbe	@f
	mov	rsi,rax
	mov	edx,MADV_DONTNEED
	mov	eax,SYS_madvise
	syscall
@@:
	ret

; edi = kind, rsi = key, edx = length, rcx = scope. eax = first slot index.
ni_hash:
	mov	eax,2166136261
	xor	r8d,r8d
	test	edi,NI_NOCASE
	jz	.bytes
	mov	r8d,0x20
.bytes:
	xor	r9d,r9d
.byte:
	cmp	r9d,edx
	jae	.mix
	movzx	r10d,byte [rsi+r9]
	or	r10d,r8d
	xor	eax,r10d
	imul	eax,eax,16777619
	inc	r9d
	jmp	.byte
.mix:
	xor	eax,edi
	imul	eax,eax,16777619
	mov	r9,rcx
	xor	eax,r9d
	shr	r9,32
	xor	eax,r9d
	imul	eax,eax,0x9E3779B1
	mov	r9d,eax
	shr	r9d,15
	xor	eax,r9d
	and	eax,[g_ni_mask]
	ret

; edi = kind, rsi = key, edx = length, rcx = scope, r8 = value. Keeps rbx, r12-r15.
ni_add:
	mov	eax,[g_ni_mask]		; (rcx is the scope)
	shr	eax,1
	cmp	[g_ni_n],eax
	jae	.full
	push	r8
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	call	ni_hash
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	r8
.probe:
	mov	r9d,eax
	shl	r9,5
	cmp	qword [g_ni_tab+r9+NI_KEY],0
	je	.slot
	inc	eax
	and	eax,[g_ni_mask]
	jmp	.probe
.slot:
	mov	[g_ni_tab+r9+NI_KEY],rsi
	mov	[g_ni_tab+r9+NI_SCOPE],rcx
	mov	[g_ni_tab+r9+NI_VAL],r8
	mov	[g_ni_tab+r9+NI_LEN],edx
	mov	[g_ni_tab+r9+NI_KIND],edi
	mov	ecx,[g_ni_n]
	mov	[g_ni_used+rcx*4],eax
	inc	dword [g_ni_n]
	ret
.full:
	mov	dword [g_ni_full],1
	ret

; edi = kind, rsi = key, edx = length, rcx = scope. rax = the first entry
; with that key (its slot: [rax+NI_VAL] is the value), or 0. Keeps rbx, r12-r15.
ni_find:
	mov	[g_ni_qkind],edi
	mov	[g_ni_qkey],rsi
	mov	[g_ni_qlen],edx
	mov	[g_ni_qscope],rcx
	call	ni_hash
	jmp	ni_scan

; rax = an entry from ni_find or ni_next: the next with the same key, or 0.
; (The key is the entry's own, so a lookup in between changes nothing.)
ni_next:
	mov	edx,[rax+NI_KIND]
	mov	[g_ni_qkind],edx
	mov	edx,[rax+NI_LEN]
	mov	[g_ni_qlen],edx
	mov	rdx,[rax+NI_KEY]
	mov	[g_ni_qkey],rdx
	mov	rdx,[rax+NI_SCOPE]
	mov	[g_ni_qscope],rdx
	sub	rax,g_ni_tab
	shr	rax,5
	inc	eax
	and	eax,[g_ni_mask]
	; eax = slot index to look from
ni_scan:
	mov	r9d,eax
	shl	r9,5
	lea	r11,[g_ni_tab+r9]
	mov	rsi,[r11+NI_KEY]
	test	rsi,rsi
	jz	.none
	mov	edx,[g_ni_qkind]
	cmp	[r11+NI_KIND],edx
	jne	.next
	mov	rcx,[g_ni_qscope]
	cmp	[r11+NI_SCOPE],rcx
	jne	.next
	mov	edx,[g_ni_qlen]
	cmp	[r11+NI_LEN],edx
	jne	.next
	push	rax
	push	r11
	mov	rdi,[g_ni_qkey]
	test	dword [g_ni_qkind],NI_NOCASE
	jnz	.nocase
	mov	ecx,edx
	repe	cmpsb
	sete	al
	jmp	.compared
.nocase:
	call	mem_eq_nocase
.compared:
	test	al,al
	pop	r11
	pop	rax
	jnz	.found
.next:
	inc	eax
	and	eax,[g_ni_mask]
	jmp	ni_scan
.found:
	mov	rax,r11
	ret
.none:
	xor	eax,eax
	ret

; rdi = node, rdx = schema entry. rax = its first child of that entry, or 0;
; kids_next then gives the next. Once KIDS_WALK children have been walked
; for one answer, the node is indexed (all its children, by entry, in order,
; the first time) and the rest is looked up, so a listener with a hundred
; thousand routes answers in constant time. Keeps everything but rax, rcx
; and rdx.
kids_first:
	mov	[g_kid_def],rdx
	mov	[g_kid_node],rdi
	mov	dword [g_kid_mode],0
	mov	dword [g_kid_k],0
	mov	rax,[rdi+N_CHILD]
	jmp	kid_walk

; After kids_first: rax = the next child of that entry, or 0. Keeps what
; kids_first keeps.
kids_next:
	mov	rax,[g_kid_cur]
	test	rax,rax
	jz	.out
	inc	dword [g_kid_k]
	cmp	dword [g_kid_mode],0
	jne	kid_lookup
	mov	rax,[rax+N_NEXT]
	jmp	kid_walk
.out:
	ret

; rax = the child to look from: the g_kid_k-th of g_kid_def, walking
kid_walk:
	mov	rdx,[g_kid_def]
	mov	ecx,KIDS_WALK
.walk:
	test	rax,rax
	jz	.done
	cmp	[rax+N_DEF],rdx
	je	.done
	mov	rax,[rax+N_NEXT]
	dec	ecx
	jnz	.walk
	; a long way: the index, if there may be one
	cmp	dword [g_ni_kids],0
	je	.rest
	cmp	dword [g_ni_full],0
	jne	.rest
	push	rax
	call	kids_index
	pop	rax
	jc	.rest
	mov	dword [g_kid_mode],1
	jmp	kid_lookup
.rest:
	test	rax,rax
	jz	.done
	cmp	[rax+N_DEF],rdx
	je	.done
	mov	rax,[rax+N_NEXT]
	jmp	.rest
.done:
	mov	[g_kid_cur],rax
	ret

; the g_kid_k-th child of g_kid_node with entry g_kid_def, from the index
kid_lookup:
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	call	kid_get
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	mov	rdx,[g_kid_def]
	ret

; g_kid_node's children into the index, unless they are there. CF when
; they cannot be (the index is full). Keeps everything but rax, rcx, rdx.
kids_index:
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	rbx
	push	r12
	push	r13
	mov	rbx,[g_kid_node]
	mov	edi,NI_KIDDONE
	mov	rsi,rbx
	xor	edx,edx
	mov	rcx,rbx
	call	ni_find
	test	rax,rax
	jnz	.ok
	; each child as the k-th of its entry (a key of its own, so a thousand
	; routes are not one long chain of equal keys)
	mov	r12,[rbx+N_CHILD]
.add:
	test	r12,r12
	jz	.added
	mov	edi,NI_KIDN
	lea	rsi,[r12+N_DEF]
	mov	edx,8
	mov	rcx,rbx
	call	ni_find
	test	rax,rax
	jnz	@f
	mov	edi,NI_KIDN
	lea	rsi,[r12+N_DEF]
	mov	edx,8
	mov	rcx,rbx
	xor	r8d,r8d
	call	ni_add
	cmp	dword [g_ni_full],0
	jne	.full
	mov	edi,NI_KIDN
	lea	rsi,[r12+N_DEF]
	mov	edx,8
	mov	rcx,rbx
	call	ni_find
@@:
	mov	edi,[rax+NI_VAL]
	inc	qword [rax+NI_VAL]
	shl	edi,NI_KSHIFT
	or	edi,NI_KIDS
	lea	rsi,[r12+N_DEF]
	mov	edx,8
	mov	rcx,rbx
	mov	r8,r12
	call	ni_add
	cmp	dword [g_ni_full],0
	jne	.full
	mov	r12,[r12+N_NEXT]
	jmp	.add
.added:
	mov	edi,NI_KIDDONE
	mov	rsi,rbx
	xor	edx,edx
	mov	rcx,rbx
	xor	r8d,r8d
	call	ni_add
	cmp	dword [g_ni_full],0
	jne	.full
.ok:
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	ret

; rax = the g_kid_k-th child of g_kid_node with entry g_kid_def, or 0
; (g_kid_cur: 0 when there is none, so kids_next stops).
kid_get:
	mov	edi,[g_kid_k]
	shl	edi,NI_KSHIFT
	or	edi,NI_KIDS
	lea	rsi,[g_kid_def]
	mov	edx,8
	mov	rcx,[g_kid_node]
	call	ni_find
	mov	[g_kid_cur],rax
	test	rax,rax
	jz	@f
	mov	rax,[rax+NI_VAL]
@@:
	ret
