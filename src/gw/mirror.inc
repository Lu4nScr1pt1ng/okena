; Mirroring: `mirror pool NAME N%` on a route sends a copy of that share of its
; requests to another pool; what it answers is thrown away.
;
; The copy is a session of its own with no client, which goes through the proxy
; as any other: it reads no socket, and what it would write to one is dropped.
; It starts on the loop's next turn, by the table of held requests (fault.inc's
; way in): to parse its head now would overwrite the one being served. A body
; still coming is teed to it as it is read, into the queue its reads take from.
; The real request never waits: if the shadow falls behind what that queue holds
; the copy is dropped, and there are at most MIR_MAX copies at once in a worker,
; past which requests are simply not copied.

SF_MIR		:= 262144			; S_FLAGS: a mirrored request: no client
MIR_MAX		:= 256

bss
	g_mir_n		dd ?
end bss

; ebx = session, r15 = record, rdi = the action, r13d = where the request goes:
; a copy, maybe. Keeps all.
mirror_spawn:
	cmp	dword [g_mir_n],MIR_MAX
	jae	.none
	cmp	dword [g_fd_n],FD_MAX
	jae	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	; this share
	rdtsc
	imul	eax,eax,0x9E3779B1
	mov	ecx,100
	mul	ecx
	cmp	edx,[r12+RA_MPCT]
	jae	.out
	test	dword [r15+H_FLAGS],HX_UPGRADE
	jnz	.out
	; what is here of it: the head, and of the body what has come. r10d: more
	; of the body is still to come
	xor	r10d,r10d
	mov	ecx,[r15+H_INLEN]
	mov	edx,[r15+H_INOFF]
	mov	eax,[r15+H_BODY]
	cmp	eax,BK_NONE
	je	.none_left
	inc	r10d
	cmp	eax,BK_LENGTH
	jne	.fits				; (chunked: its end is in the bytes)
	mov	eax,ecx
	sub	eax,edx
	cmp	rax,[r15+H_REMAIN]
	jb	.fits
	xor	r10d,r10d			; all here
	add	edx,[r15+H_REMAIN]
	mov	ecx,edx
	mov	edx,[r15+H_INOFF]
	jmp	.fits
.none_left:
	mov	ecx,edx				; (what follows is the next request's)
.fits:
	mov	r14d,ecx			; bytes to copy; edx: the head
	push	r10
	push	rdx
	mov	r13d,ebx			; the request's session
	call	session_alloc
	cmp	eax,NIL
	je	.no_session
	mov	ebx,eax
	inc	dword [g_mir_n]
	push	r15
	xchg	ebx,r13d
	call	session_ptr			; the request's
	mov	r8,rax
	xchg	ebx,r13d
	; (not in g_active or the listener's count: a copy holds no client's place,
	; and a shadow that hangs must not hold up a drain)
	call	session_ptr			; the copy's
	mov	dword [rax+S_STATE],ST_OPEN
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_MIR
	mov	dword [rax+S_CLIENT],-1
	mov	ecx,[r8+S_LST]
	mov	[rax+S_LST],ecx
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	mov	edi,ebx
	call	idle_append
	call	peer_ptr			; the client's address, as the request's
	mov	rdi,rax
	xchg	ebx,r13d
	call	peer_ptr
	xchg	ebx,r13d
	mov	rsi,rax
	mov	ecx,P_SIZE
	rep	movsb
	; its record and buffers
	mov	r8,[rsp]			; the request's record
	cmp	qword [rsp+16],0		; a body to tee: it finds the copy
	je	.no_tee
	mov	rdx,[r8+H_BUF]
	mov	[rdx+HB_MIRS],ebx
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[rdx+HB_MIRG],eax
	or	dword [r8+H_FLAGS],HX_TEE
.no_tee:
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	r15,rax
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	xor	eax,eax
	mov	[r15+H_UTLS],eax
	mov	[r15+H_EPOP],eax
	mov	[r15+H_RIDLEN],eax
	mov	[r15+H_ACT],eax
	mov	qword [r15+H_SNICERT],0
	mov	[r15+H_READY],eax
	mov	dword [r15+H_FLAGS],HX_MIRROR or HX_FAULTED
	mov	dword [r15+H_STATE],HS_FAULT
	mov	[r15+H_INLEN],r14d
	mov	eax,[rsp+8]			; the head
	mov	[r15+H_INOFF],eax
	mov	rsi,[r8+H_BUF]
	lea	rsi,[rsi+HB_IN]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN]
	mov	ecx,r14d
	rep	movsb
	mov	rax,[r15+H_BUF]
	mov	ecx,[r12+RA_MPOOL]
	mov	[rax+HB_SPLIT],ecx
	mov	dword [rax+HB_H2Q+Q_LEN],0
	mov	dword [rax+HB_H2Q+Q_OFF],0
	mov	dword [rax+HB_H2Q+Q_WAIT],0
	; on the loop's next turn
	mov	ecx,[g_fd_n]
	inc	dword [g_fd_n]
	shl	rcx,4
	mov	qword [g_fd+rcx+FD_AT],1
	mov	[g_fd+rcx+FD_SESS],ebx
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[g_fd+rcx+FD_GEN],eax
	mov	qword [g_fd_next],1
	pop	r15
.no_session:
	pop	rdx
	pop	r10
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; ebx = the request, r15 = its record, rsi = body bytes just read, ecx = how
; many: to its copy, or the copy is dropped. Keeps rbx, r15.
mirror_tee:
	push	rbx
	push	r12
	push	r15
	mov	rax,[r15+H_BUF]
	mov	r12,r15				; the request's record
	mov	r8d,[rax+HB_MIRG]
	mov	ebx,[rax+HB_MIRS]
	push	rcx
	call	session_ptr
	pop	rcx
	cmp	[rax+S_GEN],r8d
	jne	.gone
	test	dword [rax+S_FLAGS],SF_MIR
	jz	.gone
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.gone
	h_rec
	mov	r8,[r15+H_BUF]
	add	r8,HB_H2Q
	mov	eax,H2Q_CAP
	sub	eax,[r8+Q_LEN]
	cmp	ecx,eax
	ja	.behind
	mov	eax,[r8+Q_LEN]
	lea	rdi,[r8+Q_DATA+rax]
	add	[r8+Q_LEN],ecx
	rep	movsb
	cmp	dword [r8+Q_WAIT],0
	je	.out
	mov	dword [r8+Q_WAIT],0
	mov	rdi,[r8+Q_DST]
	mov	esi,[r8+Q_ROOM]
	call	mirror_take
	jmp	.out
.behind:
	mov	edi,ebx				; the shadow is that far behind: no copy
	call	session_close
.gone:
	and	dword [r12+H_FLAGS],not HX_TEE
.out:
	pop	r15
	pop	r12
	pop	rbx
	ret

; h_recv of a copy: ebx = it, rdi = buffer, esi = room
mirror_recv:
	h_rec
	mov	r8,[r15+H_BUF]
	add	r8,HB_H2Q
	mov	ecx,[r8+Q_LEN]
	sub	ecx,[r8+Q_OFF]
	jnz	mirror_take
	mov	[r8+Q_DST],rdi
	mov	[r8+Q_ROOM],esi
	mov	dword [r8+Q_WAIT],1
	ret

; r8 = its queue, rdi = buffer, esi = room, something in the queue
mirror_take:
	mov	ecx,[r8+Q_LEN]
	mov	eax,[r8+Q_OFF]
	sub	ecx,eax
	cmp	ecx,esi
	cmova	ecx,esi
	push	rcx
	lea	rsi,[r8+Q_DATA+rax]
	add	[r8+Q_OFF],ecx
	rep	movsb
	mov	eax,[r8+Q_OFF]
	cmp	eax,[r8+Q_LEN]
	jne	.deliver
	mov	dword [r8+Q_OFF],0
	mov	dword [r8+Q_LEN],0
.deliver:
	pop	rax
	mov	edx,1
	xor	ecx,ecx
	jmp	hep_queue
