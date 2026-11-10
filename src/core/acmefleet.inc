; A fleet sharing the acme directory (`acme DIR ... shared=on`: on NFS, a volume
; several hosts mount): one instance orders a certificate, the others take it.
;
; The certificate due, an instance takes DIR/NAME/lock: its content written to
; DIR/NAME/lock.ID and linked there (link is atomic, and fails when one is
; there). The lock says until when it holds (10 minutes); one past that is an
; instance that died ordering, removed. Whoever holds it orders, then removes
; it. The others look again each second: the certificate on disk not the one
; they serve (the other instance renewed it), they take it (a reload, as for
; one of their own); the lock gone and no new certificate (the order failed),
; one of them orders.
;
; HTTP-01: the CA may ask any instance for the token. The one ordering writes
; its challenges to DIR/NAME/http-01 (TOKEN KEY_AUTHORIZATION, a line each) and
; waits 2 seconds before answering; the others, waiting on the lock, put them
; in their own page's second half of slots, and their workers answer them too.
; DNS-01 needs nothing shared (the record is the zone's); TLS-ALPN-01 would need
; the handshake's certificate on every instance, and is refused with shared=on.

ACME_LOCK_TTL	:= 600
ACME_FLEET_WAIT	:= 2
SYS_link_	:= 86

rodata
	af_hex	db '0123456789abcdef'
end rodata

bss
	align 8
	g_af_lc:	rb 64			; the lock's content: UNTIL ID\n
	g_af_lcl	dd ?
	g_af_n		dd ?			; the slots taken this pass (second half)
	g_af_idok	dd ?
	g_af_id:	rb 16			; this instance's, hex
	g_af_held:	rb ACME_ALL		; the lock is ours
	g_af_said:	rb ACME_ALL		; another instance ordering it: waiting (said once)
	g_af_lock:	rb 600
	g_af_tmp:	rb 600
	g_af_gone:	rb 600
	g_af_stale:	rb 64			; a lock judged stale, as read
	g_af_stl	dd ?
	g_af_buf:	rb 4096
end bss

; rbx = a certificate whose time has come, shared=on: eax = 0 order it (the lock
; ours, or none to be had), 1 another instance renewed it (taken: acme_file_due
; done), 2 another is ordering it (its challenges taken)
acme_fleet_turn:
	call	acme_disk_tag
	test	rax,rax
	jz	@f
	cmp	rax,[g_ac_tag+rbx*8]
	jne	.adopt
@@:
	call	acme_lock
	jc	.wait
	call	acme_disk_tag			; (renewed between the look and the lock)
	test	rax,rax
	jz	.order
	cmp	rax,[g_ac_tag+rbx*8]
	je	.order
	call	acme_unlock
.adopt:
	call	acme_file_due
	mov	byte [g_af_said+rbx],0
	mov	eax,1
	ret
.order:
	mov	byte [g_af_said+rbx],0
	xor	eax,eax
	ret
.wait:
	cmp	byte [g_af_said+rbx],0
	jne	@f
	mov	byte [g_af_said+rbx],1
	call	acme_fleet_poll
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': another instance is ordering it (its lock): waiting for it'
	call	log_end
@@:
	mov	eax,2
	ret

; rbx: the tag (as g_ac_tag's) of DIR/NAME/cert.pem, 0 none
acme_disk_tag:
	cstring .f_cert, '/cert.pem',0
	lea	rsi,[.f_cert]
	call	acme_path
	call	acme_read
	jc	.none
	lea	rsi,[g_ac_file]
	mov	edx,eax
	lea	rdi,[g_ac_der]
	call	pem_first_cert
	test	eax,eax
	jz	.none
	lea	rdi,[g_ac_hash]
	lea	rsi,[g_ac_der]
	mov	edx,eax
	call	sha256
	mov	rax,qword [g_ac_hash]
	or	rax,1
	ret
.none:
	xor	eax,eax
	ret

; rbx: DIR/NAME/lock taken. CF: another instance holds it. (A directory where it
; cannot be made, or link refused: no lock, ordered as when alone.)
acme_lock:
	push	r12
	cmp	dword [g_af_idok],0
	jne	@f
	lea	rdi,[g_af_buf]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	xor	ecx,ecx
.hex:
	movzx	eax,byte [g_af_buf+rcx]
	mov	edx,eax
	shr	eax,4
	and	edx,15
	mov	al,[af_hex+rax]
	mov	dl,[af_hex+rdx]
	mov	[g_af_id+rcx*2],al
	mov	[g_af_id+rcx*2+1],dl
	inc	ecx
	cmp	ecx,8
	jb	.hex
	mov	dword [g_af_idok],1
@@:
	call	acme_now			; UNTIL ID
	add	rax,ACME_LOCK_TTL
	lea	rdi,[g_af_lc]
	call	fmt_u64
	mov	byte [rdi],' '
	lea	rsi,[g_af_id]
	lea	rdi,[rdi+1]
	mov	ecx,16
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	lea	rax,[g_af_lc]
	sub	rdi,rax
	mov	[g_af_lcl],edi
	cstring .f_lock, '/lock',0
	lea	rsi,[.f_lock]
	call	acme_path
	lea	rsi,[g_ac_fpath]
	lea	rdi,[g_af_lock]
	mov	ecx,600
	rep	movsb
	lea	rdi,[g_af_buf]			; DIR/NAME/lock.ID
	mov	dword [rdi],'/loc'
	mov	word [rdi+4],'k.'
	lea	rsi,[g_af_id]
	add	rdi,6
	mov	ecx,16
	rep	movsb
	mov	byte [rdi],0
	lea	rsi,[g_af_buf]
	call	acme_path
	lea	rsi,[g_ac_fpath]
	lea	rdi,[g_af_tmp]
	mov	ecx,600
	rep	movsb
	lea	rsi,[g_af_lc]
	mov	edx,[g_af_lcl]
	call	acme_write
	jc	.alone
	mov	r12d,2				; (a stale one removed: once more)
.try:
	lea	rdi,[g_af_tmp]
	lea	rsi,[g_af_lock]
	mov	eax,SYS_link_
	syscall
	test	eax,eax
	jz	.mine
	cmp	eax,-17				; EEXIST: held, or left
	jne	.unlinked
	lea	rsi,[g_af_lock]
	lea	rdi,[g_ac_fpath]
	mov	ecx,600
	rep	movsb
	call	acme_read
	jc	.again				; (gone meanwhile)
	mov	[g_af_stl],eax			; (as read: the one judged stale)
	lea	rsi,[g_ac_file]
	lea	rdi,[g_af_stale]
	mov	ecx,63
	cmp	eax,ecx
	cmova	eax,ecx
	mov	ecx,eax
	rep	movsb
	xor	eax,eax				; until when
	xor	ecx,ecx
	lea	rsi,[g_ac_file]
@@:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	@f
	imul	rax,rax,10
	add	rax,rdx
	inc	rsi
	inc	ecx
	cmp	ecx,18
	jb	@b
@@:
	push	rax
	call	acme_now
	pop	rcx
	cmp	rax,rcx
	jb	.held
	; its instance died ordering: moved aside (rename: one instance does), and
	; looked at: another's just taken (two judged it stale at once), put back
	lea	rsi,[g_af_tmp]
	lea	rdi,[g_af_gone]
	mov	ecx,600 - 8
	rep	movsb
	lea	rdi,[g_af_gone]
	xor	eax,eax
	mov	ecx,600
	repne	scasb
	mov	dword [rdi-1],'.gon'
	mov	word [rdi+3],'e'
	lea	rdi,[g_af_lock]
	lea	rsi,[g_af_gone]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	jnz	.again
	lea	rsi,[g_af_gone]
	lea	rdi,[g_ac_fpath]
	mov	ecx,600
	rep	movsb
	call	acme_read
	jc	.again
	cmp	eax,[g_af_stl]
	jne	.put_back
	lea	rsi,[g_ac_file]
	lea	rdi,[g_af_stale]
	mov	ecx,eax
	cmp	ecx,63
	jbe	@f
	mov	ecx,63
@@:
	repe	cmpsb
	jne	.put_back
	lea	rdi,[g_af_gone]
	mov	eax,SYS_unlink_
	syscall
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': its lock was stale (an instance gone while ordering): removed'
	call	log_end
.again:
	dec	r12d
	jnz	.try
.held:
	call	.tmp_gone
	stc
	jmp	.out
.put_back:
	lea	rdi,[g_af_gone]
	lea	rsi,[g_af_lock]
	mov	eax,SYS_link_
	syscall
	lea	rdi,[g_af_gone]
	mov	eax,SYS_unlink_
	syscall
	jmp	.held
.mine:
	mov	byte [g_af_held+rbx],1
.unlinked:
	call	.tmp_gone
.alone:
	clc
.out:
	pop	r12
	ret
.tmp_gone:
	lea	rdi,[g_af_tmp]
	mov	eax,SYS_unlink_
	syscall
	ret

; rbx: the lock removed, if ours (as written: one taken over is not), and the
; challenges with it
acme_unlock:
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	.out
	cstring .f_http, '/http-01',0
	lea	rsi,[.f_http]
	call	acme_path
	lea	rdi,[g_ac_fpath]
	mov	eax,SYS_unlink_
	syscall
	cmp	byte [g_af_held+rbx],0
	je	.out
	mov	byte [g_af_held+rbx],0
	lea	rsi,[g_af_lock]
	lea	rdi,[g_ac_fpath]
	mov	ecx,600
	rep	movsb
	call	acme_read
	jc	.out
	cmp	eax,[g_af_lcl]
	jne	.out
	lea	rsi,[g_ac_file]
	lea	rdi,[g_af_lc]
	mov	ecx,eax
	repe	cmpsb
	jne	.out
	lea	rdi,[g_af_lock]
	mov	eax,SYS_unlink_
	syscall
.out:
	ret

; in acme_prove, rbx = the certificate: the HTTP-01 challenges being answered
; (the page's first half) written to DIR/NAME/http-01, and time for the other
; instances to take them
acme_fleet_publish:
	push	r12
	mov	r8,[g_acme_page]
	lea	r8,[r8+AH_SLOT]
	lea	rdi,[g_af_buf]
	mov	r12d,ACME_NAMES
.slot:
	mov	ecx,[r8+AS_TLEN]
	test	ecx,ecx
	jz	.next
	lea	rsi,[r8+AS_TOK]
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	lea	rsi,[r8+AS_KA]
	mov	ecx,[r8+AS_KLEN]
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
.next:
	add	r8,AS_SIZE
	dec	r12d
	jnz	.slot
	push	rdi
	lea	rsi,[acme_unlock.f_http]
	call	acme_path
	pop	rdx
	lea	rsi,[g_af_buf]
	sub	rdx,rsi
	call	acme_write
	mov	eax,ACME_FLEET_WAIT * 1000
	call	acme_sleep_ms
	pop	r12
	ret

; rbx = a certificate another instance is ordering: its HTTP-01 challenges
; (DIR/NAME/http-01) in the page's second half, from g_af_n on
acme_fleet_copy:
	cmp	dword [g_plan_acme+ACM_CHAL],0
	jne	.out
	lea	rsi,[acme_unlock.f_http]
	call	acme_path
	call	acme_read
	jc	.out
	push	r12
	push	r13
	lea	rsi,[g_ac_file]
.line:
	cmp	byte [rsi],0
	je	.done
	cmp	dword [g_af_n],ACME_NAMES
	jae	.done
	mov	r12,rsi				; the token
@@:
	lodsb
	test	al,al
	jz	.done
	cmp	al,10
	je	.line
	cmp	al,' '
	jne	@b
	lea	r13,[rsi-1]
	sub	r13,r12				; its length
	jz	.skip
	cmp	r13,AS_TOKMAX
	ja	.skip
	mov	rdx,rsi				; the key authorization
@@:
	lodsb
	test	al,al
	jz	.done
	cmp	al,10
	jne	@b
	lea	rcx,[rsi-1]
	sub	rcx,rdx
	jz	.line
	cmp	ecx,AS_SIZE - AS_KA
	ja	.line
	; the slot: rewritten only when not this already (a worker may be reading it)
	mov	r8,[g_acme_page]
	mov	eax,[g_af_n]
	add	eax,ACME_NAMES
	imul	eax,eax,AS_SIZE
	lea	r8,[r8+AH_SLOT+rax]
	inc	dword [g_af_n]
	push	rsi
	cmp	[r8+AS_TLEN],r13d
	jne	.write
	cmp	[r8+AS_KLEN],ecx
	jne	.write
	push	rcx
	mov	rsi,r12
	lea	rdi,[r8+AS_TOK]
	mov	ecx,r13d
	repe	cmpsb
	pop	rcx
	jne	.write
	push	rcx
	mov	rsi,rdx
	lea	rdi,[r8+AS_KA]
	repe	cmpsb
	pop	rcx
	je	.same
.write:
	mov	dword [r8+AS_TLEN],0
	mov	[r8+AS_KLEN],ecx
	mov	rsi,rdx
	lea	rdi,[r8+AS_KA]
	rep	movsb
	mov	rsi,r12
	lea	rdi,[r8+AS_TOK]
	mov	ecx,r13d
	rep	movsb
	mov	[r8+AS_TLEN],r13d
.same:
	pop	rsi
	jmp	.line
.skip:
	lodsb
	test	al,al
	jz	.done
	cmp	al,10
	jne	.skip
	jmp	.line
.done:
	pop	r13
	pop	r12
.out:
	ret

; eax = ms, asleep. shared=on: a quarter of a second at a time, the challenges
; of the certificates another instance is ordering taken again between (this
; process may be ordering one while another orders another). Keeps all but rax,
; rcx, rdx, rsi, rdi, r11.
acme_sleep_ms:
	push	r8
	push	r9
	push	r10
	push	r12
	mov	r12d,eax
.chunk:
	mov	eax,r12d
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	@f
	cmp	eax,250
	jbe	@f
	mov	eax,250
@@:
	sub	r12d,eax
	xor	edx,edx
	mov	ecx,1000
	div	ecx
	imul	rdx,rdx,1000000
	push	rdx
	push	rax
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	.out
	call	acme_fleet_poll
	test	r12d,r12d
	jnz	.chunk
.out:
	pop	r12
	pop	r10
	pop	r9
	pop	r8
	ret

; the challenges of the certificates other instances are ordering (any
; DIR/NAME/http-01: one may order before this one has looked at it), in the
; page's second half; the rest of it freed. Keeps rbx, r12-r15.
acme_fleet_poll:
	push	rbx
	mov	dword [g_af_n],0
	xor	ebx,ebx
.cert:
	call	acme_more
	jc	.done
	call	acme_fleet_copy
	inc	ebx
	jmp	.cert
.done:
	call	acme_fleet_rest
	pop	rbx
	ret

; the page's second half past those taken this pass: free
acme_fleet_rest:
	mov	eax,[g_af_n]
	mov	rdi,[g_acme_page]
@@:
	cmp	eax,ACME_NAMES
	jae	@f
	lea	ecx,[eax+ACME_NAMES]
	imul	ecx,ecx,AS_SIZE
	mov	dword [rdi+AH_SLOT+rcx+AS_TLEN],0
	inc	eax
	jmp	@b
@@:
	mov	dword [g_af_n],0
	ret
