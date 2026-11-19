; A handler module for tests/modules/run.py: what the module interface gives
; a handler, said back.
;
;   echo   "METHOD TARGET|ARG|BODY|WORD" (WORD: what its init read)
;   json   201, {"ok":true}, application/json
;   broken a status that is none (okena answers 500)

okena_handler 'echo', mt_echo
okena_handler 'json', mt_json
okena_handler 'broken', mt_broken
okena_init mt_init

bss
	g_mt_word	rb 64
	g_mt_wlen	dd ?
end bss

cstring mt_env, 'OKENA_MODTEST_FILE='

; the supervisor: the first word of $OKENA_MODTEST_FILE, when it is set
mt_init:
	mov	dword [g_mt_wlen],0
	lea	rdi,[mt_env]
	mov	esi,mt_env.len
	call	getenv
	test	rax,rax
	jz	.ok
	mov	rsi,rax				; open, read
	mov	edi,-100			; (AT_FDCWD)
	mov	edx,O_RDONLY
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.fail
	push	rax
	mov	edi,eax
	lea	rsi,[g_mt_word]
	mov	edx,63
	mov	eax,SYS_read
	syscall
	mov	ecx,eax
	pop	rdi
	push	rcx
	mov	eax,SYS_close
	syscall
	pop	rcx
	test	ecx,ecx
	js	.fail
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	@f
	cmp	byte [g_mt_word+rax],' '
	jbe	@f
	inc	eax
	jmp	@b
@@:
	mov	[g_mt_wlen],eax
.ok:
	clc
	ret
.fail:
	call	log_begin
	out_lit 'modtest: cannot read OKENA_MODTEST_FILE'
	call	log_end
	stc
	ret

mt_echo:
	mov	r10,rdx				; the body
	mov	r11d,ecx
	mov	rax,rdi
	push	rax
	mov	rsi,[g_hm+HM_METHOD]
	mov	ecx,[g_hm+HM_MLEN]
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	rep	movsb
	mov	byte [rdi],'|'
	inc	rdi
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	byte [rdi],'|'
	inc	rdi
	mov	rsi,r10
	mov	ecx,r11d
	rep	movsb
	mov	byte [rdi],'|'
	inc	rdi
	lea	rsi,[g_mt_word]
	mov	ecx,[g_mt_wlen]
	rep	movsb
	pop	rax
	mov	rdx,rdi
	sub	rdx,rax
	mov	eax,200
	lea	rsi,[mt_plain]
	ret

mt_json:
	mov	rax,'{"ok":tr'
	mov	[rdi],rax
	mov	dword [rdi+8],'ue}'
	mov	edx,11
	mov	eax,201
	lea	rsi,[mt_jtype]
	ret

mt_broken:
	xor	edx,edx
	mov	eax,42
	xor	esi,esi
	ret

mt_plain	db 'text/plain; charset=utf-8',0
mt_jtype	db 'application/json',0
