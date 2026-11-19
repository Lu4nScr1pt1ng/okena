; A handler module for tests/modules/run.py: what the module interface gives
; a handler, said back.
;
;   echo   "METHOD TARGET|ARG|BODY|WORD" (WORD: what its init read)
;   json   201, {"ok":true}, application/json
;   broken a status that is none (okena answers 500)
;   raw    the body itself, answered from where it is (rcx), any size
;   wait   /w/MS: held MS milliseconds, then "waited MS"

okena_handler 'echo', mt_echo
okena_handler 'json', mt_json
okena_handler 'broken', mt_broken
okena_handler 'raw', mt_raw
okena_handler 'wait', mt_wait
okena_init mt_init

bss
	g_mt_word	rb 64
	g_mt_wlen	dd ?
end bss

cstring mt_env, 'OKENA_MODTEST_FILE='
cstring mt_xh, 'X-Module: json',13,10

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
	lea	rax,[mt_xh]			; a line of its own in the head
	mov	[g_mod_xh],rax
	mov	dword [g_mod_xhlen],mt_xh.len
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

mt_raw:
	mov	eax,200
	mov	r8,rdx				; where the body is
	mov	edx,ecx				; its length
	mov	rcx,r8
	test	edx,edx
	jnz	@f
	xor	ecx,ecx				; (none: from rdi, nothing)
@@:
	lea	rsi,[mt_octets]
	ret

mt_wait:
	; the milliseconds: the path's last segment
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_PLEN]
	lea	r11,[rsi+rcx]
	xor	eax,eax
@@:
	cmp	r11,rsi
	jbe	@f
	movzx	edx,byte [r11-1]
	cmp	dl,'/'
	je	@f
	dec	r11
	jmp	@b
@@:
	lea	rcx,[rsi+rcx]
.d:
	cmp	r11,rcx
	jae	.got
	movzx	edx,byte [r11]
	sub	edx,'0'
	cmp	edx,9
	ja	.got
	imul	eax,eax,10
	add	eax,edx
	inc	r11
	jmp	.d
.got:
	test	r10d,r10d
	jnz	.answer
	imul	edx,eax,1000			; held that long, then called again
	xor	eax,eax
	ret
.answer:
	mov	r8,rdi
	mov	dword [rdi],'wait'
	mov	word [rdi+4],'ed'
	mov	byte [rdi+6],' '
	add	rdi,7
	call	fmt_u64
	mov	rdx,rdi
	sub	rdx,r8
	mov	eax,200
	xor	ecx,ecx
	lea	rsi,[mt_plain]
	ret

mt_octets	db 'application/octet-stream',0
