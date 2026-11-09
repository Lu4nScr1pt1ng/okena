; Ranges of CDN providers, by name, where trusted_proxies and allow/deny take an
; address: `trusted_proxies cloudflare`, `allow cloudflare`. The lists are files in
; contrib/ranges, built into okena; `okena ranges NAME` prints one. A fresher list
; (contrib/ranges/update.sh) goes in through file:PATH, which both take too.

rodata
	rng_cloudflare	file '../../contrib/ranges/cloudflare.txt'
	rng_cloudflare.len = $ - rng_cloudflare
end rodata

; rdi/esi = a word: rsi/edx = its provider's ranges (text, a range a line). CF: not
; a provider's name. Keeps rbx, r8-r15.
ranges_named:
	cmp	esi,10
	jne	.no
	cmp	dword [rdi],'clou'
	jne	.no
	cmp	dword [rdi+4],'dfla'
	jne	.no
	cmp	word [rdi+8],'re'
	jne	.no
	lea	rsi,[rng_cloudflare]
	mov	edx,rng_cloudflare.len
	clc
	ret
.no:
	stc
	ret

; rsi/edx = text, a range a line (`#` to the end of a line is a comment), rax = what
; takes each (rdi/esi = it; it keeps rbx, r12, r13). Keeps rbx, r12, r13.
ranges_each:
	push	rbx
	push	r12
	push	r13
	mov	r13,rax
	mov	rbx,rsi
	mov	edx,edx
	lea	r12,[rsi+rdx]
.line:
	cmp	rbx,r12
	jae	.out
	mov	al,[rbx]
	cmp	al,' '
	jbe	.blank
	cmp	al,'#'
	je	.comment
	mov	rdi,rbx
@@:
	cmp	rbx,r12
	jae	@f
	cmp	byte [rbx],' '
	jbe	@f
	inc	rbx
	jmp	@b
@@:
	mov	rsi,rbx
	sub	rsi,rdi
	call	r13
	jmp	.line
.blank:
	inc	rbx
	jmp	.line
.comment:
	cmp	rbx,r12
	jae	.out
	cmp	byte [rbx],10
	je	.line
	inc	rbx
	jmp	.comment
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; `okena ranges NAME`: its list, as built in
cli_ranges:
	cmp	qword [g_argc],3
	jb	.usage
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	call	ranges_named
	jc	.usage
	mov	edi,1
	call	write_all
	xor	edi,edi
	jmp	exit_process
.usage:
	call	log_begin
	out_lit 'okena ranges NAME: the ranges okena knows by that name (cloudflare)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; compiling trusted_proxies: rdi/esi = one range, into the listener's. Keeps rbx,
; r12, r13.
trust_add:
	mov	ecx,[g_plan_trust]
	cmp	ecx,MAX_TRUST
	jae	plan_too_many
	inc	dword [g_plan_trust]
	inc	dword [g_cmp_tcount]
	imul	rdx,rcx,TR_SIZE
	lea	rdx,[g_trust+rdx]
	call	parse_cidr
	jc	plan_bad_tproxies
	ret

; rdi/esi = a trusted_proxies word: a provider's name or file:PATH, each of their
; ranges added. CF: neither (a range of its own). Keeps rbx, r12, r13.
trust_list:
	push	rdi
	push	rsi
	call	ranges_named
	jc	.file
	add	rsp,16
	lea	rax,[trust_add]
	call	ranges_each
	clc
	ret
.file:
	pop	rsi
	pop	rdi
	cmp	esi,6
	jb	.no
	cmp	dword [rdi],'file'
	jne	.no
	cmp	byte [rdi+4],':'
	jne	.no
	lea	ecx,[rsi-5]
	cmp	ecx,1000
	ja	plan_bad_tproxies
	lea	rsi,[rdi+5]
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_tproxies
	mov	rsi,rax
	lea	rax,[trust_add]
	call	ranges_each
	clc
	ret
.no:
	stc
	ret

plan_bad_tproxies:
	call	log_begin
	out_lit 'trusted_proxies takes addresses, ranges, a provider (cloudflare), or file:PATH with a range a line'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
