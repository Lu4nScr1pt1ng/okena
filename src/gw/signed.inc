; `signed_urls key=FILE [key2=FILE]` on a route: only links the origin signed are
; served, until they expire. A link carries, in its query:
;
;   expires=UNIX-SECONDS        when it stops working
;   prefix=PATH                 (optional) good for every path under it, not just this
;   ip=ADDRESS                  (optional) only for this client
;   sig=BASE64URL               HMAC-SHA256 of "PATH-OR-PREFIX\nEXPIRES\nIP" (IP empty
;                               when there is none), the path as it is in the link
;
; The key is the first line of its file; key2= is a second one taken as well, for a
; rotation. Anything wrong is a 403, the same for every way of being wrong. It is
; checked on every request, before the cache: a cached answer still needs a link.
; The cache keeps one answer for every link to the same thing: those four
; parameters are not in its key.
;
; `okena sign KEYFILE PATH TTL [prefix=P] [ip=A]` prints a link.

MAX_SIGNED	:= 64
SU_KEY1		:= 0				; 128
SU_K1LEN	:= 128				; d
SU_KEY2		:= 132				; 128
SU_K2LEN	:= 260				; d
SU_SIZE		:= 264
SU_KEY_MAX	:= 128
RA_SIGNED	:= 172				; d: the route's signed_urls + 1

bss
	align 8
	g_signed:	rb SU_SIZE * MAX_SIGNED
	g_plan_signed	dd ?
	g_sg_exp	dq ?			; the link's
	g_sg_expp	dq ?			; its text
	g_sg_expl	dd ?
	g_sg_prep	dq ?
	g_sg_prel	dd ?
	g_sg_ipp	dq ?
	g_sg_ipl	dd ?
	g_sg_sigp	dq ?
	g_sg_sigl	dd ?
	g_sg_ip:	rb 16
	g_sg_mac:	rb 32
	g_sg_b64:	rb 48
	g_sg_pre:	rb 1024			; prefix=, decoded
	g_sg_msg:	rb 2048 + 64
end bss

; rsi/ecx = a query parameter's value: g_sg_pre/eax = it percent-decoded. CF: too
; long or not hex.
sg_decode:
	lea	rdi,[g_sg_pre]
	lea	r8,[rsi+rcx]
	xor	edx,edx
.c:
	cmp	rsi,r8
	jae	.done
	cmp	edx,1023
	jae	.bad
	lodsb
	cmp	al,'%'
	jne	.put
	lea	rax,[rsi+2]
	cmp	rax,r8
	ja	.bad
	call	admin_purge.hex
	jc	.bad
	shl	eax,4
	mov	r9d,eax
	call	admin_purge.hex
	jc	.bad
	or	eax,r9d
.put:
	stosb
	inc	edx
	jmp	.c
.done:
	mov	eax,edx
	clc
	ret
.bad:
	stc
	ret

; the request's target (g_hm): its parameters of a signature into g_sg_*, and rsi/
; ecx its path. CF: no expires= or sig=, or one twice.
sg_params:
	xor	eax,eax
	mov	[g_sg_expl],eax
	mov	[g_sg_prel],eax
	mov	[g_sg_ipl],eax
	mov	[g_sg_sigl],eax
	mov	qword [g_sg_expp],0
	mov	qword [g_sg_prep],0
	mov	qword [g_sg_ipp],0
	mov	qword [g_sg_sigp],0
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	lea	r8,[rsi+rcx]
	mov	r10,rsi				; the path
@@:
	cmp	rsi,r8
	jae	@f
	cmp	byte [rsi],'?'
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	r11,rsi
	sub	r11,r10				; its length
.pair:
	cmp	rsi,r8
	jae	.done
	inc	rsi				; past ? or &
	mov	rdi,rsi				; its name
@@:
	cmp	rsi,r8
	jae	@f
	cmp	byte [rsi],'='
	je	@f
	cmp	byte [rsi],'&'
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	rcx,rsi
	sub	rcx,rdi				; the name's length
	xor	edx,edx				; its value
	mov	r9,rsi
	cmp	rsi,r8
	jae	.value
	cmp	byte [rsi],'='
	jne	.value
	inc	rsi
	mov	r9,rsi
@@:
	cmp	rsi,r8
	jae	@f
	cmp	byte [rsi],'&'
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	rdx,rsi
	sub	rdx,r9
.value:
	; which one
	lea	rax,[g_sg_expp]
	cmp	ecx,7
	jne	@f
	cmp	dword [rdi],'expi'
	jne	.pair
	cmp	dword [rdi+3],'ires'
	je	.take
	jmp	.pair
@@:
	lea	rax,[g_sg_prep]
	cmp	ecx,6
	jne	@f
	cmp	dword [rdi],'pref'
	jne	.pair
	cmp	word [rdi+4],'ix'
	je	.take
	jmp	.pair
@@:
	cmp	ecx,3
	jne	@f
	lea	rax,[g_sg_sigp]
	cmp	word [rdi],'si'
	jne	.not_sig
	cmp	byte [rdi+2],'g'
	je	.take
.not_sig:
	jmp	.pair
@@:
	cmp	ecx,2
	jne	.pair
	lea	rax,[g_sg_ipp]
	cmp	word [rdi],'ip'
	je	.take
	jmp	.pair
.take:
	cmp	qword [rax],0
	jne	.bad				; (twice: which would count?)
	mov	[rax],r9
	mov	[rax+8],edx
	jmp	.pair
.done:
	cmp	qword [g_sg_expp],0
	je	.bad
	cmp	qword [g_sg_sigp],0
	je	.bad
	mov	rsi,r10
	mov	ecx,r11d
	clc
	ret
.bad:
	stc
	ret
assert g_sg_expl = g_sg_expp + 8
assert g_sg_prel = g_sg_prep + 8
assert g_sg_ipl = g_sg_ipp + 8
assert g_sg_sigl = g_sg_sigp + 8

; rdi/esi = a message, r12 = the route's signed_urls: CF unless sig= is its MAC under
; one of the keys
sg_verify:
	push	rbx
	push	r13
	mov	rbx,rdi
	mov	r13d,esi
	cmp	dword [g_sg_sigl],43		; (32 bytes, base64url without padding)
	jne	.no
	lea	rsi,[r12+SU_KEY1]
	mov	edx,[r12+SU_K1LEN]
	call	.one
	jnc	.out
	mov	edx,[r12+SU_K2LEN]
	test	edx,edx
	jz	.no
	lea	rsi,[r12+SU_KEY2]
	call	.one
	jmp	.out
.no:
	stc
.out:
	pop	r13
	pop	rbx
	ret
; rsi/edx = a key: CF unless it signed it
.one:
	lea	rdi,[g_sg_mac]
	mov	rcx,rbx
	mov	r8d,r13d
	call	hmac_sha256
	lea	rdi,[g_sg_b64]
	lea	rsi,[g_sg_mac]
	mov	edx,32
	call	base64url_encode
	lea	rdi,[g_sg_b64]
	mov	rsi,[g_sg_sigp]
	mov	edx,43
	call	ct_equal
	cmp	eax,1				; CF when not
	ret

; eax = the action's RA_SIGNED, r15, ebx, g_hm = the request: CF refused. Keeps rbx,
; r12-r15, rcx, rdx.
signed_check:
	push	rcx
	push	rdx
	push	r12
	push	r13
	dec	eax
	imul	r12,rax,SU_SIZE
	lea	r12,[g_signed+r12]
	call	sg_params
	jc	.refused
	mov	r9,rsi				; the path
	mov	r10d,ecx
	; not expired
	mov	rsi,[g_sg_expp]
	mov	ecx,[g_sg_expl]
	test	ecx,ecx
	jz	.refused
	cmp	ecx,12
	ja	.refused
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.refused
	imul	rax,rax,10
	add	rax,rdx
	inc	rsi
	dec	ecx
	jnz	@b
	mov	[g_sg_exp],rax
	push	r9
	push	r10
	call	pr_clock
	pop	r10
	pop	r9
	mov	rax,[g_pr_now]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	cmp	rax,[g_sg_exp]
	ja	.refused
	; under its prefix, or the path itself
	cmp	qword [g_sg_prep],0
	je	.path
	mov	rsi,[g_sg_prep]
	mov	ecx,[g_sg_prel]
	push	r9
	push	r10
	call	sg_decode
	pop	r10
	pop	r9
	jc	.refused
	test	eax,eax
	jz	.refused
	cmp	eax,r10d
	ja	.refused
	mov	ecx,eax
	push	rcx
	mov	rsi,r9
	lea	rdi,[g_sg_pre]
	repe	cmpsb
	pop	rcx
	jne	.refused
	lea	r9,[g_sg_pre]
	mov	r10d,ecx
.path:
	; this client's, when it says one
	cmp	qword [g_sg_ipp],0
	je	.message
	push	r9
	push	r10
	call	http_client_resolve
	pop	r10
	pop	r9
	mov	rdi,[g_sg_ipp]
	mov	esi,[g_sg_ipl]
	cmp	dword [r15+H_CKIND],6
	je	.v6
	push	r9
	push	r10
	call	parse_ipv4_text
	pop	r10
	pop	r9
	jc	.refused
	cmp	eax,[r15+H_CLIENT]
	jne	.refused
	jmp	.message
.v6:
	lea	rdx,[g_sg_ip]
	push	r9
	push	r10
	call	parse_ipv6_text
	pop	r10
	pop	r9
	jc	.refused
	lea	rsi,[g_sg_ip]
	lea	rdi,[r15+H_CLIENT]
	mov	ecx,16
	repe	cmpsb
	jne	.refused
.message:
	; PATH-OR-PREFIX \n EXPIRES \n IP
	cmp	r10d,2000
	ja	.refused
	lea	rdi,[g_sg_msg]
	mov	rsi,r9
	mov	ecx,r10d
	rep	movsb
	mov	al,10
	stosb
	mov	rsi,[g_sg_expp]
	mov	ecx,[g_sg_expl]
	rep	movsb
	stosb
	mov	rsi,[g_sg_ipp]
	mov	ecx,[g_sg_ipl]
	cmp	ecx,46
	ja	.refused
	rep	movsb
	lea	rax,[g_sg_msg]
	mov	rsi,rdi
	sub	rsi,rax
	mov	rdi,rax
	call	sg_verify
	jc	.refused
	clc
	jmp	.out
.refused:
	stc
.out:
	pop	r13
	pop	r12
	pop	rdx
	pop	rcx
	ret

; r15's route is signed: CF (ck_make leaves a signature's parameters out of the key)
macro sg_route_signed
	local no
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	no				; (clears CF)
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_SIGNED],1	; CF when 0: the other way round
	cmc
no:
end macro

; rdi/ecx = a parameter's name: ZF when it is one of a signature's
sg_is_param:
	cmp	ecx,7
	jne	@f
	cmp	dword [rdi],'expi'
	jne	.no
	cmp	dword [rdi+3],'ires'
	ret
@@:
	cmp	ecx,6
	jne	@f
	cmp	dword [rdi],'pref'
	jne	.no
	cmp	word [rdi+4],'ix'
	ret
@@:
	cmp	ecx,3
	jne	@f
	cmp	word [rdi],'si'
	jne	.no
	cmp	byte [rdi+2],'g'
	ret
@@:
	cmp	ecx,2
	jne	.no
	cmp	word [rdi],'ip'
	ret
.no:
	or	ecx,ecx				; (ZF clear: ecx is never 0 here)
	jnz	@f
	inc	ecx
@@:
	ret

; ------------------------------------------------------------ compiling

; r13 = the route's action, rbx = its signed_urls node
compile_signed:
	mov	eax,[g_plan_signed]
	cmp	eax,MAX_SIGNED
	jae	plan_bad_signed
	inc	dword [g_plan_signed]
	lea	ecx,[rax+1]
	mov	[r13+RA_SIGNED],ecx
	imul	r12,rax,SU_SIZE
	lea	r12,[g_signed+r12]
	cstring .k_key, 'key',0
	lea	rsi,[.k_key]
	lea	rdi,[r12+SU_KEY1]
	call	.key
	jc	plan_bad_signed
	mov	[r12+SU_K1LEN],eax
	cstring .k_key2, 'key2',0
	lea	rsi,[.k_key2]
	lea	rdi,[r12+SU_KEY2]
	call	.key
	jnc	@f
	test	eax,eax
	jnz	plan_bad_signed
@@:
	mov	[r12+SU_K2LEN],eax
	ret
; rsi = the option, rdi = where: eax = the key's length (its file's first line); CF
; with eax 0 when there is no such option
.key:
	push	rdi
	mov	rdi,rbx
	call	node_option
	pop	rdi
	test	rax,rax
	jnz	@f
	xor	eax,eax
	stc
	ret
@@:
	push	rdi
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4000
	jae	.bad_pop
	lea	rdi,[g_trust_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad_pop
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
	jb	.bad_pop
	cmp	ecx,SU_KEY_MAX
	ja	.bad_pop
	pop	rdi
	mov	rsi,rax
	mov	edx,ecx
	rep	movsb
	mov	eax,edx
	clc
	ret
.bad_pop:
	pop	rdi
	mov	eax,1
	stc
	ret

plan_bad_signed:
	call	log_begin
	out_lit 'signed_urls needs key=FILE (its first line, 16 to 128 bytes, the key), key2=FILE as well for a rotation, and at most 64 routes have it'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------------ CLI

; `okena sign KEYFILE PATH TTL [prefix=P] [ip=A]`: a signed link on stdout
cli_sign:
	cmp	qword [g_argc],5
	jb	.usage
	mov	rax,[g_argv]
	mov	rsi,[rax+16]			; the key (its file: a line is all it takes)
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.usage
	mov	ebx,eax
	mov	edi,eax
	lea	rsi,[g_sg_msg]
	mov	edx,1024
	xor	eax,eax				; read
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rdx
	test	rdx,rdx
	jle	.usage
	lea	rax,[g_sg_msg]
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
	jb	.usage
	cmp	ecx,SU_KEY_MAX
	ja	.usage
	lea	rdi,[g_signed+SU_KEY1]
	mov	rsi,rax
	mov	[g_signed+SU_K1LEN],ecx
	rep	movsb
	; when it expires
	mov	rax,[g_argv]
	mov	rdi,[rax+32]
	call	.len
	call	parse_duration
	test	rax,rax
	jz	.usage
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	push	rax
	call	pr_clock
	mov	rax,[g_pr_now]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	pop	rcx
	add	rax,rcx
	mov	[g_sg_exp],rax
	; prefix=, ip=
	mov	qword [g_sg_prep],0
	mov	qword [g_sg_ipp],0
	mov	dword [g_sg_prel],0
	mov	dword [g_sg_ipl],0
	mov	r12d,5
.opt:
	cmp	r12,[g_argc]
	jae	.opts
	mov	rax,[g_argv]
	mov	rdi,[rax+r12*8]
	inc	r12d
	cmp	dword [rdi],'pref'
	jne	@f
	cmp	word [rdi+4],'ix'
	jne	@f
	cmp	byte [rdi+6],'='
	jne	@f
	add	rdi,7
	mov	[g_sg_prep],rdi
	call	.len
	mov	[g_sg_prel],esi
	jmp	.opt
@@:
	cmp	word [rdi],'ip'
	jne	.usage
	cmp	byte [rdi+2],'='
	jne	.usage
	add	rdi,3
	mov	[g_sg_ipp],rdi
	call	.len
	mov	[g_sg_ipl],esi
	jmp	.opt
.opts:
	; the message
	lea	rdi,[g_sg_msg]
	mov	rsi,[g_sg_prep]
	mov	ecx,[g_sg_prel]
	test	rsi,rsi
	jnz	@f
	mov	rax,[g_argv]
	mov	rsi,[rax+24]			; the path
	push	rdi
	mov	rdi,rsi
	call	.len
	mov	ecx,esi
	mov	rsi,rdi
	pop	rdi
@@:
	cmp	ecx,2000
	ja	.usage
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	mov	rax,[g_sg_exp]
	call	fmt_u64
	mov	byte [rdi],10
	inc	rdi
	mov	rsi,[g_sg_ipp]
	mov	ecx,[g_sg_ipl]
	cmp	ecx,46
	ja	.usage
	rep	movsb
	lea	rcx,[g_sg_msg]
	mov	r8,rdi
	sub	r8,rcx
	lea	rdi,[g_sg_mac]
	lea	rsi,[g_signed+SU_KEY1]
	mov	edx,[g_signed+SU_K1LEN]
	call	hmac_sha256
	; PATH?expires=E[&prefix=P][&ip=A]&sig=S
	mov	edi,1
	call	out_select
	mov	rax,[g_argv]
	mov	rdi,[rax+24]
	call	.len
	mov	edx,esi
	mov	rsi,rdi
	call	.write
	out_lit '?expires='
	mov	rax,[g_sg_exp]
	call	out_u64
	cmp	qword [g_sg_prep],0
	je	@f
	out_lit '&prefix='
	mov	rsi,[g_sg_prep]
	mov	edx,[g_sg_prel]
	call	out_str
@@:
	cmp	qword [g_sg_ipp],0
	je	@f
	out_lit '&ip='
	mov	rsi,[g_sg_ipp]
	mov	edx,[g_sg_ipl]
	call	out_str
@@:
	out_lit '&sig='
	lea	rdi,[g_sg_b64]
	lea	rsi,[g_sg_mac]
	mov	edx,32
	call	base64url_encode
	lea	rsi,[g_sg_b64]
	mov	edx,43
	call	out_str
	out_lit 10
	call	out_flush
	xor	edi,edi
	jmp	exit_process
.write:
	jmp	out_str
; rdi = NUL-ended: esi its length
.len:
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	ret
.usage:
	call	log_begin
	out_lit 'okena sign KEYFILE PATH TTL [prefix=PATH] [ip=ADDRESS]: a signed link (the key: the first line of the file, 16 to 128 bytes)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
