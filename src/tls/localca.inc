; A local CA, for development names (localhost, *.test, 127.0.0.1): a tls block's
; `local NAME...` is a certificate for them that okena's own CA signs, so that a
; browser or curl trusting that CA (`okena trust`) takes them without a warning.
;
;   okena { local_ca /var/lib/okena/ca }      (the default)
;   http :443 { tls { local localhost app.test 127.0.0.1 } ... }
;
; The CA: DIR/root.key (P-256, 0600) and DIR/root.pem (10 years), made at the
; first start that needs them (or by `okena trust`), the directory 0700 and the
; `user`'s. Its certificates are signed at each compile, in memory: a new key,
; 7 days, the CA as issuer (its key identifier named); a reload of okena's own
; renews them 4 days and 16 hours on (two thirds). Until there is a CA (a reload
; that finds none), a name gets one that signs itself, as acme's do meanwhile.
;
; `okena trust [-c FILE]` puts DIR/root.pem in the system's trust store and runs
; its update command (Debian/Ubuntu/Alpine, Fedora/RHEL, openSUSE, Arch);
; `okena trust remove` takes it out.

LCA_ON		:= 0			; d: a `local` line
LCA_DIRL	:= 4			; d
LCA_DIR		:= 8			; q
LCA_NEXT	:= 16			; q: realtime second: a reload renews them
LCA_LOADED	:= 24			; d: 1 the CA read, 2 none to be had
LCA_SIZE	:= 32
LCA_DAYS	:= 7
LCA_RENEW	:= 4 * 86400 + 16 * 3600
LCA_CA_DAYS	:= 3650
SYS_fork_	:= 57
SYS_execve_	:= 59
SYS_wait4_	:= 61

bss
	align 8
	g_plan_lca:	rb LCA_SIZE
	g_lc_path:	rb 600
	g_lc_pub:	rb 65
	g_lc_names:	rb 64
	g_lc_der:	rb 8192
	g_lc_store	dd ?			; okena trust: which store
end bss

rodata
	lc_default	db '/var/lib/okena/ca'
	lc_default.len = $ - lc_default
	lc_f_pem	db '/root.pem',0
	lc_f_key	db '/root.key',0
	lc_cn		db 'okena local CA '
	lc_cn.len = $ - lc_cn
	lc_hex		db '0123456789abcdef'
	; the trust stores: a directory, the file okena puts there, the command
	; that brings the system's bundle up to date (its arguments, NUL-ended)
	lc_st1		db '/usr/local/share/ca-certificates',0, 'okena-local-ca.crt',0, 'update-ca-certificates',0,0
	lc_st2		db '/etc/pki/ca-trust/source/anchors',0, 'okena-local-ca.pem',0, 'update-ca-trust',0,'extract',0,0
	lc_st3		db '/etc/pki/trust/anchors',0, 'okena-local-ca.pem',0, 'update-ca-certificates',0,0
	lc_st4		db '/etc/ca-certificates/trust-source/anchors',0, 'okena-local-ca.crt',0, 'trust',0,'extract-compat',0,0
	lc_stores	dq lc_st1, lc_st2, lc_st3, lc_st4, 0
	lc_path_def	db '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',0
end rodata

; rbx = okena's `local_ca DIR`
compile_local_ca:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,2
	jb	.bad
	cmp	edx,200
	ja	.bad
	cmp	byte [rcx],'/'
	jne	.bad
	cmp	byte [rcx+rdx-1],'/'
	jne	@f
	dec	edx
@@:
	mov	[g_plan_lca+LCA_DIR],rcx
	mov	[g_plan_lca+LCA_DIRL],edx
	ret
.bad:
	call	log_begin
	out_lit 'local_ca takes a directory: its whole path, 200 bytes at most'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rsi = a file's name ('/root.pem'): DIR/it in g_lc_path, NUL-ended
local_ca_path:
	cmp	dword [g_plan_lca+LCA_DIRL],0
	jne	@f
	lea	rax,[lc_default]
	mov	[g_plan_lca+LCA_DIR],rax
	mov	dword [g_plan_lca+LCA_DIRL],lc_default.len
@@:
	lea	rdi,[g_lc_path]
	push	rsi
	mov	rsi,[g_plan_lca+LCA_DIR]
	mov	ecx,[g_plan_lca+LCA_DIRL]
	rep	movsb
	pop	rsi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	ret

; the CA, read once a compile: its subject, key and key identifier for
; x5_selfsigned (g_x5_iss*). CF: none to be had.
local_ca_load:
	cmp	dword [g_plan_lca+LCA_LOADED],1
	je	.ok
	cmp	dword [g_plan_lca+LCA_LOADED],2
	je	.none
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	lea	rdi,[g_lc_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.none
	mov	rsi,rax
	lea	rdi,[g_lc_der]
	call	pem_first_cert
	test	eax,eax
	jz	.none
	lea	rsi,[g_lc_der]
	mov	edx,eax
	call	x509_locate
	test	eax,eax
	jz	.none
	mov	rsi,[g_x509_subj]
	mov	rcx,[g_x509_subjend]
	sub	rcx,rsi
	cmp	rcx,480
	ja	.none
	mov	[g_x5_issnl],ecx
	lea	rdi,[g_x5_issname]
	rep	movsb
	lea	rsi,[lc_f_key]
	call	local_ca_path
	lea	rdi,[g_lc_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.none
	mov	rsi,rax
	add	rdx,rax
	lea	rdi,[pem_ec_key]
	call	pem_next
	cmp	eax,0
	jle	.none
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	key_sec1
	test	eax,eax
	jnz	.none
	lea	rsi,[g_tls_d]
	lea	rdi,[g_x5_issd]
	mov	ecx,32
	rep	movsb
	lea	rdi,[g_tls_d]
	mov	ecx,32
	call	secure_zero
	lea	rdi,[g_lc_pub]
	lea	rsi,[g_x5_issd]
	call	p256_public
	lea	rdi,[g_x5_isskid]
	lea	rsi,[g_lc_pub]
	mov	edx,65
	call	sha1
	mov	dword [g_plan_lca+LCA_LOADED],1
.ok:
	clc
	ret
.none:
	mov	dword [g_plan_lca+LCA_LOADED],2
	stc
	ret

; rdi = a tls block, edx = its group: each `local NAME...` line, a certificate
; the local CA signs (one signing itself while there is none)
compile_tls_local:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,edx
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_TLSLOCAL]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	dword [g_plan_lca+LCA_ON],1
	; the names: a DNS name (a wildcard's first label '*'), or an address
	mov	r14,[rbx+N_ARGS]
	mov	r15d,[rbx+N_ARGC]
.name:
	mov	rsi,[r14+A_VAL]
	mov	ecx,[r14+A_VLEN]
	test	ecx,ecx
	jz	.bad_name
	cmp	ecx,253
	ja	.bad_name
@@:
	mov	al,[rsi]
	inc	rsi
	cmp	al,'-'
	je	.ch
	cmp	al,'.'
	je	.ch
	cmp	al,'*'
	je	.ch
	cmp	al,':'
	je	.ch
	cmp	al,'0'
	jb	.bad_name
	cmp	al,'9'
	jbe	.ch
	or	al,0x20
	cmp	al,'a'
	jb	.bad_name
	cmp	al,'z'
	ja	.bad_name
.ch:
	dec	ecx
	jnz	@b
	add	r14,A_SIZE
	dec	r15d
	jnz	.name
	mov	r14,[rbx+N_ARGS]
	lea	rdi,[g_ac_names]
	mov	rsi,r14
	mov	edx,[rbx+N_ARGC]
	call	acme_names
	call	x5_keygen
	jc	.no_key
	call	local_ca_load
	jc	.selfsigned
	mov	dword [g_x5_issuing],1
	lea	rsi,[g_ac_names]
	mov	edx,LCA_DAYS
	call	x5_selfsigned
	mov	dword [g_x5_issuing],0
	jc	.no_key
	mov	byte [g_cc_from],3		; (okena certs: the local CA's)
	cmp	qword [g_plan_lca+LCA_NEXT],0
	jne	.pem
	push	rax
	call	acme_now
	add	rax,LCA_RENEW
	mov	[g_plan_lca+LCA_NEXT],rax
	pop	rax
	jmp	.pem
.selfsigned:
	lea	rsi,[g_ac_names]
	mov	edx,LCA_DAYS
	call	x5_selfsigned
	jc	.no_key
	mov	byte [g_cc_from],4		; (no CA yet)
.pem:
	mov	ecx,eax
	lea	rsi,[g_x5_der2]
	lea	rdx,[pem_l_cert]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	mov	byte [rdi],0
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_x5_pem]
	mov	edx,ARG_MEM
	call	compile_tls_acme.arg
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_ac_kpem]
	call	x5_pem
	mov	byte [rdi],0
	lea	rdi,[g_ac_karg]
	lea	rsi,[g_ac_kpem]
	mov	edx,ARG_MEM
	call	compile_tls_acme.arg
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_ac_karg]
	mov	edx,r13d
	call	compile_cert
	mov	eax,[g_plan_tls]
	dec	eax
	mov	cl,[g_cc_from]
	mov	[g_tls_src+rax],cl
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad_name:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'tls { local NAME... }: names (letters, digits, ',39,'-',39,' and ',39,'.',39,', a wildcard',39,'s ',39,'*',39,') or addresses'
	jmp	tls_error_end
.no_key:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'tls { local NAME... }: no key could be made'
	jmp	tls_error_end

; Starting (not yet boxed in): `local` lines and no CA in DIR: one made, and the
; configuration compiled again with it
local_ca_start:
	cmp	dword [g_plan_lca+LCA_ON],0
	je	.out
	cmp	dword [g_plan_lca+LCA_LOADED],2
	jne	.out
	call	local_ca_make
	jc	.out
	call	cfg_parse_checked
	call	plan_reset
	call	plan_compile
.out:
	ret

; DIR (and its parents) made, a CA's key and certificate written there, the
; `user`'s. CF: it could not be (said).
local_ca_make:
	push	rbx
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	; the directories, each in turn (0700: the last one is DIR)
	mov	ecx,[g_plan_lca+LCA_DIRL]
	mov	byte [g_lc_path+rcx],0
	mov	ebx,1
.dir:
	cmp	ebx,ecx
	ja	.dirs
	cmp	byte [g_lc_path+rbx],'/'
	je	.mk
	cmp	ebx,ecx
	jne	.dnext
.mk:
	push	rcx
	mov	al,[g_lc_path+rbx]
	push	rax
	mov	byte [g_lc_path+rbx],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_lc_path]
	mov	edx,0x1ED			; 0755: a parent
	cmp	ebx,[rsp+8]
	jne	@f
	mov	edx,0x1C0			; 0700: DIR
@@:
	mov	eax,SYS_mkdirat_
	syscall
	pop	rax
	mov	[g_lc_path+rbx],al
	pop	rcx
.dnext:
	inc	ebx
	jmp	.dir
.dirs:
	call	.own
	; the key, and its identifier
	call	x5_keygen
	jc	.bad
	lea	rdi,[g_x5_kid]
	lea	rsi,[g_x5_pub]
	mov	edx,65
	call	sha1
	; its name: okena local CA, 8 random hex digits (one CA a machine)
	lea	rdi,[g_lc_names]
	lea	rsi,[lc_cn]
	mov	ecx,lc_cn.len
	rep	movsb
	push	rdi
	lea	rdi,[g_lc_der]
	mov	esi,4
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	rdi
	xor	ecx,ecx
@@:
	movzx	eax,byte [g_lc_der+rcx]
	mov	edx,eax
	shr	eax,4
	and	edx,15
	mov	al,[lc_hex+rax]
	mov	dl,[lc_hex+rdx]
	mov	[rdi],al
	mov	[rdi+1],dl
	add	rdi,2
	inc	ecx
	cmp	ecx,4
	jb	@b
	mov	word [rdi],0
	mov	dword [g_x5_mkca],1
	lea	rsi,[g_lc_names]
	mov	edx,LCA_CA_DAYS
	call	x5_selfsigned
	mov	dword [g_x5_mkca],0
	jc	.bad
	; the key first (0600), then the certificate (0644)
	mov	ecx,eax
	lea	rsi,[g_x5_der2]
	lea	rdx,[pem_l_cert]
	lea	rdi,[g_lc_der]
	call	x5_pem
	lea	rax,[g_lc_der]
	sub	rdi,rax
	push	rdi
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	lea	rdx,[g_x5_pem]
	sub	rdi,rdx
	mov	edx,edi
	lea	rsi,[g_x5_pem]
	push	rsi
	push	rdx
	lea	rsi,[lc_f_key]
	call	local_ca_path
	pop	rdx
	pop	rsi
	mov	r10d,0x180
	call	.write
	pop	rdx
	jc	.bad
	push	rdx
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	pop	rdx
	lea	rsi,[g_lc_der]
	mov	r10d,0x1A4
	call	.write
	jc	.bad
	lea	rdi,[g_x5_d]
	mov	ecx,32
	call	secure_zero
	call	log_begin
	out_lit 'local CA: made, '
	lea	rsi,[g_lc_path]
	call	out_cstr
	out_lit ' (okena trust: the system trusts it)'
	call	log_end
	clc
	pop	rbx
	ret
.bad:
	call	log_begin
	out_lit 'local CA: it could not be made in '
	mov	rsi,[g_plan_lca+LCA_DIR]
	mov	edx,[g_plan_lca+LCA_DIRL]
	call	out_str
	out_lit ': its certificates sign themselves'
	call	log_end
	stc
	pop	rbx
	ret
; g_lc_path: written (r10d its mode), rsi/edx what; the `user`'s. CF: not.
.write:
	push	rsi
	push	rdx
	mov	edi,AT_FDCWD
	lea	rsi,[g_lc_path]
	mov	edx,O_WRONLY or O_CREAT or O_TRUNC or O_CLOEXEC
	mov	eax,SYS_openat
	syscall
	pop	rdx
	pop	rsi
	test	eax,eax
	js	.wbad
	push	rax
	mov	edi,eax
	call	write_all
	pop	rdi
	pushfq
	mov	eax,SYS_close
	syscall
	popfq
	jc	.wbad
.own:
	cmp	dword [g_plan_user],0
	je	@f
	mov	edi,AT_FDCWD
	lea	rsi,[g_lc_path]
	mov	edx,[g_plan_uid]
	mov	r10d,[g_plan_gid]
	xor	r8d,r8d
	mov	eax,SYS_fchownat_
	syscall
@@:
	clc
	ret
.wbad:
	stc
	ret

; the supervisor, each second: the local CA's certificates due: a reload
; renews them. eax = 1 then.
local_tick:
	mov	rax,[g_plan_lca+LCA_NEXT]
	test	rax,rax
	jz	.no
	push	rax
	call	acme_now
	pop	rcx
	cmp	rax,rcx
	jb	.no
	add	rax,3600			; (a reload refused: again in an hour)
	mov	[g_plan_lca+LCA_NEXT],rax
	call	log_begin
	out_lit 'local CA: its certificates renewed: reloading'
	call	log_end
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; ------------------------------------------------------------------ CLI

; `okena trust [remove] [-c FILE]`: the local CA (made, when there is none) in the
; system's trust store, or out of it
cli_trust:
	push	rbx
	push	r12
	xor	r12d,r12d			; 1: remove
	mov	edi,2
	cmp	qword [g_argc],3
	jb	.args
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	cstring .w_remove, 'remove',0
	lea	rsi,[.w_remove]
	call	cstr_eq
	mov	edi,2
	test	eax,eax
	jz	.args
	mov	r12d,1
	mov	edi,3
.args:
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	; the store: the first whose directory is there
	lea	rbx,[lc_stores]
.store:
	mov	rsi,[rbx]
	test	rsi,rsi
	jz	.no_store
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_DIRECTORY_ or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	jns	.found
	add	rbx,8
	jmp	.store
.found:
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	mov	rbx,[rbx]			; dir, file, command...
	; its path: g_sg_msg
	lea	rdi,[g_sg_msg]
	mov	rsi,rbx
@@:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	@b
@@:
	mov	byte [rdi],'/'
	inc	rdi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	push	rsi				; (the command)
	test	r12d,r12d
	jnz	.remove
	; the CA: made if none
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	lea	rdi,[g_lc_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	jns	.have
	call	local_ca_make
	jc	.fail
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	lea	rdi,[g_lc_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.fail
.have:
	push	rax
	push	rdx
	mov	edi,AT_FDCWD
	lea	rsi,[g_sg_msg]
	mov	edx,O_WRONLY or O_CREAT or O_TRUNC or O_CLOEXEC
	mov	r10d,0x1A4			; 0644
	mov	eax,SYS_openat
	syscall
	pop	rdx
	pop	rsi
	test	eax,eax
	js	.denied
	push	rax
	mov	edi,eax
	call	write_all
	pop	rdi
	mov	eax,SYS_close
	syscall
	jmp	.update
.remove:
	lea	rdi,[g_sg_msg]
	mov	eax,SYS_unlink_
	syscall
	cmp	eax,-2				; (ENOENT: not there; said all the same)
	je	.update
	test	eax,eax
	js	.denied
.update:
	pop	rsi
	call	lc_run
	push	rax
	call	log_begin
	out_lit 'okena trust: '
	lea	rsi,[g_lc_path]
	test	r12d,r12d
	jz	@f
	out_lit 'the local CA out of '
	jmp	.said
@@:
	call	out_cstr
	out_lit ' put in '
.said:
	lea	rsi,[g_sg_msg]
	call	out_cstr
	out_lit '; '
	pop	rax
	test	eax,eax
	jnz	.cmd_bad
	out_lit 'the system',39,'s bundle brought up to date'
	call	log_end
	test	r12d,r12d
	jnz	@f
	call	log_begin
	out_lit '(browsers with their own store, as Firefox: certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n okena -i '
	lea	rsi,[g_lc_path]
	call	out_cstr
	out_lit ')'
	call	log_end
@@:
	xor	edi,edi
	jmp	exit_process
.cmd_bad:
	push	rax
	out_lit 'its update command failed (exit '
	pop	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,1
	jmp	exit_process
.no_store:
	call	log_begin
	out_lit 'okena trust: no trust store known here (/usr/local/share/ca-certificates, /etc/pki/ca-trust/source/anchors, /etc/pki/trust/anchors, /etc/ca-certificates/trust-source/anchors); trust '
	lea	rsi,[lc_f_pem]
	call	local_ca_path
	lea	rsi,[g_lc_path]
	call	out_cstr
	out_lit ' as the system says'
	call	log_end
	mov	edi,1
	jmp	exit_process
.denied:
	call	log_begin
	out_lit 'okena trust: '
	lea	rsi,[g_sg_msg]
	call	out_cstr
	out_lit ' cannot be written (as root?)'
	call	log_end
	mov	edi,1
	jmp	exit_process
.fail:
	mov	edi,1
	jmp	exit_process

; rsi = a command and its arguments (NUL between, an empty one at the end): run,
; found in PATH (then the system's directories). eax = its exit status (127:
; not found).
lc_run:
	push	rbx
	push	r12
	push	r13
	sub	rsp,8 * 8			; argv
	xor	ecx,ecx
@@:
	cmp	byte [rsi],0
	je	@f
	mov	[rsp+rcx*8],rsi
	inc	ecx
.skip:
	lodsb
	test	al,al
	jnz	.skip
	cmp	ecx,6
	jb	@b
@@:
	mov	qword [rsp+rcx*8],0
	mov	eax,SYS_fork_
	syscall
	test	eax,eax
	js	.failed
	jnz	.parent
	; the child: each directory of PATH, then the default ones
	mov	rbx,[g_envp]
@@:
	mov	rsi,[rbx]
	test	rsi,rsi
	jz	.defaults
	add	rbx,8
	cmp	dword [rsi],'PATH'
	jne	@b
	cmp	byte [rsi+4],'='
	jne	@b
	lea	rsi,[rsi+5]
	call	.dirs
.defaults:
	lea	rsi,[lc_path_def]
	call	.dirs
	mov	edi,127
	mov	eax,SYS_exit_group
	syscall
; rsi = dir:dir:...: execve each dir/argv[0]
.dirs:
	cmp	byte [rsi],0
	je	.dirs_done
	lea	rdi,[g_lc_der]
@@:
	lodsb
	test	al,al
	jz	@f
	cmp	al,':'
	je	@f
	stosb
	jmp	@b
@@:
	push	rax
	push	rsi
	mov	byte [rdi],'/'
	inc	rdi
	mov	rsi,[rsp+16+8]			; (argv[0], under the return address)
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	lea	rdi,[g_lc_der]
	lea	rsi,[rsp+16+8]
	mov	rdx,[g_envp]
	mov	eax,SYS_execve_
	syscall
	pop	rsi
	pop	rax
	test	al,al
	jnz	.dirs
.dirs_done:
	ret
.parent:
	mov	r12d,eax
	push	0
.wait:
	mov	edi,r12d
	mov	rsi,rsp
	xor	edx,edx
	xor	r10d,r10d
	mov	eax,SYS_wait4_
	syscall
	cmp	rax,-EINTR
	je	.wait
	pop	rax
	mov	ecx,eax
	and	ecx,0x7F
	jnz	.failed			; (killed by a signal)
	shr	eax,8
	and	eax,0xFF
	jmp	.out
.failed:
	mov	eax,126
.out:
	add	rsp,8 * 8
	pop	r13
	pop	r12
	pop	rbx
	ret
