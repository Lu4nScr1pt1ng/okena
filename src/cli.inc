; Command line.
;
;   okena [run] [-c FILE]          serve (default file /etc/okena/okena.conf)
;   okena check [FILE]             validate a configuration
;   okena tcp :5432 to db:5432     the configuration itself, on the line
;   okena version | help
;
; OKENA_CONFIG, when set, is configuration text and takes the place of
; the file.

OKENA_VERSION equ '0.0.1'

cstring str_cmd_check, 'check',0
cstring str_cmd_run, 'run',0
cstring str_cmd_version, 'version',0
cstring str_cmd_help, 'help',0
cstring str_cmd_health, 'health',0
cstring str_flag_help, '--help',0
cstring str_flag_version, '--version',0
cstring str_flag_c, '-c',0
cstring str_default_conf, '/etc/okena/okena.conf',0
cstring str_name_cmdline, '<command line>',0
cstring str_name_env, 'OKENA_CONFIG',0
cstring env_okena_config, 'OKENA_CONFIG='

bss
	g_cli_path	dq ?		; configuration file, or 0
	g_cli_text	dq ?		; configuration text, or 0
	g_cli_text_len	dq ?
	g_cli_command	dd ?
end bss

CMD_RUN		= 0
CMD_CHECK	= 1

cli_main:
	mov	rcx,[g_argc]
	cmp	rcx,2
	jb	.run_default
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_cmd_check]
	call	cstr_eq
	test	eax,eax
	jnz	.check
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_cmd_health]
	call	cstr_eq
	test	eax,eax
	jz	@f
	mov	edi,2
	call	cli_source_from_args
	jmp	cli_health
@@:
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_cmd_version]
	call	cstr_eq
	test	eax,eax
	jnz	cli_version
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_flag_version]
	call	cstr_eq
	test	eax,eax
	jnz	cli_version
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_cmd_help]
	call	cstr_eq
	test	eax,eax
	jnz	cli_help
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_flag_help]
	call	cstr_eq
	test	eax,eax
	jnz	cli_help
	mov	rax,[g_argv]
	mov	rdi,[rax+8]
	lea	rsi,[str_cmd_run]
	call	cstr_eq
	test	eax,eax
	jnz	.run
	; anything else is configuration text
	mov	edi,1
	call	cli_source_from_args
	jmp	cli_run
.run_default:
	mov	edi,2
	call	cli_source_from_args
	jmp	cli_run
.run:
	mov	edi,2
	call	cli_source_from_args
	jmp	cli_run
.check:
	mov	edi,2
	call	cli_source_from_args
	jmp	cli_check

; Arguments from index edi on: nothing (OKENA_CONFIG or the default
; file), "-c FILE", a single FILE, or configuration words.
cli_source_from_args:
	push	rbx
	push	r12
	mov	ebx,edi
	mov	rcx,[g_argc]
	cmp	rbx,rcx
	jb	.args
	; no arguments
	lea	rdi,[env_okena_config]
	mov	esi,env_okena_config.len
	call	getenv
	test	rax,rax
	jz	.default
	cmp	byte [rax],0
	je	.default
	mov	[g_cli_text],rax
	mov	rdi,rax
	xor	ecx,ecx
@@:
	cmp	byte [rdi+rcx],0
	je	@f
	inc	rcx
	jmp	@b
@@:
	mov	[g_cli_text_len],rcx
	lea	rax,[str_name_env]
	mov	[g_cfg_name],rax
	mov	dword [g_cfg_inline],1
	jmp	.done
.default:
	lea	rax,[str_default_conf]
	mov	[g_cli_path],rax
	jmp	.done
.args:
	mov	rax,[g_argv]
	mov	r12,[rax+rbx*8]
	mov	rdi,r12
	lea	rsi,[str_flag_c]
	call	cstr_eq
	test	eax,eax
	jz	.single
	lea	rcx,[rbx+2]
	cmp	rcx,[g_argc]
	jne	cli_usage
	mov	rax,[g_argv]
	mov	rax,[rax+rbx*8+8]
	mov	[g_cli_path],rax
	jmp	.done
.single:
	; one argument that is not a directive name: a file, unless it holds
	; a space or a brace (configuration text in one quoted argument)
	lea	rcx,[rbx+1]
	cmp	rcx,[g_argc]
	jne	.words
	xor	ecx,ecx
.scan:
	movzx	eax,byte [r12+rcx]
	test	eax,eax
	jz	.scanned
	cmp	al,' '
	je	.words
	cmp	al,'{'
	je	.words
	inc	ecx
	jmp	.scan
.scanned:
	mov	rdi,r12
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	mov	edx,M_TOP
	call	dir_lookup
	test	rax,rax
	jnz	.words
	mov	rdi,r12
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	lea	rdx,[future_names]
	call	list_index
	test	rax,rax
	jns	.words
	mov	[g_cli_path],r12
	jmp	.done
.words:
	mov	edi,ebx
	call	cli_join_args
	lea	rax,[str_name_cmdline]
	mov	[g_cfg_name],rax
	mov	dword [g_cfg_inline],1
.done:
	pop	r12
	pop	rbx
	ret

; Join argv[edi..] with spaces into g_cli_text.
cli_join_args:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	; measure
	xor	r12d,r12d
	mov	ecx,ebx
.measure:
	cmp	rcx,[g_argc]
	jae	.alloc
	mov	rax,[g_argv]
	mov	rsi,[rax+rcx*8]
@@:
	cmp	byte [rsi],0
	je	@f
	inc	rsi
	inc	r12
	jmp	@b
@@:
	inc	r12
	inc	ecx
	jmp	.measure
.alloc:
	lea	rdi,[g_ar_text]
	cmp	qword [rdi+AR_BASE],0
	jne	@f
	push	rdi
	mov	esi,128 shl 20
	call	arena_init
	pop	rdi
@@:
	lea	rsi,[r12+64]
	call	arena_alloc
	mov	[g_cli_text],rax
	mov	rdi,rax
	mov	ecx,ebx
.copy:
	cmp	rcx,[g_argc]
	jae	.copied
	cmp	ecx,ebx
	je	@f
	mov	byte [rdi],' '
	inc	rdi
@@:
	mov	rax,[g_argv]
	mov	rsi,[rax+rcx*8]
@@:
	mov	al,[rsi]
	test	al,al
	jz	@f
	mov	[rdi],al
	inc	rdi
	inc	rsi
	jmp	@b
@@:
	inc	ecx
	jmp	.copy
.copied:
	mov	rax,rdi
	sub	rax,[g_cli_text]
	mov	[g_cli_text_len],rax
	pop	r13
	pop	r12
	pop	rbx
	ret

cli_usage:
	call	log_begin
	out_lit 'usage: okena [run] [-c FILE] | okena check [FILE] | okena help'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cli_version:
	mov	edi,1
	call	out_select
	out_lit 'okena ', OKENA_VERSION, ' (x86-64, fasm2)', 10
	xor	edi,edi
	jmp	exit_process

cli_help:
	mov	edi,1
	call	out_select
	out_lit 'okena ', OKENA_VERSION, ': L4/L7 load balancer, reverse proxy and API gateway', 10, 10
	out_lit 'usage:', 10
	out_lit '  okena [run] [-c FILE]        serve (default /etc/okena/okena.conf)', 10
	out_lit '  okena check [FILE]           validate a configuration and exit', 10
	out_lit '  okena tcp :5432 to db:5432   configuration given on the command line', 10
	out_lit '  okena health [FILE]          exit 0 when the running instance is ready (/ready)', 10
	out_lit '  okena version', 10, 10
	out_lit 'OKENA_CONFIG, when set, holds configuration text used instead of the file.', 10
	xor	edi,edi
	jmp	exit_process

; Load, parse and check the configuration. Exits with EXIT_CONFIG on any
; error. Returns with the checked tree in g_cfg_root.
bss
	g_src_ptr	dq ?		; configuration text being loaded
	g_src_len	dq ?
end bss

; Read the configuration source into memory: g_src_ptr/len. rax = 0 or
; -errno (file sources only).
cfg_read_source:
	cmp	qword [g_cli_text],0
	jne	.text
	mov	rax,[g_cli_path]
	mov	[g_cfg_name],rax
	lea	rdi,[g_ar_text]
	cmp	qword [rdi+AR_BASE],0
	jne	@f
	mov	esi,128 shl 20
	call	arena_init
@@:
	mov	rdi,[g_cli_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.out
	mov	[g_src_ptr],rax
	mov	[g_src_len],rdx
	xor	eax,eax
.out:
	ret
.text:
	mov	rax,[g_cli_text]
	mov	[g_src_ptr],rax
	mov	rax,[g_cli_text_len]
	mov	[g_src_len],rax
	xor	eax,eax
	ret

cli_load_config:
	push	rbx
	call	cfg_read_source
	test	rax,rax
	js	cfg_parse_checked.read_error
	call	cfg_parse_checked
	pop	rbx
	ret

; Parse and check g_src_ptr/len. Exits with EXIT_CONFIG after printing
; the diagnostics when it is not valid.
cfg_parse_checked:
	push	rbx
	mov	rdi,[g_src_ptr]
	mov	rsi,[g_src_len]
	mov	rdx,[g_cfg_name]
	call	cfg_begin
	call	cfg_parse
	cmp	dword [g_cfg_errors],0
	jne	.failed
	call	cfg_check
	cmp	dword [g_cfg_errors],0
	jne	.failed
	pop	rbx
	ret
.failed:
	mov	edi,2
	call	out_select
	mov	eax,[g_cfg_errors]
	call	out_u64
	out_lit ' error'
	cmp	dword [g_cfg_errors],1
	je	@f
	out_lit 's'
@@:
	out_lit ' in '
	mov	rsi,[g_cfg_name]
	call	out_cstr
	mov	edi,10
	call	out_char
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.read_error:
	mov	rbx,rax
	call	log_begin
	out_lit 'cannot read '
	mov	rsi,[g_cli_path]
	call	out_cstr
	out_lit ': '
	neg	rbx
	cmp	ebx,ENOENT
	jne	@f
	out_lit 'no such file'
	jmp	.reported
@@:
	cmp	ebx,EACCES
	jne	@f
	out_lit 'permission denied'
	jmp	.reported
@@:
	cmp	ebx,EISDIR
	jne	@f
	out_lit 'not a regular file'
	jmp	.reported
@@:
	cmp	ebx,ENOMEM
	jne	@f
	out_lit 'larger than 64 MiB'
	jmp	.reported
@@:
	out_lit 'error '
	mov	eax,ebx
	call	out_u64
.reported:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cli_check:
	call	cli_load_config
	mov	edi,1
	call	out_select
	mov	rsi,[g_cfg_name]
	call	out_cstr
	out_lit ': ok ('
	mov	eax,[g_chk_listeners]
	mov	ecx,0
	call	out_count_listener
	out_lit ', '
	mov	eax,[g_chk_pools]
	call	out_u64
	out_lit ' pool'
	cmp	dword [g_chk_pools],1
	je	@f
	out_lit 's'
@@:
	out_lit ', '
	mov	eax,[g_chk_servers]
	call	out_u64
	out_lit ' server'
	cmp	dword [g_chk_servers],1
	je	@f
	out_lit 's'
@@:
	out_lit ')'
	mov	edi,10
	call	out_char
	xor	edi,edi
	jmp	exit_process

out_count_listener:
	push	rax
	call	out_u64
	out_lit ' listener'
	pop	rax
	cmp	eax,1
	je	@f
	out_lit 's'
@@:
	ret

cli_run:
	call	cli_load_config
	call	plan_compile
	jmp	supervisor_main
