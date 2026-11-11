; Configuration language: lexer and parser.
;
;   directive arg arg key=value {
;       nested directive
;   }
;
; A directive ends at a newline or ';'. '#' at the start of a token starts
; a comment. Strings are double-quoted with \" \\ \n \t escapes. A word
; whose part before the first '=' is a key ([a-z0-9_.:-]+) is key=value;
; the value may be a quoted string.
;
; The parser builds a tree of nodes (one per directive) with their
; arguments in contiguous arrays, all in arenas. Errors are reported with
; file:line:column, the source line and a caret under the offending text.

; Tokens
TK_EOF		:= 0
TK_EOL		:= 1
TK_LBRACE	:= 2
TK_RBRACE	:= 3
TK_WORD		:= 4
TK_STRING	:= 5
TK_KV		:= 6

; Node (one directive)
N_NAME		:= 0		; q: name in the source
N_NLEN		:= 8		; d
N_LINE		:= 12		; d
N_COL		:= 16		; d
N_ARGC		:= 20		; d
N_ARGS		:= 24		; q: first argument
N_CHILD		:= 32		; q: first nested directive
N_NEXT		:= 40		; q: next sibling
N_PARENT	:= 48		; q
N_BLOCK		:= 56		; d: 1 when the directive has a block
N_BLINE		:= 60		; d: line of its '{'
N_BRACE		:= 64		; q: the '{' in the source
N_DEF		:= 72		; q: schema entry, set by the checker
N_SIZE		:= 80

; Argument
A_KIND		:= 0		; d: ARG_*
A_LINE		:= 4		; d
A_KLEN		:= 8		; d: key length (ARG_KV)
A_VLEN		:= 12		; d: value length
A_KEY		:= 16		; q: key (ARG_KV)
A_VAL		:= 24		; q: value (unescaped for strings)
A_RAW		:= 32		; q: the argument in the source, for carets
A_RAWLEN	:= 40		; d
A_QUOTED	:= 44		; d: the value was a quoted string
A_SIZE		:= 48

ARG_WORD	:= 0
ARG_STRING	:= 1
ARG_KV		:= 2
ARG_MEM		:= 3		; (made by the compiler: A_VAL is the text itself)

CFG_MAX_DEPTH	:= 16
CFG_MAX_ERRORS	:= 20
CFG_MAX_ARGS	:= 256		; per directive

bss
	g_cfg_src	dq ?		; source text, NUL after the end
	g_cfg_end	dq ?
	g_cfg_name	dq ?		; NUL-terminated name for messages
	g_cfg_inline	dd ?		; source came from the command line
	g_cfg_errors	dd ?
	g_cfg_warnings	dd ?
	g_cfg_root	dq ?		; virtual node whose children are the top level
	g_lex_pos	dq ?
	g_lex_line	dd ?
	g_lex_pushed	dd ?		; one token of lookahead was pushed back
	g_tok_kind	dd ?
	g_tok_line	dd ?
	g_tok_ptr	dq ?		; token text (value for TK_KV)
	g_tok_len	dd ?
	g_tok_klen	dd ?
	g_tok_key	dq ?
	g_tok_raw	dq ?		; whole token in the source
	g_tok_rawlen	dd ?
	g_tok_quoted	dd ?
	g_err_ptr	dq ?		; caret target of the current message
	g_err_len	dd ?
	g_err_line	dd ?
	g_ar_nodes:	rq 3
	g_ar_args:	rq 3
	g_ar_text:	rq 3
	; the files read (the first, then those included): for messages
	g_cfg_nfiles	dd ?
	g_inc_depth	dd ?
	g_cfg_files	rq CFG_FILES * 3	; source, end, name
	g_diag_src	dq ?			; the one a message is about
	g_diag_end	dq ?
	g_inc_dir	rb 4096
	g_cfg_ndirs	dd ?			; the directories globs looked in (reload on-change)
	g_cfg_dirs	rq CFG_DIRS
	g_inc_pat	rb 256
	g_inc_dents	rb 8192
end bss

CFG_FILES	:= 256
CFG_DIRS	:= 64
CFG_INC_DEPTH	:= 8
SYS_getdents64_	:= 217

; ---------------------------------------------------------------- errors

; Start a diagnostic. rdi = text it is about, esi = its length, edx = line.
; Prints "name:line:col: error: "; the message follows with out_* calls
; and cfg_diag_end prints the source excerpt.
cfg_error:
	inc	dword [g_cfg_errors]
	push	rdi
	push	rsi
	push	rdx
	call	cfg_diag_head
	out_lit 'error: '
	add	rsp,24
	ret

cfg_warning:
	inc	dword [g_cfg_warnings]
	push	rdi
	push	rsi
	push	rdx
	call	cfg_diag_head
	out_lit 'warning: '
	add	rsp,24
	ret

; [rsp+8] = line, [rsp+16] = length, [rsp+24] = text
cfg_diag_head:
	mov	edi,2
	call	out_select
	mov	rax,[rsp+24]
	mov	[g_err_ptr],rax
	mov	eax,[rsp+16]
	mov	[g_err_len],eax
	mov	eax,[rsp+8]
	mov	[g_err_line],eax
	mov	rdi,[g_err_ptr]
	call	cfg_diag_buf			; rsi = its file's name
	call	out_cstr
	out_lit ':'
	mov	eax,[g_err_line]
	call	out_u64
	out_lit ':'
	mov	rdi,[g_err_ptr]
	call	cfg_column
	call	out_u64
	out_lit ': '
	ret

; rdi = a pointer into a source: g_diag_src/end, the file it is in (the one
; being read when it is in none: a value unescaped elsewhere), rsi = its name
cfg_diag_buf:
	mov	rax,[g_cfg_src]
	mov	[g_diag_src],rax
	mov	rax,[g_cfg_end]
	mov	[g_diag_end],rax
	mov	rsi,[g_cfg_name]
	xor	ecx,ecx
.file:
	cmp	ecx,[g_cfg_nfiles]
	jae	.out
	imul	eax,ecx,24
	cmp	rdi,[g_cfg_files+rax]
	jb	.next
	cmp	rdi,[g_cfg_files+rax+8]
	ja	.next
	mov	rdx,[g_cfg_files+rax]
	mov	[g_diag_src],rdx
	mov	rdx,[g_cfg_files+rax+8]
	mov	[g_diag_end],rdx
	mov	rsi,[g_cfg_files+rax+16]
	ret
.next:
	inc	ecx
	jmp	.file
.out:
	ret

; rdi = pointer into the source. rax = 1-based column (characters).
cfg_column:
	call	cfg_line_start
	mov	rcx,rax
	mov	eax,1
.next:
	cmp	rcx,rdi
	jae	.done
	movzx	edx,byte [rcx]
	inc	rcx
	and	edx,0xC0
	cmp	edx,0x80			; UTF-8 continuation byte
	je	.next
	inc	eax
	jmp	.next
.done:
	ret

; rdi = pointer into the source. rax = start of its line. Keeps rdi.
cfg_line_start:
	mov	rax,rdi
	mov	rdx,[g_diag_src]
.back:
	cmp	rax,rdx
	jbe	.done
	cmp	byte [rax-1],10
	je	.done
	dec	rax
	jmp	.back
.done:
	ret

; End the message line and print the excerpt:
;    12 |     timout 5s
;       |     ^^^^^^
cfg_diag_end:
	push	rbx
	push	r12
	push	r13
	mov	edi,10
	call	out_char
	mov	rdi,[g_err_ptr]
	call	cfg_line_start
	mov	rbx,rax				; line start
	mov	eax,[g_err_line]
	call	cfg_gutter_number
	; the line itself, up to 200 bytes
	mov	r12,rbx
	mov	rdx,[g_diag_end]
.measure:
	cmp	r12,rdx
	jae	.measured
	mov	al,[r12]
	cmp	al,10
	je	.measured
	cmp	al,13
	je	.measured
	inc	r12
	mov	rax,r12
	sub	rax,rbx
	cmp	rax,200
	jb	.measure
.measured:
	mov	rsi,rbx
	mov	rdx,r12
	sub	rdx,rbx
	call	out_str
	mov	edi,10
	call	out_char
	call	cfg_gutter_blank
	; caret prefix keeps tabs so it lines up in a terminal
	mov	r13,[g_err_ptr]
.prefix:
	cmp	rbx,r13
	jae	.carets
	movzx	edi,byte [rbx]
	inc	rbx
	mov	eax,edi
	and	eax,0xC0
	cmp	eax,0x80
	je	.prefix
	cmp	edi,9
	je	@f
	mov	edi,' '
@@:
	call	out_char
	jmp	.prefix
.carets:
	mov	r12d,[g_err_len]
	xor	ebx,ebx				; carets printed
.caret:
	test	r12d,r12d
	jz	.end
	movzx	eax,byte [r13]
	inc	r13
	dec	r12d
	cmp	eax,10
	je	.end
	and	eax,0xC0
	cmp	eax,0x80
	je	.caret
	mov	edi,'^'
	call	out_char
	inc	ebx
	jmp	.caret
.end:
	test	ebx,ebx
	jnz	@f
	mov	edi,'^'
	call	out_char
@@:
	mov	edi,10
	call	out_char
	pop	r13
	pop	r12
	pop	rbx
	ret

; "  12 | "
cfg_gutter_number:
	push	rax
	xor	ecx,ecx
	mov	r8d,10
@@:
	inc	ecx
	xor	edx,edx
	div	r8
	test	rax,rax
	jnz	@b
	mov	edi,6
	sub	edi,ecx
	jg	@f
	mov	edi,1
@@:
	call	out_spaces
	pop	rax
	call	out_u64
	out_lit ' | '
	ret

cfg_gutter_blank:
	mov	edi,7
	call	out_spaces
	out_lit '| '
	ret

; A note under a diagnostic: "       = help: " then the text, then
; cfg_note_end.
cfg_note:
	mov	edi,7
	call	out_spaces
	out_lit '= '
	ret

cfg_note_end:
	mov	edi,10
	jmp	out_char

; Print rsi/edx in backquotes.
cfg_quote:
	push	rsi
	push	rdx
	mov	edi,'`'
	call	out_char
	pop	rdx
	pop	rsi
	call	out_str
	mov	edi,'`'
	jmp	out_char

; Stop when too many errors were reported.
cfg_error_limit:
	cmp	dword [g_cfg_errors],CFG_MAX_ERRORS
	jb	.ok
	mov	edi,2
	call	out_select
	out_lit 'too many errors, stopping'
	mov	edi,10
	call	out_char
	call	out_flush
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.ok:
	ret

; ----------------------------------------------------------------- lexer

; rdi = source, rsi = length, rdx = name for messages. The source must be
; followed by at least one zero byte.
cfg_begin:
	mov	[g_cfg_src],rdi
	mov	[g_lex_pos],rdi
	add	rsi,rdi
	mov	[g_cfg_end],rsi
	mov	[g_cfg_name],rdx
	mov	dword [g_lex_line],1
	mov	dword [g_lex_pushed],0
	mov	dword [g_cfg_errors],0
	mov	dword [g_cfg_warnings],0
	mov	dword [g_chk_listeners],0
	mov	dword [g_chk_pools],0
	mov	dword [g_chk_servers],0
	mov	[g_cfg_files],rdi		; the first file
	mov	[g_cfg_files+8],rsi
	mov	[g_cfg_files+16],rdx
	mov	[g_diag_src],rdi
	mov	[g_diag_end],rsi
	mov	dword [g_cfg_nfiles],1
	mov	dword [g_cfg_ndirs],0
	mov	dword [g_inc_depth],0
	call	cfg_flat_begin			; (rdi: the text) last_good's copy
	cmp	qword [g_ar_nodes+AR_BASE],0
	jne	.ready
	lea	rdi,[g_ar_nodes]
	mov	esi,256 shl 20
	call	arena_init
	lea	rdi,[g_ar_args]
	mov	esi,256 shl 20
	call	arena_init
	lea	rdi,[g_ar_text]
	mov	esi,128 shl 20
	call	arena_init
.ready:
	ret

; Byte classes for words: anything printable except { } ; " and space.
; '#' and '=' are ordinary inside a word, and so is "{*}" after its first
; byte.
; al = byte. ZF set when it ends a word.
macro lex_word_end_test
	cmp	al,' '
	jbe	.end_word
	cmp	al,'{'
	je	.end_word
	cmp	al,'}'
	je	.end_word
	cmp	al,';'
	je	.end_word
	cmp	al,'"'
	je	.end_word
	cmp	al,0x7F
	je	.end_word
end macro

; Next token into g_tok_*. Lexical errors are reported and skipped.
lex_next:
	cmp	dword [g_lex_pushed],0
	je	.scan
	mov	dword [g_lex_pushed],0
	ret
.scan:
	mov	rsi,[g_lex_pos]
.skip:
	cmp	rsi,[g_cfg_end]
	jae	.eof
	movzx	eax,byte [rsi]
	cmp	al,' '
	je	.blank
	cmp	al,9
	je	.blank
	cmp	al,13
	je	.blank
	cmp	al,10
	je	.newline
	cmp	al,';'
	je	.semicolon
	cmp	al,'#'
	je	.comment
	cmp	al,'{'
	je	.lbrace
	cmp	al,'}'
	je	.rbrace
	cmp	al,'"'
	je	.string
	cmp	al,' '
	jb	.control
	cmp	al,0x7F
	je	.control
	jmp	.word
.blank:
	inc	rsi
	jmp	.skip
.comment:
	inc	rsi
	cmp	rsi,[g_cfg_end]
	jae	.eof
	cmp	byte [rsi],10
	jne	.comment
	jmp	.skip
.newline:
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	inc	dword [g_lex_line]
	mov	[g_tok_raw],rsi
	inc	rsi
	mov	[g_lex_pos],rsi
	mov	dword [g_tok_kind],TK_EOL
	ret
.semicolon:
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	mov	[g_tok_raw],rsi
	mov	dword [g_tok_rawlen],1
	inc	rsi
	mov	[g_lex_pos],rsi
	mov	dword [g_tok_kind],TK_EOL
	ret
.eof:
	mov	[g_lex_pos],rsi
	mov	[g_tok_raw],rsi
	mov	dword [g_tok_rawlen],0
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	mov	dword [g_tok_kind],TK_EOF
	ret
.lbrace:
	mov	edx,TK_LBRACE
	jmp	.single
.rbrace:
	mov	edx,TK_RBRACE
.single:
	mov	[g_tok_kind],edx
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	mov	[g_tok_raw],rsi
	mov	[g_tok_ptr],rsi
	mov	dword [g_tok_rawlen],1
	mov	dword [g_tok_len],1
	inc	rsi
	mov	[g_lex_pos],rsi
	ret
.control:
	push	rsi
	mov	rdi,rsi
	mov	esi,1
	mov	edx,[g_lex_line]
	call	cfg_error
	out_lit 'control character in the configuration'
	call	cfg_diag_end
	call	cfg_error_limit
	pop	rsi
	inc	rsi
	jmp	.skip

.string:
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	mov	[g_tok_raw],rsi
	mov	dword [g_tok_klen],0
	mov	rdi,rsi
	call	lex_string			; rax = end of the string token
	mov	rsi,rax
	mov	[g_lex_pos],rsi
	sub	rax,[g_tok_raw]
	mov	[g_tok_rawlen],eax
	mov	dword [g_tok_kind],TK_STRING
	ret

.word:
	mov	eax,[g_lex_line]
	mov	[g_tok_line],eax
	mov	[g_tok_raw],rsi
	mov	[g_tok_ptr],rsi
	mov	dword [g_tok_quoted],0
	mov	rdi,rsi				; word start
	xor	r8d,r8d				; 1 while the text so far can be a key
	inc	r8d
.word_loop:
	cmp	rsi,[g_cfg_end]
	jae	.end_word
	movzx	eax,byte [rsi]
	cmp	al,'='
	je	.equals
	; "{*}" inside a word is part of it (a redirect target: /new/{*});
	; a block opens with a '{' of its own
	cmp	al,'{'
	jne	.not_star
	cmp	rsi,rdi
	je	.not_star
	lea	rax,[rsi+3]
	cmp	rax,[g_cfg_end]
	ja	.not_star
	cmp	word [rsi+1],'*}'
	jne	.not_star
	add	rsi,3
	xor	r8d,r8d
	jmp	.word_loop
.not_star:
	movzx	eax,byte [rsi]
	lex_word_end_test
	test	r8d,r8d
	jz	.word_next
	call	lex_key_char
	jnc	.word_next
	xor	r8d,r8d
.word_next:
	inc	rsi
	jmp	.word_loop
.equals:
	test	r8d,r8d
	jz	.word_next
	cmp	rsi,rdi
	je	.word_next			; "=x" is a plain word
	; key=value
	mov	[g_tok_key],rdi
	mov	rax,rsi
	sub	rax,rdi
	mov	[g_tok_klen],eax
	inc	rsi
	cmp	rsi,[g_cfg_end]
	jae	.empty_value
	cmp	byte [rsi],'"'
	je	.kv_string
	mov	[g_tok_ptr],rsi
	mov	r9,rsi
.kv_loop:
	cmp	rsi,[g_cfg_end]
	jae	.kv_end
	movzx	eax,byte [rsi]
	cmp	al,' '
	jbe	.kv_end
	cmp	al,'{'
	je	.kv_end
	cmp	al,'}'
	je	.kv_end
	cmp	al,';'
	je	.kv_end
	cmp	al,'"'
	je	.kv_end
	cmp	al,0x7F
	je	.kv_end
	inc	rsi
	jmp	.kv_loop
.kv_end:
	mov	rax,rsi
	sub	rax,r9
	mov	[g_tok_len],eax
	jmp	.kv_done
.empty_value:
	mov	[g_tok_ptr],rsi
	mov	dword [g_tok_len],0
	jmp	.kv_done
.kv_string:
	mov	rdi,rsi
	call	lex_string
	mov	rsi,rax
.kv_done:
	mov	[g_lex_pos],rsi
	mov	rax,rsi
	sub	rax,[g_tok_raw]
	mov	[g_tok_rawlen],eax
	mov	dword [g_tok_kind],TK_KV
	ret
.end_word:
	mov	[g_lex_pos],rsi
	mov	rax,rsi
	sub	rax,rdi
	mov	[g_tok_len],eax
	mov	[g_tok_rawlen],eax
	mov	dword [g_tok_klen],0
	mov	dword [g_tok_kind],TK_WORD
	ret

; al = byte. CF clear when it may appear in a key.
lex_key_char:
	cmp	al,'a'
	jb	@f
	cmp	al,'z'
	jbe	.yes
@@:
	cmp	al,'0'
	jb	@f
	cmp	al,'9'
	jbe	.yes
@@:
	cmp	al,'_'
	je	.yes
	cmp	al,'-'
	je	.yes
	cmp	al,'.'
	je	.yes
	cmp	al,':'
	je	.yes
	stc
	ret
.yes:
	clc
	ret

; rdi = opening quote. Sets g_tok_ptr/len to the value (unescaped into the
; text arena when it has escapes) and g_tok_quoted. rax = after the token.
lex_string:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	dword [g_tok_quoted],1
	lea	r12,[rdi+1]			; scan position
	xor	r13d,r13d			; escapes seen
.scan:
	cmp	r12,[g_cfg_end]
	jae	.unterminated
	movzx	eax,byte [r12]
	cmp	al,'"'
	je	.closed
	cmp	al,10
	je	.unterminated
	cmp	al,'\'
	jne	@f
	inc	r13d
	inc	r12
	cmp	r12,[g_cfg_end]
	jae	.unterminated
	movzx	eax,byte [r12]
	cmp	al,'"'
	je	.esc_ok
	cmp	al,'\'
	je	.esc_ok
	cmp	al,'n'
	je	.esc_ok
	cmp	al,'t'
	je	.esc_ok
	cmp	al,'$'
	je	.esc_ok
	lea	rdi,[r12-1]
	mov	esi,2
	mov	edx,[g_lex_line]
	call	cfg_error
	out_lit 'unknown escape in a string'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: the escapes are \" \\ \n \t and \$'
	call	cfg_note_end
	call	cfg_error_limit
.esc_ok:
	inc	r12
	jmp	.scan
@@:
	cmp	al,9
	je	.ordinary
	cmp	al,' '
	jb	.control
.ordinary:
	inc	r12
	jmp	.scan
.control:
	mov	rdi,r12
	mov	esi,1
	mov	edx,[g_lex_line]
	call	cfg_error
	out_lit 'control character in a string'
	call	cfg_diag_end
	call	cfg_error_limit
	inc	r12
	jmp	.scan
.closed:
	lea	rax,[rbx+1]
	mov	[g_tok_ptr],rax
	mov	rax,r12
	sub	rax,rbx
	dec	eax
	mov	[g_tok_len],eax
	test	r13d,r13d
	jz	.plain
	; unescape into the text arena
	lea	rdi,[g_ar_text]
	lea	rsi,[rax+1]
	call	arena_alloc
	mov	rdi,rax
	mov	[g_tok_ptr],rax
	lea	rsi,[rbx+1]
.copy:
	cmp	rsi,r12
	jae	.copied
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'\'
	jne	.store
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'n'
	jne	@f
	mov	al,10
	jmp	.store
@@:
	cmp	al,'t'
	jne	.store
	mov	al,9
.store:
	mov	[rdi],al
	inc	rdi
	jmp	.copy
.copied:
	mov	rax,rdi
	sub	rax,[g_tok_ptr]
	mov	[g_tok_len],eax
.plain:
	lea	rax,[r12+1]
	pop	r13
	pop	r12
	pop	rbx
	ret
.unterminated:
	mov	rdi,rbx
	mov	esi,1
	mov	edx,[g_lex_line]
	call	cfg_error
	out_lit 'unterminated string'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: close it with " on the same line'
	call	cfg_note_end
	call	cfg_error_limit
	lea	rax,[rbx+1]
	mov	[g_tok_ptr],rax
	mov	rax,r12
	sub	rax,rbx
	dec	eax
	mov	[g_tok_len],eax
	mov	rax,r12
	pop	r13
	pop	r12
	pop	rbx
	ret

lex_push_back:
	mov	dword [g_lex_pushed],1
	ret

; ---------------------------------------------------------------- parser

; Parse the whole source. g_cfg_root = virtual root node. Errors counted
; in g_cfg_errors.
cfg_parse:
	push	rbx
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	mov	[g_cfg_root],rax
	mov	rdi,rax
	xor	esi,esi				; depth
	call	parse_block
	mov	rdi,[g_cfg_end]
	call	cfg_flat_to
	pop	rbx
	ret

; rdi = parent node, esi = depth (0 = top level).
parse_block:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12d,esi
	xor	r13d,r13d			; last child
.next:
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_EOL
	je	.next
	cmp	eax,TK_EOF
	je	.eof
	cmp	eax,TK_RBRACE
	je	.rbrace
	cmp	eax,TK_WORD
	je	.directive
	cmp	eax,TK_LBRACE
	je	.stray_brace
	; a string or key=value where a directive name should be
	mov	rdi,[g_tok_raw]
	mov	esi,[g_tok_rawlen]
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit 'expected a directive name'
	call	cfg_diag_end
	call	cfg_error_limit
	call	parse_skip_line
	jmp	.next
.stray_brace:
	mov	rdi,[g_tok_raw]
	mov	esi,1
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit '`{` without a directive'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: a block opens on the same line as its directive: `pool api {`'
	call	cfg_note_end
	call	cfg_error_limit
	mov	rdi,rbx
	lea	esi,[r12+1]
	call	parse_skip_block
	jmp	.next
.rbrace:
	test	r12d,r12d
	jnz	.done
	mov	rdi,[g_tok_raw]
	mov	esi,1
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit '`}` without a matching `{`'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.next
.eof:
	test	r12d,r12d
	jz	.done
	mov	rdi,[rbx+N_BRACE]
	mov	esi,1
	mov	edx,[rbx+N_BLINE]
	call	cfg_error
	out_lit 'this block is never closed'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: add `}` for the block of '
	mov	rsi,[rbx+N_NAME]
	mov	edx,[rbx+N_NLEN]
	call	cfg_quote
	call	cfg_note_end
	call	lex_push_back			; let outer levels see the end too
	jmp	.done
.directive:
	test	r12d,r12d			; `include` at the top: the files' directives here
	jnz	.not_include
	cmp	dword [g_tok_len],7
	jne	.not_include
	mov	rax,[g_tok_ptr]
	cmp	dword [rax],'incl'
	jne	.not_include
	cmp	dword [rax+3],'lude'
	jne	.not_include
	mov	rdi,rbx
	mov	rsi,r13
	call	parse_include			; rax = the last child now
	mov	r13,rax
	jmp	.next
.not_include:
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	mov	r14,rax
	mov	rcx,[g_tok_ptr]
	mov	[r14+N_NAME],rcx
	mov	ecx,[g_tok_len]
	mov	[r14+N_NLEN],ecx
	mov	ecx,[g_tok_line]
	mov	[r14+N_LINE],ecx
	mov	[r14+N_PARENT],rbx
	test	r13,r13
	jz	.first
	mov	[r13+N_NEXT],r14
	jmp	.linked
.first:
	mov	[rbx+N_CHILD],r14
.linked:
	mov	r13,r14
	; arguments
	mov	rax,[g_ar_args+AR_NEXT]
	mov	[r14+N_ARGS],rax
.arg:
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_WORD
	je	.add_arg
	cmp	eax,TK_STRING
	je	.add_arg
	cmp	eax,TK_KV
	je	.add_arg
	cmp	eax,TK_LBRACE
	je	.open
	cmp	eax,TK_RBRACE
	jne	.next				; end of line or file
	call	lex_push_back
	jmp	.next
.add_arg:
	cmp	dword [r14+N_ARGC],CFG_MAX_ARGS
	jae	.too_many_args
	lea	rdi,[g_ar_args]
	mov	esi,A_SIZE
	call	arena_alloc
	mov	ecx,[g_tok_kind]
	mov	edx,ARG_WORD
	cmp	ecx,TK_STRING
	jne	@f
	mov	edx,ARG_STRING
@@:
	cmp	ecx,TK_KV
	jne	@f
	mov	edx,ARG_KV
@@:
	mov	[rax+A_KIND],edx
	mov	ecx,[g_tok_line]
	mov	[rax+A_LINE],ecx
	mov	rcx,[g_tok_key]
	mov	[rax+A_KEY],rcx
	mov	ecx,[g_tok_klen]
	mov	[rax+A_KLEN],ecx
	mov	rcx,[g_tok_ptr]
	mov	[rax+A_VAL],rcx
	mov	ecx,[g_tok_len]
	mov	[rax+A_VLEN],ecx
	mov	rcx,[g_tok_raw]
	mov	[rax+A_RAW],rcx
	mov	ecx,[g_tok_rawlen]
	mov	[rax+A_RAWLEN],ecx
	mov	ecx,[g_tok_quoted]
	cmp	edx,ARG_WORD
	jne	@f
	xor	ecx,ecx
@@:
	mov	[rax+A_QUOTED],ecx
	inc	dword [r14+N_ARGC]
	jmp	.arg
.too_many_args:
	mov	rdi,[g_tok_raw]
	mov	esi,[g_tok_rawlen]
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit 'too many arguments (the limit is 256)'
	call	cfg_diag_end
	call	cfg_error_limit
	call	parse_skip_line
	jmp	.next
.open:
	mov	dword [r14+N_BLOCK],1
	mov	rax,[g_tok_raw]
	mov	[r14+N_BRACE],rax
	mov	eax,[g_tok_line]
	mov	[r14+N_BLINE],eax
	lea	esi,[r12+1]
	cmp	esi,CFG_MAX_DEPTH
	ja	.too_deep
	mov	rdi,r14
	call	parse_block
	; after '}' only the end of the line, ';' or another '}' may follow
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_EOL
	je	.next
	cmp	eax,TK_EOF
	je	.after_eof
	cmp	eax,TK_RBRACE
	je	.after_rbrace
	; on the command line there are no newlines: `okena { ... } tcp ...`
	cmp	dword [g_cfg_inline],0
	je	@f
	cmp	eax,TK_WORD
	je	.after_rbrace
@@:
	mov	rdi,[g_tok_raw]
	mov	esi,[g_tok_rawlen]
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit 'expected the end of the line after `}`'
	call	cfg_diag_end
	call	cfg_error_limit
	call	parse_skip_line
	jmp	.next
.after_eof:
.after_rbrace:
	call	lex_push_back
	jmp	.next
.too_deep:
	mov	rdi,[g_tok_raw]
	mov	esi,1
	mov	edx,[g_tok_line]
	call	cfg_error
	out_lit 'blocks are nested too deeply (the limit is 16)'
	call	cfg_diag_end
	call	cfg_error_limit
	mov	rdi,r14
	lea	esi,[r12+1]
	call	parse_skip_block
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; `include "PATH"` (the name read): rdi = the parent (the top), rsi = its last
; child. The files PATH names (a * or ? in its last part: those that match, in
; sorted order, none being fine; else the one, which must be there), relative
; to the file that includes them, parsed as if written here. rax = the last
; child after them.
parse_include:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12,rsi
	mov	r14,[g_tok_raw]			; (for messages: the directive)
	mov	r15d,[g_tok_line]
	mov	rdi,r14				; last_good's copy: up to the line
	call	cfg_flat_to
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_STRING
	je	@f
	cmp	eax,TK_WORD
	jne	.shape
@@:
	mov	ecx,[g_tok_len]
	test	ecx,ecx
	jz	.shape
	cmp	ecx,3000
	ja	.shape
	; the path: from the including file's directory when not from /
	lea	rdi,[g_inc_dir]
	mov	rsi,[g_tok_ptr]
	cmp	byte [rsi],'/'
	je	.absolute
	cmp	dword [g_cfg_inline],0
	jne	.absolute
	mov	rsi,[g_cfg_name]
	xor	edx,edx				; after the last /
	xor	eax,eax
@@:
	cmp	byte [rsi+rax],0
	je	@f
	inc	eax
	cmp	byte [rsi+rax-1],'/'
	jne	@b
	mov	edx,eax
	cmp	eax,1000
	jb	@b
@@:
	mov	ecx,edx
	rep	movsb
.absolute:
	mov	rsi,[g_tok_ptr]
	mov	ecx,[g_tok_len]
	rep	movsb
	mov	byte [rdi],0
	push	rdi
	call	lex_next			; the end of the line
	pop	rdi
	mov	eax,[g_tok_kind]
	cmp	eax,TK_EOL
	je	@f
	cmp	eax,TK_EOF
	jne	.shape
	call	lex_push_back
@@:
	cmp	dword [g_inc_depth],CFG_INC_DEPTH
	jae	.deep
	; its last part: a pattern?
	lea	r13,[g_inc_dir]
	mov	rsi,rdi
@@:
	dec	rsi
	cmp	byte [rsi],'/'
	jne	@b
	lea	r13,[rsi+1]			; (the last part)
	xor	eax,eax
	mov	rdx,r13
@@:
	mov	cl,[rdx]
	test	cl,cl
	jz	@f
	cmp	cl,'*'
	je	.pattern
	cmp	cl,'?'
	je	.pattern
	inc	rdx
	jmp	@b
@@:
	lea	rdi,[g_inc_dir]			; one file
	call	parse_include_file
	jmp	.out
.pattern:
	; the pattern apart, the directory alone
	lea	rdi,[g_inc_pat]
	mov	rsi,r13
@@:
	lodsb
	stosb
	test	al,al
	jz	@f
	cmp	rdi,g_inc_pat + 250
	jb	@b
	jmp	.shape
@@:
	mov	byte [r13],0			; g_inc_dir: "DIR/"
	call	parse_include_glob
	jmp	.out
.deep:
	mov	rdi,r14
	mov	esi,7
	mov	edx,r15d
	call	cfg_error
	out_lit 'files include each other too deeply (the limit is 8)'
	call	cfg_diag_end
	call	cfg_error_limit
	jmp	.out
.shape:
	mov	rdi,r14
	mov	esi,7
	mov	edx,r15d
	call	cfg_error
	out_lit '`include` takes a path, alone on its line'
	call	cfg_diag_end
	call	cfg_note
	out_lit 'help: `include "conf.d/*.conf"`'
	call	cfg_note_end
	call	cfg_error_limit
	call	parse_skip_line
.out:
	mov	rax,[g_lex_pos]			; last_good's copy: on after the line
	mov	[g_flat_from],rax
	mov	rax,r12
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; (rbx = parent, r12 = last child, r14/r15d = the directive: kept by both below)

; g_inc_dir = "DIR/", g_inc_pat = a pattern: the files that match, sorted
parse_include_glob:
	; the directory, kept (a file added there later is a change: cfgwatch.inc)
	mov	eax,[g_cfg_ndirs]
	cmp	eax,CFG_DIRS
	jae	.dir_kept
	lea	rsi,[g_inc_dir]
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	lea	rdi,[g_ar_text]
	lea	rsi,[rcx+1]
	call	arena_alloc
	pop	rcx
	mov	rdi,rax
	lea	rsi,[g_inc_dir]
	inc	ecx
	rep	movsb
	mov	ecx,[g_cfg_ndirs]
	mov	[g_cfg_dirs+rcx*8],rax
	inc	dword [g_cfg_ndirs]
.dir_kept:
	mov	edi,AT_FDCWD
	lea	rsi,[g_inc_dir]
	mov	edx,O_RDONLY or O_DIRECTORY_ or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.none				; (no directory: no files)
	push	rax
	; the names that match, kept in the text arena, then sorted
	sub	rsp,8 * 256 + 8
	mov	qword [rsp],0			; how many
.read:
	mov	edi,[rsp + 8 * 256 + 8]
	lea	rsi,[g_inc_dents]
	mov	edx,8192
	mov	eax,SYS_getdents64_
	syscall
	test	rax,rax
	jle	.listed
	lea	r8,[g_inc_dents]
	lea	r9,[r8+rax]
.dent:
	cmp	r8,r9
	jae	.read
	movzx	eax,word [r8+16]		; d_reclen
	lea	r10,[r8+19]			; d_name
	add	r8,rax
	cmp	byte [r10],'.'
	jne	@f
	cmp	byte [g_inc_pat],'.'
	jne	.dent				; (hidden: only when asked for)
@@:
	mov	rdi,r10
	lea	rsi,[g_inc_pat]
	call	glob_match
	jne	.dent
	mov	rcx,[rsp]
	cmp	ecx,256
	jae	.dent
	; kept
	xor	ecx,ecx
@@:
	cmp	byte [r10+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	r8
	push	r9
	push	r10
	push	rcx
	lea	rdi,[g_ar_text]
	lea	rsi,[rcx+1]
	call	arena_alloc
	pop	rcx
	pop	rsi
	mov	rdi,rax
	inc	ecx
	rep	movsb
	pop	r9
	pop	r8
	mov	rcx,[rsp]
	mov	[rsp+8+rcx*8],rax
	inc	qword [rsp]
	jmp	.dent
.listed:
	mov	edi,[rsp + 8 * 256 + 8]
	mov	eax,SYS_close
	syscall
	; sorted (insertion: a directory's few files)
	mov	r8d,1
.sort:
	cmp	r8,[rsp]
	jae	.sorted
	mov	r9,[rsp+8+r8*8]
	mov	r10,r8
.sift:
	test	r10,r10
	jz	.place
	mov	rsi,[rsp+8+r10*8-8]
	mov	rdi,r9
	call	str_before			; CF: rdi before rsi
	jnc	.place
	mov	rax,[rsp+8+r10*8-8]
	mov	[rsp+8+r10*8],rax
	dec	r10
	jmp	.sift
.place:
	mov	[rsp+8+r10*8],r9
	inc	r8
	jmp	.sort
.sorted:
	; each, as DIR/NAME
	xor	r8d,r8d
.each:
	cmp	r8,[rsp]
	jae	.done
	push	r8
	lea	rdi,[g_inc_dir]
	xor	eax,eax
@@:
	cmp	byte [rdi],0
	je	@f
	inc	rdi
	jmp	@b
@@:
	push	rdi				; (where DIR/ ends)
	mov	rsi,[rsp+16+8+r8*8]
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	lea	rdi,[g_inc_dir]
	call	parse_include_file
	pop	rdi
	mov	byte [rdi],0			; back to DIR/
	pop	r8
	inc	r8
	jmp	.each
.done:
	add	rsp,8 * 256 + 8 + 8
.none:
	ret

; rdi = a NUL-ended path: its directives parsed after r12 under rbx (r12 the
; last after them)
parse_include_file:
	push	r13
	; its name, kept for messages
	mov	r13,rdi
	xor	ecx,ecx
@@:
	cmp	byte [r13+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	lea	rdi,[g_ar_text]
	lea	rsi,[rcx+1]
	call	arena_alloc
	pop	rcx
	inc	ecx
	mov	rdi,rax
	mov	rsi,r13
	rep	movsb
	mov	r13,rax
	mov	rdi,r13
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.unreadable
	cmp	dword [g_cfg_nfiles],CFG_FILES
	jae	.many
	; the lexer on it, then back
	push	qword [g_cfg_src]
	push	qword [g_cfg_end]
	push	qword [g_cfg_name]
	push	qword [g_lex_pos]
	push	qword [g_lex_line]
	mov	[g_cfg_src],rax
	mov	[g_lex_pos],rax
	add	rdx,rax
	mov	[g_cfg_end],rdx
	mov	[g_cfg_name],r13
	mov	dword [g_lex_line],1
	mov	ecx,[g_cfg_nfiles]
	imul	ecx,ecx,24
	mov	[g_cfg_files+rcx],rax
	mov	[g_cfg_files+rcx+8],rdx
	mov	[g_cfg_files+rcx+16],r13
	inc	dword [g_cfg_nfiles]
	; into a node of its own, its children then moved here
	push	qword [g_flat_from]		; (last_good's copy: this file, whole)
	mov	rax,[g_cfg_src]
	mov	[g_flat_from],rax
	lea	rdi,[g_ar_nodes]
	mov	esi,N_SIZE
	call	arena_alloc
	push	rax
	mov	rdi,rax
	xor	esi,esi
	inc	dword [g_inc_depth]
	call	parse_block
	dec	dword [g_inc_depth]
	mov	rdi,[g_cfg_end]
	call	cfg_flat_to
	call	cfg_flat_nl
	pop	rax
	pop	qword [g_flat_from]
	mov	dword [g_lex_pushed],0
	pop	qword [g_lex_line]
	pop	qword [g_lex_pos]
	pop	qword [g_cfg_name]
	pop	qword [g_cfg_end]
	pop	qword [g_cfg_src]
	mov	rcx,[rax+N_CHILD]
.move:
	test	rcx,rcx
	jz	.out
	mov	[rcx+N_PARENT],rbx
	test	r12,r12
	jz	.first
	mov	[r12+N_NEXT],rcx
	jmp	.linked
.first:
	mov	[rbx+N_CHILD],rcx
.linked:
	mov	r12,rcx
	mov	rcx,[rcx+N_NEXT]
	mov	qword [r12+N_NEXT],0
	test	rcx,rcx
	jz	.out
	jmp	.move
.many:
.unreadable:
	mov	rdi,r14
	mov	esi,7
	mov	edx,r15d
	call	cfg_error
	out_lit 'cannot read '
	mov	rsi,r13
	call	out_cstr
	call	cfg_diag_end
	call	cfg_error_limit
.out:
	pop	r13
	ret

; rdi = a name, rsi = a pattern (* any run, ? one byte), both NUL-ended: ZF when
; it matches. Keeps r8-r15.
glob_match:
	xor	edx,edx				; after the last *: where in the pattern
	xor	ecx,ecx				; and in the name
.next:
	mov	al,[rsi]
	cmp	al,'*'
	je	.star
	mov	ah,[rdi]
	test	ah,ah
	jz	.name_end
	cmp	al,'?'
	je	.one
	cmp	al,ah
	jne	.back
.one:
	inc	rsi
	inc	rdi
	jmp	.next
.star:
	inc	rsi
	mov	rdx,rsi
	mov	rcx,rdi
	jmp	.next
.back:
	test	rdx,rdx
	jz	.no
	mov	rsi,rdx
	inc	rcx
	mov	rdi,rcx
	cmp	byte [rdi-1],0
	je	.no
	jmp	.next
.name_end:
	; the rest of the pattern only *
@@:
	cmp	byte [rsi],'*'
	jne	@f
	inc	rsi
	jmp	@b
@@:
	cmp	byte [rsi],0
	jne	.no
	cmp	eax,eax				; ZF
	ret
.no:
	or	eax,1				; NZ
	ret

; rdi, rsi = NUL-ended: CF when rdi sorts before rsi (by byte)
str_before:
.c:
	mov	al,[rdi]
	mov	ah,[rsi]
	cmp	al,ah
	jne	.differ
	test	al,al
	jz	.equal
	inc	rdi
	inc	rsi
	jmp	.c
.differ:
	ret					; (CF from the compare)
.equal:
	clc
	ret

; Skip to the end of the current line (after an error).
parse_skip_line:
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_EOL
	je	.done
	cmp	eax,TK_EOF
	je	.back
	cmp	eax,TK_RBRACE
	je	.back
	cmp	eax,TK_LBRACE
	jne	parse_skip_line
	; a block on a broken line: skip it whole
	xor	edi,edi
	mov	esi,1
	call	parse_skip_block
	jmp	parse_skip_line
.back:
	call	lex_push_back
.done:
	ret

; Skip tokens up to the '}' that closes a block already opened.
parse_skip_block:
	push	rbx
	mov	ebx,1
.loop:
	call	lex_next
	mov	eax,[g_tok_kind]
	cmp	eax,TK_EOF
	je	.eof
	cmp	eax,TK_LBRACE
	jne	@f
	inc	ebx
	jmp	.loop
@@:
	cmp	eax,TK_RBRACE
	jne	.loop
	dec	ebx
	jnz	.loop
	pop	rbx
	ret
.eof:
	call	lex_push_back
	pop	rbx
	ret
