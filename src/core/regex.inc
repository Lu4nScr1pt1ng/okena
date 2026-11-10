; Regular expressions, matched in linear time: compiled to a program a Pike VM
; runs (Thompson's NFA, a thread a state, with captures), so no input makes it
; backtrack: a route's regex is no way to stall a worker (ReDoS).
;
; The syntax, a subset of PCRE's: literals; . (any byte); [abc], [^a-z], with
; \d \w \s inside; \d \D \w \W \s \S; \n \t \r, and \ before a punctuation mark for
; itself; ^ and $ (the subject's start and end); ( ) capturing (9 groups), (?: )
; not; |; * + ? {n} {n,} {n,m} (up to 255), each lazy with a ? after it; (?i)
; first: letters in either case. Leftmost, then as the alternatives and
; quantifiers prefer (PCRE's choice), not leftmost-longest. A search: unanchored
; unless ^ says so.
;
; Compiled at load into a pool shared by every regex (a plan region); a regex is
; its start there, its length and its groups. Matching keeps two lists of
; threads, the program's length each, a visit mark per instruction, and the
; captures each thread carries.

RX_MAX		:= 256				; regexes
RX_POOL		:= 16384			; instructions, all of them
RX_PER		:= 2048				; one regex's at most
RX_CLASSES	:= 1024
RX_SLOTS	:= 20				; captures: 0-1 the match, then 9 groups

RXE_START	:= 0				; d: its first instruction in the pool
RXE_LEN		:= 4				; d
RXE_NGRP	:= 8				; d
RXE_SIZE	:= 16

RI_OP		:= 0				; d
RI_A		:= 4				; d: a char, a class, a target (its regex's own
RI_B		:= 8				; d: count), a slot
RI_SIZE		:= 16

RXO_CHAR	:= 1
RXO_ANY		:= 2
RXO_CLASS	:= 3
RXO_SPLIT	:= 4				; a first, then b
RXO_JMP		:= 5
RXO_SAVE	:= 6
RXO_MATCH	:= 7
RXO_BOL		:= 8
RXO_EOL		:= 9

RXT_SIZE	:= 4 + RX_SLOTS * 4		; a thread: its pc, its captures
RXT_STRIDE	:= 88

bss
	align 8
	g_rx:		rb RXE_SIZE * RX_MAX	; (plan regions: reload.inc)
	g_rx_prog:	rb RI_SIZE * RX_POOL
	g_rx_cls:	rb 32 * RX_CLASSES
	g_plan_rx	dd ?
	g_plan_rxpc	dd ?
	g_plan_rxcls	dd ?
	g_plan_rxroutes	dd ?			; routes by a regex (proxy.inc: looked at only when some are)
	; compiling
	g_rxc_p		dq ?			; the pattern: where
	g_rxc_end	dq ?			; its end
	g_rxc_err	dq ?			; why it is refused (NUL-ended)
	g_rxc_base	dd ?			; the regex's first instruction
	g_rxc_ngrp	dd ?
	g_rxc_icase	dd ?
	g_rxc_depth	dd ?
	; matching (each process its own)
	align 8
	g_rx_cap	rd RX_SLOTS		; the match's captures: offsets, -1 none
	g_rx_subj	dq ?			; in this subject
	g_rxm_prog	dq ?
	g_rxm_s		dq ?
	g_rxm_len	dd ?
	g_rxm_gen	dd ?
	g_rxm_cn	dd ?			; threads in the current list
	g_rxm_nn	dd ?			; in the next
	g_rxm_cl	dq ?			; the lists
	g_rxm_nl	dq ?
	g_rxm_cur	rd RX_SLOTS		; the captures of the thread being added
	g_rxm_mark	rd RX_PER
	g_rxm_l0:	rb RXT_STRIDE * RX_PER
	g_rxm_l1:	rb RXT_STRIDE * RX_PER
	g_rxm_stk	rq RX_PER * 4
end bss

; ----------------------------------------------------------------- compiling

; rsi/ecx = a pattern: eax = its regex. CF: refused, g_rxc_err why.
rx_compile:
	push	rbx
	push	r12
	push	r13
	mov	[g_rxc_p],rsi
	lea	rax,[rsi+rcx]
	mov	[g_rxc_end],rax
	mov	eax,[g_plan_rx]
	cmp	eax,RX_MAX
	jae	.too_many
	mov	eax,[g_plan_rxpc]
	mov	[g_rxc_base],eax
	xor	eax,eax
	mov	[g_rxc_ngrp],eax
	mov	[g_rxc_icase],eax
	mov	[g_rxc_depth],eax
	mov	rsi,[g_rxc_p]			; (?i) first
	lea	rax,[rsi+4]
	cmp	rax,[g_rxc_end]
	ja	@f
	cmp	dword [rsi],'(?i)'
	jne	@f
	mov	dword [g_rxc_icase],1
	add	qword [g_rxc_p],4
@@:
	mov	eax,RXO_SAVE
	xor	edx,edx
	xor	ecx,ecx
	call	rx_emit
	jc	.bad
	call	rx_alt
	jc	.bad
	mov	rax,[g_rxc_p]
	cmp	rax,[g_rxc_end]
	jne	.unbalanced			; (a ')' with no '(')
	mov	eax,RXO_SAVE
	mov	edx,1
	xor	ecx,ecx
	call	rx_emit
	jc	.bad
	mov	eax,RXO_MATCH
	xor	edx,edx
	xor	ecx,ecx
	call	rx_emit
	jc	.bad
	mov	eax,[g_plan_rx]
	inc	dword [g_plan_rx]
	imul	rcx,rax,RXE_SIZE
	mov	edx,[g_rxc_base]
	mov	[g_rx+rcx+RXE_START],edx
	mov	edx,[g_plan_rxpc]
	sub	edx,[g_rxc_base]
	mov	[g_rx+rcx+RXE_LEN],edx
	mov	edx,[g_rxc_ngrp]
	mov	[g_rx+rcx+RXE_NGRP],edx
	clc
	jmp	.out
.unbalanced:
	cstring .e_paren, 'a ) with no ( before it',0
	lea	rax,[.e_paren]
	mov	[g_rxc_err],rax
	jmp	.bad
.too_many:
	cstring .e_many, 'more than 256 regular expressions',0
	lea	rax,[.e_many]
	mov	[g_rxc_err],rax
.bad:
	mov	eax,[g_rxc_base]		; (its instructions given back)
	mov	[g_plan_rxpc],eax
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = op, edx = a, ecx = b: an instruction. eax = its index (the regex's).
; CF: too long.
rx_emit:
	mov	r8d,[g_plan_rxpc]
	cmp	r8d,RX_POOL
	jae	rx_too_long
	mov	r9d,r8d
	sub	r9d,[g_rxc_base]
	cmp	r9d,RX_PER - 1
	jae	rx_too_long
	imul	r10,r8,RI_SIZE
	mov	[g_rx_prog+r10+RI_OP],eax
	mov	[g_rx_prog+r10+RI_A],edx
	mov	[g_rx_prog+r10+RI_B],ecx
	inc	dword [g_plan_rxpc]
	mov	eax,r9d
	clc
	ret
rx_too_long:
	cstring .e_long, 'too long once compiled (2048 instructions; a large {n,m}?)',0
	lea	rax,[.e_long]
	mov	[g_rxc_err],rax
	stc
	ret

; edi = an index (the regex's): an instruction made room for there, those from it
; moved up one, and the targets with them: in what moved, those at it or past it;
; before it, those past it (one at it meant "what comes next", which is now the
; new instruction). CF: too long.
rx_insert:
	mov	r8d,[g_plan_rxpc]
	cmp	r8d,RX_POOL
	jae	rx_too_long
	mov	r9d,r8d
	sub	r9d,[g_rxc_base]
	cmp	r9d,RX_PER - 1
	jae	rx_too_long
	push	rdi
	mov	eax,[g_rxc_base]
	lea	esi,[rax+rdi]			; the first moved
	mov	ecx,r8d
	sub	ecx,esi				; how many
	imul	rsi,rsi,RI_SIZE
	lea	rsi,[g_rx_prog+rsi]
	imul	rcx,rcx,RI_SIZE
	lea	rdi,[rsi+rcx+RI_SIZE-1]
	lea	rsi,[rsi+rcx-1]
	std
	rep	movsb
	cld
	inc	dword [g_plan_rxpc]
	pop	rdi
	; the targets
	mov	ecx,[g_rxc_base]
	imul	r8,rcx,RI_SIZE
	lea	r8,[g_rx_prog+r8]		; the regex's first
	mov	r9d,[g_plan_rxpc]
	sub	r9d,ecx				; how many now
	xor	ecx,ecx
.fix:
	cmp	ecx,r9d
	jae	.fixed
	cmp	ecx,edi
	je	.next				; (the new one: its maker sets it)
	mov	r10d,edi			; the first target that moves: past it
	jg	@f				; for what moved, at it for what did not
	inc	r10d
@@:
	mov	eax,[r8+RI_OP]
	cmp	eax,RXO_JMP
	je	.a
	cmp	eax,RXO_SPLIT
	jne	.next
	cmp	dword [r8+RI_B],r10d
	jl	.a
	inc	dword [r8+RI_B]
.a:
	cmp	dword [r8+RI_A],r10d
	jl	.next
	inc	dword [r8+RI_A]
.next:
	add	r8,RI_SIZE
	inc	ecx
	jmp	.fix
.fixed:
	clc
	ret

; edi = an index (the regex's), eax/edx/ecx = op, a, b: that instruction put there
rx_set:
	push	rax
	mov	eax,[g_rxc_base]
	add	eax,edi
	imul	rax,rax,RI_SIZE
	lea	r8,[g_rx_prog+rax]
	pop	rax
	mov	[r8+RI_OP],eax
	mov	[r8+RI_A],edx
	mov	[r8+RI_B],ecx
	ret

; eax = the next index (the regex's)
rx_pc:
	mov	eax,[g_plan_rxpc]
	sub	eax,[g_rxc_base]
	ret

; al = the next pattern byte; CF: none left
rx_peek:
	mov	rax,[g_rxc_p]
	cmp	rax,[g_rxc_end]
	jae	.none
	movzx	eax,byte [rax]
	clc
	ret
.none:
	stc
	ret

; alternatives: a|b|c
rx_alt:
	push	rbx
	push	r12
	inc	dword [g_rxc_depth]
	cmp	dword [g_rxc_depth],32
	ja	.deep
	call	rx_pc
	mov	ebx,eax				; this alternative's first
	xor	r12d,r12d			; the jumps to patch, on the stack
	call	rx_seq
	jc	.bad
.more:
	call	rx_peek
	jc	.patch
	cmp	al,'|'
	jne	.patch
	inc	qword [g_rxc_p]
	mov	edi,ebx				; SPLIT before this alternative, a JMP after it
	call	rx_insert
	jc	.bad
	mov	eax,RXO_JMP
	mov	edx,-1
	xor	ecx,ecx
	call	rx_emit
	jc	.bad
	push	rax
	inc	r12d
	call	rx_pc
	mov	ecx,eax
	lea	edx,[rbx+1]
	mov	edi,ebx
	mov	eax,RXO_SPLIT
	call	rx_set
	call	rx_pc
	mov	ebx,eax
	call	rx_seq
	jc	.bad
	jmp	.more
.patch:
	test	r12d,r12d
	jz	.done
	pop	rdi
	dec	r12d
	call	rx_pc
	mov	edx,eax
	mov	eax,RXO_JMP
	xor	ecx,ecx
	call	rx_set
	jmp	.patch
.done:
	dec	dword [g_rxc_depth]
	clc
	pop	r12
	pop	rbx
	ret
.deep:
	cstring .e_deep, 'groups nested more than 32 deep',0
	lea	rax,[.e_deep]
	mov	[g_rxc_err],rax
.bad:
	lea	rsp,[rsp+r12*8]
	dec	dword [g_rxc_depth]
	stc
	pop	r12
	pop	rbx
	ret

; a sequence: up to a | or a ) or the end
rx_seq:
	call	rx_peek
	jc	.done
	cmp	al,'|'
	je	.done
	cmp	al,')'
	je	.done
	call	rx_quant
	jc	.bad
	jmp	rx_seq
.done:
	clc
	ret
.bad:
	stc
	ret

; an atom and its quantifier
rx_quant:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,[g_rxc_p]			; the atom: where it starts
	call	rx_pc
	mov	ebx,eax				; its first instruction
	mov	r13d,[g_rxc_ngrp]		; the groups before it
	call	rx_atom
	jc	.bad
	mov	r14,[g_rxc_p]			; where it ends
	call	rx_peek
	jc	.done
	cmp	al,'*'
	je	.star
	cmp	al,'+'
	je	.plus
	cmp	al,'?'
	je	.opt
	cmp	al,'{'
	je	.braces
.done:
	clc
	jmp	.out
.star:
	inc	qword [g_rxc_p]
	call	.lazy
	mov	r15d,eax
	mov	edi,ebx
	call	.make_star
	jc	.bad
	jmp	.done
.plus:
	inc	qword [g_rxc_p]
	call	.lazy
	mov	r15d,eax
	call	rx_pc
	lea	ecx,[rax+1]			; after the SPLIT
	mov	edx,ebx				; back to the atom
	test	r15d,r15d
	jz	@f
	xchg	edx,ecx
@@:
	mov	eax,RXO_SPLIT
	call	rx_emit
	jc	.bad
	jmp	.done
.opt:
	inc	qword [g_rxc_p]
	call	.lazy
	mov	r15d,eax
	mov	edi,ebx
	call	.make_opt
	jc	.bad
	jmp	.done
.braces:
	; {n}, {n,}, {n,m}: the atom n times, then m-n optional ones (or a star)
	inc	qword [g_rxc_p]
	call	.number
	jc	.bad_braces
	mov	r8d,eax				; n
	mov	r9d,eax				; m
	call	rx_peek
	jc	.bad_braces
	cmp	al,'}'
	je	.closed
	cmp	al,','
	jne	.bad_braces
	inc	qword [g_rxc_p]
	mov	r9d,-1				; (none: no end)
	call	rx_peek
	jc	.bad_braces
	cmp	al,'}'
	je	.closed
	push	r8
	call	.number
	pop	r8
	jc	.bad_braces
	mov	r9d,eax
	cmp	r9d,r8d
	jb	.bad_braces
	call	rx_peek
	jc	.bad_braces
	cmp	al,'}'
	jne	.bad_braces
.closed:
	inc	qword [g_rxc_p]
	push	r8
	push	r9
	call	.lazy
	mov	r15d,eax
	pop	r9
	pop	r8
	push	qword [g_rxc_p]			; (on from here, after)
	; the copy already made is dropped: each one parsed again, the same groups
	mov	eax,[g_rxc_base]
	add	eax,ebx
	mov	[g_plan_rxpc],eax
	xor	ecx,ecx
.mandatory:
	cmp	ecx,r8d
	jae	.optional
	push	rcx
	push	r8
	push	r9
	call	.again
	pop	r9
	pop	r8
	pop	rcx
	jc	.bad_pop
	inc	ecx
	jmp	.mandatory
.optional:
	cmp	r9d,-1
	jne	.bounded
	call	rx_pc				; {n,}: a star of one more
	push	rax
	call	.again
	pop	rdi
	jc	.bad_pop
	call	.make_star
	jc	.bad_pop
	jmp	.braced
.bounded:
	sub	r9d,r8d
.opt_copy:
	test	r9d,r9d
	jz	.braced
	push	r9
	call	rx_pc
	push	rax
	call	.again
	pop	rdi
	jc	.bad_pop2
	call	.make_opt
	pop	r9
	jc	.bad_pop
	dec	r9d
	jmp	.opt_copy
.braced:
	pop	qword [g_rxc_p]
	jmp	.done
.bad_pop2:
	add	rsp,8
.bad_pop:
	add	rsp,8
	jmp	.bad
.bad_braces:
	cstring .e_braces, 'a {n,m} that does not read (numbers up to 255, n <= m)',0
	lea	rax,[.e_braces]
	mov	[g_rxc_err],rax
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; the atom [r12, r14) parsed again, with the groups it had
.again:
	mov	[g_rxc_p],r12
	mov	[g_rxc_ngrp],r13d
	call	rx_atom
	ret
; eax = 1 when a ? follows (lazy), taken
.lazy:
	call	rx_peek
	jc	.greedy
	cmp	al,'?'
	jne	.greedy
	inc	qword [g_rxc_p]
	mov	eax,1
	ret
.greedy:
	xor	eax,eax
	ret
; edi = the atom's first instruction, the atom up to now: a star of it (r15d lazy)
.make_star:
	push	rdi
	call	rx_insert			; L: SPLIT L+1, E; atom; JMP L; E:
	pop	rdi
	jc	.ms_bad
	push	rdi
	mov	eax,RXO_JMP
	mov	edx,edi
	xor	ecx,ecx
	call	rx_emit
	pop	rdi
	jc	.ms_bad
	call	rx_pc
	mov	ecx,eax
	lea	edx,[rdi+1]
	test	r15d,r15d
	jz	@f
	xchg	edx,ecx
@@:
	mov	eax,RXO_SPLIT
	call	rx_set
	clc
	ret
.ms_bad:
	stc
	ret
; edi = the atom's first instruction: optional (r15d lazy)
.make_opt:
	push	rdi
	call	rx_insert			; SPLIT L+1, E; atom; E:
	pop	rdi
	jc	.ms_bad
	call	rx_pc
	mov	ecx,eax
	lea	edx,[rdi+1]
	test	r15d,r15d
	jz	@f
	xchg	edx,ecx
@@:
	mov	eax,RXO_SPLIT
	call	rx_set
	clc
	ret
; eax = a decimal number (1-3 digits, 255 at most). CF: none.
.number:
	xor	eax,eax
	xor	ecx,ecx
@@:
	push	rax
	call	rx_peek
	mov	edx,eax
	pop	rax
	jc	.num_end
	sub	edx,'0'
	cmp	edx,9
	ja	.num_end
	imul	eax,eax,10
	add	eax,edx
	inc	qword [g_rxc_p]
	inc	ecx
	cmp	ecx,3
	jbe	@b
	stc
	ret
.num_end:
	test	ecx,ecx
	jz	.num_bad
	cmp	eax,255
	ja	.num_bad
	clc
	ret
.num_bad:
	stc
	ret

; one atom: a char, ., a class, an escape, ^, $, a group
rx_atom:
	call	rx_peek
	jc	.nothing
	inc	qword [g_rxc_p]
	cmp	al,'('
	je	.group
	cmp	al,'['
	je	.class
	cmp	al,'.'
	je	.any
	cmp	al,'^'
	je	.bol
	cmp	al,'$'
	je	.eol
	cmp	al,'\'
	je	.escape
	cmp	al,'*'
	je	.nothing
	cmp	al,'+'
	je	.nothing
	cmp	al,'?'
	je	.nothing
	cmp	al,'{'
	je	.nothing
	cmp	al,')'
	je	.nothing
	cmp	al,'|'
	je	.nothing
.char:
	; eax = a byte: itself (in either case with (?i))
	cmp	dword [g_rxc_icase],0
	je	.plain
	mov	edx,eax
	or	edx,0x20
	cmp	edx,'a'
	jb	.plain
	cmp	edx,'z'
	ja	.plain
	push	rax
	call	rx_newclass
	pop	rax
	jc	.bad
	push	rdx
	call	rx_setbit			; (rdi = the bitmap, eax the byte)
	xor	eax,0x20
	call	rx_setbit
	pop	rdx
	mov	eax,RXO_CLASS
	xor	ecx,ecx
	jmp	rx_emit
.plain:
	mov	edx,eax
	mov	eax,RXO_CHAR
	xor	ecx,ecx
	jmp	rx_emit
.any:
	mov	eax,RXO_ANY
	jmp	.op
.bol:
	mov	eax,RXO_BOL
	jmp	.op
.eol:
	mov	eax,RXO_EOL
.op:
	xor	edx,edx
	xor	ecx,ecx
	jmp	rx_emit
.escape:
	call	rx_peek
	jc	.trailing
	inc	qword [g_rxc_p]
	call	rx_esc_set			; \d \w \s ...: a class
	jnc	.set
	call	rx_esc_char			; eax = the byte. CF: an unknown escape
	jc	.unknown
	jmp	.char
.set:
	mov	eax,RXO_CLASS
	xor	ecx,ecx
	jmp	rx_emit
.class:
	call	rx_class			; edx = the class
	jc	.bad
	mov	eax,RXO_CLASS
	xor	ecx,ecx
	jmp	rx_emit
.group:
	; (?: ...) or ( ... )
	mov	rax,[g_rxc_p]
	lea	rcx,[rax+2]
	cmp	rcx,[g_rxc_end]
	ja	.capture
	cmp	word [rax],'?:'
	jne	.capture
	add	qword [g_rxc_p],2
	call	rx_alt
	jc	.bad
	jmp	.close
.capture:
	mov	eax,[g_rxc_ngrp]
	inc	eax
	cmp	eax,9
	ja	.groups
	mov	[g_rxc_ngrp],eax
	push	rax
	lea	edx,[rax*2]
	mov	eax,RXO_SAVE
	xor	ecx,ecx
	call	rx_emit
	jc	.bad_pop
	call	rx_alt
	jc	.bad_pop
	pop	rax
	lea	edx,[rax*2+1]
	mov	eax,RXO_SAVE
	xor	ecx,ecx
	call	rx_emit
	jc	.bad
.close:
	call	rx_peek
	jc	.unclosed
	cmp	al,')'
	jne	.unclosed
	inc	qword [g_rxc_p]
	clc
	ret
.bad_pop:
	add	rsp,8
.bad:
	stc
	ret
.nothing:
	cstring .e_nothing, 'a quantifier, ) or | with nothing before it',0
	lea	rax,[.e_nothing]
	jmp	.err
.trailing:
	cstring .e_trailing, 'a \ at the end',0
	lea	rax,[.e_trailing]
	jmp	.err
.unknown:
	cstring .e_unknown, 'an escape it does not know (\d \w \s \D \W \S \n \t \r, or \ and a mark)',0
	lea	rax,[.e_unknown]
	jmp	.err
.groups:
	cstring .e_groups, 'more than 9 capturing groups (use (?: ) for the others)',0
	lea	rax,[.e_groups]
	jmp	.err
.unclosed:
	cstring .e_unclosed, 'a ( with no ) after it',0
	lea	rax,[.e_unclosed]
.err:
	mov	[g_rxc_err],rax
	stc
	ret

; al = the byte after a \: \d \D \w \W \s \S as a new class, edx = it. CF: not one.
rx_esc_set:
	mov	ecx,eax
	or	ecx,0x20
	cmp	ecx,'d'
	je	.yes
	cmp	ecx,'w'
	je	.yes
	cmp	ecx,'s'
	je	.yes
	stc
	ret
.yes:
	push	rax
	call	rx_newclass
	pop	rax
	jc	.full
	push	rdx
	call	rx_addset
	pop	rdx
	clc
	ret
.full:
	stc
	ret

; al = the byte after a \ (not a set): eax = the byte it means. CF: unknown.
rx_esc_char:
	cmp	al,'n'
	jne	@f
	mov	eax,10
	clc
	ret
@@:
	cmp	al,'t'
	jne	@f
	mov	eax,9
	clc
	ret
@@:
	cmp	al,'r'
	jne	@f
	mov	eax,13
	clc
	ret
@@:
	cmp	al,'0'				; letters and digits: an escape it does not know
	jb	.mark
	cmp	al,'9'
	jbe	.no
	mov	ecx,eax
	or	ecx,0x20
	cmp	ecx,'a'
	jb	.mark
	cmp	ecx,'z'
	jbe	.no
.mark:
	clc
	ret
.no:
	stc
	ret

; edx = a new class (zeroed), rdi = its bitmap. CF: too many.
rx_newclass:
	mov	edx,[g_plan_rxcls]
	cmp	edx,RX_CLASSES
	jae	.full
	inc	dword [g_plan_rxcls]
	mov	edi,edx
	shl	edi,5
	lea	rdi,[g_rx_cls+rdi]
	xor	eax,eax
	mov	[rdi],rax
	mov	[rdi+8],rax
	mov	[rdi+16],rax
	mov	[rdi+24],rax
	clc
	ret
.full:
	cstring .e_cls, 'more than 1024 character classes',0
	lea	rax,[.e_cls]
	mov	[g_rxc_err],rax
	stc
	ret

; rdi = a bitmap, eax = a byte: in it. Keeps all but rcx.
rx_setbit:
	mov	ecx,eax
	and	ecx,255
	bts	[rdi],ecx
	ret

; rdi = a bitmap, eax = d D w W s S: that set in it
rx_addset:
	push	rbx
	mov	ebx,eax
	mov	eax,'0'
@@:
	cmp	ebx,'d'
	je	.digits
	cmp	ebx,'D'
	je	.digits
	cmp	ebx,'s'
	je	.spaces
	cmp	ebx,'S'
	je	.spaces
	; \w: letters, digits, _
	mov	eax,'a'
.lower:
	call	rx_setbit
	inc	eax
	cmp	eax,'z'
	jbe	.lower
	mov	eax,'A'
.upper:
	call	rx_setbit
	inc	eax
	cmp	eax,'Z'
	jbe	.upper
	mov	eax,'_'
	call	rx_setbit
.digits:
	mov	eax,'0'
@@:
	call	rx_setbit
	inc	eax
	cmp	eax,'9'
	jbe	@b
	jmp	.negate
.spaces:
	mov	eax,' '
	call	rx_setbit
	mov	eax,9
@@:
	call	rx_setbit
	inc	eax
	cmp	eax,13
	jbe	@b
.negate:
	cmp	ebx,'a'				; the upper-case ones: all but it
	jae	.out
	not	qword [rdi]
	not	qword [rdi+8]
	not	qword [rdi+16]
	not	qword [rdi+24]
.out:
	pop	rbx
	ret

; after a [: the class, edx = it
rx_class:
	push	rbx
	push	r12
	push	r13
	call	rx_newclass
	jc	.bad
	mov	r12d,edx
	mov	r13,rdi				; the bitmap
	xor	ebx,ebx				; bit 0: negated, bit 1: one taken
	call	rx_peek
	jc	.unclosed
	cmp	al,'^'
	jne	.item
	inc	qword [g_rxc_p]
	or	ebx,1
.item:
	call	rx_peek
	jc	.unclosed
	inc	qword [g_rxc_p]
	cmp	al,']'
	jne	@f
	test	ebx,2
	jnz	.done				; (a ] first is itself)
@@:
	or	ebx,2
	cmp	al,'\'
	jne	.low
	call	rx_peek
	jc	.unclosed
	inc	qword [g_rxc_p]
	mov	ecx,eax
	or	ecx,0x20
	cmp	ecx,'d'
	je	.esc_set
	cmp	ecx,'w'
	je	.esc_set
	cmp	ecx,'s'
	je	.esc_set
	call	rx_esc_char
	jc	.unknown
	jmp	.low
.esc_set:
	mov	rdi,r13
	call	rx_addset_or			; (into it, not over it)
	jmp	.item
.low:
	mov	r8d,eax				; a byte; a range from it?
	mov	rcx,[g_rxc_p]
	lea	rdx,[rcx+1]
	cmp	rdx,[g_rxc_end]
	jae	.single
	cmp	byte [rcx],'-'
	jne	.single
	cmp	byte [rcx+1],']'
	je	.single
	add	qword [g_rxc_p],2
	movzx	r9d,byte [rcx+1]
	cmp	r9d,'\'
	jne	@f
	call	rx_peek
	jc	.unclosed
	inc	qword [g_rxc_p]
	call	rx_esc_char
	jc	.unknown
	mov	r9d,eax
@@:
	cmp	r9d,r8d
	jb	.backwards
.range:
	mov	eax,r8d
	call	.add
	inc	r8d
	cmp	r8d,r9d
	jbe	.range
	jmp	.item
.single:
	mov	eax,r8d
	call	.add
	jmp	.item
.done:
	test	ebx,1
	jz	@f
	not	qword [r13]
	not	qword [r13+8]
	not	qword [r13+16]
	not	qword [r13+24]
@@:
	mov	edx,r12d
	clc
	jmp	.out
.backwards:
	cstring .e_range, 'a range in [ ] that goes backwards',0
	lea	rax,[.e_range]
	jmp	.err
.unknown:
	lea	rax,[rx_atom.e_unknown]
	jmp	.err
.unclosed:
	cstring .e_unclosed, 'a [ with no ] after it',0
	lea	rax,[.e_unclosed]
.err:
	mov	[g_rxc_err],rax
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; eax = a byte: in the class (and its other case, with (?i))
.add:
	mov	rdi,r13
	call	rx_setbit
	cmp	dword [g_rxc_icase],0
	je	@f
	mov	ecx,eax
	or	ecx,0x20
	cmp	ecx,'a'
	jb	@f
	cmp	ecx,'z'
	ja	@f
	push	rax
	xor	eax,0x20
	call	rx_setbit
	pop	rax
@@:
	ret

; rdi = a bitmap, eax = d D w W s S: that set or-ed into it (a scratch class made
; and given back)
rx_addset_or:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	ebx,eax
	mov	edx,[g_plan_rxcls]
	cmp	edx,RX_CLASSES
	jae	.out
	mov	edi,edx
	shl	edi,5
	lea	rdi,[g_rx_cls+rdi]
	xor	eax,eax
	mov	[rdi],rax
	mov	[rdi+8],rax
	mov	[rdi+16],rax
	mov	[rdi+24],rax
	mov	eax,ebx
	push	rdi
	call	rx_addset
	pop	rdi
	mov	rax,[rdi]
	or	[r12],rax
	mov	rax,[rdi+8]
	or	[r12+8],rax
	mov	rax,[rdi+16]
	or	[r12+16],rax
	mov	rax,[rdi+24]
	or	[r12+24],rax
.out:
	pop	r12
	pop	rbx
	ret

; rsi/ecx = a pattern (after its ~), from the configuration: eax = its regex. Exits
; with why when it is not one.
rx_compile_or_exit:
	push	rsi
	push	rcx
	call	rx_compile
	pop	rcx
	pop	rsi
	jc	.bad
	ret
.bad:
	push	rsi
	push	rcx
	call	log_begin
	out_lit 'a regular expression, ~'
	pop	rdx
	pop	rsi
	call	out_str
	out_lit ': '
	mov	rsi,[g_rxc_err]
	call	out_cstr
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------------------------ matching

; eax = a regex, rsi/ecx = a subject: eax = 1 when it matches somewhere (^ $
; anchor), with g_rx_cap its captures (offsets in it, -1 for a group that took
; no part) and g_rx_subj it; else 0. Linear in the subject.
rx_match:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	imul	rax,rax,RXE_SIZE
	mov	edx,[g_rx+rax+RXE_START]
	imul	rdx,rdx,RI_SIZE
	lea	rdx,[g_rx_prog+rdx]
	mov	[g_rxm_prog],rdx
	mov	[g_rxm_s],rsi
	mov	[g_rx_subj],rsi
	mov	[g_rxm_len],ecx
	lea	rax,[g_rxm_l0]
	mov	[g_rxm_cl],rax
	lea	rax,[g_rxm_l1]
	mov	[g_rxm_nl],rax
	xor	eax,eax
	mov	[g_rxm_cn],eax
	inc	dword [g_rxm_gen]
	jnz	@f				; (wrapped: marks from before could pass)
	lea	rdi,[g_rxm_mark]
	mov	ecx,RX_PER
	rep	stosd
	mov	dword [g_rxm_gen],1
@@:
	xor	r12d,r12d			; matched
	xor	ebx,ebx				; pos
.step:
	test	r12d,r12d
	jnz	@f
	; a new thread from here (a search), after the others: the lowest priority
	lea	rdi,[g_rxm_cur]
	mov	eax,-1
	mov	ecx,RX_SLOTS
	rep	stosd
	mov	rdi,[g_rxm_cl]
	lea	rsi,[g_rxm_cn]
	xor	eax,eax
	mov	edx,ebx
	mov	r8d,[g_rxm_gen]
	call	rx_add
@@:
	cmp	dword [g_rxm_cn],0
	je	.end
	inc	dword [g_rxm_gen]		; the next list's
	mov	dword [g_rxm_nn],0
	xor	r13d,r13d			; the thread
.thread:
	cmp	r13d,[g_rxm_cn]
	jae	.stepped
	imul	r14,r13,RXT_STRIDE
	add	r14,[g_rxm_cl]			; it
	mov	eax,[r14]
	imul	rax,rax,RI_SIZE
	add	rax,[g_rxm_prog]
	mov	ecx,[rax+RI_OP]
	cmp	ecx,RXO_MATCH
	je	.match
	cmp	ebx,[g_rxm_len]
	jae	.next_thread			; (nothing left to take)
	mov	rdx,[g_rxm_s]
	movzx	edx,byte [rdx+rbx]
	cmp	ecx,RXO_CHAR
	je	.char
	cmp	ecx,RXO_ANY
	je	.take
	; a class
	mov	ecx,[rax+RI_A]
	shl	ecx,5
	lea	rcx,[g_rx_cls+rcx]
	bt	[rcx],edx
	jc	.take
	jmp	.next_thread
.char:
	cmp	edx,[rax+RI_A]
	jne	.next_thread
.take:
	lea	rsi,[r14+4]			; its captures, as the one going on
	lea	rdi,[g_rxm_cur]
	mov	ecx,RX_SLOTS
	rep	movsd
	mov	eax,[r14]
	inc	eax
	lea	edx,[rbx+1]
	mov	rdi,[g_rxm_nl]
	lea	rsi,[g_rxm_nn]
	mov	r8d,[g_rxm_gen]
	call	rx_add
.next_thread:
	inc	r13d
	jmp	.thread
.match:
	mov	r12d,1				; this one; the ones after it are cut
	lea	rsi,[r14+4]
	lea	rdi,[g_rx_cap]
	mov	ecx,RX_SLOTS
	rep	movsd
.stepped:
	mov	rax,[g_rxm_cl]			; the next list becomes the current
	xchg	rax,[g_rxm_nl]
	mov	[g_rxm_cl],rax
	mov	eax,[g_rxm_nn]
	mov	[g_rxm_cn],eax
	cmp	ebx,[g_rxm_len]
	jae	.end
	inc	ebx
	jmp	.step
.end:
	mov	eax,r12d
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = a list, rsi = its count, eax = a pc, edx = the position, r8d = the
; list's mark: the threads from pc, through jumps, splits, saves and anchors, with
; g_rxm_cur's captures, in priority order.
rx_add:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	mov	r14d,edx
	xor	r15d,r15d			; the stack
	mov	[g_rxm_stk],rax
	inc	r15d
.pop:
	test	r15d,r15d
	jz	.done
	dec	r15d
	mov	rax,[g_rxm_stk+r15*8]
	bt	rax,63
	jnc	.explore
	mov	rcx,rax				; a capture put back
	shr	rcx,32
	and	ecx,255
	mov	[g_rxm_cur+rcx*4],eax
	jmp	.pop
.explore:
	cmp	[g_rxm_mark+rax*4],r8d
	je	.pop
	mov	[g_rxm_mark+rax*4],r8d
	mov	ebx,eax
	imul	rcx,rax,RI_SIZE
	add	rcx,[g_rxm_prog]
	mov	edx,[rcx+RI_OP]
	cmp	edx,RXO_JMP
	je	.jmp
	cmp	edx,RXO_SPLIT
	je	.split
	cmp	edx,RXO_SAVE
	je	.save
	cmp	edx,RXO_BOL
	je	.bol
	cmp	edx,RXO_EOL
	je	.eol
	; one that takes a byte, or the match: a thread
	mov	eax,[r13]
	cmp	eax,RX_PER
	jae	.pop
	inc	dword [r13]
	imul	rdi,rax,RXT_STRIDE
	add	rdi,r12
	mov	[rdi],ebx
	add	rdi,4
	lea	rsi,[g_rxm_cur]
	mov	ecx,RX_SLOTS
	rep	movsd
	jmp	.pop
.jmp:
	mov	eax,[rcx+RI_A]
	jmp	.push
.split:
	mov	eax,[rcx+RI_B]			; b after a: a pushed last
	mov	[g_rxm_stk+r15*8],rax
	inc	r15d
	mov	eax,[rcx+RI_A]
	jmp	.push
.save:
	mov	edx,[rcx+RI_A]			; the slot: its value put back after
	mov	eax,[g_rxm_cur+rdx*4]
	mov	rsi,rdx
	shl	rsi,32
	or	rax,rsi
	bts	rax,63
	mov	[g_rxm_stk+r15*8],rax
	inc	r15d
	mov	[g_rxm_cur+rdx*4],r14d
	lea	eax,[rbx+1]
	jmp	.push
.bol:
	test	r14d,r14d
	jnz	.pop
	lea	eax,[rbx+1]
	jmp	.push
.eol:
	cmp	r14d,[g_rxm_len]
	jne	.pop
	lea	eax,[rbx+1]
.push:
	cmp	r15d,RX_PER * 4
	jae	.pop
	mov	[g_rxm_stk+r15*8],rax
	inc	r15d
	jmp	.pop
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; `okena regex PATTERN TEXT...`: each TEXT, a line: no, or the match and each
; group as start-end (- for one that took no part), offsets in it
cli_regex:
	cmp	qword [g_argc],3
	jb	.usage
	mov	edi,1
	call	out_select
	mov	rax,[g_argv]
	mov	rsi,[rax+16]
	call	.len
	call	rx_compile
	jc	.bad
	push	rax
	mov	r12d,3
.text:
	cmp	r12,[g_argc]
	jae	.done
	mov	rax,[g_argv]
	mov	rsi,[rax+r12*8]
	call	.len
	mov	eax,[rsp]
	call	rx_match
	test	eax,eax
	jnz	.matched
	out_lit 'no'
	jmp	.eol
.matched:
	mov	eax,[rsp]
	imul	rax,rax,RXE_SIZE
	mov	r13d,[g_rx+rax+RXE_NGRP]
	xor	ebx,ebx
.group:
	cmp	ebx,r13d
	ja	.eol
	test	ebx,ebx
	jz	@f
	mov	edi,' '
	call	out_char
@@:
	mov	eax,[g_rx_cap+rbx*8]
	cmp	eax,-1
	je	.unset
	call	out_u64
	mov	edi,'-'
	call	out_char
	mov	eax,[g_rx_cap+rbx*8+4]
	call	out_u64
	jmp	.group_next
.unset:
	mov	edi,'-'
	call	out_char
.group_next:
	inc	ebx
	jmp	.group
.eol:
	mov	edi,10
	call	out_char
	inc	r12d
	jmp	.text
.done:
	call	out_flush
	xor	edi,edi
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'okena regex: '
	mov	rsi,[g_rxc_err]
	call	out_cstr
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.usage:
	call	log_begin
	out_lit 'okena regex PATTERN TEXT...: what ~PATTERN makes of each TEXT (the match, then its groups, start-end)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
; rsi = a C string: ecx = its length
.len:
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	ret
