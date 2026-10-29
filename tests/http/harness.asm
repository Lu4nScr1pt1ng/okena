; Test harness for the HTTP parser and the chunked decoder (not part of
; okena). Reads stdin: the first byte selects what to parse.
;   'Q' request head   'S' response head   'C' chunked body
; For C, the second byte is the piece size the body is fed in (1-255),
; so resumption at every boundary is exercised. Prints a canonical
; description of the result on stdout.

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/limits.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/http/parse.inc'
include '../../src/http/chunk.inc'

INPUT_MAX = 1 shl 20

bss
	align 8
	g_in_len	dq ?
	g_msg:		rb HM_SIZE
	g_ck:		rb CK_SIZE
	g_in:		rb INPUT_MAX + 64
end bss

start:
	mov	dword [g_out_fd],1
	xor	ebx,ebx
.read:
	xor	edi,edi
	lea	rsi,[g_in+rbx]
	mov	edx,INPUT_MAX
	sub	edx,ebx
	jz	.got
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.got
	add	rbx,rax
	jmp	.read
.got:
	mov	[g_in_len],rbx
	test	rbx,rbx
	jz	.done
	cmp	byte [g_in],'C'
	je	chunked
	lea	rdi,[g_in+1]
	lea	esi,[ebx-1]
	call	http_head_end
	cmp	eax,-1
	je	.bad_framing
	test	eax,eax
	jz	.incomplete
	mov	esi,eax
	lea	rdi,[g_in+1]
	lea	rdx,[g_msg]
	cmp	byte [g_in],'S'
	je	.response
	call	http_parse_request
	jmp	.print
.response:
	call	http_parse_response
.print:
	test	eax,eax
	jnz	.error
	call	print_message
	jmp	.done
.error:
	push	rax
	out_lit 'error '
	pop	rax
	call	out_u64
	out_lit 10
	jmp	.done
.bad_framing:
	out_lit 'error 400',10
	jmp	.done
.incomplete:
	out_lit 'incomplete',10
.done:
	call	out_flush
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall

; "ok", then one line per parsed property and per forwarded field
print_message:
	push	rbx
	push	r12
	lea	r12,[g_msg]
	out_lit 'ok',10,'head '
	mov	eax,[r12+HM_HEADLEN]
	call	out_u64
	out_lit 10,'version '
	mov	eax,[r12+HM_VERSION]
	call	out_u64
	cmp	byte [g_in],'S'
	je	.status
	out_lit 10,'method '
	mov	rsi,[r12+HM_METHOD]
	mov	edx,[r12+HM_MLEN]
	call	out_str
	out_lit 10,'target '
	mov	rsi,[r12+HM_TARGET]
	mov	edx,[r12+HM_TLEN]
	call	out_str
	out_lit 10,'path '
	mov	rsi,[r12+HM_TARGET]
	mov	edx,[r12+HM_PLEN]
	call	out_str
	jmp	.common
.status:
	out_lit 10,'status '
	mov	eax,[r12+HM_STATUS]
	call	out_u64
.common:
	out_lit 10,'length '
	mov	rax,[r12+HM_LENGTH]
	cmp	rax,-1
	jne	@f
	out_lit 'none'
	jmp	.flags
@@:
	call	out_u64
.flags:
	out_lit 10,'flags'
	mov	ebx,[r12+HM_FLAGS]
	test	ebx,HMF_CHUNKED
	jz	@f
	out_lit ' chunked'
@@:
	test	ebx,HMF_CLOSE
	jz	@f
	out_lit ' close'
@@:
	test	ebx,HMF_UPGRADE
	jz	@f
	out_lit ' upgrade'
@@:
	test	ebx,HMF_CONTINUE
	jz	@f
	out_lit ' continue'
@@:
	out_lit 10
	mov	eax,[r12+HM_HOST]
	cmp	eax,-1
	je	.fields
	imul	rax,rax,HF_SIZE
	lea	rbx,[r12+HM_HDRS+rax]
	out_lit 'host '
	mov	rsi,[rbx+HF_VALUE]
	mov	edx,[rbx+HF_VLEN]
	call	out_str
	out_lit 10
.fields:
	xor	ebx,ebx
.field:
	cmp	ebx,[r12+HM_NHDR]
	jae	.out
	imul	rax,rbx,HF_SIZE
	lea	rax,[r12+HM_HDRS+rax]
	test	dword [rax+HF_FLAGS],HFF_HOP
	jnz	.next
	push	rax
	out_lit 'h '
	mov	rax,[rsp]
	mov	rsi,[rax+HF_NAME]
	mov	edx,[rax+HF_NLEN]
	call	out_str
	out_lit ': '
	pop	rax
	mov	rsi,[rax+HF_VALUE]
	mov	edx,[rax+HF_VLEN]
	call	out_str
	out_lit 10
.next:
	inc	ebx
	jmp	.field
.out:
	pop	r12
	pop	rbx
	ret

; Feed g_in[2..] in pieces of g_in[1] bytes; print the data, then "end
; <bytes consumed>" or "error" or "more".
chunked:
	movzx	r12d,byte [g_in+1]
	test	r12d,r12d
	jnz	@f
	inc	r12d
@@:
	lea	r13,[g_in+2]			; next unread byte
	mov	r14,[g_in_len]
	sub	r14,2				; bytes left
	out_lit 'data '
	xor	r15d,r15d			; pending bytes in the current piece
.piece:
	; the decoder sees at most one piece at a time
	mov	rdx,r14
	cmp	rdx,r12
	jbe	@f
	mov	rdx,r12
@@:
	mov	r15d,edx
.step:
	lea	rdi,[g_ck]
	mov	rsi,r13
	mov	edx,r15d
	call	chunk_step
	add	r13,rcx
	sub	r14,rcx
	sub	r15d,ecx
	cmp	eax,CK_DATAOUT
	je	.data
	cmp	eax,CK_END
	je	.end
	cmp	eax,CK_ERROR
	je	.error
	; more: next piece, if any
	test	r14,r14
	jnz	.piece
	out_lit 10,'more',10
	jmp	start.done
.data:
	mov	rsi,r8
	mov	edx,r9d
	call	out_str
	test	r15d,r15d
	jnz	.step
	test	r14,r14
	jnz	.piece
	jmp	.step				; let it report what it needs
.end:
	out_lit 10,'end '
	mov	rax,r13
	lea	rcx,[g_in+2]
	sub	rax,rcx
	call	out_u64
	out_lit 10
	jmp	start.done
.error:
	out_lit 10,'error',10
	jmp	start.done

segment readable
	rodata_emit

segment readable writeable
	bss_emit
