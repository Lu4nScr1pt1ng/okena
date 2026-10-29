; Chunked transfer coding (RFC 9112 7.1), decoded incrementally.
;
; The decoder sees the body as it arrives, in pieces of any size, and
; hands out the data it carries; the proxy writes its own chunk framing,
; so sizes, extensions and trailers never reach the next hop as they
; came. Strict: hex sizes of at most 15 digits, CRLF only, bounded
; extensions and trailers.

CK_STATE	:= 0		; d
CK_EXTRA	:= 4		; d: bytes of extensions or trailers so far
CK_REMAIN	:= 8		; q: data bytes left in the current chunk
CK_DIGITS	:= 16		; d
CK_SIZE		:= 24

CKS_SIZE	:= 0		; the first hex digit of a size
CKS_SIZE_MORE	:= 1		; more digits, ';' or CR
CKS_EXT		:= 2		; an extension, up to CR
CKS_SIZE_LF	:= 3
CKS_DATA	:= 4
CKS_DATA_CR	:= 5
CKS_DATA_LF	:= 6
CKS_TRAIL	:= 7		; start of a trailer line (or the final CRLF)
CKS_TRAIL_LINE	:= 8
CKS_TRAIL_LF	:= 9
CKS_END_LF	:= 10
CKS_DONE	:= 11

CK_EXT_MAX	:= 4096
CK_TRAIL_MAX	:= 8192

CK_MORE		:= 0		; everything consumed, more bytes needed
CK_DATAOUT	:= 1		; a data span is ready
CK_END		:= 2		; the body is complete
CK_ERROR	:= -1

; rdi = decoder (zeroed to start), rsi = bytes, edx = how many.
; eax = CK_*, ecx = bytes consumed, r8 = data span, r9d = its length
; (CK_DATAOUT). Call again with the rest after each span.
chunk_step:
	xor	ecx,ecx
.next:
	cmp	dword [rdi+CK_STATE],CKS_DONE
	je	.end
	cmp	ecx,edx
	jae	.more
	mov	eax,[rdi+CK_STATE]
	cmp	eax,CKS_DATA
	je	.data
	movzx	r10d,byte [rsi+rcx]
	inc	ecx
	cmp	eax,CKS_SIZE
	je	.size
	cmp	eax,CKS_SIZE_MORE
	je	.size_more
	cmp	eax,CKS_EXT
	je	.ext
	cmp	eax,CKS_SIZE_LF
	je	.size_lf
	cmp	eax,CKS_DATA_CR
	je	.data_cr
	cmp	eax,CKS_DATA_LF
	je	.data_lf
	cmp	eax,CKS_TRAIL
	je	.trail
	cmp	eax,CKS_TRAIL_LINE
	je	.trail_line
	cmp	eax,CKS_TRAIL_LF
	je	.trail_lf
	cmp	eax,CKS_END_LF
	je	.end_lf
	jmp	.error
.size:
	call	.hex
	jc	.error
	mov	qword [rdi+CK_REMAIN],0
	mov	dword [rdi+CK_DIGITS],0
	mov	dword [rdi+CK_STATE],CKS_SIZE_MORE
	jmp	.add_digit
.size_more:
	cmp	r10d,13
	je	.size_cr
	cmp	r10d,';'
	je	.ext_start
	call	.hex
	jc	.error
.add_digit:
	cmp	dword [rdi+CK_DIGITS],15
	jae	.error
	inc	dword [rdi+CK_DIGITS]
	mov	rax,[rdi+CK_REMAIN]
	shl	rax,4
	or	rax,r10
	mov	[rdi+CK_REMAIN],rax
	jmp	.next
.ext_start:
	mov	dword [rdi+CK_EXTRA],0
	mov	dword [rdi+CK_STATE],CKS_EXT
	jmp	.next
.ext:
	cmp	r10d,13
	je	.size_cr
	cmp	r10d,9
	je	@f
	cmp	r10d,' '
	jb	.error
	cmp	r10d,0x7F
	je	.error
@@:
	inc	dword [rdi+CK_EXTRA]
	cmp	dword [rdi+CK_EXTRA],CK_EXT_MAX
	ja	.error
	jmp	.next
.size_cr:
	mov	dword [rdi+CK_STATE],CKS_SIZE_LF
	jmp	.next
.size_lf:
	cmp	r10d,10
	jne	.error
	cmp	qword [rdi+CK_REMAIN],0
	je	.last
	mov	dword [rdi+CK_STATE],CKS_DATA
	jmp	.next
.last:
	mov	dword [rdi+CK_EXTRA],0
	mov	dword [rdi+CK_STATE],CKS_TRAIL
	jmp	.next
.data:
	; hand out as much of the chunk as there is
	mov	r9d,edx
	sub	r9d,ecx
	mov	rax,[rdi+CK_REMAIN]
	cmp	rax,r9
	jae	@f
	mov	r9d,eax
@@:
	lea	r8,[rsi+rcx]
	add	ecx,r9d
	sub	[rdi+CK_REMAIN],r9
	jnz	@f
	mov	dword [rdi+CK_STATE],CKS_DATA_CR
@@:
	mov	eax,CK_DATAOUT
	ret
.data_cr:
	cmp	r10d,13
	jne	.error
	mov	dword [rdi+CK_STATE],CKS_DATA_LF
	jmp	.next
.data_lf:
	cmp	r10d,10
	jne	.error
	mov	dword [rdi+CK_STATE],CKS_SIZE
	jmp	.next
.trail:
	cmp	r10d,13
	je	.final_cr
	mov	dword [rdi+CK_STATE],CKS_TRAIL_LINE
	jmp	.trail_byte
.trail_line:
	cmp	r10d,13
	je	.trail_cr
.trail_byte:
	cmp	r10d,9
	je	@f
	cmp	r10d,' '
	jb	.error
	cmp	r10d,0x7F
	je	.error
@@:
	inc	dword [rdi+CK_EXTRA]
	cmp	dword [rdi+CK_EXTRA],CK_TRAIL_MAX
	ja	.error
	jmp	.next
.trail_cr:
	mov	dword [rdi+CK_STATE],CKS_TRAIL_LF
	jmp	.next
.trail_lf:
	cmp	r10d,10
	jne	.error
	mov	dword [rdi+CK_STATE],CKS_TRAIL
	jmp	.next
.final_cr:
	mov	dword [rdi+CK_STATE],CKS_END_LF
	jmp	.next
.end_lf:
	cmp	r10d,10
	jne	.error
	mov	dword [rdi+CK_STATE],CKS_DONE
.end:
	mov	eax,CK_END
	ret
.more:
	mov	eax,CK_MORE
	ret
.error:
	mov	eax,CK_ERROR
	ret
; r10d = byte: its hex value, CF when not a hex digit
.hex:
	mov	eax,r10d
	sub	eax,'0'
	cmp	eax,9
	jbe	.hex_ok
	mov	eax,r10d
	or	eax,0x20
	sub	eax,'a'
	cmp	eax,5
	ja	.hex_bad
	add	eax,10
.hex_ok:
	mov	r10d,eax
	clc
	ret
.hex_bad:
	stc
	ret
