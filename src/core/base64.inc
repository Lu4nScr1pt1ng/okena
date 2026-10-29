; Base64 (RFC 4648), from fasm2Crud: standard alphabet with padding
; (PEM files) and URL-safe without padding.

rodata
	b64_std		db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	b64_url		db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
	; Decoding tables: 6-bit value, or 0xFF for bytes outside the alphabet.
	b64_std_dec:
	repeat 256, c:0
		if c >= 'A' & c <= 'Z'
			db c - 'A'
		else if c >= 'a' & c <= 'z'
			db c - 'a' + 26
		else if c >= '0' & c <= '9'
			db c - '0' + 52
		else if c = '+'
			db 62
		else if c = '/'
			db 63
		else
			db 0xFF
		end if
	end repeat
	b64_url_dec:
	repeat 256, c:0
		if c >= 'A' & c <= 'Z'
			db c - 'A'
		else if c >= 'a' & c <= 'z'
			db c - 'a' + 26
		else if c >= '0' & c <= '9'
			db c - '0' + 52
		else if c = '-'
			db 62
		else if c = '_'
			db 63
		else
			db 0xFF
		end if
	end repeat
end rodata

; rdi = destination, rsi = bytes, edx = length. rax = characters written;
; rdi is left just past them.
base64_encode:
	lea	r9,[b64_std]
	mov	r10d,1				; pad
	jmp	b64_encode

base64url_encode:
	lea	r9,[b64_url]
	xor	r10d,r10d
	jmp	b64_encode

; Standard alphabet without padding (PHC strings).
base64_encode_nopad:
	lea	r9,[b64_std]
	xor	r10d,r10d

; r9 = alphabet, r10d = 1 to pad with '='.
b64_encode:
	mov	r11,rdi
.triple:
	cmp	edx,3
	jb	.tail
	movzx	eax,byte [rsi]
	shl	eax,16
	movzx	ecx,byte [rsi+1]
	shl	ecx,8
	or	eax,ecx
	movzx	ecx,byte [rsi+2]
	or	eax,ecx
	mov	ecx,eax
	shr	ecx,18
	mov	cl,[r9+rcx]
	mov	[rdi],cl
	mov	ecx,eax
	shr	ecx,12
	and	ecx,63
	mov	cl,[r9+rcx]
	mov	[rdi+1],cl
	mov	ecx,eax
	shr	ecx,6
	and	ecx,63
	mov	cl,[r9+rcx]
	mov	[rdi+2],cl
	and	eax,63
	mov	al,[r9+rax]
	mov	[rdi+3],al
	add	rsi,3
	add	rdi,4
	sub	edx,3
	jmp	.triple
.tail:
	test	edx,edx
	jz	.done
	movzx	eax,byte [rsi]
	shl	eax,16
	cmp	edx,2
	jb	@f
	movzx	ecx,byte [rsi+1]
	shl	ecx,8
	or	eax,ecx
@@:
	mov	ecx,eax
	shr	ecx,18
	mov	cl,[r9+rcx]
	mov	[rdi],cl
	mov	ecx,eax
	shr	ecx,12
	and	ecx,63
	mov	cl,[r9+rcx]
	mov	[rdi+1],cl
	add	rdi,2
	cmp	edx,2
	jb	.pad1
	shr	eax,6
	and	eax,63
	mov	al,[r9+rax]
	mov	[rdi],al
	inc	rdi
	test	r10d,r10d
	jz	.done
	mov	byte [rdi],'='
	inc	rdi
	jmp	.done
.pad1:
	test	r10d,r10d
	jz	.done
	mov	word [rdi],'=='
	add	rdi,2
.done:
	mov	rax,rdi
	sub	rax,r11
	ret

; rdi = destination, rsi = text, edx = length.
; rax = bytes written, or -1 when the text is not canonical base64.
base64_decode:
	lea	r9,[b64_std_dec]
	mov	r10d,1				; padding required
	jmp	b64_decode

base64url_decode:
	lea	r9,[b64_url_dec]
	xor	r10d,r10d			; padding forbidden
	jmp	b64_decode

base64_decode_nopad:
	lea	r9,[b64_std_dec]
	xor	r10d,r10d

b64_decode:
	push	rbx
	mov	r11,rdi
	; Strip padding (std only): length must be a multiple of 4.
	test	r10d,r10d
	jz	.unpadded
	test	edx,3
	jnz	.bad
	test	edx,edx
	jz	.done
	cmp	byte [rsi+rdx-1],'='
	jne	.unpadded
	dec	edx
	cmp	byte [rsi+rdx-1],'='
	jne	.unpadded
	dec	edx
.unpadded:
	mov	eax,edx
	and	eax,3
	cmp	eax,1
	je	.bad				; one leftover character never encodes a byte
.quad:
	cmp	edx,4
	jb	.tail
	xor	eax,eax
	repeat 4, k:0
		movzx	ecx,byte [rsi+k]
		movzx	ecx,byte [r9+rcx]
		cmp	ecx,0xFF
		je	.bad
		shl	eax,6
		or	eax,ecx
	end repeat
	mov	ecx,eax
	shr	ecx,16
	mov	[rdi],cl
	mov	[rdi+1],ah
	mov	[rdi+2],al
	add	rsi,4
	add	rdi,3
	sub	edx,4
	jmp	.quad
.tail:
	test	edx,edx
	jz	.done
	; 2 or 3 characters: 1 or 2 bytes; unused low bits must be zero.
	xor	eax,eax
	xor	ebx,ebx
.tail_char:
	movzx	ecx,byte [rsi+rbx]
	movzx	ecx,byte [r9+rcx]
	cmp	ecx,0xFF
	je	.bad
	shl	eax,6
	or	eax,ecx
	inc	ebx
	cmp	ebx,edx
	jb	.tail_char
	cmp	edx,2
	jne	.three
	test	eax,0x0F
	jnz	.bad
	shr	eax,4
	mov	[rdi],al
	inc	rdi
	jmp	.done
.three:
	test	eax,0x03
	jnz	.bad
	shr	eax,2
	mov	[rdi],ah
	mov	[rdi+1],al
	add	rdi,2
.done:
	mov	rax,rdi
	sub	rax,r11
	pop	rbx
	ret
.bad:
	mov	rax,-1
	pop	rbx
	ret
