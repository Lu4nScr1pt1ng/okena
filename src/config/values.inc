; Value syntax shared by the checker and the compiler.
;
; Every parser takes rdi = text, esi = length (not NUL-terminated) and
; returns its result with CF clear, or CF set when the text is invalid.

; Parsed address (ADDR_*). Listen addresses may be ADDR_ANY (":port");
; backends may be names, resolved later.
AD_KIND		:= 0		; d
AD_PORT		:= 4		; d: host byte order
AD_IP		:= 8		; 16 bytes: IPv4 in the first 4, network order
AD_NAME		:= 24		; q: name or unix path in the source
AD_NLEN		:= 32		; d
AD_SIZE		:= 40

ADDR_ANY	:= 0
ADDR_V4		:= 1
ADDR_V6		:= 2
ADDR_UNIX	:= 3
ADDR_NAME	:= 4

UNIX_PATH_MAX	:= 107

; rdi/esi = decimal digits only. rax = value (at most 2^63), CF on error.
parse_decimal:
	test	esi,esi
	jz	.bad
	cmp	esi,18
	ja	.bad
	xor	eax,eax
	xor	ecx,ecx
.digit:
	movzx	edx,byte [rdi+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	rax,rax,10
	add	rax,rdx
	inc	ecx
	cmp	ecx,esi
	jb	.digit
	clc
	ret
.bad:
	stc
	ret

; Split rdi/esi into a leading number and the rest.
; rax = integer part, rdx = fraction scaled to 1000 (three digits),
; rcx = pointer to the rest, r8d = length of the rest. CF when there is
; no leading digit or more than three decimals.
parse_number_prefix:
	xor	eax,eax
	xor	edx,edx
	xor	ecx,ecx				; index
	xor	r9d,r9d				; integer digits
.int:
	cmp	ecx,esi
	jae	.int_end
	movzx	r10d,byte [rdi+rcx]
	sub	r10d,'0'
	cmp	r10d,9
	ja	.int_end
	cmp	r9d,15
	jae	.bad
	imul	rax,rax,10
	add	rax,r10
	inc	ecx
	inc	r9d
	jmp	.int
.int_end:
	test	r9d,r9d
	jz	.bad
	cmp	ecx,esi
	jae	.rest
	cmp	byte [rdi+rcx],'.'
	jne	.rest
	inc	ecx
	mov	r11d,100			; place value of the next decimal
	xor	r9d,r9d
.frac:
	cmp	ecx,esi
	jae	.frac_end
	movzx	r10d,byte [rdi+rcx]
	sub	r10d,'0'
	cmp	r10d,9
	ja	.frac_end
	cmp	r9d,3
	jae	.bad
	imul	r10d,r11d
	add	edx,r10d
	push	rax
	push	rdx
	mov	eax,r11d
	xor	edx,edx
	mov	r10d,10
	div	r10d
	mov	r11d,eax
	pop	rdx
	pop	rax
	inc	ecx
	inc	r9d
	jmp	.frac
.frac_end:
	test	r9d,r9d
	jz	.bad				; "1." is not a number
.rest:
	lea	r10,[rdi+rcx]
	mov	r8d,esi
	sub	r8d,ecx
	mov	rcx,r10
	clc
	ret
.bad:
	stc
	ret

; rcx/r8d = unit text, r9 = table of (dq name, dq multiplier) ending with
; name 0; names are NUL-terminated. rax = multiplier, CF when unknown.
match_unit:
	push	rbx
	mov	rbx,r9
.next:
	mov	r10,[rbx]
	test	r10,r10
	jz	.bad
	xor	r11d,r11d
.cmp:
	cmp	r11d,r8d
	je	.end
	mov	al,[rcx+r11]
	cmp	al,[r10+r11]
	jne	.skip
	inc	r11d
	jmp	.cmp
.end:
	cmp	byte [r10+r11],0
	jne	.skip
	mov	rax,[rbx+8]
	pop	rbx
	clc
	ret
.skip:
	add	rbx,16
	jmp	.next
.bad:
	pop	rbx
	stc
	ret

cstring u_us, 'us',0
cstring u_ms, 'ms',0
cstring u_s, 's',0
cstring u_m, 'm',0
cstring u_h, 'h',0
cstring u_d, 'd',0
cstring u_b, 'B',0
cstring u_kib, 'KiB',0
cstring u_mib, 'MiB',0
cstring u_gib, 'GiB',0
cstring u_tib, 'TiB',0

rodata
	align 8
	units_duration:			; multipliers in microseconds
		dq u_us, 1
		dq u_ms, 1000
		dq u_s, 1000000
		dq u_m, 60000000
		dq u_h, 3600000000
		dq u_d, 86400000000
		dq 0, 0
	units_size:
		dq u_b, 1
		dq u_kib, 1 shl 10
		dq u_mib, 1 shl 20
		dq u_gib, 1 shl 30
		dq u_tib, 1 shl 40
		dq 0, 0
	units_rate:			; per-unit length in seconds
		dq u_s, 1
		dq u_m, 60
		dq u_h, 3600
		dq 0, 0
end rodata

; number * multiplier with the fraction (in thousandths). rax = int,
; rdx = fraction, r10 = multiplier. rax = result, CF on overflow or when
; the result is not a whole number of base units.
scale_number:
	push	rdx
	mul	r10
	jo	.overflow
	jc	.overflow
	mov	r11,rax
	pop	rax				; fraction
	mul	r10
	jc	.bad
	mov	r10d,1000
	div	r10
	test	rdx,rdx
	jnz	.bad				; 1.5us has no exact value
	add	rax,r11
	jc	.bad
	clc
	ret
.overflow:
	pop	rdx
.bad:
	stc
	ret

; "250ms", "30s", "1.5m". rax = microseconds.
parse_duration:
	call	parse_number_prefix
	jc	.bad
	push	rax
	push	rdx
	lea	r9,[units_duration]
	call	match_unit
	mov	r10,rax
	pop	rdx
	pop	rax
	jc	.bad
	jmp	scale_number
.bad:
	stc
	ret

; "16KiB", "4MiB", "512B". rax = bytes.
parse_size:
	call	parse_number_prefix
	jc	.bad
	push	rax
	push	rdx
	lea	r9,[units_size]
	call	match_unit
	mov	r10,rax
	pop	rdx
	pop	rax
	jc	.bad
	jmp	scale_number
.bad:
	stc
	ret

; "100/s", "5000/m". rax = count, rdx = period in seconds.
parse_rate:
	call	parse_number_prefix
	jc	.bad
	test	rdx,rdx
	jnz	.bad				; whole numbers only
	test	rax,rax
	jz	.bad
	cmp	r8d,2
	jb	.bad
	cmp	byte [rcx],'/'
	jne	.bad
	inc	rcx
	dec	r8d
	push	rax
	lea	r9,[units_rate]
	call	match_unit
	mov	rdx,rax
	pop	rax
	ret
.bad:
	stc
	ret

; "20%", "0.5%". rax = hundredths of a percent (0..10000).
parse_percent:
	call	parse_number_prefix
	jc	.bad
	cmp	r8d,1
	jne	.bad
	cmp	byte [rcx],'%'
	jne	.bad
	imul	rax,rax,100
	mov	r10,rax
	mov	rax,rdx				; thousandths of the number
	xor	edx,edx
	mov	ecx,10
	div	rcx
	test	rdx,rdx
	jnz	.bad				; more than two decimals
	add	rax,r10
	cmp	rax,10000
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; A range of addresses (trusted_proxies).
TR_KIND		:= 0		; d: 4 or 6
TR_BITS		:= 4		; d: prefix length
TR_IP		:= 8		; 16 bytes, network order (IPv4 in the first 4)
TR_SIZE		:= 24

; rdi/esi = "10.0.0.0/8", "192.168.1.10", "2001:db8::/32". rdx = TR_*
; record to fill. CF on error.
parse_cidr:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	r14,rdx
	xor	eax,eax
	mov	[r14+TR_IP],rax
	mov	[r14+TR_IP+8],rax
	xor	ebx,ebx				; the address part ends at '/'
	xor	ecx,ecx				; ':' seen
@@:
	cmp	ebx,r13d
	jae	@f
	cmp	byte [r12+rbx],'/'
	je	@f
	cmp	byte [r12+rbx],':'
	jne	.not_colon
	inc	ecx
.not_colon:
	inc	ebx
	jmp	@b
@@:
	test	ebx,ebx
	jz	.bad
	mov	rdi,r12
	mov	esi,ebx
	test	ecx,ecx
	jnz	.v6
	call	parse_ipv4_text
	jc	.bad
	mov	[r14+TR_IP],eax
	mov	dword [r14+TR_KIND],4
	mov	dword [r14+TR_BITS],32
	jmp	.bits
.v6:
	lea	rdx,[r14+TR_IP]
	call	parse_ipv6_text
	jc	.bad
	mov	dword [r14+TR_KIND],6
	mov	dword [r14+TR_BITS],128
.bits:
	cmp	ebx,r13d
	je	.ok
	lea	rdi,[r12+rbx+1]
	mov	esi,r13d
	sub	esi,ebx
	dec	esi
	jz	.bad
	call	parse_decimal
	jc	.bad
	cmp	eax,[r14+TR_BITS]
	ja	.bad
	mov	[r14+TR_BITS],eax
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = "a.b.c.d". eax = address in network byte order, CF on error.
parse_ipv4_text:
	xor	eax,eax				; result
	xor	ecx,ecx				; index
	xor	r8d,r8d				; octets seen
.octet:
	xor	edx,edx				; value
	xor	r9d,r9d				; digits
.digit:
	cmp	ecx,esi
	jae	.end_octet
	movzx	r10d,byte [rdi+rcx]
	sub	r10d,'0'
	cmp	r10d,9
	ja	.end_octet
	test	r9d,r9d
	jz	@f
	test	edx,edx
	jz	.bad				; leading zero: "01" is ambiguous (octal)
@@:
	imul	edx,edx,10
	add	edx,r10d
	inc	r9d
	inc	ecx
	cmp	r9d,3
	jbe	.digit
	jmp	.bad
.end_octet:
	test	r9d,r9d
	jz	.bad
	cmp	edx,255
	ja	.bad
	push	rcx
	lea	ecx,[r8*8]
	shl	edx,cl
	pop	rcx
	or	eax,edx
	inc	r8d
	cmp	r8d,4
	je	.last
	cmp	ecx,esi
	jae	.bad
	cmp	byte [rdi+rcx],'.'
	jne	.bad
	inc	ecx
	jmp	.octet
.last:
	cmp	ecx,esi
	jne	.bad
	clc
	ret
.bad:
	stc
	ret

; rdi/esi = IPv6 text (RFC 4291 section 2.2, with "::" and a trailing
; dotted IPv4). rdx = 16-byte output. CF on error.
parse_ipv6_text:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,16
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	xor	r14d,r14d			; groups written
	mov	r15d,-1				; group index of "::"
	xor	ecx,ecx				; position
	; zero the output
	xor	eax,eax
	mov	[r13],rax
	mov	[r13+8],rax
	cmp	r12d,2
	jb	.bad
	cmp	word [rbx],'::'
	jne	.group
	mov	r15d,0
	add	ecx,2
	cmp	ecx,r12d
	je	.done
.group:
	cmp	r14d,8
	jae	.bad
	; IPv4 tail? look for '.' before the next ':'
	mov	edx,ecx
.peek:
	cmp	edx,r12d
	jae	.hex
	mov	al,[rbx+rdx]
	cmp	al,':'
	je	.hex
	cmp	al,'.'
	je	.v4
	inc	edx
	jmp	.peek
.v4:
	cmp	r14d,6
	ja	.bad
	lea	rdi,[rbx+rcx]
	mov	esi,r12d
	sub	esi,ecx
	call	parse_ipv4_text
	jc	.bad
	mov	[rsp],eax
	movzx	edx,word [rsp]
	mov	[r13+r14*2],dx
	inc	r14d
	movzx	edx,word [rsp+2]
	mov	[r13+r14*2],dx
	inc	r14d
	jmp	.expand
.hex:
	xor	eax,eax
	xor	edx,edx				; digits
.hex_digit:
	cmp	ecx,r12d
	jae	.hex_end
	movzx	r8d,byte [rbx+rcx]
	mov	r9d,r8d
	sub	r9d,'0'
	cmp	r9d,9
	jbe	.hex_ok
	or	r8d,0x20
	mov	r9d,r8d
	sub	r9d,'a'
	cmp	r9d,5
	ja	.hex_end
	add	r9d,10
.hex_ok:
	cmp	edx,4
	jae	.bad
	shl	eax,4
	or	eax,r9d
	inc	edx
	inc	ecx
	jmp	.hex_digit
.hex_end:
	test	edx,edx
	jz	.bad
	xchg	al,ah				; network byte order
	mov	[r13+r14*2],ax
	inc	r14d
	cmp	ecx,r12d
	je	.expand
	cmp	byte [rbx+rcx],':'
	jne	.bad
	inc	ecx
	cmp	ecx,r12d
	jae	.bad				; trailing single ':'
	cmp	byte [rbx+rcx],':'
	jne	.group
	; "::" in the middle
	cmp	r15d,0
	jge	.bad				; only one "::"
	mov	r15d,r14d
	inc	ecx
	cmp	ecx,r12d
	je	.expand
	jmp	.group
.expand:
	cmp	r15d,0
	jl	.full
	cmp	r14d,7
	ja	.bad				; "::" must stand for at least one group
	; move groups after "::" to the end
	mov	eax,r14d			; groups written
	mov	edx,r14d
	sub	edx,r15d			; groups after "::"
	mov	r8d,8
	sub	r8d,edx				; destination of the first of them
.move:
	test	edx,edx
	jz	.zero
	dec	edx
	lea	r9d,[r15+rdx]
	movzx	r10d,word [r13+r9*2]
	lea	r11d,[r8+rdx]
	mov	[r13+r11*2],r10w
	jmp	.move
.zero:
	; zero from r15 up to r8
	mov	edx,r15d
@@:
	cmp	edx,r8d
	jae	.done
	mov	word [r13+rdx*2],0
	inc	edx
	jmp	@b
.full:
	cmp	r14d,8
	jne	.bad
.done:
	add	rsp,16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	clc
	ret
.bad:
	add	rsp,16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	stc
	ret

; rdi/esi = decimal port. eax = 1..65535, CF on error.
parse_port:
	test	esi,esi
	jz	.bad
	cmp	esi,5
	ja	.bad
	cmp	byte [rdi],'0'
	je	.bad
	call	parse_decimal
	jc	.bad
	test	eax,eax
	jz	.bad
	cmp	eax,65535
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; rdi/esi = DNS name (RFC 1123 labels). CF when invalid, or when every
; label is numeric (a mistyped IPv4 address).
check_hostname:
	test	esi,esi
	jz	.bad
	cmp	esi,253
	ja	.bad
	xor	ecx,ecx
	xor	edx,edx				; label length
	xor	r8d,r8d				; 1 once a label has a letter or '-'
	xor	r9d,r9d				; previous byte
.loop:
	cmp	ecx,esi
	jae	.end
	movzx	eax,byte [rdi+rcx]
	cmp	al,'.'
	je	.dot
	cmp	al,'-'
	je	.hyphen
	mov	r10d,eax
	sub	r10d,'0'
	cmp	r10d,9
	jbe	.char
	or	eax,0x20
	sub	eax,'a'
	cmp	eax,25
	ja	.bad
	mov	r8d,1
.char:
	inc	edx
	cmp	edx,63
	ja	.bad
	movzx	r9d,byte [rdi+rcx]
	inc	ecx
	jmp	.loop
.hyphen:
	test	edx,edx
	jz	.bad				; label starts with '-'
	mov	r8d,1
	jmp	.char
.dot:
	test	edx,edx
	jz	.bad				; empty label
	cmp	r9b,'-'
	je	.bad
	xor	edx,edx
	mov	r9d,'.'
	inc	ecx
	jmp	.loop
.end:
	cmp	r9b,'-'
	je	.bad
	test	r8d,r8d
	jz	.bad
	clc
	ret
.bad:
	stc
	ret

; Address with a port: ":443", "10.0.0.1:80", "[::1]:443",
; "unix:/run/app.sock", "db.internal:5432".
; rdi/esi = text, rdx = AD_SIZE output, ecx = 1 when names and unix
; paths are allowed (backends), 0 for listen addresses.
; CF on error; eax = ADDR_ERR_* reason.
ADDR_ERR_SYNTAX	:= 1
ADDR_ERR_PORT	:= 2
ADDR_ERR_IP	:= 3
ADDR_ERR_NAME	:= 4
ADDR_ERR_ANY	:= 5		; ":port" where a host is needed
ADDR_ERR_PATH	:= 6

parse_address:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	mov	r14d,ecx
	xor	eax,eax
	mov	[r13+AD_KIND],eax
	mov	[r13+AD_PORT],eax
	mov	[r13+AD_IP],rax
	mov	[r13+AD_IP+8],rax
	mov	[r13+AD_NAME],rax
	mov	[r13+AD_NLEN],eax
	; unix:/path
	cmp	r12d,5
	jbe	.not_unix
	cmp	dword [rbx],'unix'
	jne	.not_unix
	cmp	byte [rbx+4],':'
	jne	.not_unix
	test	r14d,r14d
	jz	.syntax
	cmp	byte [rbx+5],'/'
	jne	.path
	lea	eax,[r12-5]
	cmp	eax,UNIX_PATH_MAX
	ja	.path
	mov	dword [r13+AD_KIND],ADDR_UNIX
	lea	rax,[rbx+5]
	mov	[r13+AD_NAME],rax
	lea	eax,[r12-5]
	mov	[r13+AD_NLEN],eax
	jmp	.ok
.not_unix:
	test	r12d,r12d
	jz	.syntax
	cmp	byte [rbx],'['
	je	.v6
	; host:port, split at the last ':'
	mov	ecx,r12d
@@:
	dec	ecx
	js	.no_port
	cmp	byte [rbx+rcx],':'
	jne	@b
	; only one ':' allowed outside brackets
	mov	edx,ecx
@@:
	dec	edx
	js	@f
	cmp	byte [rbx+rdx],':'
	je	.bare_v6
	jmp	@b
@@:
	push	rcx
	lea	rdi,[rbx+rcx+1]
	mov	esi,r12d
	sub	esi,ecx
	dec	esi
	call	parse_port
	pop	rcx
	jc	.port
	mov	[r13+AD_PORT],eax
	test	ecx,ecx
	jz	.any
	mov	rdi,rbx
	mov	esi,ecx
	push	rcx
	call	parse_ipv4_text
	pop	rcx
	jc	.name
	mov	dword [r13+AD_KIND],ADDR_V4
	mov	[r13+AD_IP],eax
	jmp	.ok
.any:
	test	r14d,r14d
	jnz	.need_host
	mov	dword [r13+AD_KIND],ADDR_ANY
	jmp	.ok
.name:
	; digits and dots only: a broken IPv4, not a name
	mov	rdi,rbx
	mov	esi,ecx
	push	rcx
	call	all_digits_and_dots
	pop	rcx
	jnc	.ip
	test	r14d,r14d
	jz	.ip				; listeners need an address
	mov	rdi,rbx
	mov	esi,ecx
	push	rcx
	call	check_hostname
	pop	rcx
	jc	.badname
	mov	dword [r13+AD_KIND],ADDR_NAME
	mov	[r13+AD_NAME],rbx
	mov	[r13+AD_NLEN],ecx
	jmp	.ok
.v6:
	; [addr]:port
	mov	ecx,1
@@:
	cmp	ecx,r12d
	jae	.syntax
	cmp	byte [rbx+rcx],']'
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	edx,[rcx+1]
	cmp	edx,r12d
	jae	.no_port
	cmp	byte [rbx+rdx],':'
	jne	.syntax
	push	rcx
	lea	rdi,[rbx+rdx+1]
	mov	esi,r12d
	sub	esi,edx
	dec	esi
	call	parse_port
	pop	rcx
	jc	.port
	mov	[r13+AD_PORT],eax
	lea	rdi,[rbx+1]
	lea	esi,[rcx-1]
	lea	rdx,[r13+AD_IP]
	call	parse_ipv6_text
	jc	.ip
	mov	dword [r13+AD_KIND],ADDR_V6
	jmp	.ok
.ok:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	clc
	ret
.no_port:
.bare_v6:
	mov	eax,ADDR_ERR_SYNTAX
	jmp	.fail
.syntax:
	mov	eax,ADDR_ERR_SYNTAX
	jmp	.fail
.port:
	mov	eax,ADDR_ERR_PORT
	jmp	.fail
.ip:
	mov	eax,ADDR_ERR_IP
	jmp	.fail
.badname:
	mov	eax,ADDR_ERR_NAME
	jmp	.fail
.need_host:
	mov	eax,ADDR_ERR_ANY
	jmp	.fail
.path:
	mov	eax,ADDR_ERR_PATH
.fail:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	stc
	ret

; rdi/esi. CF clear when every byte is a digit or '.'.
all_digits_and_dots:
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	.yes
	movzx	eax,byte [rdi+rcx]
	cmp	al,'.'
	je	.next
	sub	eax,'0'
	cmp	eax,9
	ja	.no
.next:
	inc	ecx
	jmp	@b
.yes:
	clc
	ret
.no:
	stc
	ret

; rdi/esi = name: [a-z0-9][a-z0-9_-]*, at most 64 bytes. CF when invalid.
check_name:
	test	esi,esi
	jz	.bad
	cmp	esi,64
	ja	.bad
	xor	ecx,ecx
.loop:
	movzx	eax,byte [rdi+rcx]
	mov	edx,eax
	sub	edx,'a'
	cmp	edx,25
	jbe	.ok
	mov	edx,eax
	sub	edx,'0'
	cmp	edx,9
	jbe	.ok
	test	ecx,ecx
	jz	.bad
	cmp	al,'_'
	je	.ok
	cmp	al,'-'
	jne	.bad
.ok:
	inc	ecx
	cmp	ecx,esi
	jb	.loop
	clc
	ret
.bad:
	stc
	ret

; Edit distance (Levenshtein) between rdi/esi and rdx/ecx, both at most
; 31 bytes. eax = distance (99 when either is too long).
edit_distance:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,64*2
	cmp	esi,31
	ja	.far
	cmp	ecx,31
	ja	.far
	mov	r12,rdi
	mov	r13d,esi
	mov	r14,rdx
	mov	r15d,ecx
	; row[j] = j
	xor	eax,eax
@@:
	mov	[rsp+rax*2],ax
	inc	eax
	cmp	eax,r15d
	jbe	@b
	xor	ebx,ebx				; i
.row:
	cmp	ebx,r13d
	jae	.finish
	movzx	r8d,word [rsp]			; diagonal = row[0]
	lea	eax,[rbx+1]
	mov	[rsp],ax
	xor	ecx,ecx				; j
.col:
	cmp	ecx,r15d
	jae	.row_done
	movzx	r9d,word [rsp+rcx*2+2]		; above = row[j+1]
	; substitution cost
	mov	al,[r12+rbx]
	xor	r10d,r10d
	cmp	al,[r14+rcx]
	setne	r10b
	add	r10d,r8d			; diagonal + cost
	lea	r11d,[r9+1]			; deletion
	cmp	r11d,r10d
	cmovb	r10d,r11d
	movzx	r11d,word [rsp+rcx*2]		; left (already new)
	inc	r11d				; insertion
	cmp	r11d,r10d
	cmovb	r10d,r11d
	mov	r8d,r9d
	mov	[rsp+rcx*2+2],r10w
	inc	ecx
	jmp	.col
.row_done:
	inc	ebx
	jmp	.row
.finish:
	movzx	eax,word [rsp+r15*2]
	jmp	.out
.far:
	mov	eax,99
.out:
	add	rsp,64*2
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
