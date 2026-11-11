; `discover file /etc/okena/users.list [port=8080] [max=64]` in a pool: its
; servers are the lines of a file, `ADDRESS[:PORT] [weight=N]` (`#` starts a
; comment), so anything that can write a file can place backends:
; consul-template, a script, a CI job.
;
; The control process looks at the file once a second (its inode, size and
; time: a stat, nothing more when nothing changed) and when it changed reads
; it whole and publishes the set, as it does for the addresses of names: one
; shared entry per source under a sequence counter, copied by every worker
; (and the health and admin processes) into the source's server slots, `max`
; of them, without a lock. A weight changes in place; an address that stays
; keeps its slot, its health and its connections. The supervisor reads the
; file once before the workers start, so they start with the servers.
;
; A file that cannot be read, or has a line that is not an address, changes
; nothing: the last servers known go on, and it is said once. One that turns
; up empty after having servers is believed only once it has stayed empty for
; three seconds (an editor that truncates before it writes); writing a new file and
; renaming it over the old one is the way that never shows half a file.

GK_DNS		:= 0
GK_FILE		:= 1
GK_SRV		:= 2
GK_DOCKER	:= 3
GK_KUBE		:= 4
GK_CONSUL	:= 5

DISC_MAX	:= 256			; servers a source may have
DISC_SOURCES	:= 32
DISC_FILE_MAX	:= 65536
DISC_EMPTY_WAIT	:= 3			; seconds a file must stay empty to be believed
DE_ADDR		:= 0			; 16 bytes
DE_FAMILY	:= 16			; d: 4 or 6
DE_PORT		:= 20			; d
DE_WEIGHT	:= 24			; d
DE_BACKUP	:= 28			; d: srv: a priority past the lowest
DE_SIZE		:= 32
DX_SEQ		:= 0			; q
DX_COUNT	:= 8			; d
DX_E		:= 64
DX_SIZE		:= DX_E + DISC_MAX * DE_SIZE
DS_LEN		:= 112			; d (a sockaddr first)
DS_FAMILY	:= 116			; d
DS_USED		:= 120			; d
DS_SIZE		:= 128

bss
	align 8
	g_disc_tbl	dq ?		; shared: DISC_SOURCES entries
	g_plan_discs	dd ?
	g_disc_seen	rq DISC_SOURCES	; a reader: the sequence last copied
	g_disc_stat	rq DISC_SOURCES * 3	; control: inode, size, time of the last read
	g_disc_empty	rd DISC_SOURCES	; control: an empty read not believed yet
	g_disc_said	rd DISC_SOURCES	; control: an error already told
	g_plan_dshare	rd DISC_SOURCES	; share=: the source's weight, between its servers (0 none)
	g_disc_copy:	rb DX_SIZE
	g_disc_new:	rb DX_SIZE
	g_disc_path:	rb 4096 + 8
	g_disc_st:	rb 144
	g_disc_tok:	rb 80
	g_disc_ad:	rb AD_SIZE
	g_disc_sa:	rb DISC_MAX * DS_SIZE	; a reader: the entries as sockaddrs
	g_disc_buf	dq ?		; control: the file, read
end bss

; before any fork
disc_table_init:
	xor	edi,edi
	mov	esi,DISC_SOURCES * DX_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_disc_tbl],rax
	xor	edi,edi
	mov	esi,DISC_FILE_MAX + 1
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_disc_buf],rax
	lea	rdi,[g_disc_stat]
	mov	ecx,DISC_SOURCES * 3
	xor	eax,eax
	rep	stosq
	lea	rdi,[g_disc_empty]
	mov	ecx,DISC_SOURCES * 2
	rep	stosd
	ret

; ebx = group of a file: look at it, and publish what changed. eax = seconds
; to the next look.
disc_file_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	r13d,[r12+GR_DISC]		; its source
	imul	r15,r13,24			; what it was at the last read
	lea	r15,[g_disc_stat+r15]
	; the path, with its end
	mov	rsi,[r12+GR_NAME]
	mov	ecx,[r12+GR_NLEN]
	lea	rdi,[g_disc_path]
	rep	movsb
	mov	byte [rdi],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_disc_path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.unreadable
	mov	r14d,eax
	mov	edi,r14d
	lea	rsi,[g_disc_st]
	mov	eax,SYS_fstat
	syscall
	test	eax,eax
	js	.unreadable_close
	; the same file as last time?
	mov	rax,[g_disc_st+8]		; st_ino
	cmp	rax,[r15]
	jne	.changed
	mov	rax,[g_disc_st+48]		; st_size
	cmp	rax,[r15+8]
	jne	.changed
	mov	rax,[g_disc_st+88]		; st_mtime, then its nanoseconds
	xor	rax,[g_disc_st+96]
	cmp	rax,[r15+16]
	jne	.changed
	cmp	dword [g_disc_empty+r13*4],0
	je	.unchanged			; (an empty read waits for a second look)
.changed:
	cmp	qword [g_disc_st+48],DISC_FILE_MAX
	ja	.too_big
	; read it whole
	xor	r8d,r8d
.read:
	mov	edi,r14d
	mov	rsi,[g_disc_buf]
	add	rsi,r8
	mov	edx,DISC_FILE_MAX
	sub	edx,r8d
	jz	.read_done
	xor	eax,eax
	syscall
	test	rax,rax
	js	.unreadable_close
	jz	.read_done
	add	r8d,eax
	jmp	.read
.read_done:
	push	r8
	mov	edi,r14d
	mov	eax,SYS_close
	syscall
	pop	r8
	call	disc_parse			; g_disc_new, CF on a bad line
	jc	.bad
	; empty after having servers: once more before it is believed
	mov	rax,r13
	imul	rax,rax,DX_SIZE
	add	rax,[g_disc_tbl]
	cmp	dword [g_disc_new+DX_COUNT],0
	jne	.full
	cmp	dword [rax+DX_COUNT],0
	je	.full
	call	monotonic_seconds
	cmp	dword [g_disc_empty+r13*4],0
	jne	@f
	mov	[g_disc_empty+r13*4],eax	; empty since now
	jmp	.unchanged_kept
@@:
	sub	eax,[g_disc_empty+r13*4]
	cmp	eax,DISC_EMPTY_WAIT
	jb	.unchanged_kept			; not yet: and looked at again
.full:
	mov	dword [g_disc_empty+r13*4],0
	call	disc_publish
	mov	dword [g_disc_said+r13*4],0
.seen:
	mov	rax,[g_disc_st+8]
	mov	[r15],rax
	mov	rax,[g_disc_st+48]
	mov	[r15+8],rax
	mov	rax,[g_disc_st+88]
	xor	rax,[g_disc_st+96]
	mov	[r15+16],rax
	jmp	.out
.unchanged:
	mov	edi,r14d
	mov	eax,SYS_close
	syscall
	jmp	.out
.unchanged_kept:
	; (its stat is not kept: the next look reads it again)
	jmp	.out
.too_big:
	mov	edi,r14d
	mov	eax,SYS_close
	syscall
	mov	eax,3
	cstring str_disc_big, ': larger than 64 KiB; keeping the servers known so far'
	lea	rsi,[str_disc_big]
	mov	edx,str_disc_big.len
	jmp	.tell
.bad:
	mov	eax,2
	cstring str_disc_bad, ': a line that is not ADDRESS[:PORT] [weight=N]; keeping the servers known so far'
	lea	rsi,[str_disc_bad]
	mov	edx,str_disc_bad.len
	jmp	.tell
.unreadable_close:
	mov	edi,r14d
	mov	eax,SYS_close
	syscall
.unreadable:
	mov	eax,1
	cstring str_disc_gone, ': cannot be read; keeping the servers known so far'
	lea	rsi,[str_disc_gone]
	mov	edx,str_disc_gone.len
.tell:
	cmp	[g_disc_said+r13*4],eax
	je	.out				; said already
	mov	[g_disc_said+r13*4],eax
	push	rsi
	push	rdx
	call	log_begin
	out_lit 'discover file '
	lea	rsi,[g_disc_path]
	call	out_cstr
	pop	rdx
	pop	rsi
	call	out_str
	mov	edi,AL_DISCOVERY
	call	log_end_alert
	; a file that comes back the same must still be read
	xor	eax,eax
	mov	[r15],rax
.out:
	mov	eax,1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_disc_buf, r8d bytes; r12 = its group: g_disc_new. CF when a line is not
; an address (with r8d left as it was; nothing published).
disc_parse:
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	dword [g_disc_new+DX_COUNT],0
	mov	rbx,[g_disc_buf]
	lea	r13,[rbx+r8]			; the end
.line:
	cmp	rbx,r13
	jae	.done
	; the next word
	call	.blank
	cmp	rbx,r13
	jae	.done
	cmp	byte [rbx],10
	je	.next_line
	cmp	byte [rbx],'#'
	je	.skip_line
	mov	r14,rbx				; the address
@@:
	cmp	rbx,r13
	jae	@f
	movzx	eax,byte [rbx]
	cmp	al,' '
	je	@f
	cmp	al,9
	je	@f
	cmp	al,10
	je	@f
	cmp	al,'#'
	je	@f
	cmp	al,13
	je	@f
	inc	rbx
	jmp	@b
@@:
	mov	r15,rbx
	sub	r15,r14				; its length
	cmp	r15,62
	ja	.bad
	call	.address
	jc	.bad
	; then weight=N, or nothing
	mov	r15d,1
	call	.blank
	cmp	rbx,r13
	jae	.store
	movzx	eax,byte [rbx]
	cmp	al,10
	je	.store
	cmp	al,'#'
	je	.store
	cmp	al,13
	je	.store
	lea	rax,[r13-7]
	cmp	rbx,rax
	ja	.bad
	cmp	dword [rbx],'weig'
	jne	.bad
	cmp	word [rbx+4],'ht'
	jne	.bad
	cmp	byte [rbx+6],'='
	jne	.bad
	add	rbx,7
	xor	r15d,r15d
	xor	ecx,ecx
@@:
	cmp	rbx,r13
	jae	@f
	movzx	eax,byte [rbx]
	sub	eax,'0'
	cmp	eax,9
	ja	@f
	imul	r15d,r15d,10
	add	r15d,eax
	inc	rbx
	inc	ecx
	cmp	ecx,6
	ja	.bad
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	test	r15d,r15d
	jz	.bad
	cmp	r15d,65535
	ja	.bad
	call	.blank
	cmp	rbx,r13
	jae	.store
	movzx	eax,byte [rbx]
	cmp	al,10
	je	.store
	cmp	al,13
	je	.store
	cmp	al,'#'
	jne	.bad
.store:
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[r12+GR_SLOTS]
	jae	.skip_line			; more than it has slots for: the first ones
	inc	dword [g_disc_new+DX_COUNT]
	imul	rax,rax,DE_SIZE
	lea	rdi,[g_disc_new+DX_E+rax]
	mov	rcx,[g_disc_ad+AD_IP]
	mov	[rdi+DE_ADDR],rcx
	mov	rcx,[g_disc_ad+AD_IP+8]
	mov	[rdi+DE_ADDR+8],rcx
	mov	dword [rdi+DE_FAMILY],6
	cmp	dword [g_disc_ad+AD_KIND],ADDR_V4
	jne	@f
	mov	dword [rdi+DE_FAMILY],4
@@:
	mov	eax,[g_disc_ad+AD_PORT]
	mov	[rdi+DE_PORT],eax
	mov	[rdi+DE_WEIGHT],r15d
	mov	dword [rdi+DE_BACKUP],0
.skip_line:
	cmp	rbx,r13
	jae	.done
	cmp	byte [rbx],10
	je	.next_line
	inc	rbx
	jmp	.skip_line
.next_line:
	inc	rbx
	jmp	.line
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
.blank:
	cmp	rbx,r13
	jae	.blank_end
	cmp	byte [rbx],' '
	je	@f
	cmp	byte [rbx],9
	jne	.blank_end
@@:
	inc	rbx
	jmp	.blank
.blank_end:
	ret
; r14/r15 = a word: g_disc_ad, an IP address and a port (the source's port
; when it has none). CF when it is not.
.address:
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[g_disc_ad]
	xor	ecx,ecx				; no names, no unix paths
	call	parse_address
	jnc	.parsed
	mov	eax,[r12+GR_PORT]
	test	eax,eax
	jz	.not_one
	; no port: the source's, "a.b.c.d:P" or "[v6]:P"
	lea	rdi,[g_disc_tok]
	mov	rsi,r14
	mov	ecx,r15d
	xor	r8d,r8d				; a colon in it: IPv6
@@:
	test	ecx,ecx
	jz	@f
	cmp	byte [rsi],':'
	sete	al
	or	r8b,al
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],'['
	inc	rdi
@@:
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],']'
	inc	rdi
@@:
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,[r12+GR_PORT]
	call	.decimal
	lea	rsi,[g_disc_tok]
	sub	rdi,rsi
	mov	esi,edi
	mov	rdi,rsi
	lea	rdi,[g_disc_tok]
	lea	rdx,[g_disc_ad]
	xor	ecx,ecx
	call	parse_address
	jc	.not_one
.parsed:
	mov	eax,[g_disc_ad+AD_KIND]
	cmp	eax,ADDR_V4
	je	.ip
	cmp	eax,ADDR_V6
	jne	.not_one
.ip:
	clc
	ret
.not_one:
	stc
	ret
; eax = a number: its digits at rdi, rdi after them
.decimal:
	push	rbx
	mov	ebx,eax
	xor	ecx,ecx
@@:
	xor	edx,edx
	mov	eax,ebx
	mov	r9d,10
	div	r9d
	mov	ebx,eax
	add	edx,'0'
	push	rdx
	inc	ecx
	test	ebx,ebx
	jnz	@b
@@:
	pop	rax
	stosb
	dec	ecx
	jnz	@b
	pop	rbx
	ret

; r12 = group, r13d = source: g_disc_new is what it has now. Published when
; it differs, and said.
disc_publish:
	; share=N: N between them, each its part (1000 a share, 1 to 65535)
	mov	ecx,[g_plan_dshare+r13*4]
	test	ecx,ecx
	jz	.weighed
	mov	r8d,[g_disc_new+DX_COUNT]
	test	r8d,r8d
	jz	.weighed
	imul	eax,ecx,1000
	xor	edx,edx
	div	r8d
	cmp	eax,65535
	jbe	@f
	mov	eax,65535
@@:
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	xor	ecx,ecx
.share:
	imul	rdx,rcx,DE_SIZE
	mov	[g_disc_new+DX_E+rdx+DE_WEIGHT],eax
	inc	ecx
	cmp	ecx,r8d
	jb	.share
.weighed:
	mov	rdi,r13
	imul	rdi,rdi,DX_SIZE
	add	rdi,[g_disc_tbl]
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[rdi+DX_COUNT]
	jne	.differs
	imul	ecx,eax,DE_SIZE
	lea	rsi,[g_disc_new+DX_E]
	push	rdi
	add	rdi,DX_E
	repe	cmpsb
	pop	rdi
	je	.same
.differs:
	inc	qword [rdi+DX_SEQ]		; odd: being written
	mov	eax,[g_disc_new+DX_COUNT]
	mov	[rdi+DX_COUNT],eax
	push	rdi
	imul	ecx,eax,DE_SIZE
	lea	rsi,[g_disc_new+DX_E]
	add	rdi,DX_E
	rep	movsb
	pop	rdi
	inc	qword [rdi+DX_SEQ]		; even: done
	call	log_begin
	cmp	dword [r12+GR_KIND],GK_DOCKER
	jae	.docker
	cmp	dword [r12+GR_KIND],GK_SRV
	je	@f
	out_lit 'discover file '
	jmp	.named
@@:
	out_lit 'discover srv '
.named:
	mov	rsi,[r12+GR_NAME]
	mov	edx,[r12+GR_NLEN]
	call	out_str
	jmp	.told
.docker:
	cmp	dword [r12+GR_KIND],GK_KUBE
	je	.kube
	cmp	dword [r12+GR_KIND],GK_CONSUL
	jne	@f
	out_lit 'discover consul '
	jmp	.named
@@:
	out_lit 'discover docker '
	imul	rax,r13,DK_SIZE
	mov	rsi,[g_plan_dk+rax+DK_LABEL]
	mov	edx,[g_plan_dk+rax+DK_LLEN]
	call	out_str
	jmp	.told
.kube:
	out_lit 'discover kubernetes '
	imul	rax,r13,KB_SIZE
	push	rax
	mov	rsi,[g_plan_kb+rax+KB_NS]
	mov	edx,[g_plan_kb+rax+KB_NSLEN]
	call	out_str
	out_lit '/'
	pop	rax
	mov	rsi,[g_plan_kb+rax+KB_SVC]
	mov	edx,[g_plan_kb+rax+KB_SVCLEN]
	call	out_str
.told:
	out_lit ': '
	mov	eax,[g_disc_new+DX_COUNT]
	call	out_u64
	out_lit ' servers'
	call	log_end
.same:
	ret

; a reader, group ebx of a source: its slots, from the shared entry, when it
; changed. Keeps rbx.
disc_refresh:
	push	r12
	push	r13
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	eax,[r12+GR_DISC]
	mov	r13,rax
	imul	rax,rax,DX_SIZE
	add	rax,[g_disc_tbl]
	mov	r8,rax
.read:
	mov	r9,[r8+DX_SEQ]
	cmp	r9,[g_disc_seen+r13*8]
	je	.out				; unchanged
	test	r9,1
	jnz	.read
	lea	rdi,[g_disc_copy]
	mov	rsi,r8
	mov	ecx,DX_SIZE
	rep	movsb
	cmp	r9,[r8+DX_SEQ]
	jne	.read
	mov	[g_disc_seen+r13*8],r9
	call	disc_apply
.out:
	pop	r13
	pop	r12
	ret

; r12 = group: g_disc_copy to its slots. An address that stays keeps its
; slot (its health, its connections); one that went frees its slot, and its
; idle connections are closed; a new one takes a free slot.
disc_apply:
	push	rbx
	push	r13
	push	r14
	push	r15
	; every entry as a sockaddr
	xor	r13d,r13d
.build:
	cmp	r13d,[g_disc_copy+DX_COUNT]
	jae	.built
	imul	rax,r13,DE_SIZE
	lea	rsi,[g_disc_copy+DX_E+rax]
	sub	rsp,AD_SIZE
	mov	rcx,[rsi+DE_ADDR]
	mov	[rsp+AD_IP],rcx
	mov	rcx,[rsi+DE_ADDR+8]
	mov	[rsp+AD_IP+8],rcx
	mov	dword [rsp+AD_KIND],ADDR_V6
	cmp	dword [rsi+DE_FAMILY],4
	jne	@f
	mov	dword [rsp+AD_KIND],ADDR_V4
@@:
	mov	eax,[rsi+DE_PORT]
	mov	[rsp+AD_PORT],eax
	imul	rdi,r13,DS_SIZE
	lea	rdi,[g_disc_sa+rdi]
	mov	rsi,rsp
	call	sockaddr_build
	imul	rcx,r13,DS_SIZE
	mov	[g_disc_sa+rcx+DS_LEN],eax
	mov	[g_disc_sa+rcx+DS_FAMILY],edx
	mov	dword [g_disc_sa+rcx+DS_USED],0
	add	rsp,AD_SIZE
	inc	r13d
	jmp	.build
.built:
	; the slots that have an address: kept, or freed
	xor	r13d,r13d
.keep:
	cmp	r13d,[r12+GR_SLOTS]
	jae	.kept
	mov	r14d,[r12+GR_FIRST]
	add	r14d,r13d
	imul	rbx,r14,SV_SIZE
	lea	rbx,[g_servers+rbx]
	cmp	dword [rbx+SV_ACTIVE],0
	je	.keep_next
	call	.find				; r15d = its entry, or -1
	test	r15d,r15d
	js	.free
	imul	rax,r15,DS_SIZE
	mov	dword [g_disc_sa+rax+DS_USED],1
	imul	rax,r15,DE_SIZE
	mov	ecx,[g_disc_copy+DX_E+rax+DE_WEIGHT]
	mov	[rbx+SV_WEIGHT],ecx
	mov	ecx,[g_disc_copy+DX_E+rax+DE_BACKUP]
	mov	[rbx+SV_BACKUP],ecx
	jmp	.keep_next
.free:
	mov	dword [rbx+SV_ACTIVE],0
	inc	dword [g_sv_gen+r14*4]
	mov	edi,r14d
	call	pool_flush
.keep_next:
	inc	r13d
	jmp	.keep
.kept:
	; new addresses into free slots
	xor	r15d,r15d
	xor	r13d,r13d			; slot looked at
.new:
	cmp	r15d,[g_disc_copy+DX_COUNT]
	jae	.done
	imul	rax,r15,DS_SIZE
	cmp	dword [g_disc_sa+rax+DS_USED],0
	jne	.new_next
.slot:
	cmp	r13d,[r12+GR_SLOTS]
	jae	.done				; (no more slots than entries: cannot happen)
	mov	r14d,[r12+GR_FIRST]
	add	r14d,r13d
	imul	rbx,r14,SV_SIZE
	lea	rbx,[g_servers+rbx]
	inc	r13d
	cmp	dword [rbx+SV_ACTIVE],0
	jne	.slot
	imul	rax,r15,DS_SIZE
	lea	rsi,[g_disc_sa+rax]
	lea	rdi,[rbx+SV_SA]
	mov	ecx,112
	rep	movsb
	imul	rax,r15,DS_SIZE
	mov	ecx,[g_disc_sa+rax+DS_LEN]
	mov	[rbx+SV_SALEN],ecx
	mov	ecx,[g_disc_sa+rax+DS_FAMILY]
	mov	[rbx+SV_FAMILY],ecx
	imul	rax,r15,DE_SIZE
	mov	ecx,[g_disc_copy+DX_E+rax+DE_WEIGHT]
	mov	[rbx+SV_WEIGHT],ecx
	mov	ecx,[g_disc_copy+DX_E+rax+DE_BACKUP]
	mov	[rbx+SV_BACKUP],ecx
	mov	dword [g_sv_fails+r14*4],0
	mov	dword [g_sv_down+r14*4],0
	inc	dword [g_sv_gen+r14*4]
	mov	edi,r14d
	call	pool_flush			; (another address's, from before)
	mov	dword [rbx+SV_ACTIVE],1
.new_next:
	inc	r15d
	jmp	.new
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
; rbx = a slot with an address: r15d = the entry not yet taken with the same
; one, or -1
.find:
	xor	r15d,r15d
.f_next:
	cmp	r15d,[g_disc_copy+DX_COUNT]
	jae	.f_none
	imul	rax,r15,DS_SIZE
	cmp	dword [g_disc_sa+rax+DS_USED],0
	jne	.f_skip
	mov	edx,[g_disc_sa+rax+DS_LEN]
	cmp	edx,[rbx+SV_SALEN]
	jne	.f_skip
	lea	rdi,[g_disc_sa+rax]
	lea	rsi,[rbx+SV_SA]
	call	mem_eq
	test	eax,eax
	jnz	.f_found
.f_skip:
	inc	r15d
	jmp	.f_next
.f_none:
	mov	r15d,-1
.f_found:
	ret

; edi = server slot: its idle connections, closed (they are another address's)
pool_flush:
	push	rbx
	push	r12
	mov	ebx,edi
	imul	r12d,ebx,POOL_MAX
.next:
	cmp	dword [g_pool_n+rbx*4],0
	je	.done
	dec	dword [g_pool_n+rbx*4]
	mov	eax,[g_pool_n+rbx*4]
	add	eax,r12d
	mov	edi,[g_pool_h+rax*4]
	push	rdi
	cmp	dword [g_engine],ENGINE_EPOLL
	je	@f
	mov	eax,edi
	call	pool_unwatch
@@:
	pop	rdi
	call	pool_close_handle
	jmp	.next
.done:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ srv

; ebx = group of `discover srv NAME`: its records, then their targets'
; addresses. eax = seconds to the next look (the shortest TTL, as for names).
; A lookup that fails, or gives nothing, keeps the servers known so far, as
; DNS going away must never empty a pool.
disc_srv_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	r13d,[r12+GR_DISC]
	call	rs_load
	; the name, as given (a full name: no search domains)
	mov	ecx,[r12+GR_NLEN]
	mov	rsi,[r12+GR_NAME]
	lea	rdi,[g_rs_name]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_rs_result]
	xor	eax,eax
	mov	ecx,RR_SIZE
	rep	stosb
	mov	dword [g_rs_result+RR_TTL],DNS_TTL_MAX
	mov	dword [g_srv_n],0
	mov	edi,33
	mov	esi,[r12+GR_NLEN]
	call	rs_query
	cmp	eax,RS_OK
	jne	.failed
	mov	r15d,[g_rs_result+RR_TTL]	; the records' TTL
	; the lowest priority: the others are backups
	mov	r14d,0x10000
	xor	ecx,ecx
@@:
	cmp	ecx,[g_srv_n]
	jae	@f
	imul	rax,rcx,SRV_SIZE
	mov	eax,[g_srv+rax+SRV_PRIO]
	cmp	eax,r14d
	cmovb	r14d,eax
	inc	ecx
	jmp	@b
@@:
	; every target's addresses (the lowest priority first: those fill the slots)
	mov	dword [g_disc_new+DX_COUNT],0
	xor	ebx,ebx				; pass: 0 the lowest priority, 1 the rest
.pass:
	xor	ecx,ecx
.record:
	cmp	ecx,[g_srv_n]
	jae	.passed
	imul	rax,rcx,SRV_SIZE
	lea	rsi,[g_srv+rax]
	mov	eax,[rsi+SRV_PRIO]
	cmp	eax,r14d
	sete	al
	movzx	eax,al
	xor	eax,1				; 1 for a backup
	cmp	eax,ebx
	jne	.next_record
	push	rcx
	push	rsi
	lea	rdi,[rsi+SRV_NAME]
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	call	rs_lookup			; g_rs_result: its addresses
	pop	rsi
	pop	rcx
	cmp	eax,RS_OK
	jne	.next_record			; a target that does not resolve: left out
	mov	eax,[g_rs_result+RR_TTL]
	cmp	eax,r15d
	cmovb	r15d,eax
	push	rcx
	xor	ecx,ecx
.address:
	cmp	ecx,[g_rs_result+RR_COUNT]
	jae	.addressed
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[r12+GR_SLOTS]
	jae	.addressed
	inc	dword [g_disc_new+DX_COUNT]
	imul	rax,rax,DE_SIZE
	lea	rdi,[g_disc_new+DX_E+rax]
	mov	eax,ecx
	shl	eax,4
	mov	rdx,[g_rs_result+RR_ADDRS+rax]
	mov	[rdi+DE_ADDR],rdx
	mov	rdx,[g_rs_result+RR_ADDRS+rax+8]
	mov	[rdi+DE_ADDR+8],rdx
	movzx	eax,byte [g_rs_result+RR_FAMILY+rcx]
	mov	[rdi+DE_FAMILY],eax
	mov	eax,[rsi+SRV_PORT]
	mov	[rdi+DE_PORT],eax
	mov	eax,[rsi+SRV_WEIGHT]		; 0 is the least, not none
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	mov	[rdi+DE_WEIGHT],eax
	mov	[rdi+DE_BACKUP],ebx
	inc	ecx
	jmp	.address
.addressed:
	pop	rcx
.next_record:
	inc	ecx
	jmp	.record
.passed:
	inc	ebx
	cmp	ebx,2
	jb	.pass
	cmp	dword [g_disc_new+DX_COUNT],0
	je	.no_address
	call	disc_publish
	mov	dword [g_disc_said+r13*4],0
	mov	eax,r15d
	cmp	eax,DNS_TTL_MIN
	jae	@f
	mov	eax,DNS_TTL_MIN
@@:
	cmp	eax,DNS_TTL_MAX
	jbe	.out
	mov	eax,DNS_TTL_MAX
	jmp	.out
.no_address:
	mov	eax,RS_NODATA + 10		; (its own reason: no target resolved)
.failed:
	cmp	[g_disc_said+r13*4],eax
	je	.retry
	mov	[g_disc_said+r13*4],eax
	push	rax
	call	log_begin
	out_lit 'discover srv '
	mov	rsi,[r12+GR_NAME]
	mov	edx,[r12+GR_NLEN]
	call	out_str
	pop	rax
	cmp	eax,RS_NXDOMAIN
	jne	@f
	out_lit ': no such name'
	jmp	.said
@@:
	cmp	eax,RS_NODATA
	jne	@f
	out_lit ': no SRV records'
	jmp	.said
@@:
	cmp	eax,RS_FAILED
	jne	@f
	out_lit ': no answer from the DNS servers'
	jmp	.said
@@:
	out_lit ': none of its targets resolves'
.said:
	out_lit '; keeping the servers known so far'
	mov	edi,AL_DISCOVERY
	call	log_end_alert
.retry:
	mov	eax,DNS_RETRY_S
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
