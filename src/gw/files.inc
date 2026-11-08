; `files /srv/site index=index.html fallback=/index.html precompressed=br,zst,gz
; cache=1y` on a route: answers from a directory, by the request's whole path. HEAD
; and GET; conditional requests by ETag and date, one byte range, a compressed
; variant that is already on disk.
;
; How the worker gets at it, as a worker can open nothing otherwise: each root is
; opened at the start and everything is opened beneath it with openat2 and
; RESOLVE_BENEATH, so the kernel, not this code, keeps a path inside, symlinks
; included; and the worker is confined by Landlock to reading those roots, so that
; not even a bug here reaches a private key. Only a worker with `files` routes has
; the system calls for it (filter_worker_uring_f, filter_worker_epoll_f). Where the
; kernel has no Landlock it says so at the start, and the first guard is the one left.
;
; Names that begin with a dot are not served, but for .well-known: .git, .env.
;
; A file is a backend that is not there, as a cache hit is: the head goes through
; http_resp_head, the body through h_recv on the upstream side, with a READ on the
; ring when there is one: a slow disk does not stop the loop. With epoll it does.

SF_FILE		:= 33554432			; S_FLAGS: its answer comes from a file

MAX_FILES	:= 64
FI_ROOT		:= 0				; q
FI_RLEN		:= 8				; d
FI_ILEN		:= 12				; d
FI_INDEX	:= 16				; q
FI_FALL		:= 24				; q
FI_FLEN		:= 32				; d
FI_PRE		:= 36				; d: F_BR, F_ZST, F_GZ, a byte each, in order
FI_CC		:= 40				; q: Cache-Control's value, 0 none
FI_CCLEN	:= 48				; d
FI_SIZE		:= 56

FE_BR		:= 1
FE_ZST		:= 2
FE_GZ		:= 3

SYS_lseek_	:= 8
SYS_openat2	:= 437
SYS_ll_create	:= 444
SYS_ll_add	:= 445
SYS_ll_restrict	:= 446
LL_READ		:= 4 or 8			; READ_FILE, READ_DIR
LL_ALL		:= 0x1FFF			; the first version's rights
O_PATH_		:= 0x200000
O_DIRECTORY_	:= 0x10000
O_NONBLOCK_	:= 0x800
O_CLOEXEC_	:= 0x80000
RESOLVE_BENEATH_ := 8
RESOLVE_NO_MAGIC := 2
S_IFMT_		:= 0xF000
S_IFREG_	:= 0x8000
S_IFDIR_	:= 0x4000
ST_MODE		:= 24
ST_SIZE		:= 48
ST_MTIME	:= 88

bss
	align 8
	g_files:	rb FI_SIZE * MAX_FILES
	g_plan_files	dd ?
	g_fi_fd		rd MAX_FILES		; a worker's: the roots
	g_ll_on		dd ?			; a worker: confined
	align 8
	g_fs_stat:	rb 144
	g_fs_how	rq 3
	g_fs_size	dq ?
	g_fs_mtime	dq ?
	g_fs_from	dq ?			; the range
	g_fs_to		dq ?
	g_fs_fd		dd ?
	g_fs_enc	dd ?			; FE_*, 0 none
	g_fs_plen	dd ?
	g_fs_range	dd ?			; 1 a range, 2 none satisfiable
	g_fs_etag:	rb 48
	g_fs_elen	dd ?
	g_fs_date:	rb 32
	g_fs_path:	rb 8192
end bss

rodata
	fi_names	db 0,0,0,0,0,0,0,0		; by FE_*: length, then the name
			db 3,'.br',0,0,0,0
			db 4,'.zst',0,0,0
			db 3,'.gz',0,0,0,0
	fi_days		db 'Thu','Fri','Sat','Sun','Mon','Tue','Wed'
	fi_months	db 'JanFebMarAprMayJunJulAugSepOctNovDec'
end rodata

; a worker, at its start: the roots, and what it may read from then on
files_init:
	cmp	dword [g_plan_files],0
	je	ll_confine_none			; (no file at all: none to read)
	push	rbx
	push	r12
	xor	ebx,ebx
.root:
	cmp	ebx,[g_plan_files]
	jae	.rooted
	imul	rax,rbx,FI_SIZE
	lea	r12,[g_files+rax]
	mov	rsi,[r12+FI_ROOT]		; (NUL-terminated at load)
	mov	edi,-100
	mov	edx,O_PATH_ or O_DIRECTORY_ or O_CLOEXEC_
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	mov	[g_fi_fd+rbx*4],eax
	inc	ebx
	jmp	.root
.rooted:
	; Landlock: reading only beneath them
	call	ll_begin
	jc	.unconfined
	xor	ebx,ebx
.rule:
	cmp	ebx,[g_plan_files]
	jae	.rules
	mov	edi,[g_fi_fd+rbx*4]
	mov	esi,LL_READS
	call	ll_fd
	inc	ebx
	jmp	.rule
.rules:
	call	ll_end
	test	eax,eax
	js	.unconfined
	mov	dword [g_ll_on],1
	jmp	.out
.unconfined:
	cmp	dword [g_worker_id],0		; (one says it)
	jne	.out
	call	log_begin
	out_lit 'files: this kernel gives no Landlock here: a worker is kept beneath its roots by openat2 alone'
	call	log_end
.out:
	pop	r12
	pop	rbx
.none:
	ret

; r15 = record, H_ACT: eax = 1 the route has files and it is taken care of.
; Keeps rbx, r12-r15.
files_check:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_FILES]
	test	eax,eax
	jnz	.yes
.no:
	xor	eax,eax
	ret
.yes:
	push	r12
	push	r13
	dec	eax
	mov	r13d,eax
	imul	r12,rax,FI_SIZE
	lea	r12,[g_files+r12]
	call	files_answer
	pop	r13
	pop	r12
	mov	eax,1
	ret

; rdi = g_fs_path's end: NUL it, and open what is there. CF: nothing. r13d = root.
; g_fs_fd, g_fs_stat.
fs_open:
	mov	byte [rdi],0
	mov	qword [g_fs_how],O_NONBLOCK_ or O_CLOEXEC_
	mov	qword [g_fs_how+8],0
	mov	qword [g_fs_how+16],RESOLVE_BENEATH_ or RESOLVE_NO_MAGIC
	mov	edi,[g_fi_fd+r13*4]
	lea	rsi,[g_fs_path]
	cmp	byte [rsi],0
	jne	@f
	lea	rsi,[.here]
@@:
	lea	rdx,[g_fs_how]
	mov	r10d,24
	mov	eax,SYS_openat2
	syscall
	test	eax,eax
	js	.none
	mov	[g_fs_fd],eax
	mov	edi,eax
	lea	rsi,[g_fs_stat]
	mov	eax,SYS_fstat
	syscall
	test	eax,eax
	js	.shut
	clc
	ret
.shut:
	mov	edi,[g_fs_fd]
	mov	eax,SYS_close
	syscall
.none:
	stc
	ret
.here	db '.',0

fs_close:
	mov	edi,[g_fs_fd]
	mov	eax,SYS_close
	syscall
	ret

; r12 = the files, r13d = which, g_hm, g_npath: the answer
files_answer:
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.method_ok
	cmp	dword [g_hm+HM_MLEN],3
	jne	.bad_method
	mov	rax,[g_hm+HM_METHOD]
	mov	eax,[rax]
	and	eax,0xFFFFFF
	cmp	eax,'GET'
	je	.method_ok
.bad_method:
	lea	rsi,[.h405]
	mov	ecx,.h405_len
	jmp	fs_short
.method_ok:
	mov	dword [g_fs_enc],0
	mov	dword [g_fs_range],0
	call	fs_path
	jc	.missing
	lea	rdi,[g_fs_path]
	mov	eax,[g_fs_plen]
	add	rdi,rax
	call	fs_open
	jc	.missing
	mov	eax,dword [g_fs_stat+ST_MODE]
	and	eax,S_IFMT_
	cmp	eax,S_IFREG_
	je	.regular
	cmp	eax,S_IFDIR_
	jne	.not_file
	call	fs_close
	; a directory: its index, under a name that ends in /
	mov	eax,[g_fs_plen]
	test	eax,eax
	jz	.dir
	cmp	byte [g_fs_path+rax-1],'/'
	je	.dir
	jmp	fs_slash
.dir:
	mov	ecx,[r12+FI_ILEN]
	lea	edx,[rax+rcx]
	cmp	edx,8000
	ja	.missing
	mov	[g_fs_plen],edx
	lea	rdi,[g_fs_path+rax]
	mov	rsi,[r12+FI_INDEX]
	rep	movsb
	call	fs_open
	jc	.missing
	mov	eax,dword [g_fs_stat+ST_MODE]
	and	eax,S_IFMT_
	cmp	eax,S_IFREG_
	je	.regular
.not_file:
	call	fs_close
.missing:
	mov	ecx,[r12+FI_FLEN]
	test	ecx,ecx
	jz	.none
	; (a fallback only once)
	cmp	dword [g_fs_enc],-1
	je	.none
	mov	dword [g_fs_enc],-1
	mov	[g_fs_plen],ecx
	mov	rsi,[r12+FI_FALL]
	lea	rdi,[g_fs_path]
	rep	movsb
	call	fs_open
	jc	.none
	mov	eax,dword [g_fs_stat+ST_MODE]
	and	eax,S_IFMT_
	cmp	eax,S_IFREG_
	je	.regular
	call	fs_close
.none:
	mov	edi,404
	jmp	http_error
.regular:
	mov	dword [g_fs_enc],0
	mov	rax,[g_fs_stat+ST_SIZE]
	mov	[g_fs_size],rax
	mov	rax,[g_fs_stat+ST_MTIME]
	mov	[g_fs_mtime],rax
	call	fs_precompressed
	jmp	fs_serve
.h405	db 'HTTP/1.1 405 Method Not Allowed',13,10,'Allow: GET, HEAD',13,10,'Content-Length: 0',13,10
.h405_len := $ - .h405

; g_npath: the name beneath the root, decoded, in g_fs_path, with no leading /.
; CF: not one that is served.
fs_path:
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	lea	rdi,[g_fs_path]
	cmp	ecx,8000
	ja	.bad
	test	ecx,ecx
	jz	.bad
	cmp	byte [rsi],'/'
	jne	.bad
	inc	rsi
	dec	ecx
	mov	r8b,1				; at the start of a segment
.byte:
	test	ecx,ecx
	jz	.done
	movzx	eax,byte [rsi]
	inc	rsi
	dec	ecx
	cmp	al,'%'
	jne	.plain
	cmp	ecx,2
	jb	.bad
	movzx	eax,byte [rsi]
	call	.hex
	jc	.bad
	mov	edx,eax
	shl	edx,4
	movzx	eax,byte [rsi+1]
	call	.hex
	jc	.bad
	or	eax,edx
	add	rsi,2
	sub	ecx,2
	test	eax,eax
	jz	.bad
	cmp	al,'/'
	je	.bad				; (path_normalize refuses these: and here)
.plain:
	cmp	r8b,0
	je	.put
	cmp	al,'.'
	jne	.put
	; a dot first: .well-known alone
	cmp	ecx,10
	jb	.bad
	mov	rax,[rsi]
	mov	rdx,'well-kno'
	cmp	rax,rdx
	jne	.bad
	cmp	word [rsi+8],'wn'
	jne	.bad
	cmp	ecx,10
	je	.dotted
	cmp	byte [rsi+10],'/'
	jne	.bad
.dotted:
	mov	al,'.'
.put:
	cmp	al,'/'
	sete	r8b
	stosb
	jmp	.byte
.done:
	mov	rax,rdi
	lea	rdx,[g_fs_path]
	sub	rax,rdx
	mov	[g_fs_plen],eax
	clc
	ret
.bad:
	stc
	ret
.hex:
	sub	eax,'0'
	cmp	eax,9
	jbe	.hex_ok
	or	eax,0x20
	sub	eax,'a' - '0'
	cmp	eax,5
	ja	.hex_bad
	add	eax,10
.hex_ok:
	clc
	ret
.hex_bad:
	stc
	ret

; a directory asked for with no slash: there
fs_slash:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	memit_x 'HTTP/1.1 301 Moved Permanently',13,10,'Location: '
	lea	rsi,[g_npath]
	mov	ecx,[g_npath_len]
	rep	movsb
	mov	byte [rdi],'/'
	inc	rdi
	mov	rax,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	mov	edx,[g_hm+HM_PLEN]
	sub	ecx,edx
	jbe	@f
	lea	rsi,[rax+rdx]
	rep	movsb
@@:
	memit_x 13,10,'Content-Length: 0',13,10,13,10
	jmp	fs_head_ready

; rsi = a head, ecx = its length, no last line, no body
fs_short:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	rep	movsb
	memit_x 13,10
; the head is in UP, to rdi: as an answer. No file with it.
fs_head_ready:
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_UP]
	sub	rdi,rax
	mov	[r15+H_UPLEN],edi
	mov	dword [r15+H_UPOFF],0
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; (its body is not read)
@@:
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_CACHED
	mov	dword [rax+S_SERVER],NIL
	mov	qword [r15+H_UPT0],0
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_CE],NIL
	mov	qword [rax+HB_HT0],0
	mov	dword [rax+HB_CLEFT],0
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	jmp	http_resp_head

; r12, r13d, g_fs_path: a compressed one, if there is, and the client takes it
fs_precompressed:
	mov	eax,[r12+FI_PRE]
	test	eax,eax
	jz	.none
	push	rbx
	push	r14
	mov	ebx,eax
	lea	rdi,[.ae]
	mov	esi,15
	call	limit_find
	test	ecx,ecx
	jz	.out
	mov	r14,rsi
	mov	r8d,ecx
.next:
	test	bl,bl
	jz	.out
	movzx	r9d,bl
	shr	ebx,8
	push	r8
	mov	rsi,r14
	mov	ecx,r8d
	mov	eax,r9d
	call	fs_accepts
	pop	r8
	test	eax,eax
	jz	.next
	lea	rsi,[fi_names]
	lea	rsi,[rsi+r9*8]
	movzx	ecx,byte [rsi]
	inc	rsi
	mov	eax,[g_fs_plen]
	lea	rdi,[g_fs_path+rax]
	push	r9
	push	r8
	rep	movsb
	mov	eax,[g_fs_fd]
	push	rax
	call	fs_open
	pop	rax
	pop	r8
	pop	r9
	jc	.keep
	mov	ecx,dword [g_fs_stat+ST_MODE]
	and	ecx,S_IFMT_
	cmp	ecx,S_IFREG_
	jne	.not
	; this one
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	mov	[g_fs_enc],r9d
	mov	rax,[g_fs_stat+ST_SIZE]
	mov	[g_fs_size],rax
	mov	rax,[g_fs_stat+ST_MTIME]
	mov	[g_fs_mtime],rax
	jmp	.out
.not:
	push	rax
	call	fs_close
	pop	rax
.keep:
	mov	[g_fs_fd],eax
	jmp	.next
.out:
	pop	r14
	pop	rbx
.none:
	ret
.ae	db 'accept-encoding'

; rsi = Accept-Encoding, ecx = its length, eax = FE_*: eax = 1 when it says so, and
; not with q=0. Keeps r9, rbx, r12-r15.
fs_accepts:
	lea	rdx,[rsi+rcx]
	; the token
	lea	r8,[.br]
	mov	r10d,2
	cmp	eax,FE_BR
	je	.look
	lea	r8,[.zst]
	mov	r10d,4
	cmp	eax,FE_ZST
	je	.look
	lea	r8,[.gz]
	mov	r10d,4
.look:
	cmp	rsi,rdx
	jae	.no
	cmp	byte [rsi],' '
	je	.sp
	cmp	byte [rsi],','
	jne	.tok
.sp:
	inc	rsi
	jmp	.look
.tok:
	mov	rdi,rsi
.t:
	cmp	rsi,rdx
	jae	.t_end
	mov	al,[rsi]
	cmp	al,','
	je	.t_end
	cmp	al,';'
	je	.t_end
	cmp	al,' '
	je	.t_end
	inc	rsi
	jmp	.t
.t_end:
	mov	rax,rsi
	sub	rax,rdi
	cmp	rax,r10
	jne	.skip
	mov	rcx,r10
	push	rsi
	mov	rsi,r8
	repe	cmpsb
	pop	rsi
	jne	.skip
	; q=0?
.param:
	cmp	rsi,rdx
	jae	.yes
	cmp	byte [rsi],','
	je	.yes
	cmp	byte [rsi],'='
	jne	.p
	inc	rsi
	cmp	rsi,rdx
	jae	.yes
	cmp	byte [rsi],'0'
	jne	.yes
	; 0, 0.0, 0.000: all zeros
.z:
	inc	rsi
	cmp	rsi,rdx
	jae	.no
	mov	al,[rsi]
	cmp	al,'0'
	je	.z
	cmp	al,'.'
	je	.z
	cmp	al,','
	je	.no
	cmp	al,' '
	je	.no
	jmp	.yes
.p:
	inc	rsi
	jmp	.param
.skip:
	cmp	rsi,rdx
	jae	.no
	cmp	byte [rsi],','
	je	.look
	inc	rsi
	jmp	.skip
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret
.br	db 'br'
.zst	db 'zstd'
.gz	db 'gzip'

; r12 = the files, g_fs_*, the file open: conditions, range, and the head
fs_serve:
	call	fs_validators
	call	fs_conditions			; eax = 1 not modified
	test	eax,eax
	jnz	.not_modified
	call	fs_ranges
	cmp	dword [g_fs_range],2
	je	.unsatisfiable
	push	r14
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	cmp	dword [g_fs_range],1
	jne	.whole
	memit_x 'HTTP/1.1 206 Partial Content',13,10,'Content-Range: bytes '
	mov	rax,[g_fs_from]
	call	fmt_u64
	mov	byte [rdi],'-'
	inc	rdi
	mov	rax,[g_fs_to]
	call	fmt_u64
	mov	byte [rdi],'/'
	inc	rdi
	mov	rax,[g_fs_size]
	call	fmt_u64
	memit_x 13,10,'Content-Length: '
	mov	rax,[g_fs_to]
	sub	rax,[g_fs_from]
	inc	rax
	jmp	.length
.whole:
	mov	qword [g_fs_from],0
	memit_x 'HTTP/1.1 200 OK',13,10,'Content-Length: '
	mov	rax,[g_fs_size]
.length:
	mov	r14,rax				; what the body is
	call	fmt_u64
	memit_x 13,10
	call	fs_common
	memit_x 13,10
	mov	r8,[r15+H_BUF]
	mov	[r8+HB_FLEFT],r14
	pop	r14
	; where it reads from
	mov	rsi,[g_fs_from]
	test	rsi,rsi
	jz	@f
	push	rdi
	mov	edi,[g_fs_fd]
	xor	edx,edx
	mov	eax,SYS_lseek_
	syscall
	pop	rdi
@@:
	mov	rax,[r15+H_BUF]
	mov	ecx,[g_fs_fd]
	mov	[rax+HB_FFD],ecx
	push	rdi
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_FILE
	pop	rdi
	jmp	.send
.not_modified:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	memit_x 'HTTP/1.1 304 Not Modified',13,10
	call	fs_common
	memit_x 13,10
	jmp	.no_body
.unsatisfiable:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP]
	memit_x 'HTTP/1.1 416 Range Not Satisfiable',13,10,'Content-Range: bytes */'
	mov	rax,[g_fs_size]
	call	fmt_u64
	memit_x 13,10,'Content-Length: 0',13,10,13,10
.no_body:
	push	rdi
	call	fs_close
	pop	rdi
	jmp	fs_head_ready
.send:
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_UP]
	sub	rdi,rax
	mov	[r15+H_UPLEN],edi
	mov	dword [r15+H_UPOFF],0
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	call	session_ptr
	mov	dword [rax+S_SERVER],NIL
	mov	qword [r15+H_UPT0],0
	mov	rax,[r15+H_BUF]
	mov	qword [rax+HB_HT0],0
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	jmp	http_resp_head

; g_fs_*: the ETag and the date the file answers with
fs_validators:
	lea	rdi,[g_fs_etag]
	mov	byte [rdi],'"'
	inc	rdi
	mov	rax,[g_fs_size]
	call	.hex
	mov	byte [rdi],'-'
	inc	rdi
	mov	rax,[g_fs_mtime]
	call	.hex
	; (a compressed variant is another representation: another tag)
	mov	eax,[g_fs_enc]
	test	eax,eax
	jz	@f
	lea	rsi,[fi_names]
	lea	rsi,[rsi+rax*8]
	movzx	ecx,byte [rsi]
	dec	ecx
	add	rsi,2
	mov	byte [rdi],'-'
	inc	rdi
	rep	movsb
@@:
	mov	byte [rdi],'"'
	inc	rdi
	lea	rax,[g_fs_etag]
	mov	rcx,rdi
	sub	rcx,rax
	mov	[g_fs_elen],ecx
	; Thu, 01 Jan 1970 00:00:00 GMT
	mov	rax,[g_fs_mtime]
	lea	rdi,[g_fs_date]
	jmp	fmt_http_date
.hex:
	mov	ecx,60
	xor	edx,edx
.nib:
	mov	r8,rax
	shr	r8,cl
	and	r8d,15
	jnz	.put
	test	edx,edx
	jnz	.put
	test	ecx,ecx
	jnz	.skip
.put:
	mov	edx,1
	movzx	r8d,byte [.digits+r8]
	mov	[rdi],r8b
	inc	rdi
.skip:
	sub	ecx,4
	jns	.nib
	ret
.digits	db '0123456789abcdef'

; rax = seconds since the epoch, rdi = out (29 bytes). Keeps r12-r15, rbx.
fmt_http_date:
	mov	r8,rax
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	mov	r9,rax				; days
	mov	r10,rdx				; seconds of the day
	xor	edx,edx
	mov	ecx,7
	div	rcx
	lea	rsi,[fi_days+rdx*2+rdx]
	mov	ecx,3
	rep	movsb
	mov	word [rdi],', '
	add	rdi,2
	; civil from days (H. Hinnant)
	lea	rax,[r9+719468]
	xor	edx,edx
	mov	ecx,146097
	div	rcx
	mov	r8,rax				; era
	mov	r11,rdx				; day of era
	mov	rax,r11
	xor	edx,edx
	mov	ecx,1460
	div	rcx
	mov	rcx,r11
	sub	rcx,rax
	push	rcx
	mov	rax,r11
	xor	edx,edx
	mov	ecx,36524
	div	rcx
	pop	rcx
	add	rcx,rax
	push	rcx
	mov	rax,r11
	xor	edx,edx
	mov	ecx,146096
	div	rcx
	pop	rcx
	sub	rcx,rax
	mov	rax,rcx
	xor	edx,edx
	mov	ecx,365
	div	rcx				; rax = year of era
	mov	rsi,rax
	imul	rcx,r8,400
	add	rcx,rax				; y
	push	rcx
	imul	rcx,rsi,365
	mov	rax,rsi
	shr	rax,2
	add	rcx,rax
	mov	rax,rsi
	push	rcx
	xor	edx,edx
	mov	ecx,100
	div	rcx
	pop	rcx
	sub	rcx,rax
	mov	rax,r11
	sub	rax,rcx				; day of year, from March
	mov	r11,rax
	imul	rax,rax,5
	add	rax,2
	xor	edx,edx
	mov	ecx,153
	div	rcx
	mov	rsi,rax				; month, from March
	imul	rax,rax,153
	add	rax,2
	xor	edx,edx
	mov	ecx,5
	div	rcx
	mov	rcx,r11
	sub	rcx,rax
	inc	rcx				; day of the month
	pop	r8				; y
	lea	rax,[rsi+3]
	cmp	rax,12
	jbe	@f
	sub	rax,12
@@:
	cmp	rax,2
	ja	@f
	inc	r8
@@:
	mov	rsi,rax
	mov	rax,rcx
	call	.two
	mov	byte [rdi],' '
	inc	rdi
	mov	rax,rsi
	dec	rax
	push	rsi
	lea	rsi,[fi_months+rax*2+rax]
	mov	ecx,3
	rep	movsb
	pop	rsi
	mov	byte [rdi],' '
	inc	rdi
	mov	rax,r8
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	rax,r10
	xor	edx,edx
	mov	ecx,3600
	div	rcx
	mov	r10,rdx
	call	.two
	mov	byte [rdi],':'
	inc	rdi
	mov	rax,r10
	xor	edx,edx
	mov	ecx,60
	div	rcx
	mov	r10,rdx
	call	.two
	mov	byte [rdi],':'
	inc	rdi
	mov	rax,r10
	call	.two
	mov	dword [rdi],' GMT'
	add	rdi,4
	ret
.two:
	xor	edx,edx
	mov	ecx,10
	div	rcx
	add	al,'0'
	mov	[rdi],al
	add	dl,'0'
	mov	[rdi+1],dl
	add	rdi,2
	ret

; eax = 1 when the client has this one already. If-None-Match, when it is there,
; is what counts.
fs_conditions:
	lea	rdi,[.inm]
	mov	esi,13
	call	limit_find
	test	ecx,ecx
	jz	.since
	; `*`, or the tag among those listed, weak or not
	cmp	ecx,1
	jne	@f
	cmp	byte [rsi],'*'
	je	.yes
@@:
	mov	edx,[g_fs_elen]
.scan:
	cmp	ecx,edx
	jb	.no
	push	rsi
	push	rcx
	lea	rdi,[g_fs_etag]
	mov	ecx,edx
	repe	cmpsb
	pop	rcx
	pop	rsi
	je	.yes
	inc	rsi
	dec	ecx
	jmp	.scan
.since:
	lea	rdi,[.ims]
	mov	esi,17
	call	limit_find
	cmp	ecx,29
	jne	.no
	lea	rdi,[g_fs_date]
	mov	edx,ecx
	mov	ecx,edx
	repe	cmpsb
	je	.yes
.no:
	xor	eax,eax
	ret
.yes:
	mov	eax,1
	ret
.inm	db 'if-none-match'
.ims	db 'if-modified-since'

; g_fs_range, g_fs_from, g_fs_to from Range. Anything but one plain range is the
; whole file, as it may be; If-Range that is not this tag too.
fs_ranges:
	cmp	dword [g_fs_enc],0
	jne	.out				; (bytes of what? no ranges of a variant)
	cmp	qword [g_fs_size],0
	je	.out
	lea	rdi,[.r]
	mov	esi,5
	call	limit_find
	test	ecx,ecx
	jz	.out
	push	rsi
	push	rcx
	lea	rdi,[.ir]
	mov	esi,8
	call	limit_find
	mov	edx,ecx
	mov	r8,rsi
	pop	rcx
	pop	rsi
	test	edx,edx
	jz	.plain
	cmp	edx,[g_fs_elen]
	jne	.out
	push	rsi
	push	rcx
	mov	rsi,r8
	lea	rdi,[g_fs_etag]
	mov	ecx,edx
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.out
.plain:
	cmp	ecx,7
	jb	.out
	mov	rax,'bytes='
	mov	rdx,[rsi]
	shl	rdx,16
	shl	rax,16
	cmp	rax,rdx
	jne	.out
	add	rsi,6
	sub	ecx,6
	lea	rdx,[rsi+rcx]
	call	.number
	mov	r8,rax				; from, -1 none
	cmp	rsi,rdx
	jae	.out
	cmp	byte [rsi],'-'
	jne	.out
	inc	rsi
	call	.number
	mov	r9,rax				; to, -1 none
	cmp	rsi,rdx
	jne	.out				; (more than one, or something else)
	mov	r10,[g_fs_size]
	cmp	r8,-1
	jne	.from
	; the last N
	cmp	r9,-1
	je	.out
	test	r9,r9
	jz	.none
	mov	rax,r10
	sub	rax,r9
	jns	@f
	xor	eax,eax
@@:
	mov	r8,rax
	lea	r9,[r10-1]
	jmp	.got
.from:
	cmp	r8,r10
	jae	.none
	cmp	r9,-1
	je	.to_end
	cmp	r9,r8
	jb	.out
	cmp	r9,r10
	jb	.got
.to_end:
	lea	r9,[r10-1]
.got:
	mov	[g_fs_from],r8
	mov	[g_fs_to],r9
	mov	dword [g_fs_range],1
.out:
	ret
.none:
	mov	dword [g_fs_range],2
	ret
.number:
	xor	eax,eax
	xor	ecx,ecx
.d:
	cmp	rsi,rdx
	jae	.d_end
	movzx	edi,byte [rsi]
	sub	edi,'0'
	cmp	edi,9
	ja	.d_end
	mov	r10,10
	push	rdx
	mul	r10
	pop	rdx
	add	rax,rdi
	inc	ecx
	inc	rsi
	jmp	.d
.d_end:
	test	ecx,ecx
	jnz	@f
	mov	rax,-1
@@:
	ret
.r	db 'range'
.ir	db 'if-range'

; rdi = where in the head: what every answer of a file says. r12 = the files.
fs_common:
	memit_x 'ETag: '
	lea	rsi,[g_fs_etag]
	mov	ecx,[g_fs_elen]
	rep	movsb
	memit_x 13,10,'Last-Modified: '
	lea	rsi,[g_fs_date]
	mov	ecx,29
	rep	movsb
	memit_x 13,10,'Accept-Ranges: bytes',13,10
	cmp	dword [r12+FI_PRE],0
	je	@f
	memit_x 'Vary: Accept-Encoding',13,10
@@:
	mov	eax,[g_fs_enc]
	test	eax,eax
	jz	@f
	memit_x 'Content-Encoding: '
	mov	eax,[g_fs_enc]
	lea	rsi,[fs_accepts.br]
	mov	ecx,2
	cmp	eax,FE_BR
	je	.enc
	lea	rsi,[fs_accepts.zst]
	mov	ecx,4
	cmp	eax,FE_ZST
	je	.enc
	lea	rsi,[fs_accepts.gz]
.enc:
	rep	movsb
	memit_x 13,10
@@:
	mov	ecx,[r12+FI_CCLEN]
	test	ecx,ecx
	jz	@f
	memit_x 'Cache-Control: '
	mov	ecx,[r12+FI_CCLEN]
	mov	rsi,[r12+FI_CC]
	rep	movsb
	memit_x 13,10
@@:
	memit_x 'Content-Type: '
	call	fs_type
	rep	movsb
	memit_x 13,10
	ret

; g_fs_path: rsi = its type, ecx = how long. Keeps rdi.
fs_type:
	push	rdi
	mov	eax,[g_fs_plen]
	lea	rdx,[g_fs_path]
	; (a compressed name ends in .gz: the name before it was g_fs_plen long)
	lea	r8,[rdx+rax]
	mov	rsi,r8
.dot:
	cmp	rsi,rdx
	jbe	.none
	dec	rsi
	cmp	byte [rsi],'/'
	je	.none
	cmp	byte [rsi],'.'
	jne	.dot
	inc	rsi
	mov	r9,r8
	sub	r9,rsi				; the extension's length
	lea	r10,[.table]
.entry:
	movzx	eax,byte [r10]
	test	eax,eax
	jz	.none
	cmp	rax,r9
	jne	.other
	mov	rdi,rsi
	mov	edx,eax
	push	rsi
	lea	rsi,[r10+1]
	push	r8
	push	r9
	push	r10
	call	mem_eq_nocase
	pop	r10
	pop	r9
	pop	r8
	pop	rsi
	test	eax,eax
	jz	.other_len
	movzx	eax,byte [r10]
	lea	r10,[r10+rax+1]
	movzx	ecx,byte [r10]
	lea	rsi,[r10+1]
	pop	rdi
	ret
.other_len:
	movzx	eax,byte [r10]
.other:
	lea	r10,[r10+rax+1]
	movzx	eax,byte [r10]
	lea	r10,[r10+rax+1]
	jmp	.entry
.none:
	lea	rsi,[.octets]
	mov	ecx,24
	pop	rdi
	ret
.octets	db 'application/octet-stream'
macro ft ext*, type*
	local a, b
	db lengthof ext, ext, lengthof type, type
end macro
.table:
	ft 'html','text/html; charset=utf-8'
	ft 'htm','text/html; charset=utf-8'
	ft 'css','text/css; charset=utf-8'
	ft 'js','text/javascript; charset=utf-8'
	ft 'mjs','text/javascript; charset=utf-8'
	ft 'json','application/json'
	ft 'map','application/json'
	ft 'webmanifest','application/manifest+json'
	ft 'txt','text/plain; charset=utf-8'
	ft 'md','text/markdown; charset=utf-8'
	ft 'xml','application/xml'
	ft 'svg','image/svg+xml'
	ft 'png','image/png'
	ft 'jpg','image/jpeg'
	ft 'jpeg','image/jpeg'
	ft 'gif','image/gif'
	ft 'webp','image/webp'
	ft 'avif','image/avif'
	ft 'ico','image/x-icon'
	ft 'woff','font/woff'
	ft 'woff2','font/woff2'
	ft 'ttf','font/ttf'
	ft 'otf','font/otf'
	ft 'pdf','application/pdf'
	ft 'wasm','application/wasm'
	ft 'mp4','video/mp4'
	ft 'webm','video/webm'
	ft 'mp3','audio/mpeg'
	ft 'ogg','audio/ogg'
	db 0

; h_recv on the upstream side of a file: ebx = session, rdi = buffer, esi = room
file_recv:
	h_rec
	mov	r8,[r15+H_BUF]
	mov	rcx,[r8+HB_FLEFT]
	cmp	rcx,rsi
	cmova	rcx,rsi
	test	rcx,rcx
	jz	.end
	sub	[r8+HB_FLEFT],rcx
	mov	r9d,[r8+HB_FFD]
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	push	rdi
	push	rcx
	push	r9
	mov	edi,OP_H_RECV_U
	mov	esi,ebx
	call	sess_sqe
	pop	r9
	pop	rcx
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	[rax+SQE_FD],r9d
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],ecx
	mov	qword [rax+SQE_OFF],-1		; where the file is
	ret
.epoll:
	mov	rsi,rdi
	mov	edi,r9d
	mov	edx,ecx
	mov	eax,SYS_read
	syscall
	jmp	.done
.end:
	xor	eax,eax
.done:
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue

; the end of a file's answer, or of its session: ebx, r15
file_done:
	call	session_ptr
	and	dword [rax+S_FLAGS],not SF_FILE
	mov	rax,[r15+H_BUF]
	mov	edi,[rax+HB_FFD]
	mov	eax,SYS_close
	syscall
	and	dword [r15+H_FLAGS],not HX_UPKEEP
	ret

; rbx = the `files` node, r12 = the route's action
compile_files:
	push	r13
	push	r14
	push	r15
	mov	eax,[g_plan_files]
	cmp	eax,MAX_FILES
	jae	plan_bad_files
	inc	dword [g_plan_files]
	lea	ecx,[rax+1]
	mov	[r12+RA_FILES],ecx
	imul	r13,rax,FI_SIZE
	lea	r13,[g_files+r13]
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	byte [rsi],'/'
	jne	plan_bad_files
	cmp	ecx,1000
	ja	plan_bad_files
	push	rcx
	lea	rdi,[g_ar_text]
	lea	esi,[rcx+1]
	call	arena_alloc
	pop	rcx
	mov	[r13+FI_ROOT],rax
	mov	[r13+FI_RLEN],ecx
	mov	rdi,rax
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	rep	movsb
	mov	byte [rdi],0
	; it must be there, now
	mov	edi,-100
	mov	rsi,[r13+FI_ROOT]
	mov	edx,O_PATH_ or O_DIRECTORY_ or O_CLOEXEC_
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	plan_bad_files
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	; index=
	lea	rax,[.index_html]
	mov	[r13+FI_INDEX],rax
	mov	dword [r13+FI_ILEN],10
	mov	rdi,rbx
	lea	rsi,[.k_index]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r13+FI_INDEX],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r13+FI_ILEN],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[.k_fallback]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	byte [rcx],'/'
	jne	plan_bad_files
	inc	rcx
	dec	edx
	jz	plan_bad_files
	mov	[r13+FI_FALL],rcx
	mov	[r13+FI_FLEN],edx
@@:
	mov	rdi,rbx
	lea	rsi,[.k_pre]
	call	node_option
	test	rax,rax
	jz	.no_pre
	mov	r14,[rax+A_VAL]
	mov	eax,[rax+A_VLEN]
	lea	r15,[r14+rax]
	xor	r8d,r8d				; a shift
.pre:
	mov	rcx,r14
@@:
	cmp	rcx,r15
	jae	@f
	cmp	byte [rcx],','
	je	@f
	inc	rcx
	jmp	@b
@@:
	mov	rdx,rcx
	sub	rdx,r14
	mov	eax,FE_BR
	cmp	rdx,2
	jne	@f
	cmp	word [r14],'br'
	je	.pre_add
	mov	eax,FE_GZ
	cmp	word [r14],'gz'
	je	.pre_add
	jmp	plan_bad_files
@@:
	cmp	rdx,3
	jne	plan_bad_files
	mov	eax,[r14]
	and	eax,0xFFFFFF
	cmp	eax,'zst'
	jne	plan_bad_files
	mov	eax,FE_ZST
.pre_add:
	cmp	r8d,24
	ja	plan_bad_files
	push	rcx
	mov	ecx,r8d
	shl	eax,cl
	pop	rcx
	or	[r13+FI_PRE],eax
	add	r8d,8
	lea	r14,[rcx+1]
	cmp	rcx,r15
	jb	.pre
.no_pre:
	; cache=immutable, or a time
	mov	rdi,rbx
	lea	rsi,[.k_cache]
	call	node_option
	test	rax,rax
	jz	.done
	mov	r14,rax
	mov	rdi,[r14+A_VAL]
	mov	esi,[r14+A_VLEN]
	cmp	esi,9
	jne	.time
	lea	rdx,[.immutable]
	call	mem_eq_cstr
	test	eax,eax
	jz	.time0
	lea	rax,[.cc_imm]
	mov	[r13+FI_CC],rax
	mov	dword [r13+FI_CCLEN],.cc_imm_len
	jmp	.done
.time0:
	mov	rdi,[r14+A_VAL]
	mov	esi,[r14+A_VLEN]
.time:
	call	parse_duration
	jc	plan_bad_files
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	r14,rax
	lea	rdi,[g_ar_text]
	mov	esi,48
	call	arena_alloc
	mov	[r13+FI_CC],rax
	mov	rdi,rax
	lea	rsi,[.cc_pub]
	mov	ecx,.cc_pub_len
	rep	movsb
	mov	rax,r14
	call	fmt_u64
	mov	rax,rdi
	sub	rax,[r13+FI_CC]
	mov	[r13+FI_CCLEN],eax
.done:
	pop	r15
	pop	r14
	pop	r13
	ret
cstring .k_index, 'index',0
cstring .k_fallback, 'fallback',0
cstring .k_pre, 'precompressed',0
cstring .k_cache, 'cache',0
cstring .immutable, 'immutable',0
.index_html	db 'index.html'
.cc_imm		db 'public, max-age=31536000, immutable'
.cc_imm_len := $ - .cc_imm
.cc_pub		db 'public, max-age='
.cc_pub_len := $ - .cc_pub

plan_bad_files:
	call	log_begin
	out_lit 'files needs an absolute directory that exists; fallback= an absolute path; precompressed= from br, zst, gz; cache= a time or immutable; at most 64'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
