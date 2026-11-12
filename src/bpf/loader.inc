; Loading eBPF: maps, programs (their map numbers made descriptors), XDP links.
; Needs CAP_BPF and CAP_NET_ADMIN (the supervisor before it drops them, or
; `okena xdp` run by root); every call reports -errno, nothing is fatal here.

SYS_bpf		:= 321
BPF_MAP_CREATE	:= 0
BPF_MAP_LOOKUP_ELEM := 1
BPF_MAP_UPDATE_ELEM := 2
BPF_MAP_DELETE_ELEM := 3
BPF_PROG_LOAD	:= 5
BPF_LINK_CREATE	:= 28
BPF_MAP_TYPE_HASH := 1
BPF_MAP_TYPE_ARRAY := 2
BPF_MAP_TYPE_PERCPU_ARRAY := 6
BPF_MAP_TYPE_LRU_PERCPU_HASH := 10
BPF_PROG_TYPE_XDP := 6
BPF_XDP		:= 37			; attach type
XDP_FLAGS_SKB_MODE := 2
XDP_FLAGS_DRV_MODE := 4
EB_LOG_SIZE	:= 65536
EB_MAPS_MAX	:= 32

bss
	align 8
	g_eb_attr:	rb 128
	g_eb_mapfd	rd EB_MAPS_MAX		; a program's maps, by number
	g_eb_insns	dq ?			; the program being loaded, patched
	g_eb_log:	rb EB_LOG_SIZE		; the verifier's say
	g_eb_ifr:	rb 40
	g_eb_ncpu	dd ?			; possible CPUs (per-CPU maps' values)
end bss

rodata
	eb_license	db 'GPL',0		; (helpers like fib_lookup ask for it)
end rodata

; edi = type, esi = key size, edx = value size, ecx = entries, r8d = number:
; the map made, g_eb_mapfd[number] = its descriptor. eax = it, or -errno.
eb_map_create:
	push	r8
	push	rdi
	push	rsi
	push	rdx
	push	rcx
	lea	rdi,[g_eb_attr]
	xor	eax,eax
	mov	ecx,128 / 8
	rep	stosq
	pop	rcx
	pop	rdx
	pop	rsi
	pop	rdi
	mov	[g_eb_attr],edi
	mov	[g_eb_attr+4],esi
	mov	[g_eb_attr+8],edx
	mov	[g_eb_attr+12],ecx
	mov	edi,BPF_MAP_CREATE
	lea	rsi,[g_eb_attr]
	mov	edx,72
	mov	eax,SYS_bpf
	syscall
	pop	r8
	test	eax,eax
	js	@f
	mov	[g_eb_mapfd+r8*4],eax
@@:
	ret

; rsi = instructions (copied to rdi, a buffer of rdx bytes, then patched),
; edx = their bytes: an XDP program. eax = its descriptor, or -errno
; (g_eb_log says why).
eb_prog_load_xdp:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,edx
	mov	ecx,edx
	rep	movsb
	; map numbers to descriptors: a 64-bit load with BPF_PSEUDO_MAP_FD
	xor	ebx,ebx
.insn:
	cmp	ebx,r13d
	jae	.patched
	cmp	byte [r12+rbx],EB_LD or EB_DW or EB_IMM
	jne	.next1
	mov	al,[r12+rbx+1]
	shr	al,4
	cmp	al,EB_PSEUDO_MAP_FD
	jne	.next2
	mov	eax,[r12+rbx+4]
	cmp	eax,EB_MAPS_MAX
	jae	.next2
	mov	eax,[g_eb_mapfd+rax*4]
	mov	[r12+rbx+4],eax
.next2:
	add	ebx,16
	jmp	.insn
.next1:
	add	ebx,8
	jmp	.insn
.patched:
	lea	rdi,[g_eb_attr]
	xor	eax,eax
	mov	ecx,128 / 8
	rep	stosq
	mov	dword [g_eb_attr],BPF_PROG_TYPE_XDP
	mov	eax,r13d
	shr	eax,3
	mov	[g_eb_attr+4],eax		; insn_cnt
	mov	[g_eb_attr+8],r12		; insns
	lea	rax,[eb_license]
	mov	[g_eb_attr+16],rax
	mov	dword [g_eb_attr+24],1		; log_level: on failure, why
	mov	dword [g_eb_attr+28],EB_LOG_SIZE
	lea	rax,[g_eb_log]
	mov	[g_eb_attr+32],rax
	mov	dword [g_eb_attr+48],'oken'	; prog_name
	mov	word [g_eb_attr+52],'a'
	mov	dword [g_eb_attr+68],BPF_XDP	; expected_attach_type
	mov	byte [g_eb_log],0
	mov	edi,BPF_PROG_LOAD
	lea	rsi,[g_eb_attr]
	mov	edx,128
	mov	eax,SYS_bpf
	syscall
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = an interface's name (NUL-ended): eax = its index, or -errno
eb_ifindex:
	lea	rdi,[g_eb_ifr]
	mov	ecx,15
@@:
	lodsb
	stosb
	test	al,al
	loopnz	@b
	mov	byte [g_eb_ifr+15],0
	mov	edi,AF_INET
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.out
	push	rax
	mov	edi,eax
	mov	esi,SIOCGIFINDEX_
	lea	rdx,[g_eb_ifr]
	mov	eax,SYS_ioctl_
	syscall
	pop	rdi
	push	rax
	mov	eax,SYS_close
	syscall
	pop	rax
	test	eax,eax
	js	.out
	mov	eax,[g_eb_ifr+16]
.out:
	ret

; edi = program, esi = interface index, edx = XDP_FLAGS_*: the program
; attached (a link: it goes when its descriptor closes, or the process ends).
; eax = the link's descriptor, or -errno.
eb_xdp_attach:
	push	rdx
	push	rsi
	push	rdi
	lea	rdi,[g_eb_attr]
	xor	eax,eax
	mov	ecx,128 / 8
	rep	stosq
	pop	rdi
	pop	rsi
	pop	rdx
	mov	[g_eb_attr],edi
	mov	[g_eb_attr+4],esi
	mov	dword [g_eb_attr+8],BPF_XDP
	mov	[g_eb_attr+12],edx
	mov	edi,BPF_LINK_CREATE
	lea	rsi,[g_eb_attr]
	mov	edx,64
	mov	eax,SYS_bpf
	syscall
	ret

; edi = map descriptor, rsi = key, rdx = value: eax = 0 or -errno
eb_map_lookup:
	push	rdx
	push	rsi
	push	rdi
	lea	rdi,[g_eb_attr]
	xor	eax,eax
	mov	ecx,32 / 8
	rep	stosq
	pop	rdi
	pop	rsi
	pop	rdx
	mov	[g_eb_attr],edi
	mov	[g_eb_attr+8],rsi
	mov	[g_eb_attr+16],rdx
	mov	edi,BPF_MAP_LOOKUP_ELEM
	lea	rsi,[g_eb_attr]
	mov	edx,32
	mov	eax,SYS_bpf
	syscall
	ret

; edi = map descriptor, rsi = key, rdx = value, ecx = flags (0 any):
; eax = 0 or -errno
eb_map_update:
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	lea	rdi,[g_eb_attr]
	xor	eax,eax
	mov	ecx,32 / 8
	rep	stosq
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	mov	[g_eb_attr],edi
	mov	[g_eb_attr+8],rsi
	mov	[g_eb_attr+16],rdx
	mov	[g_eb_attr+24],rcx
	mov	edi,BPF_MAP_UPDATE_ELEM
	lea	rsi,[g_eb_attr]
	mov	edx,32
	mov	eax,SYS_bpf
	syscall
	ret

; g_eb_ncpu = the possible CPUs ("0-N" in /sys/devices/system/cpu/possible):
; a per-CPU map's value comes as that many, 8 bytes each
eb_ncpu:
	cmp	dword [g_eb_ncpu],0
	jne	.out
	mov	dword [g_eb_ncpu],1
	cstring .path, '/sys/devices/system/cpu/possible',0
	mov	edi,AT_FDCWD
	lea	rsi,[.path]
	mov	edx,O_RDONLY or O_CLOEXEC
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out
	push	rax
	mov	edi,eax
	lea	rsi,[g_eb_ifr]
	mov	edx,32
	xor	eax,eax				; SYS_read
	syscall
	pop	rdi
	push	rax
	mov	eax,SYS_close
	syscall
	pop	rcx
	test	rcx,rcx
	jle	.out
	; the number after the last '-' (or the only one), plus one
	lea	rsi,[g_eb_ifr]
	xor	eax,eax
	xor	edx,edx
.c:
	test	ecx,ecx
	jz	.done
	movzx	r8d,byte [rsi]
	inc	rsi
	dec	ecx
	cmp	r8d,'-'
	jne	@f
	xor	eax,eax
	jmp	.c
@@:
	sub	r8d,'0'
	cmp	r8d,9
	ja	.done
	imul	eax,eax,10
	add	eax,r8d
	jmp	.c
.done:
	inc	eax
	mov	[g_eb_ncpu],eax
.out:
	ret
