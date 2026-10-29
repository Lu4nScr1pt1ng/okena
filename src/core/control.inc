; Control process and the backend names it resolves.
;
; A backend written as a name (`server db:5432`, `to app:3000`) becomes a
; group of DNS_MAX_ADDRS server slots, active only while they hold an
; address. The control process resolves every name, again when its TTL
; runs out (at most a minute, two seconds after a failure) and at once
; when a worker reports a failed connect to it. It publishes each name's
; addresses in a shared table under a sequence counter; workers copy them
; into their own slots on their tick, without a lock (seqlock: the writer
; never waits, a reader retries when it saw a write in progress).
;
; Failures keep the last known addresses: DNS going away never empties a
; pool. A name that does not resolve yet (a container that starts later)
; does not stop okena from starting.

MAX_GROUPS	= 64
DT_SIZE		= 256		; one shared entry per name
DT_SEQ		= 0		; q: odd while being written
DT_COUNT	= 8		; d
DT_ADDRS	= 16		; DNS_MAX_ADDRS * 16
DT_FAMILY	= DT_ADDRS + DNS_MAX_ADDRS * 16	; DNS_MAX_ADDRS bytes
DT_WANT_OFF	= MAX_GROUPS * DT_SIZE		; then one dword per name: refresh wanted

; Group (plan)
GR_NAME		= 0		; q
GR_NLEN		= 8		; d
GR_PORT		= 12		; d
GR_FIRST	= 16		; d: first server slot
GR_SIZE		= 32

CONTROL_POLL_NS	= 250000000	; refresh requests are noticed within 250 ms

bss
	align 8
	g_plan_groups	dd ?
	g_control_pid	dd ?
	g_dns_table	dq ?			; shared mapping
	g_groups:	rb GR_SIZE * MAX_GROUPS
	g_grp_seen	rq MAX_GROUPS		; worker: sequence last copied
	g_grp_due	rq MAX_GROUPS		; control: monotonic second of next lookup
	g_grp_last	rq MAX_GROUPS		; control: second of the last lookup
	g_grp_status	rd MAX_GROUPS		; control: last RS_* (for logging changes)
	g_grp_copy:	rb DT_SIZE
end bss

rodata
	align 8
	ts_control_poll	dq 0, CONTROL_POLL_NS
	control_name	db 'okena-control',0
end rodata

; Shared table, before any fork.
dns_table_init:
	xor	edi,edi
	mov	esi,DT_WANT_OFF + MAX_GROUPS * 4
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_dns_table],rax
	ret

; Resolve group ebx now and publish the result. Logs when what is known
; about the name changes. Returns the seconds until the next lookup in eax.
group_resolve:
	push	rbx
	push	r12
	push	r13
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	call	monotonic_seconds
	mov	[g_grp_last+rbx*8],rax
	mov	rdi,[r12+GR_NAME]
	mov	esi,[r12+GR_NLEN]
	call	rs_lookup
	mov	r13d,eax
	cmp	eax,RS_OK
	jne	.failed
	; publish
	mov	rdi,rbx
	shl	rdi,8
	add	rdi,[g_dns_table]
	call	group_changed			; CF when the set differs
	jnc	.same
	inc	qword [rdi+DT_SEQ]		; odd: being written
	mov	eax,[g_rs_result+RR_COUNT]
	mov	[rdi+DT_COUNT],eax
	push	rdi
	lea	rsi,[g_rs_result+RR_ADDRS]
	add	rdi,DT_ADDRS
	mov	ecx,DNS_MAX_ADDRS * 16 + DNS_MAX_ADDRS
	rep	movsb
	pop	rdi
	inc	qword [rdi+DT_SEQ]		; even: done
	call	log_begin
	mov	rsi,[r12+GR_NAME]
	mov	edx,[r12+GR_NLEN]
	call	out_str
	out_lit ' resolved to'
	call	log_addresses
	call	log_end
.same:
	mov	[g_grp_status+rbx*4],r13d
	mov	eax,[g_rs_result+RR_TTL]
	cmp	eax,DNS_TTL_MIN
	jae	@f
	mov	eax,DNS_TTL_MIN
@@:
	cmp	eax,DNS_TTL_MAX
	jbe	.out
	mov	eax,DNS_TTL_MAX
	jmp	.out
.failed:
	cmp	r13d,[g_grp_status+rbx*4]
	je	.retry				; already said so
	mov	[g_grp_status+rbx*4],r13d
	call	log_begin
	out_lit 'cannot resolve '
	mov	rsi,[r12+GR_NAME]
	mov	edx,[r12+GR_NLEN]
	call	out_str
	cmp	r13d,RS_NXDOMAIN
	jne	@f
	out_lit ': no such name'
@@:
	cmp	r13d,RS_NODATA
	jne	@f
	out_lit ': the name has no address'
@@:
	cmp	r13d,RS_FAILED
	jne	@f
	out_lit ': no answer from the DNS servers'
@@:
	mov	rax,rbx
	shl	rax,8
	add	rax,[g_dns_table]
	cmp	dword [rax+DT_COUNT],0
	je	@f
	out_lit '; keeping the addresses known so far'
	jmp	.said
@@:
	out_lit '; retrying'
.said:
	call	log_end
.retry:
	mov	eax,DNS_RETRY_S
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = shared entry. CF when g_rs_result differs from it.
group_changed:
	mov	eax,[g_rs_result+RR_COUNT]
	cmp	eax,[rdi+DT_COUNT]
	jne	.yes
	push	rdi
	lea	rsi,[g_rs_result+RR_ADDRS]
	add	rdi,DT_ADDRS
	mov	ecx,DNS_MAX_ADDRS * 16 + DNS_MAX_ADDRS
	repe	cmpsb
	pop	rdi
	jne	.yes
	clc
	ret
.yes:
	stc
	ret

; " 10.0.0.5, 10.0.0.6" from g_rs_result.
log_addresses:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_rs_result+RR_COUNT]
	jae	.done
	test	ebx,ebx
	jz	@f
	out_lit ','
@@:
	out_lit ' '
	mov	eax,ebx
	shl	eax,4
	lea	rsi,[g_rs_result+RR_ADDRS+rax]
	movzx	edi,byte [g_rs_result+RR_FAMILY+rbx]
	call	out_ip
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; rsi = address, edi = 4 or 6. Prints it (IPv6 in full hex groups, with
; the longest run of zero groups as "::").
out_ip:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rsi
	cmp	edi,4
	jne	.v6
	xor	r12d,r12d
.octet:
	movzx	eax,byte [rbx+r12]
	call	out_u64
	inc	r12d
	cmp	r12d,4
	je	.done
	out_lit '.'
	jmp	.octet
.v6:
	; longest run of zero groups
	xor	r12d,r12d			; index
	mov	r13d,-1				; best start
	xor	r14d,r14d			; best length
	xor	ecx,ecx				; current start
	xor	edx,edx				; current length
.scan:
	cmp	r12d,8
	jae	.scanned
	cmp	word [rbx+r12*2],0
	jne	.nz
	test	edx,edx
	jnz	@f
	mov	ecx,r12d
@@:
	inc	edx
	cmp	edx,r14d
	jbe	.adv
	mov	r14d,edx
	mov	r13d,ecx
	jmp	.adv
.nz:
	xor	edx,edx
.adv:
	inc	r12d
	jmp	.scan
.scanned:
	cmp	r14d,2
	jae	@f
	mov	r13d,-1				; a single zero group stays "0"
@@:
	xor	r12d,r12d
.group:
	cmp	r12d,8
	jae	.done
	cmp	r12d,r13d
	jne	.print
	out_lit '::'
	add	r12d,r14d
	jmp	.group
.print:
	test	r12d,r12d
	jz	@f
	lea	eax,[r12-1]
	cmp	eax,r13d
	jl	.colon
	mov	ecx,r13d
	add	ecx,r14d
	cmp	r12d,ecx
	je	@f				; right after "::"
.colon:
	out_lit ':'
@@:
	movzx	eax,word [rbx+r12*2]
	xchg	al,ah
	call	out_hex16
	inc	r12d
	jmp	.group
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = 16-bit value: lowercase hex without leading zeros.
out_hex16:
	push	rbx
	mov	ebx,eax
	mov	ecx,12
	xor	edx,edx				; started
.digit:
	mov	eax,ebx
	shr	eax,cl
	and	eax,15
	test	edx,edx
	jnz	.emit
	test	eax,eax
	jnz	.emit
	test	ecx,ecx
	jnz	.skip
.emit:
	mov	edx,1
	push	rcx
	push	rdx
	cmp	eax,10
	jb	@f
	add	eax,'a' - '0' - 10
@@:
	add	eax,'0'
	mov	edi,eax
	call	out_char
	pop	rdx
	pop	rcx
.skip:
	sub	ecx,4
	jns	.digit
	pop	rbx
	ret

; Supervisor, before forking: resolve every name once so workers start
; with addresses (each lookup is bounded by the DNS timeouts).
groups_resolve_all:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_groups]
	jae	.done
	call	group_resolve
	push	rax
	call	monotonic_seconds
	pop	rcx
	add	rax,rcx
	mov	[g_grp_due+rbx*8],rax
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; Supervisor: start the control process (only when there are names).
spawn_control:
	cmp	dword [g_plan_groups],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	control_main
	js	.none
	mov	[g_control_pid],eax
.none:
	ret

; Never returns.
control_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	mov	edi,EXIT_OK
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[control_name]
	mov	eax,SYS_prctl
	syscall
	seccomp_for filter_control
.loop:
	call	monotonic_seconds
	mov	r12,rax
	xor	ebx,ebx
.group:
	cmp	ebx,[g_plan_groups]
	jae	.sleep
	; due, or a worker failed to connect to it (and not looked up this second)
	cmp	r12,[g_grp_due+rbx*8]
	jae	.resolve
	mov	rax,[g_dns_table]
	cmp	dword [rax+DT_WANT_OFF+rbx*4],0
	je	.next
	cmp	r12,[g_grp_last+rbx*8]
	jbe	.next
.resolve:
	mov	rax,[g_dns_table]
	mov	dword [rax+DT_WANT_OFF+rbx*4],0
	call	group_resolve
	add	rax,r12
	mov	[g_grp_due+rbx*8],rax
.next:
	inc	ebx
	jmp	.group
.sleep:
	lea	rdi,[ts_control_poll]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.loop

; Worker: copy the names' current addresses into this worker's server
; slots. Cheap when nothing changed: one load per name.
groups_refresh:
	push	rbx
	push	r12
	push	r13
	push	r14
	xor	ebx,ebx
.group:
	cmp	ebx,[g_plan_groups]
	jae	.done
	mov	r12,rbx
	shl	r12,8
	add	r12,[g_dns_table]
.read:
	mov	r13,[r12+DT_SEQ]
	cmp	r13,[g_grp_seen+rbx*8]
	je	.next				; unchanged
	test	r13,1
	jnz	.read				; being written right now
	lea	rdi,[g_grp_copy]
	mov	rsi,r12
	mov	ecx,DT_SIZE
	rep	movsb
	cmp	r13,[r12+DT_SEQ]
	jne	.read				; changed while copying
	mov	[g_grp_seen+rbx*8],r13
	call	group_apply
.next:
	inc	ebx
	jmp	.group
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Apply g_grp_copy to the slots of group ebx.
group_apply:
	push	rbx
	push	r12
	push	r13
	push	r14
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	xor	r13d,r13d			; slot
.slot:
	cmp	r13d,DNS_MAX_ADDRS
	jae	.done
	mov	eax,[r12+GR_FIRST]
	add	eax,r13d
	mov	r14d,eax
	imul	rbx,rax,SV_SIZE
	lea	rbx,[g_servers+rbx]
	cmp	r13d,[g_grp_copy+DT_COUNT]
	jae	.off
	; build the sockaddr in a scratch area, compare, then store
	sub	rsp,AD_SIZE
	mov	eax,r13d
	shl	eax,4
	mov	rcx,[g_grp_copy+DT_ADDRS+rax]
	mov	[rsp+AD_IP],rcx
	mov	rcx,[g_grp_copy+DT_ADDRS+rax+8]
	mov	[rsp+AD_IP+8],rcx
	mov	dword [rsp+AD_KIND],ADDR_V6
	cmp	byte [g_grp_copy+DT_FAMILY+r13],4
	jne	@f
	mov	dword [rsp+AD_KIND],ADDR_V4
@@:
	mov	eax,[r12+GR_PORT]
	mov	[rsp+AD_PORT],eax
	sub	rsp,112
	mov	rdi,rsp
	lea	rsi,[rsp+112]
	call	sockaddr_build
	mov	r8d,eax
	mov	r9d,edx
	; a new address for this slot: forget the old one's failures
	cmp	dword [rbx+SV_ACTIVE],0
	je	.changed
	cmp	r8d,[rbx+SV_SALEN]
	jne	.changed
	lea	rdi,[rbx+SV_SA]
	mov	rsi,rsp
	mov	edx,r8d
	push	r8
	push	r9
	call	mem_eq
	pop	r9
	pop	r8
	test	eax,eax
	jnz	.same
.changed:
	mov	rsi,rsp
	lea	rdi,[rbx+SV_SA]
	mov	ecx,112
	rep	movsb
	mov	[rbx+SV_SALEN],r8d
	mov	[rbx+SV_FAMILY],r9d
	mov	dword [g_sv_fails+r14*4],0
	mov	dword [g_sv_down+r14*4],0
	mov	dword [rbx+SV_ACTIVE],1
.same:
	add	rsp,112 + AD_SIZE
	inc	r13d
	jmp	.slot
.off:
	mov	dword [rbx+SV_ACTIVE],0
	inc	r13d
	jmp	.slot
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
