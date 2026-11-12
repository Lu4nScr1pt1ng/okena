; eBPF, assembled by fasm2 like the rest of okena: no clang, no object files,
; no libbpf. A program is bytes in rodata; its maps are named by an index in a
; 64-bit load (BPF_PSEUDO_MAP_FD), which the loader swaps for the map's
; descriptor before BPF_PROG_LOAD (loader.inc). Jumps name labels; the macros
; work out the offsets in instructions.
;
; Registers: BR0 the return value and a helper's, BR1-BR5 a helper's
; arguments (BR1 the context on entry), BR6-BR9 kept across calls, BR10 the
; frame pointer (read only; the stack is the 512 bytes below it).

BR0 := 0
BR1 := 1
BR2 := 2
BR3 := 3
BR4 := 4
BR5 := 5
BR6 := 6
BR7 := 7
BR8 := 8
BR9 := 9
BR10 := 10

; classes, sizes, modes
EB_LD		:= 0x00
EB_LDX		:= 0x01
EB_ST		:= 0x02
EB_STX		:= 0x03
EB_ALU		:= 0x04
EB_JMP		:= 0x05
EB_JMP32	:= 0x06
EB_ALU64	:= 0x07
EB_W		:= 0x00
EB_H		:= 0x08
EB_B		:= 0x10
EB_DW		:= 0x18
EB_IMM		:= 0x00
EB_MEM		:= 0x60
EB_ATOMIC	:= 0xc0
EB_K		:= 0x00
EB_X		:= 0x08
; ALU operations
EB_ADD		:= 0x00
EB_SUB		:= 0x10
EB_MUL		:= 0x20
EB_DIV		:= 0x30
EB_OR		:= 0x40
EB_AND		:= 0x50
EB_LSH		:= 0x60
EB_RSH		:= 0x70
EB_NEG		:= 0x80
EB_MOD		:= 0x90
EB_XOR		:= 0xa0
EB_MOV		:= 0xb0
EB_ARSH		:= 0xc0
EB_END		:= 0xd0
; jumps
EB_JA		:= 0x00
EB_JEQ		:= 0x10
EB_JGT		:= 0x20
EB_JGE		:= 0x30
EB_JSET		:= 0x40
EB_JNE		:= 0x50
EB_JSGT		:= 0x60
EB_JSGE		:= 0x70
EB_CALL		:= 0x80
EB_EXIT		:= 0x90
EB_JLT		:= 0xa0
EB_JLE		:= 0xb0
EB_JSLT		:= 0xc0
EB_JSLE		:= 0xd0
EB_PSEUDO_MAP_FD := 1

; helpers (enum bpf_func_id)
BPF_FUNC_map_lookup_elem := 1
BPF_FUNC_map_update_elem := 2
BPF_FUNC_map_delete_elem := 3
BPF_FUNC_ktime_get_ns	:= 5
BPF_FUNC_get_smp_processor_id := 8
BPF_FUNC_csum_diff	:= 28
BPF_FUNC_xdp_adjust_head := 44
BPF_FUNC_xdp_adjust_tail := 65
BPF_FUNC_fib_lookup	:= 69

; XDP: struct xdp_md (32-bit fields, made pointers by the verifier), actions
XDP_MD_DATA	:= 0
XDP_MD_DATA_END	:= 4
XDP_MD_META	:= 8
XDP_MD_IFINDEX	:= 12
XDP_MD_RXQ	:= 16
XDP_ABORTED	:= 0
XDP_DROP	:= 1
XDP_PASS	:= 2
XDP_TX		:= 3
XDP_REDIRECT	:= 4

macro ebpf_insn op*, dst*, src*, off*, imm*
	db	op
	db	((src) shl 4) or (dst)
	dw	(off) and 0xFFFF
	dd	(imm) and 0xFFFFFFFF
end macro

; dst = src / imm (64 bits; the 32-bit forms end in 32)
irp <name,code>, mov,EB_MOV, add,EB_ADD, sub,EB_SUB, mul,EB_MUL, div,EB_DIV, or,EB_OR, \
	and,EB_AND, lsh,EB_LSH, rsh,EB_RSH, mod,EB_MOD, xor,EB_XOR, arsh,EB_ARSH
	macro e_#name dst*, src*
		ebpf_insn EB_ALU64 or code or EB_X, dst, src, 0, 0
	end macro
	macro e_#name#i dst*, imm*
		ebpf_insn EB_ALU64 or code or EB_K, dst, 0, 0, imm
	end macro
	macro e_#name#32 dst*, src*
		ebpf_insn EB_ALU or code or EB_X, dst, src, 0, 0
	end macro
	macro e_#name#32i dst*, imm*
		ebpf_insn EB_ALU or code or EB_K, dst, 0, 0, imm
	end macro
end irp

; byte order: dst to big endian, 16/32/64 bits (to_be on a little endian host)
macro e_be dst*, bits*
	ebpf_insn EB_ALU or EB_END or EB_X, dst, 0, 0, bits
end macro

; dst = a 64-bit constant, two instructions
macro e_ld64 dst*, imm*
	ebpf_insn EB_LD or EB_DW or EB_IMM, dst, 0, 0, (imm) and 0xFFFFFFFF
	ebpf_insn 0, 0, 0, 0, ((imm) shr 32) and 0xFFFFFFFF
end macro
; dst = map number idx (the loader puts its descriptor there)
macro e_ldmap dst*, idx*
	ebpf_insn EB_LD or EB_DW or EB_IMM, dst, EB_PSEUDO_MAP_FD, 0, idx
	ebpf_insn 0, 0, 0, 0, 0
end macro

; dst = *(size *)(src + off) ; *(size *)(dst + off) = src / imm
irp <sz,code>, 8,EB_B, 16,EB_H, 32,EB_W, 64,EB_DW
	macro e_ldx#sz dst*, src*, off*
		ebpf_insn EB_LDX or EB_MEM or code, dst, src, off, 0
	end macro
	macro e_stx#sz dst*, off*, src*
		ebpf_insn EB_STX or EB_MEM or code, dst, src, off, 0
	end macro
	macro e_st#sz dst*, off*, imm*
		ebpf_insn EB_ST or EB_MEM or code, dst, 0, off, imm
	end macro
end irp
; *(u64 *)(dst + off) += src, atomically (shared counters)
macro e_xadd64 dst*, off*, src*
	ebpf_insn EB_STX or EB_ATOMIC or EB_DW, dst, src, off, 0
end macro

; jumps: to a label; conditional ones compare dst with src / imm (64 bits)
macro e_ja target*
	local here
here:	ebpf_insn EB_JMP or EB_JA, 0, 0, (target - here) / 8 - 1, 0
end macro
irp <name,code>, jeq,EB_JEQ, jne,EB_JNE, jgt,EB_JGT, jge,EB_JGE, jlt,EB_JLT, jle,EB_JLE, \
	jset,EB_JSET, jsgt,EB_JSGT, jsge,EB_JSGE, jslt,EB_JSLT, jsle,EB_JSLE
	macro e_#name dst*, src*, target*
		local here
	here:	ebpf_insn EB_JMP or code or EB_X, dst, src, (target - here) / 8 - 1, 0
	end macro
	macro e_#name#i dst*, imm*, target*
		local here
	here:	ebpf_insn EB_JMP or code or EB_K, dst, 0, (target - here) / 8 - 1, imm
	end macro
end irp
macro e_call helper*
	ebpf_insn EB_JMP or EB_CALL, 0, 0, 0, helper
end macro
macro e_exit
	ebpf_insn EB_JMP or EB_EXIT, 0, 0, 0, 0
end macro
