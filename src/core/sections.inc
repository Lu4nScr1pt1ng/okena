; Section collectors.
;
; An ELF executable built by fasm2 is laid out one segment after another, so
; code, read-only data and zero-initialised data cannot be interleaved in the
; source. Modules therefore write their constants inside "rodata ... end rodata"
; and their mutable state inside "bss ... end bss"; both blocks are collected
; into virtual areas and emitted once, at the end of main.asm, by rodata_emit
; and bss_emit. The BSS area is emitted as reserved bytes only, so it costs
; nothing in the file.

virtual at RODATA.base
	RODATA.buffer::
end virtual

virtual at BSS.base
	BSS.buffer::
end virtual

macro rodata?
	virtual RODATA.buffer
end macro

macro end?.rodata?
	end virtual
end macro

macro bss?
	virtual BSS.buffer
end macro

macro end?.bss?
	end virtual
end macro

macro rodata_emit
	align 64
	RODATA.base:
	virtual RODATA.buffer
		load RODATA.data:$-$$ from $$
	end virtual
	db RODATA.data
end macro

macro bss_emit
	align 4096
	BSS.base:
	virtual BSS.buffer
		BSS.size = $-$$
	end virtual
	rb BSS.size
end macro

; Read-only string with a "<name>.len" constant next to it.
macro cstring name*, text&
	rodata
		name = $
		db text
		name.len = $ - name
	end rodata
end macro
