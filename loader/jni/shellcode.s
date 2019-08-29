.global _inject_code_start
.global _inject_code_end

.global _dlopen_param2
.global _saved_cpsr_value

.global _dlopen_addr
.global _dlsym_addr
.global _dlclose_addr
.global _dlerror_addr

.global _so_path_addr
.global _so_init_func_addr
.global _so_func_arg_addr
.global _saved_r0_pc_addr

.global _so_path_value
.global _so_init_func_value
.global _so_func_arg_value
.global _saved_r0_pc_value

.data

_inject_code_start:
	NOP
	NOP

	LDR R1, =0
	LDR R0, _so_path_addr
	LDR R3, _dlopen_addr
	BLX R3
	MOV R1, #1
	SUBS R4, R0, #0
	BEQ 3f

	LDR R1, _so_init_func_addr
	LDR R3, _dlsym_addr
	BLX R3
	MOV R1, #2
	SUBS R3, R0, #0
	BEQ 1f
	MOV R1, #3
	LDR R0, _so_func_arg_addr
	BLX R3
	SUBS R0, R0, #0
	BEQ 2f
	MOV R1, #4
1:
	MOV R0, R4
	LDR R3, _dlclose_addr
	BLX R3
2:
	MOV PC, #0
3:	LDR R3, _dlerror_addr
	BLX R3
	MOV R2, R0
	MOV PC, #0

_dlopen_param2:
.word 0x0

_saved_cpsr_value:
.word 0x11111111

_dlopen_addr:
.word 0x11111111
_dlsym_addr:
.word 0x11111111
_dlclose_addr:
.word 0x11111111
_dlerror_addr:
.word 0x11111111

_so_path_addr:
.word 0x11111111
_so_init_func_addr:
.word 0x11111111
_so_func_arg_addr:
.word 0x11111111
_saved_r0_pc_addr:
.word 0x11111111

_saved_r0_pc_value:
.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
_so_path_value:
.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
_so_init_func_value:
.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
_so_func_arg_value:
.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

_inject_code_end:

.end
