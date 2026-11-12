.text
.globl entry
entry:
  addq $1, %rcx
  jmp fragment
primary_end:
.p2align 4
fragment:
  movq %rcx, %rax
  retq
fragment_end:
independent:
  movq %rdx, %rax
  retq
independent_end:

.section .xdata,"dr"
.p2align 2
primary_info:
  .byte 1, 0, 0, 0
fragment_info:
  .byte 0x21, 0, 0, 0  # version 1, UNW_FLAG_CHAININFO
  .rva entry, primary_end, primary_info

.section .pdata,"dr"
  .rva entry, primary_end, primary_info
  .rva fragment, fragment_end, fragment_info
  .rva independent, independent_end, primary_info
