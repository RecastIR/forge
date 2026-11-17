.text
.globl entry
.seh_proc entry
entry:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    movq %rcx, 32(%rsp)
    addq %rdx, bridge_value(%rip)
    call *__imp_GetLastError(%rip)
    movq 32(%rsp), %rax
    movq bridge_value(%rip), %rdx
    xorq %rdx, %rax
    movq 40(%rsp), %rdx
    addq %rdx, %rax
    movq bridge_constant(%rip), %rdx
    addq %rdx, %rax
    addq $56, %rsp
    ret
.seh_endproc

.globl guard_then_service
.seh_proc guard_then_service
guard_then_service:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    # Offset 0 selects the local above shadow space. Offset 8 selects the entry return slot.
    movq %rdx, 32(%rsp,%rcx)
    call *__imp_GetLastError(%rip)
    addq $40, %rsp
    ret
.seh_endproc

.data
.globl bridge_value
bridge_value:
    .quad 11
.bss
    .space 4096

.section .rdata,"dr"
.globl bridge_constant
bridge_constant:
    .quad 41
