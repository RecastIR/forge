.section .initial,"dw"
.quad 0x10002

.section .other,"dw"
.quad 0x20003

.section .ptrslot,"dw"
.quad .initial

.text
.globl global_retarget
.seh_proc global_retarget
global_retarget:
    .seh_endprologue
    # Zero keeps the pointer from the preceding call. One and two select a new target.
    testq %rcx, %rcx
    je 2f
    leaq .other(%rip), %r9
    cmpq $1, %rcx
    je 1f
    leaq .initial(%rip), %r9
1:
    movq %r9, .ptrslot(%rip)
2:
    movq .ptrslot(%rip), %r8
    leaq 2(%r8), %r9
    addw %dx, (%r9)
    movq (%r8), %rax
    ret
    .seh_endproc

.section .drectve
.ascii " -export:global_retarget"
