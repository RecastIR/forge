.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq callback_ref(%rip), %rax
    movq (%rax), %rax
    testq %rax, %rax
    je .Lafter
    xorl %r8d, %r8d
    movl $42, %edx
    xorl %ecx, %ecx
    callq *%rax
.Lafter:
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc callback
callback:
    .seh_endprologue
    movl %edx, %eax
    retq
.seh_endproc

.section .rdata,"dr"
.p2align 3
callback_ref: .quad callback_cell
callback_cell: .quad callback
