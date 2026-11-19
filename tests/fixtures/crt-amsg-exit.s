.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
.ifdef error_number
    movl $error_number, %ecx
    callq _amsg_exit
.endif
.ifdef observe_continuation
    callq write_marker
.endif
    # The control returns 42. This continuation remains in each fatal PE.
    movl $42, %eax
    addq $40, %rsp
    retq
.seh_endproc

.ifndef error_number
    # Keep the load-time import even though the control never calls it.
    .section .rdata,"dr"
    .quad __imp__amsg_exit
.endif

.ifdef observe_continuation
    # Both marker variants contain this same stdout write.
    .text
    .seh_proc write_marker
write_marker:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq marker(%rip), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    addq $56, %rsp
    retq
    .seh_endproc

    .section .rdata,"dr"
marker:
    .ascii "M"
.endif
