.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
    movl $37, %ebx
    movl $73, %ecx
    callq *__imp_SetLastError(%rip)
    movl $42, pages(%rip)
    movl $43, pages+4096(%rip)
    movl $55, 40(%rsp)
.macro protect offset, count, mode
    leaq pages+\offset(%rip), %rcx
    movl $\count, %edx
    movl $\mode, %r8d
    leaq 32(%rsp), %r9
    callq *__imp_VirtualProtect(%rip)
    cmpl $1, %eax
    jne .Lbad
.endm
    protect 1, 1, 2
    cmpl $4, 32(%rsp)
    jne .Lbad
    cmpl $42, pages(%rip)
    jne .Lbad
.ifdef deny_write
    movl $27, pages(%rip)
.endif
    movl $44, pages+4096(%rip)
    protect 4095, 2, 2
    cmpl $2, 32(%rsp)
    jne .Lbad
    protect 4096, 1, 2
    cmpl $2, 32(%rsp)
    jne .Lbad
    protect 4095, 2, 4
    cmpl $2, 32(%rsp)
    jne .Lbad
    addl $1, pages(%rip)
    cmpl $43, pages(%rip)
    jne .Lbad
    cmpl $44, pages+4096(%rip)
    jne .Lbad
    callq *__imp_GetLastError(%rip)
    cmpl $73, %eax
    jne .Lbad
    cmpl $55, 40(%rsp)
    jne .Lbad
    cmpl $37, %ebx
    jne .Lbad
    movl $42, %eax
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc
.data
.p2align 12
pages:
    .space 8192
