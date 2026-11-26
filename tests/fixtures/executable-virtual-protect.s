.macro protect offset, count, mode
    leaq pages+\offset(%rip), %rcx
    movl $\count, %edx
    movl $\mode, %r8d
    leaq 32(%rsp), %r9
    callq *__imp_VirtualProtect(%rip)
    cmpl $1, %eax
    jne .Lbad
.endm
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
.ifdef fresh_page
    protect 0, 1, 2
    cmpl $8, 32(%rsp)
    jne .Lbad
    protect 0, 1, 4
    cmpl $2, 32(%rsp)
    jne .Lbad
.endif
    movl $42, pages(%rip)
    movl $43, pages+4096(%rip)
    movl $55, 40(%rsp)
    protect 1, 1, 2
    movl 32(%rsp), %eax
    movl %eax, 36(%rsp)
    cmpl $42, pages(%rip)
    jne .Lbad
.ifdef deny_write
    movl $27, pages(%rip)
.endif
.ifdef deny_rmw
    addl $1, pages(%rip)
.endif
.ifdef deny_atomic
    movl $1, %eax
    xchgq %rax, pages(%rip)
.endif
.ifdef deny_adapter
    leaq pages(%rip), %rcx
    callq *__imp_GetStartupInfoW(%rip)
.endif
.ifdef deny_guard
    protect 0, 1, 0x102
.endif
.ifdef deny_executable
    protect 0, 1, 0x20
.endif
.ifdef deny_code
    leaq entry(%rip), %rcx
.endif
.ifdef deny_iat
    leaq __imp_VirtualProtect(%rip), %rcx
.endif
.ifdef deny_immutable
    leaq constant(%rip), %rcx
.endif
.ifdef bad_target
    movl $1, %edx
    movl $4, %r8d
    leaq 32(%rsp), %r9
    callq *__imp_VirtualProtect(%rip)
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
.ifdef observe_original
    # The reference harness compares the exact old value on each backend.
    movl 36(%rsp), %eax
    addl $38, %eax
.else
    movl $42, %eax
.endif
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
.section .rdata,"dr"
constant:
    .long 19
