.text
.globl entry
.seh_proc entry
entry:
    subq $72, %rsp
    .seh_stackalloc 72
    .seh_endprologue
    leaq 40(%rsp), %rcx
    leaq 48(%rsp), %rdx
    leaq 56(%rsp), %r8
    xorl %r9d, %r9d
    movq $0, 32(%rsp)
    call *__imp___getmainargs(%rip)
    testl %eax, %eax
    jne .Ldone
    cmpl $2, 40(%rsp)
    jl .Ldone
    movq 48(%rsp), %rdx
    movq 8(%rdx), %rcx
    call *__imp_strlen(%rip)
.Ldone:
    addq $72, %rsp
    retq
.seh_endproc
