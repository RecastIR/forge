# ABI probe for external MSVCRT services. The conventional CRT fixtures separately test startup.
.text
.globl entry
.seh_proc entry
entry:
    subq $88, %rsp
    .seh_stackalloc 88
    .seh_endprologue
    movq __imp__fmode(%rip), %rdx
    movl (%rdx), %ecx
    cmpl $0x4000, %ecx
    jne .Lbad
    movl $0x8000, (%rdx)
    movq __imp__fmode(%rip), %rdx
    movl (%rdx), %ecx
    cmpl $0x8000, %ecx
    jne .Lbad
    movq __imp__commode(%rip), %rdx
    movl (%rdx), %ecx
    testl %ecx, %ecx
    jne .Lbad
    # The imported address is a guest DATA cell, handed directly to a checked byte service.
    movq __imp__commode(%rip), %rcx
    call *__imp_strlen(%rip)
    testq %rax, %rax
    jne .Lbad
    movq __imp___initenv(%rip), %rdx
    movq (%rdx), %rcx
    testq %rcx, %rcx
    je .Lbad
    movq __imp__acmdln(%rip), %rdx
    movq (%rdx), %rdx
    movb $'!', (%rdx)
    call *__imp_GetCommandLineA(%rip)
    movzbl (%rax), %ecx
    cmpl $'!', %ecx
    je .Lbad
    movq %rax, %rcx
    call *__imp_strlen(%rip)
    testq %rax, %rax
    je .Lbad
    leaq 48(%rsp), %rcx
    leaq 56(%rsp), %rdx
    leaq 64(%rsp), %r8
    xorl %r9d, %r9d
    movq $0, 32(%rsp)
    call *__imp___getmainargs(%rip)
    testl %eax, %eax
    jne .Lbad
    movq __imp___initenv(%rip), %rdx
    movq (%rdx), %rcx
    movq 64(%rsp), %rdx
    testq %rdx, %rdx
    je .Lbad
    cmpq %rcx, %rdx
    jne .Lbad
    movq 56(%rsp), %rdx
    movq %rdx, 80(%rsp)
    leaq 48(%rsp), %rcx
    leaq 56(%rsp), %rdx
    leaq 64(%rsp), %r8
    xorl %r9d, %r9d
    movq $0, 32(%rsp)
    call *__imp___getmainargs(%rip)
    testl %eax, %eax
    jne .Lbad
    movq 56(%rsp), %rdx
    movq 80(%rsp), %rcx
    cmpq %rdx, %rcx
    je .Lbad
    movl 48(%rsp), %ecx
    cmpl $1, %ecx
    je .Lnoargs
    cmpl $2, %ecx
    jne .Lbad
    movl $2, %ecx
    movl $8, %edx
    call *__imp_calloc(%rip)
    testq %rax, %rax
    je .Lbad
    movq %rax, 72(%rsp)
    movq (%rax), %rcx
    testq %rcx, %rcx
    jne .Lbad
    movq $0x002a2a, (%rax)
    movq %rax, %rcx
    call *__imp_strlen(%rip)
    cmpq $2, %rax
    jne .Lbad
    movq 72(%rsp), %rcx
    call *__imp_free(%rip)
    movq 56(%rsp), %rdx
    movq 8(%rdx), %rdx
    movzbl (%rdx), %eax
    addq $88, %rsp
    retq
.Lbad:
    movl $1, %eax
    addq $88, %rsp
    retq
.Lnoargs:
    movl $41, %eax
    addq $88, %rsp
    retq
.seh_endproc
