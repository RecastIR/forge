.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
    movl $8, %ecx
    callq malloc
    testq %rax, %rax
    je failed
    movq %rax, %rbx
    movl $0x434241, (%rbx)
    leaq 1(%rbx), %rcx
    callq puts
    testl %eax, %eax
    jne failed
    movq %rbx, %rcx
    callq free

    movl $2, %ecx
    movl $4, %edx
    callq calloc
    testq %rax, %rax
    je failed
    movq %rax, %rbx
    movl $0x434241, (%rbx)
    addq $3, %rax
    movq %rax, 32(%rsp)
    movq 32(%rsp), %rcx
    subq $2, %rcx
    callq puts
    testl %eax, %eax
    jne failed
    movq %rbx, %rcx
    callq free
    xorl %eax, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc
