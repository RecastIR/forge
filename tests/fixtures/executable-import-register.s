.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq __imp_Sleep(%rip), %r10
    xorl %ecx, %ecx
    callq *%r10

    movl $2, %ecx
    callq run_loop
    cmpl $41, %eax
    jne .Lfailed
    xorl %ecx, %ecx
    callq run_loop
    cmpl $9, %eax
    jne .Lfailed
    movl $42, %eax
    jmp .Ldone
.Lfailed:
    xorl %eax, %eax
.Ldone:
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc run_loop
run_loop:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %r12
    .seh_pushreg %r12
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl %ecx, %ebx
    movl $9, %ecx
    callq *__imp_SetLastError(%rip)
    movq __imp_SetLastError(%rip), %r12
    jmp .Lcheck
.Lbody:
    leal 40(%rbx), %ecx
    callq *%r12
    decl %ebx
.Lcheck:
    testl %ebx, %ebx
    jne .Lbody

    # The loaded identity must survive a nested guest stack save on both paths.
    callq save_and_restore
    testq %r12, %r12
    je .Lbad
    movq __imp_SetLastError(%rip), %r10
    cmpq %r10, %r12
    jne .Lbad
    movq __imp_Sleep(%rip), %r10
    cmpq %r10, %r12
    je .Lbad
    callq *__imp_GetLastError(%rip)
    jmp .Lrestore
.Lbad:
    xorl %eax, %eax
.Lrestore:
    addq $40, %rsp
    popq %r12
    popq %rbx
    retq
.seh_endproc

.seh_proc save_and_restore
save_and_restore:
    pushq %r12
    .seh_pushreg %r12
    .seh_endprologue
    xorl %r12d, %r12d
    popq %r12
    retq
.seh_endproc
