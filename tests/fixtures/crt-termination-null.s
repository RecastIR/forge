.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $91, %ecx
    callq *__imp_SetLastError(%rip)
    movq $0, %rcx
    callq _onexit
    testq %rax, %rax
    jne failed
    callq helper
    testq %rax, %rax
    jne failed
    callq *__imp_GetLastError(%rip)
    jmp done
failed:
    movl $1, %eax
done:
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc helper
helper:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $0, %ecx
    callq wrapper
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc wrapper
wrapper:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq *__imp__onexit(%rip)
    addq $40, %rsp
    retq
.seh_endproc
