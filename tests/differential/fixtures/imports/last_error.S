.text
.globl last_error
.seh_proc last_error
last_error:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    testq %rdx, %rdx
    jne .Lread
    call last_error_set
.Lread:
    call *__imp_GetLastError(%rip)
    movl %eax, 32(%rsp)
    call *__imp_GetLastError(%rip)
    cmpl 32(%rsp), %eax
    je .Ldone
    movq $-1, %rax
.Ldone:
    addq $40, %rsp
    ret
.seh_endproc

.seh_proc last_error_set
last_error_set:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    call *__imp_SetLastError(%rip)
    addq $40, %rsp
    ret
.seh_endproc

.section .drectve
.ascii " -export:last_error"
