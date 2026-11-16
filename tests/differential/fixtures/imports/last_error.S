.text
.globl last_error
.seh_proc last_error
last_error:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    cmpq $2, %rdx
    je .Lspill
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
    jmp .Ldone
.Lspill:
    call last_error_spill
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

.seh_proc last_error_spill
last_error_spill:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq 40(%rsp), %r8
    movq %r8, 32(%rsp)
    call *__imp_GetLastError(%rip)
    movq 32(%rsp), %r8
    movzbl (%r8), %eax
    addq $40, %rsp
    ret
.seh_endproc

.section .drectve
.ascii " -export:last_error"
