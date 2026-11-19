.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $42, %ecx
    call *__imp_SetLastError(%rip)
    call *__imp_GetLastError(%rip)
    addq $40, %rsp
    ret
.seh_endproc
