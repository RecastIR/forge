.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $42, %ecx
    callq SetLastError
    callq GetLastError
    movl %eax, %ecx
    callq ExitProcess
    ud2
.seh_endproc
