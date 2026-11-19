# Isolate the OS command-line import and translated scalar loads from the CRT.
.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    call *__imp_GetCommandLineA(%rip)
    movq %rax, %rdx
    xorl %eax, %eax
.Lnext:
    movzbl (%rdx), %ecx
    testl %ecx, %ecx
    jz .Ldone
    movl %eax, %r8d
    shll $5, %eax
    addl %r8d, %eax
    addl %ecx, %eax
    incq %rdx
    jmp .Lnext
.Ldone:
    addq $40, %rsp
    retq
.seh_endproc
