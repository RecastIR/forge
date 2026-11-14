.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    movq %rdx, %rax
    testl %ecx, %ecx
    je exit
header:
    adcl %ecx, %eax
    decl %ecx
    je early
    js negative
    jmp header
negative:
    notq %rax
    jmp header
early:
    ret
exit:
    ret
    .seh_endproc
