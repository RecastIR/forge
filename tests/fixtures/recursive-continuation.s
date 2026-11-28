.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    testl %ecx, %ecx
    je read_slot
    xorl %ecx, %ecx
    callq entry
    addq $40, %rsp
    retq
read_slot:
    movq 40(%rsp), %r10
    movzbl (%r10), %eax
    addq $40, %rsp
    retq
.seh_endproc

# Selecting this unused writable section would exceed the image mapping budget.
.bss
.space 0x10001000
