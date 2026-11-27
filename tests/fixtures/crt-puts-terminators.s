.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movb $65, pending(%rip)
    leaq pending(%rip), %rcx
    callq puts
    testl %eax, %eax
    jne done
    leaq pointer+2(%rip), %rcx
    callq puts
done:
    addq $40, %rsp
    retq
.seh_endproc

.section .sra,"dw"
.space 4095
pending: .byte 0
.section .srb,"dr"
.asciz "B"
pointer: .quad entry
