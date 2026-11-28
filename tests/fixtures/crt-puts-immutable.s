.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    leaq message(%rip), %rcx
    callq puts
    addq $40, %rsp
    retq
.seh_endproc

.section .sra,"dr"
message: .asciz "OK"
.space 4093
# Adjacent in the PE. Selecting any of this unrelated writable section would
# charge its entire virtual extent to the image mapping budget.
.section .srb,"bw"
.space 0x10001000
