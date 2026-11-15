.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq Named
    addq $40, %rsp
    retq
    .seh_endproc
