.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    movl $42, %eax
    ret
.seh_endproc
