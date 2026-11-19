.text
# The PE entry is deliberately not the first function in the image.
calculate:
    leal 2(%rcx), %eax
    ret

.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $40, %ecx
    call calculate
    addq $40, %rsp
    ret
.seh_endproc
