.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    movl (%rcx), %eax
    ret
.seh_endproc

.section .ranges,"dr"
ranges:
.rept fields
    .long 0x78563412
    .long ranges           # HIGHLOW is protected on AMD64.
    .quad ranges           # DIR64 is a readable and rebasable pointer.
.endr
