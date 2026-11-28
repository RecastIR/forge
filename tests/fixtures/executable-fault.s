.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    movq pointer(%rip), %rcx
    movl (%rcx), %eax
    ret
.seh_endproc

.data
# Import the pointer from writable memory so the actual guest load is checked.
pointer:
    .quad 1
