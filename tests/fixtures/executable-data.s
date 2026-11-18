.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    addl $1, counter(%rip)
    addl $1, zero_fill(%rip)
    movl counter(%rip), %eax
    addl zero_fill(%rip), %eax
    ret
.seh_endproc

.data
counter:
    .long 40
.bss
    # Keep the tested value beyond the initialized section's file alignment.
    .space 4096
zero_fill:
    .space 4
