.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    .seh_handler __C_specific_handler, @except
protected_begin:
    movl $42, %eax
protected_end:
    ret
.seh_handlerdata
    .long 1
    .rva protected_begin, protected_end, filter, protected_end
.text
.seh_endproc

.seh_proc filter
filter:
    pushq %rbx
    .seh_pushreg %rbx
    .seh_endprologue
    movl $1, %eax
    popq %rbx
    ret
.seh_endproc
