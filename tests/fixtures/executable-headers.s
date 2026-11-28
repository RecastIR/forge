.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    leaq __ImageBase(%rip), %rcx
    call *__imp_lstrlenA(%rip)
    addl __ImageBase(%rip), %eax

    # Load a relocated VA from writable storage and walk the actual header offsets.
    movq header_pointer(%rip), %rdx
    movl 0x3c(%rdx), %r8d
    addq %rdx, %r8
    addl (%r8), %eax
    xorl 48(%r8), %eax
    movzwl 20(%r8), %ecx
    addl 24(%r8,%rcx), %eax
    addq $40, %rsp
    ret
.seh_endproc

.data
header_pointer:
    .quad __ImageBase
