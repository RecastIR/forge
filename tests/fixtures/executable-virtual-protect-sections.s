.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    leaq first+4095(%rip), %rcx
.ifdef split_output
    movl $1, %edx
    leaq first+4094(%rip), %r9
.else
.ifdef dynamic_count
    movq length(%rip), %rdx
.else
    movl $2, %edx
.endif
    leaq 32(%rsp), %r9
.endif
    movl $4, %r8d
    callq *__imp_VirtualProtect(%rip)
    cmpl $1, %eax
    jne .Lbad
.ifdef split_output
    # The low half of the DWORD is in the first section on both backends.
    cmpl $0, first+4092(%rip)
    je .Lbad
.endif
    movl $42, %eax
.Lbad:
    addq $40, %rsp
    retq
.seh_endproc

.ifdef dynamic_count
.data
length: .quad 2
.endif
.section .vpa,"dw"
first: .space 4096
# No instruction references this section. Only the API range selects its backing.
.section .vpb,"dw"
.space 4096
