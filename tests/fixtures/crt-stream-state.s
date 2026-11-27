# Binary snapshots after writes to separate FILEs, and again after returning cleanup.
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rsi
    .seh_pushreg %rsi
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    callq __iob_func
    movq %rax, %rbx
    callq _errno
    movq %rax, %rsi

.macro snapshot offset, slot
    movq \offset(%rbx), %rax
    subq \offset+16(%rbx), %rax
    movq %rax, records+\slot(%rip)
    movl \offset+8(%rbx), %eax
    movl %eax, records+\slot+8(%rip)
    movl \offset+24(%rbx), %eax
    movl %eax, records+\slot+12(%rip)
    movl \offset+28(%rbx), %eax
    movl %eax, records+\slot+16(%rip)
    movl \offset+36(%rbx), %eax
    movl %eax, records+\slot+20(%rip)
.endm
    snapshot 0, 0
    snapshot 48, 24
    snapshot 96, 48
    movl $37, (%rsi)
    movl $91, %ecx
    callq SetLastError
    leaq source(%rip), %rcx
    movl $2, %edx
    movl $2, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
    movq %rax, records+72(%rip)
    movl (%rsi), %eax
    movl %eax, records+80(%rip)
    callq GetLastError
    movl %eax, records+84(%rip)
    snapshot 48, 88
    snapshot 96, 112
    callq _cexit
    snapshot 48, 136
    movl $-12, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq records(%rip), %rdx
    movl $160, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
    movl $42, %eax
    addq $56, %rsp
    popq %rsi
    popq %rbx
    retq
.seh_endproc
.section .rdata,"dr"
source: .byte 65, 0, 10, 66
.data
records: .space 160
