# Observe overflow, input-only FILE, and a direct write independently of handle success.
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
.macro seed
    movl $37, (%rsi)
    movl $91, %ecx
    callq SetLastError
.endm
.macro report offset, slot
    movq %rax, records+\slot(%rip)
    movl (%rsi), %eax
    movl %eax, records+\slot+8(%rip)
    callq GetLastError
    movl %eax, records+\slot+12(%rip)
    movl \offset+24(%rbx), %eax
    movl %eax, records+\slot+16(%rip)
    movl \offset+28(%rbx), %eax
    movl %eax, records+\slot+20(%rip)
.endm
    seed
    leaq data(%rip), %rcx
    movabsq $0x8000000000000000, %rdx
    movl $2, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
    report 48, 0

    seed
    leaq data(%rip), %rcx
    movl $2, %edx
    movl $3, %r8d
    movq %rbx, %r9
    callq fwrite
    report 0, 24

    seed
    leaq data(%rip), %rcx
    movl $2, %edx
    movl $4096, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
    report 48, 48
    movl $-12, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq records(%rip), %rdx
    movl $72, %r8d
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
data: .byte 65,0,10,13,10,90
.space 8186
.data
records: .space 72
