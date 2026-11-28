# Each completed indirect call emits its id, last error, full SIZE_T, image base,
# query VA, supplied length, and the 48 output bytes bracketed by two sentinels.
.macro query id, target, length=48, alias=0
    movl $0x51a70000+\id, 48(%rsp)
    movl $73, %ecx
    callq *__imp_SetLastError(%rip)
    movabsq $0xa5a5a5a5a5a5a5a5, %rax
    .irp offset,88,96,104,112,120,128,136,144
        movq %rax, \offset(%rsp)
    .endr
    leaq \target(%rip), %rcx
    movq %rcx, 72(%rsp)
    movabsq $\length, %r8
    movq %r8, 80(%rsp)
    .if \alias
        leaq second+64(%rip), %rdx
    .else
        leaq 96(%rsp), %rdx
    .endif
    movq %rdx, 152(%rsp)
    callq *__imp_VirtualQuery(%rip)
    movq %rax, 56(%rsp)
    callq *__imp_GetLastError(%rip)
    movl %eax, 52(%rsp)
    .if \alias
        .irp offset,0,8,16,24,32,40,48,56
            movq second+56+\offset(%rip), %rax
            movq %rax, 88+\offset(%rsp)
        .endr
    .endif
    movq %rbx, %rcx
    leaq 48(%rsp), %rdx
    movl $112, %r8d
    leaq 160(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    testl %eax, %eax
    je .Lbad
    cmpl $112, 160(%rsp)
    jne .Lbad
.endm

.macro protect value
    leaq first+4096(%rip), %rcx
    movl $1, %edx
    movl $\value, %r8d
    leaq 160(%rsp), %r9
    callq *__imp_VirtualProtect(%rip)
    testl %eax, %eax
    je .Lbad
.endm

.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $176, %rsp
    .seh_stackalloc 176
    .seh_endprologue
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rbx
    leaq __ImageBase(%rip), %rax
    movq %rax, 64(%rsp)
    movl $0x43212345, 164(%rsp)
.ifdef transitions
    query 31,first
    protect 2
    query 32,first
    query 33,first+4096
    query 34,first+8192
    movl $39, first+8192(%rip)
    query 35,first+8192
    protect 4
    query 36,first
    movl $45, first+4096(%rip)
    query 37,first+4096
.else
    query 1,__ImageBase
    query 2,entry
    query 3,immutable
    query 4,zeros
    query 5,first
    query 6,first+4103
    query 7,first+12287
    query 8,second
    query 9,first,0
    query 10,first,1
    query 11,first,32
    query 12,first,47
    query 13,first,96
    query 14,first,0x100000000
    query 15,first,0x100000030
    query 16,second,48,1
    query 17,second
    movl $19, first+4096(%rip)
    query 18,first
    query 19,first+4096
    query 20,first+8192
.endif
    cmpl $0x43212345, 164(%rsp)
    jne .Lbad
    movl $42, %eax
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    addq $176, %rsp
    popq %rbx
    retq
.seh_endproc

.section .rdata,"dr"
immutable: .quad 73
.bss
.p2align 12
zeros: .space 4096
.section .vqa,"dw"
first: .fill 12288,1,0xa5
.section .vqb,"dw"
second: .fill 4096,1,0xa5
