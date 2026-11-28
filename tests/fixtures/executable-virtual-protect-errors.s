# Emit (BOOL, old DWORD, last error) after each request. All target VAs and
# stack outputs go through the same service calls as an ordinary PE entry.
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $80, %rsp
    .seh_stackalloc 80
    .seh_endprologue
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rbx
.macro probe number
    leaq pages(%rip), %rcx
    movl $1, %edx
    movl $4, %r8d
    leaq 60(%rsp), %r9
    callq *__imp_VirtualProtect(%rip)
    testl %eax, %eax
    je .Lbad
    movl $19, pages(%rip)
    movl $73, %ecx
    callq *__imp_SetLastError(%rip)
    movl $0x11223344, 52(%rsp)
    leaq pages(%rip), %rcx
    movl $1, %edx
    movl $2, %r8d
    leaq 52(%rsp), %r9
    .if \number == 2
        xorl %edx, %edx
    .elseif \number == 3
        leaq pages+1(%rip), %rcx
        xorl %edx, %edx
    .elseif \number == 4
        xorl %ecx, %ecx
    .elseif \number == 6
        movq $-2, %rcx
        movl $4, %edx
    .elseif \number == 7
        movl $3, %r8d
    .elseif \number == 10
        xorl %r9d, %r9d
    .elseif \number == 11
        movl $1, %r9d
    .elseif \number == 12
        leaq immutable(%rip), %r9
    .elseif \number == 44
        xorl %edx, %edx
        leaq pages+4096(%rip), %r9
    .elseif \number == 13
        movl $0, pages+8(%rip)
        leaq pages+8(%rip), %r9
    .endif
    callq *__imp_VirtualProtect(%rip)
    movl %eax, 48(%rsp)
    .if \number == 13
        movl pages+8(%rip), %eax
        movl %eax, 52(%rsp)
    .elseif \number == 44
        movl pages+4096(%rip), %eax
        movl %eax, 52(%rsp)
    .endif
    callq *__imp_GetLastError(%rip)
    movl %eax, 56(%rsp)
    .if \number == 44
        # A stack output lets us observe the first probe's effect on the neighboring page.
        leaq pages+4096(%rip), %rcx
        movl $1, %edx
        movl $2, %r8d
        leaq 60(%rsp), %r9
        callq *__imp_VirtualProtect(%rip)
        testl %eax, %eax
        je .Lbad
    .endif
    movq %rbx, %rcx
    leaq 48(%rsp), %rdx
    .if \number == 44
        movl $16, %r8d
    .else
        movl $12, %r8d
    .endif
    leaq 64(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    testl %eax, %eax
    je .Lbad
.endm
    probe 2
    probe 3
    probe 4
    probe 6
    probe 7
    probe 10
    probe 11
    probe 12
    probe 13
    probe 44
    movl $42, %eax
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    addq $80, %rsp
    popq %rbx
    retq
.seh_endproc

.section .rdata,"dr"
immutable:
    .long 0x11223344
.data
.p2align 12
pages:
    .space 8192
