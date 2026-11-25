.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
.ifdef fatal_type
.ifndef caller_argument
    movabsq $0x5a5a000000000002, %rcx
    callq __set_app_type
    movl $fatal_type, %ecx
.endif
    callq *__imp___set_app_type(%rip)
    movl $8, %ecx
    callq _amsg_exit
.else
    movl $93, %ebx
    movq $79, 40(%rsp)
    leaq first(%rip), %rcx
    leaq last(%rip), %rdx
    callq _initterm
    cmpl $93, %ebx
    jne failed
    movq 40(%rsp), %rax
    cmpq $79, %rax
    jne failed
    movl __mingw_app_type(%rip), %eax
    cmpl $97, %eax
    jne failed
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq observations(%rip), %rdx
    movl $48, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    testl %eax, %eax
    je failed
    movl 40(%rsp), %eax
    cmpl $48, %eax
    jne failed
.endif
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc

.ifndef fatal_type
# Snapshot both error cells before making another CRT call. A nonzero upper half
# in RCX checks that only the low signed DWORD reaches the adapter.
.macro observe value, slot, callee
    movl $(100 + \slot), (%rbx)
    movl $(700 + \slot), %ecx
    callq *__imp_SetLastError(%rip)
    movabsq $\value, %rcx
    callq \callee
    movl (%rbx), %edx
    movl %edx, observations+4+\slot(%rip)
    callq *__imp_GetLastError(%rip)
    movl %eax, observations+\slot(%rip)
.endm

.seh_proc initialize
initialize:
    pushq %rbx
    .seh_pushreg %rbx
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    callq *__imp__errno(%rip)
    movq %rax, %rbx
    observe 0x5a5a000000000001, 0, __set_app_type
    observe 0x5a5a000000000002, 8, *__imp___set_app_type(%rip)
    observe 0x5a5a000000000000, 16, __set_app_type
    observe 0x5a5a0000fffffff9, 24, *__imp___set_app_type(%rip)
    observe 0x5a5a000080000000, 32, __set_app_type
    observe 0x5a5a000000000001, 40, *__imp___set_app_type(%rip)
    addq $32, %rsp
    popq %rbx
    retq
.seh_endproc
.section .CRT,"dw"
.p2align 3
first: .quad initialize
last: .quad 0
.data
__mingw_app_type: .long 97
observations: .space 48
.endif
