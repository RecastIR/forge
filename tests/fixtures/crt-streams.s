.ifndef bad_source
bad_source = 0
.endif
.ifndef write_field
write_field = 0
.endif
# MinGW's legacy stream selection is __iob_func() + index * 48.
.macro output slot, data, width, count
    leaq \data(%rip), %rcx
    movl $\width, %edx
    movl $\count, %r8d
    leaq \slot(%rbx), %r9
    callq *__imp_fwrite(%rip)
.endm

.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
    callq __iob_func
    movq %rax, %rbx
    callq *__imp___iob_func(%rip)
    cmpq %rax, %rbx
    jne .Lfailed
    cmpl $1, 76(%rbx)
    jne .Lfailed
    cmpl $2, 124(%rbx)
    jne .Lfailed

    # Neither empty transfer may touch the null source.
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $7, %r8d
    leaq 96(%rbx), %r9
    callq fwrite
    testq %rax, %rax
    jne .Lfailed
    xorl %ecx, %ecx
    movl $3, %edx
    xorl %r8d, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
    testq %rax, %rax
    jne .Lfailed

.ifdef invalid_stream
    output 49, head, 1, 1
.elseif bad_source
    leaq 96(%rsp), %rcx
    movl $1, %edx
    movl $2, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
.elseif write_field
    movl $1, 76(%rbx)
.else
    leaq callback(%rip), %rcx
    callq _onexit
    output 48, head, 2, 2
    cmpq $2, %rax
    jne .Lfailed
    output 96, tail, 1, 3
    cmpq $3, %rax
    jne .Lfailed
    callq _cexit
    callq _cexit
    movl $-11, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq marker(%rip), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
    output 48, tail, 1, 3
    cmpq $3, %rax
    jne .Lfailed
    movl $42, %eax
.ifdef crt_exit
    movl %eax, %ecx
    callq exit
.endif
    jmp .Lend
.endif
.Lfailed:
    movl $1, %eax
.Lend:
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc

.seh_proc callback
callback:
    pushq %rbx
    .seh_pushreg %rbx
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    callq __iob_func
    movq %rax, %rbx
    output 96, marker, 1, 1
    addq $32, %rsp
    popq %rbx
    retq
.seh_endproc
.section .rdata,"dr"
head: .byte 65, 0, 10, 66
tail: .byte 13, 10, 90
marker: .byte 35
