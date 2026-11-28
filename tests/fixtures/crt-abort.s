# The normal control uses the same stream setup and registers the same handler.
# The written letters identify entry (R), the call (B), continuation (X) and handler (H).
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
    movl $82, %ecx
    callq mark
.if buffered
    leaq handler(%rip), %rcx
    callq _onexit
    testq %rax, %rax
    je failed
    callq __iob_func
    movq %rax, %rbx
    leaq output(%rip), %rcx
    movl $1, %edx
    movl $2, %r8d
    leaq 48(%rbx), %r9
    callq fwrite
    cmpq $2, %rax
    jne failed
    leaq 96(%rbx), %rcx
    leaq diagnostic(%rip), %rdx
    leaq 40(%rsp), %r8
    callq vfprintf
    cmpl $2, %eax
    jne failed
.endif
.if initializer
    leaq table(%rip), %rcx
    leaq table_end(%rip), %rdx
    callq _initterm
.elseif cleanup
    leaq handler(%rip), %rcx
    callq _onexit
    testq %rax, %rax
    je failed
    leaq fatal(%rip), %rcx
    callq _onexit
    testq %rax, %rax
    je failed
    movl $77, %ecx
    callq exit
.elseif control
    movl $66, %ecx
    callq mark
    movl $3, %ecx
    callq exit
.else
    callq fatal
.endif
    movl $88, %ecx
    callq mark
failed:
    movl $99, %eax
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc

.if !control
.seh_proc fatal
fatal:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $66, %ecx
    callq mark
    callq abort
    movl $88, %ecx
    callq mark
    addq $40, %rsp
    retq
.seh_endproc
.else
    .section .rdata,"dr"
    .quad __imp_abort
.endif

.text
.seh_proc handler
handler:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $72, %ecx
    callq mark
    xorl %eax, %eax
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc mark
mark:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    movl %ecx, 48(%rsp)
    movl $-11, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq 48(%rsp), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
    addq $56, %rsp
    retq
.seh_endproc

.if initializer
.section .CRT,"dw"
.p2align 3
table: .quad fatal, handler
table_end: .quad 0
.endif
.if buffered
.section .rdata,"dr"
output: .ascii "o\n"
diagnostic: .asciz "e\n"
.endif
