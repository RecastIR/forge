# The guest wrapper deliberately forwards RCX from two different public call sites.
.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
.ifdef crt_stream
    callq *__imp_fopen(%rip)
.endif
    callq _cexit
.ifdef changed_target
    leaq second(%rip), %rax
    movq %rax, evidence(%rip)
    movq evidence(%rip), %rax
.else
.ifdef unmapped_target
    movq $1, evidence(%rip)
    movq evidence(%rip), %rax
.else
.ifdef data_target
    leaq evidence(%rip), %rax
.else
    leaq first(%rip), %rax
.endif
.endif
.endif
    movq %rax, %rcx
    callq register_callback
    testl %eax, %eax
    jne failed
    leaq first(%rip), %rcx
    callq _onexit
    leaq first(%rip), %rcx
    cmpq %rcx, %rax
    jne failed
    leaq second(%rip), %rcx
    callq register_callback
    testl %eax, %eax
    jne failed
.ifdef normal_exit
    movl $0xcafe002a, %ecx
    callq *__imp_exit(%rip)
    movl $88, %ecx
    callq mark
.else
    callq *__imp__cexit(%rip)
    callq *__imp_GetLastError(%rip)
    cmpl $73, %eax
    jne failed
    movl $77, %ecx
    callq mark
    callq _cexit
.endif
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc register_callback
register_callback:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq *__imp__onexit(%rip)
    cmpq $1, %rax
    sbbl %eax, %eax
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc first
first:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $65, %ecx
    callq mark
    movl $73, %ecx
    callq *__imp_SetLastError(%rip)
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc second
second:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $66, %ecx
    callq mark
.ifdef add_during
    leaq late(%rip), %rcx
    callq _onexit
.endif
.ifdef recurse
    callq _cexit
.ifdef trace_recursive_return
    movl $68, %ecx
    callq mark
.endif
.endif
.ifdef recurse_forever
    leaq second(%rip), %rcx
    callq _onexit
    callq _cexit
.endif
.ifdef recursive_exit
    movl $67, %ecx
    callq exit
.endif
.ifdef terminal
    movl $57, %ecx
    callq *__imp_ExitProcess(%rip)
.endif
.ifdef fault
    movq invalid(%rip), %rcx
    movb (%rcx), %al
.endif
.ifdef stack_above
    leaq 80(%rsp), %rcx
    movq %rcx, invalid(%rip)
    movq invalid(%rip), %rax
    movb (%rax), %al
.endif
.ifdef corrupt_return
    movq $1, 40(%rsp)
.endif
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc late
late:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $67, %ecx
    callq mark
.ifdef nested_fault
    movq invalid(%rip), %rcx
    movb (%rcx), %al
.endif
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
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq 48(%rsp), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    addq $56, %rsp
    retq
.seh_endproc
.data
invalid: .quad 1

.ifdef needs_evidence
.p2align 3
evidence: .quad first
.endif
