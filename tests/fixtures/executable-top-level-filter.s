.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    # The CRT loads the guest function VA through an immutable DIR64 cell.
    movq filter_a_ref(%rip), %rcx
    callq *__imp_SetUnhandledExceptionFilter(%rip)
    testq %rax, %rax
    jne .Lfailed

.ifdef check_guest_fault
    # Only the native fault regression includes this checked load.
    movq unmapped_pointer(%rip), %rcx
    movl (%rcx), %eax
.endif

    movq filter_b_ref(%rip), %rcx
    callq *__imp_SetUnhandledExceptionFilter(%rip)
    movq %rax, previous_filter(%rip)
    leaq filter_a(%rip), %rdx
    cmpq %rdx, %rax
    jne .Lfailed

    # Restore the previous filter from guest storage, as an opaque guest VA.
    movq previous_filter(%rip), %rcx
    callq *__imp_SetUnhandledExceptionFilter(%rip)
    leaq filter_b(%rip), %rdx
    cmpq %rdx, %rax
    jne .Lfailed

    xorl %ecx, %ecx
    callq *__imp_SetUnhandledExceptionFilter(%rip)
    leaq filter_a(%rip), %rdx
    cmpq %rdx, %rax
    jne .Lfailed

    # A final install proves the clear and leaves state behind for isolation tests.
    movq filter_b_ref(%rip), %rcx
    callq *__imp_SetUnhandledExceptionFilter(%rip)
    testq %rax, %rax
    jne .Lfailed
    movl $42, %eax
    jmp .Ldone
.Lfailed:
    movl $1, %eax
.Ldone:
    addq $40, %rsp
    retq
.seh_endproc

# Any callback invocation is observable, even if its return value would be ignored.
.macro filter name, status
.seh_proc \name
\name:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $\status, %ecx
    callq *__imp_ExitProcess(%rip)
.seh_endproc
.endm
filter filter_a, 61
filter filter_b, 62

.section .rdata,"dr"
.p2align 3
filter_a_ref: .quad filter_a
filter_b_ref: .quad filter_b

.data
.p2align 3
previous_filter: .quad 0
.ifdef check_guest_fault
unmapped_pointer: .quad 1
.endif
