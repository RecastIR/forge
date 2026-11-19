# The generator selects one initializer body per PE. A later initializer and
# the caller both emit M, making unexpected continuation externally observable.
.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
.ifdef nonvolatile_arg
    movq %rbx, 32(%rsp)
    movl $23, %ebx
.endif
    leaq first(%rip), %rcx
    leaq table_end(%rip), %rdx
    callq _initterm
.ifdef other_initializer
    leaq other_table(%rip), %rcx
    leaq other_end(%rip), %rdx
    callq _initterm
.endif
    callq marker
    movl $42, %eax
.ifdef nonvolatile_arg
    movq 32(%rsp), %rbx
.endif
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc initializer
initializer:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
.ifdef terminal
    movl $57, %ecx
    callq *__imp_ExitProcess(%rip)
.endif
.ifdef guest_fault
    movq bad_address(%rip), %rcx
    movb (%rcx), %al
.endif
.ifdef unknown_target
    leaq marker+1(%rip), %rax
    movq %rax, later(%rip)
.endif
.ifdef other_function
    # This is a translated entry, outside the target set of the active call.
    leaq entry(%rip), %rax
    movq %rax, later(%rip)
.endif
.ifdef other_initializer
    # A second call admits this initializer, but the active call has no such target.
    leaq other_leaf(%rip), %rax
    movq %rax, later(%rip)
.endif
.ifdef data_target
    leaq later(%rip), %rax
    movq %rax, later(%rip)
.endif
.ifdef clobber
    movl $23, %ebx
.endif
.ifdef read_return
    movq 40(%rsp), %rax
.endif
.ifdef before_return
    # Uninitialized guest byte precedes the synthetic return. Report the first failure.
    movzwl 39(%rsp), %eax
.endif
.ifdef write_return
    movq $1, 40(%rsp)
.endif
.ifdef service_return
    leaq 40(%rsp), %rcx
    callq *__imp_lstrlenA(%rip)
.endif
.ifdef register_arg
    movq %rcx, %rax
.endif
.ifdef nonvolatile_arg
    movq %rbx, %rcx
    callq *__imp_SetLastError(%rip)
.endif
.ifdef stack_arg
    movq 80(%rsp), %rax
.endif
.ifdef stack_alias
    leaq 72(%rsp), %rcx
    movq %rcx, saved_alias(%rip)
    callq read_alias
.endif
.ifdef service_alias
    # Both branch alternatives are proven stack addresses. Only one lies in the home area.
    movl service_offset(%rip), %eax
    testl %eax, %eax
    je home_alias
    leaq 88(%rsp), %rcx
    jmp use_alias
home_alias:
    leaq 72(%rsp), %rcx
use_alias:
    callq *__imp_lstrlenA(%rip)
.endif
.ifdef nested_table
    leaq later(%rip), %rcx
    leaq table_end(%rip), %rdx
    callq _initterm
.endif
.ifdef stack_exhaustion
    leaq first(%rip), %rcx
    leaq later(%rip), %rdx
    callq _initterm
.endif
.ifdef bad_rsp
    addq $8, %rsp
.endif
    addq $40, %rsp
    retq
.seh_endproc

.ifdef other_initializer
other_leaf:
    retq
.endif

.ifdef stack_alias
.seh_proc read_alias
read_alias:
    .seh_endprologue
    # Reload the last home slot address and offset from writable guest memory.
    movq saved_alias(%rip), %rcx
    movq delta(%rip), %rdx
    movq (%rcx,%rdx), %rax
    retq
.seh_endproc
.endif

.seh_proc marker
marker:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq letter(%rip), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq *__imp_WriteFile(%rip)
    addq $56, %rsp
    retq
.seh_endproc

.section .CRT,"dw"
.p2align 3
first: .quad initializer
later: .quad marker
table_end: .quad 0
.ifdef other_initializer
other_table: .quad other_leaf
other_end: .quad 0
.endif

.section .rdata,"dr"
letter: .ascii "M"
.ifdef guest_fault
.data
.p2align 3
bad_address: .quad 1
.endif
.ifdef stack_alias
.data
.p2align 3
delta: .quad 16
saved_alias: .quad 0
.endif
.ifdef service_alias
.data
.p2align 2
service_offset: .long 16
.endif
