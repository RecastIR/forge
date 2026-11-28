.text
.globl entry
.seh_proc entry
entry:
    subq $136, %rsp
    .seh_stackalloc 136
    .seh_endprologue
.ifdef conditional_title
    movl $-11, %ecx
    callq *__imp_GetStdHandle(%rip)
    testq %rax, %rax
    movl $41, %eax
    jz .Lreturn
.endif

# The capture parent supplies three real handles. The Forge launcher leaves the flag clear.
# Return separate observations for these launch modes and for older Wine's cached handles.
.macro check_handle selector, slot
    movl $\selector, %ecx
    callq *__imp_GetStdHandle(%rip)
    testq %rax, %rax
    jnz .Lcompare\@
    # Wine 8 caches INVALID_HANDLE_VALUE for an absent process handle.
    movl 92(%rsp), %edx
    andl $256, %edx
    jnz .Lcompare\@
    movq $-1, %rax
.Lcompare\@:
    movq \slot(%rsp), %rdx
    cmpq %rdx, %rax
    jne .Lfailure
.endm

.macro probe variant
.ifdef measured_fields
    movl $0x5a5a5a5a, 36(%rsp)
    movl $0x5a5a5a5a, 100(%rsp)
.endif
    movq $17, 112(%rsp)
    movq $34, 120(%rsp)
    movq $51, 128(%rsp)
    movl $91, %ecx
    callq *__imp_SetLastError(%rip)
.ifdef fault
    # The final output byte overlaps the protected outer return address.
    leaq 33(%rsp), %rcx
.else
    leaq 32(%rsp), %rcx
.endif
    callq *__imp_GetStartupInfo\variant(%rip)
    callq *__imp_GetLastError(%rip)
    cmpl $91, %eax
    jne .Lfailure
    cmpl $104, 32(%rsp)
    jne .Lfailure
    cmpq $0, 40(%rsp)
.ifdef measured_fields
    je .Lwine_fields\@
    movl 36(%rsp), %edx
    cmpl $0x5a5a5a5a, %edx
    jne .Lfailure
    movl 100(%rsp), %edx
    cmpl $0x5a5a5a5a, %edx
    jne .Lfailure
    jmp .Lhandles\@
.Lwine_fields\@:
    cmpl $0, 36(%rsp)
    jne .Lfailure
    cmpl $0, 100(%rsp)
    jne .Lfailure
.Lhandles\@:
    cmpq $0, 104(%rsp)
    jne .Lfailure
.else
    # Original Task 13.3H probe retained byte-for-byte for reference comparison.
    jne .Lfailure
.endif
    movl 92(%rsp), %eax
    andl $256, %eax
    jnz .Lcurrent\@
.ifc \variant,A
    cmpq $-1, 112(%rsp)
    jne .Lcurrent\@
    cmpq $-1, 120(%rsp)
    jne .Lcurrent\@
    cmpq $-1, 128(%rsp)
    jne .Lcurrent\@
.else
    cmpq $17, 112(%rsp)
    jne .Lcurrent\@
    cmpq $34, 120(%rsp)
    jne .Lcurrent\@
    cmpq $51, 128(%rsp)
    jne .Lcurrent\@
.endif
    movl $42, %eax
    jmp .Ldone\@
.Lcurrent\@:
    check_handle -10, 112
    check_handle -11, 120
    check_handle -12, 128
    movl 92(%rsp), %edx
    andl $256, %edx
    movl $43, %eax
    jnz .Ldone\@
    movl $44, %eax
.Ldone\@:
.endm

.ifdef probe_a
    probe A
.endif
.ifdef probe_w
.ifdef probe_a
    movl %eax, first_result(%rip)
.endif
    probe W
.ifdef probe_a
    movl first_result(%rip), %edx
    cmpl %edx, %eax
    jne .Lfailure
.endif
.endif
    jmp .Lreturn
.Lfailure:
    movl $1, %eax
.Lreturn:
    addq $136, %rsp
    retq
.seh_endproc
.ifdef probe_a
.ifdef probe_w
.data
.p2align 2
first_result: .long 0
.endif
.endif
