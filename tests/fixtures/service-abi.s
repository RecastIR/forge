.text
.globl entry
entry:
    ret

.macro begin name, frame=56
.globl \name
.seh_proc \name
\name:
    subq $\frame, %rsp
    .seh_stackalloc \frame
    .seh_endprologue
.endm

.macro finish frame=56
    addq $\frame, %rsp
    ret
.seh_endproc
.endm

begin pair
    movabsq $0x11111111fffffff9, %rcx
    movabsq $0x22222222fffffffe, %rdx
    call *__imp_Pair(%rip)
finish

begin triple
    movabsq $0x6000000000000000, %rcx
    movq $-9, %rdx
    movq $7, %r8
    call *__imp_Triple(%rip)
finish

begin four
    movabsq $0x12345678fffffffd, %rcx
    movq $-2, %rdx
    movq $-5, %r8
    movabsq $0xfedcba9876543210, %r9
    call *__imp_Four(%rip)
finish

begin echo_bits
    movabsq $0xfedcba9876543210, %rcx
    call *__imp_Address(%rip)
    movq %rax, %rcx
    call *__imp_Handle(%rip)
finish

begin six
    # Shadow space deliberately contains different values from the argument registers.
    movq $1, 0(%rsp)
    movq $2, 8(%rsp)
    movq $3, 16(%rsp)
    movq $4, 24(%rsp)
    movq $-1, %r8
    movq $13, %r9
    movl $-17, 32(%rsp)
    testq %rcx, %rcx
    jz .Lsix_call
    movabsq $0x7000000000000013, %rax
    movq %rax, 40(%rsp)
.Lsix_call:
    call *__imp_Six(%rip)
finish

begin bad_stack, 40
    # Argument six aliases the outer synthetic return address.
    movq $2, %r8
    movq $3, %r9
    movl $4, 32(%rsp)
    call *__imp_Six(%rip)
finish 40

begin bad_sig
    call *__imp_Bad(%rip)
finish

begin void_result
    call *__imp_SetLastError(%rip)
finish

begin write_nested
    call write_stack_pointer
finish

begin write_stack_pointer, 104
    # Stack argument five holds a pointer relative to this nested activation.
    leaq 56(%rsp), %rax
    movq %rax, 32(%rsp)
    movq $7, 56(%rsp)
    movq $0, 64(%rsp)
    movq $0, 72(%rsp)
    movq $0, 80(%rsp)
    leaq 48(%rsp), %r9
    leaq input_bytes(%rip), %rdx
    movabsq $0xfedcba9876543210, %rcx
    movl $3, %r8d
    call *__imp_WriteProbe(%rip)
    movl 56(%rsp), %eax
finish 104

begin unmapped
    leaq -8192(%rsp), %rdx
    movq $0, 32(%rsp)
    leaq 48(%rsp), %r9
    movl $1, %r8d
    call *__imp_WriteProbe(%rip)
finish

# Mode 0 uses a null fifth argument. Mode 1 lends a complete in/out record.
# Other modes exercise failures and a null output.
.globl write_call
.seh_proc write_call
write_call:
    pushq %rbx
    .seh_pushreg %rbx
    subq $112, %rsp
    .seh_stackalloc 112
    .seh_endprologue
    movq %rcx, %rbx
    movl $0xdeadbeef, %ecx
    call *__imp_SetLastError(%rip)
    movabsq $0xfedcba9876543210, %rcx
    leaq input_bytes(%rip), %rdx
    movl $3, %r8d
    leaq 48(%rsp), %r9
    movq $0, 32(%rsp)
    cmpq $1, %rbx
    jne .Linput
    leaq 56(%rsp), %rax
    movq %rax, 32(%rsp)
    movq $11, 56(%rsp)
    movq $0, 64(%rsp)
    movq $0, 72(%rsp)
    movq $0, 80(%rsp)
.Linput:
    cmpq $2, %rbx
    jne .Loutput
    movl $4, %r8d
.Loutput:
    cmpq $3, %rbx
    jne .Loptional
    leaq 120(%rsp), %r9
.Loptional:
    cmpq $5, %rbx
    jne .Lrequired
    xorq %r9, %r9
.Lrequired:
    cmpq $6, %rbx
    jne .Lwrite
    xorq %rdx, %rdx
.Lwrite:
    call *__imp_WriteProbe(%rip)
    cmpq $5, %rbx
    je .Lsave
    movl 48(%rsp), %ecx
    addq %rcx, %rax
    cmpq $1, %rbx
    jne .Lsave
    movl 56(%rsp), %ecx
    addq %rcx, %rax
.Lsave:
    movq %rax, 88(%rsp)
    call *__imp_GetLastError(%rip)
    cmpl $0xdeadbeef, %eax
    jne .Lfailed
    movq 88(%rsp), %rax
    jmp .Ldone
.Lfailed:
    movq $-1, %rax
.Ldone:
    addq $112, %rsp
    popq %rbx
    ret
.seh_endproc

.macro spill_test name, output
begin \name, 72
    leaq message(%rip), %rax
    movq %rax, 56(%rsp)
    leaq \output(%rsp), %r9
    movq %rax, %rdx
    movl $3, %r8d
    movq $0, 32(%rsp)
    call *__imp_WriteProbe(%rip)
    movq 56(%rsp), %rcx
    call *__imp_lstrlenA(%rip)
finish 72
.endm
spill_test stale_spill, 56
spill_test disjoint_spill, 48

begin image_output
    leaq input_bytes(%rip), %rdx
    movl $3, %r8d
    leaq image_count(%rip), %r9
    movq $0, 32(%rsp)
    call *__imp_WriteProbe(%rip)
    movl image_count(%rip), %eax
finish

begin readonly_output
    leaq input_bytes(%rip), %rdx
    movl $3, %r8d
    movq %rdx, %r9
    movq $0, 32(%rsp)
    call *__imp_WriteProbe(%rip)
finish

.data
image_count:
    .long -1
.section .rdata,"dr"
message:
    .asciz "saved"
.section .probe,"dr"
input_bytes:
    .ascii "ABC"
