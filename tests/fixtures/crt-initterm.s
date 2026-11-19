# A conventional import thunk calls MSVCRT against the executable's writable .CRT.
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    subq $48, %rsp
    .seh_stackalloc 48
    .seh_endprologue
    movl $37, %ebx
    movq $41, 32(%rsp)
    leaq initializer_a(%rip), %rax
    movq replaced_slot(%rip), %rdx
    cmpq %rdx, %rax
    jne failed

    # No callbacks, one NULL, and one callback before the full table.
    leaq first(%rip), %rcx
    leaq first(%rip), %rdx
    callq _initterm
    leaq null_slot(%rip), %rcx
    leaq singleton(%rip), %rdx
    callq _initterm
    leaq singleton(%rip), %rcx
    leaq repeat_slot(%rip), %rdx
    callq _initterm
    movl state(%rip), %eax
    cmpl $2, %eax
    jne failed

    # The MinGW startup shape loads the two guest VAs from readonly DIR64 cells.
    movq first_address(%rip), %rcx
    movq end_address(%rip), %rdx
    callq _initterm
    movl state(%rip), %eax
    cmpl $21222, %eax
    jne failed
    cmpl $37, %ebx
    jne failed
    movq 32(%rsp), %rax
    cmpq $41, %rax
    jne failed
    callq *__imp_GetLastError(%rip)
    cmpl $73, %eax
    jne failed
    movq saved_allocation(%rip), %rcx
    movl (%rcx), %eax
    cmpl $42, %eax
    jne failed
    callq *__imp_free(%rip)
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $48, %rsp
    popq %rbx
    retq
.seh_endproc

.seh_proc initializer_a
initializer_a:
    pushq %rbx
    .seh_pushreg %rbx
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    leaq 40(%rsp), %rax
    andl $15, %eax
    cmpl $8, %eax
    jne bad_frame
    # Use the first and last home slots. The nested call owns a different home area.
    movq $1, 48(%rsp)
    movq $73, 72(%rsp)
    movl state(%rip), %ebx
    movl $10, %ecx
    imull %ecx, %ebx
    movl 48(%rsp), %eax
    addl %eax, %ebx
    movl %ebx, state(%rip)
    leaq initializer_b(%rip), %rax
    movq %rax, replaced_slot(%rip)
    movl $8, %ecx
    callq *__imp_malloc(%rip)
    testq %rax, %rax
    je bad_frame
    movl $20, (%rax)
    movq %rax, saved_allocation(%rip)
    movl 72(%rsp), %ecx
    callq *__imp_SetLastError(%rip)
    jmp a_done
bad_frame:
    movl $-1, state(%rip)
a_done:
    addq $32, %rsp
    popq %rbx
    retq
.seh_endproc

.seh_proc initializer_b
initializer_b:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq append_two
    callq fetch_continuation
after_fetch:
    leaq after_fetch(%rip), %rcx
    cmpq %rcx, %rax
    jne bad_continuation
    movq saved_allocation(%rip), %rdx
    movl (%rdx), %eax
    addl $11, %eax
    movl %eax, (%rdx)
    jmp b_done
bad_continuation:
    movl $-1, state(%rip)
b_done:
    addq $40, %rsp
    retq
.seh_endproc

# No unwind entry. Both a table slot and initializer_b's direct call name this leaf.
append_two:
    movl state(%rip), %eax
    movl $10, %ecx
    imull %ecx, %eax
    addl $2, %eax
    movl %eax, state(%rip)
    retq

# Guest-to-guest CALL still pushes the PE continuation when its caller is an initializer.
fetch_continuation:
    movq (%rsp), %rax
    retq

.section .rdata,"dr"
.p2align 3
first_address: .quad first
end_address: .quad table_end

.section .CRT,"dw"
.p2align 3
first: .quad initializer_a
null_slot: .quad 0
singleton: .quad append_two
repeat_slot: .quad initializer_b
replaced_slot: .quad initializer_a
table_end:
    # Keep the exclusive end inside a mapped section, like MinGW's __xc_z sentinel.
    .quad 0

.data
.p2align 2
state: .long 0
.p2align 3
saved_allocation: .quad 0
