.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $41, %ecx
    call *__imp_SetLastError(%rip)
    leaq continued(%rip), %rdx
    movl $7, %r10d
    call source
continued:
    jne failed
    cmpl $42, %eax
    jne failed
    cmpl $1, visits(%rip)
    jne failed
    call *__imp_GetLastError(%rip)
    cmpl $41, %eax
    jne failed
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $40, %rsp
    retq
.seh_endproc

# The once-only path mirrors __main. Force the five-byte near encoding.
.seh_proc source
source:
    .seh_endprologue
    cmpl $0, visits(%rip)
    jne already
    movl $1, visits(%rip)
    .byte 0xe9
    .long save - . - 4
already:
    movl $1, %eax
    retq
.seh_endproc

.seh_proc save
save:
    pushq %rbx
    .seh_pushreg %rbx
    .seh_endprologue
    movl $35, %ebx
    cmpl $7, %r10d
    jmp finish
.seh_endproc

.seh_proc finish
finish:
    .seh_endprologue
    jne bad
    movq 8(%rsp), %rax
    cmpq %rdx, %rax
    jne bad
    # Make an ordinary nested call with the original frame still live.
    subq $32, %rsp
    call compute
    leaq 32(%rsp), %rsp
    cmpl $42, %eax
    popq %rbx
    retq
bad:
    movl $2, %eax
    popq %rbx
    retq
.seh_endproc

.seh_proc compute
compute:
    .seh_endprologue
    leal (%rbx,%r10), %eax
    retq
.seh_endproc

# Each export below isolates a checked outcome in the managed-process harness.
.globl bad_register, bad_stack, terminal, pivot
.seh_proc bad_register
bad_register:
    .seh_endprologue
    jmp clobber
.seh_endproc
.seh_proc clobber
clobber:
    .seh_endprologue
    movl $3, %ebx
    movl $42, %eax
    retq
.seh_endproc

.seh_proc bad_stack
bad_stack:
    .seh_endprologue
    jmp unbalanced
.seh_endproc
.seh_proc unbalanced
unbalanced:
    .seh_endprologue
    subq $8, %rsp
    movl $42, %eax
    retq
.seh_endproc

.seh_proc terminal
terminal:
    .seh_endprologue
    subq $40, %rsp
    movl $57, %ecx
    call terminate_transfer
    int3
.seh_endproc
.seh_proc terminate_transfer
terminate_transfer:
    .seh_endprologue
    jmp terminate
.seh_endproc
.seh_proc terminate
terminate:
    .seh_endprologue
    subq $40, %rsp
    call *__imp_ExitProcess(%rip)
    int3
.seh_endproc

.globl bad_memory
.seh_proc bad_memory
bad_memory:
    .seh_endprologue
    jmp load_word
.seh_endproc
.seh_proc load_word
load_word:
    .seh_endprologue
    movq (%rcx), %rax
    retq
.seh_endproc

# This pivot would authorize a nested call over the original return slot
# if the tail target used the live RSP as its frame ceiling.
.seh_proc pivot
pivot:
    .seh_endprologue
    addq $48, %rsp
    jmp pivot_call
.seh_endproc
.seh_proc pivot_call
pivot_call:
    .seh_endprologue
    subq $40, %rsp
    call simple
    movl $42, %eax
    retq
.seh_endproc
.seh_proc simple
simple:
    .seh_endprologue
    movl $42, %eax
    retq
.seh_endproc

.data
visits: .long 0
.section .rdata,"dr"
.quad entry
