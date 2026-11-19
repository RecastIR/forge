# The pointer in the caller's local survives an empty range and an all-NULL range.
.text
.globl entry
.seh_proc entry
entry:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    leaq message(%rip), %rax
    movq %rax, 40(%rsp)
    movq first_address(%rip), %rcx
    leaq first(%rip), %rdx
    callq _initterm
    movq 40(%rsp), %rcx
    callq *__imp_strlen(%rip)
    cmpl $2, %eax
    jne done
    leaq first(%rip), %rcx
    leaq second(%rip), %rdx
    callq _initterm
    movq 40(%rsp), %rcx
    callq *__imp_strlen(%rip)
done:
    addq $56, %rsp
    retq
.seh_endproc

callback:
    retq

.section .CRT,"dw"
.p2align 3
first: .quad 0
second: .quad callback
table_end: .quad 0

.section .rdata,"dr"
message: .asciz "hi"

# At base 0x400000 the upper half of this DIR64 is zero. The test reduces the
# section's raw size to 512, so those bytes come from the virtual zero tail.
.section .refs,"dr"
.zero 508
first_address: .quad first
