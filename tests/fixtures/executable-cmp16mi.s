.text
.globl entry
.seh_proc entry
entry:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue

    # Each output word contains SETO in AL and the LAHF flags in AH.
.macro capture offset
    seto %al
    lahf
    movw %ax, observations+\offset(%rip)
.endm

    movq image_pointer(%rip), %rax
    cmpw $0x5a4d, (%rax)
    jne failed
    movq %rax, %r10
    capture 0
    leaq __ImageBase(%rip), %rax
    cmpq %rax, %r10
    jne failed

    leaq guarded(%rip), %r8
    movl $1, %r9d
    cmpw $0x7fff, (%r8,%r9,1)
    jno failed
    js failed
    capture 2
    # Check the address registers and both neighboring bytes independently.
    leaq guarded(%rip), %rax
    cmpq %rax, %r8
    jne failed
    cmpq $1, %r9
    jne failed
    movl guarded(%rip), %eax
    cmpl $0xa580005a, %eax
    jne failed

    movw $0, 41(%rsp)
    cmpw $0x8000, 41(%rsp)
    jae failed
    jns failed
    capture 4
    movzwl 41(%rsp), %eax
    testl %eax, %eax
    jne failed

    cmpw $0x1201, odd_parity(%rip)
    jp failed
    capture 6
    cmpw $0x00ff, max_word(%rip)
    jnp failed
    capture 8

    movq $-11, %rcx
    call *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq observations(%rip), %rdx
    movl $10, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    call *__imp_WriteFile(%rip)
    testl %eax, %eax
    jz failed
    cmpl $10, 40(%rsp)
    jne failed
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $56, %rsp
    retq
.seh_endproc

# The process harness supplies a guest address and observes the service marker
# on either successful branch. The last local byte borders the protected return.
.globl compare_at
.seh_proc compare_at
compare_at:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movb $0x34, 39(%rsp)
    cmpw $0x8000, (%rcx)
    je equal
    movl $1, 32(%rsp)
    jmp marker
equal:
    movl $2, 32(%rsp)
marker:
    call *__imp_GetLastError(%rip)
    movl 32(%rsp), %eax
    addq $40, %rsp
    retq
.seh_endproc

.section .rdata,"dr"
image_pointer: .quad __ImageBase
.data
observations: .space 10
.section .worda,"dr"
odd_parity: .short 0x1330
max_word: .short 0xffff
.section .wordb,"dw"
guarded: .byte 0x5a, 0x00, 0x80, 0xa5
