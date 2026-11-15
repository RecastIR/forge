.section .choicea,"dr"
.long 0
.short 21

.section .choiceb,"dr"
.long 0
.short 40000

# Unrelated virtual-only writable extent exceeds Forge's writable budget.
.section .wrpad,"b"
.space 257 * 1024 * 1024

.text
.globl image_target_join
.seh_proc image_target_join
image_target_join:
    .seh_endprologue
    testq %rcx, %rcx
    je 1f
    leaq .choiceb(%rip), %r8
    xorq %r10, %r10
    subq %r11, %r11
    jmp 2f
1:
    leaq .choicea(%rip), %r8
    xorl %r10d, %r10d
    subl %r11d, %r11d
2:
    # After 32-bit underflow R10 holds UINT32_MAX, and wide subtraction makes it zero.
    subl $1, %r10d
    movl $0xffffffff, %eax
    subq %rax, %r10
    # Overflow the same 32-bit maximum to get the interior offset of three.
    addl $4, %eax
    movq %r8, %r9
    addq %r10, %r9
    addq %r11, %r9
    addq %rax, %r9
    movq %r9, 8(%rsp)
    movq 8(%rsp), %r10
    movzwl 1(%r10), %eax
    addq %rdx, %rax
    ret
    .seh_endproc

.section .drectve
.ascii " -export:image_target_join"
