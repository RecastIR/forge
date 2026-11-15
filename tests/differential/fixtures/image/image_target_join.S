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
    jmp 2f
1:
    leaq .choicea(%rip), %r8
2:
    movq %r8, %r9
    addq $3, %r9
    movq %r9, 8(%rsp)
    movq 8(%rsp), %r10
    movzwl 1(%r10), %eax
    addq %rdx, %rax
    ret
    .seh_endproc

.section .drectve
.ascii " -export:image_target_join"
