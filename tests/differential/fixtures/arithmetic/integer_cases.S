.text
.macro leaf name
    .globl \name
    .seh_proc \name
\name:
    .seh_endprologue
    .section .drectve
    .ascii " -export:\name"
    .text
.endm
.macro finish
    ret
    .seh_endproc
.endm

# Capture OF separately. LAHF puts SF/ZF/AF/PF/CF in AH.
.macro snapshot
    seto %al
    lahf
    movzwl %ax, %eax
.endm

leaf flag_add
    addb %dl, %cl
    snapshot
    finish

leaf flag_sub
    subw %dx, %cx
    snapshot
    finish

leaf flag_adc
    cmpq %rdx, %rcx
    adcb %dl, %cl
    snapshot
    finish

leaf flag_sbb
    cmpq %rdx, %rcx
    sbbb %dl, %cl
    snapshot
    finish

leaf carry_chain
    movq %rcx, %rax
    addq %rdx, %rax
    incw %ax
    notq %rax
    adcq $-1, %rax
    decb %ah
    sbbq $0, %rax
    finish

leaf neg_flags
    shlq $63, %rcx
    negq %rcx
    snapshot
    finish

leaf mixed_widths
    movq %rcx, %rax
    movb %dl, %ah
    xorb %ch, %dh
    addw %dx, %ax
    finish

leaf extensions
    movsbl %ch, %eax
    movslq %eax, %rax
    movzbw %dl, %r8w
    movswq %r8w, %rdx
    xorq %rdx, %rax
    finish

leaf multiply_flags
    imulw %dx, %cx
    setc %al
    seto %ah
    movzwl %ax, %eax
    shll $16, %eax
    movw %cx, %ax
    finish

leaf logic_flags
    orq %rdx, %rcx
    andq $-3, %rcx
    testq %rcx, %rcx
    setz %al
    setp %ah
    movzwl %ax, %eax
    sets %cl
    setc %dl
    seto %dh
    movzwl %dx, %edx
    shll $16, %edx
    orl %edx, %eax
    movzbl %cl, %ecx
    shlq $32, %rcx
    orq %rcx, %rax
    finish

# Each SETcc contributes a distinct bit. MOV and SETcc preserve all flags.
.macro pair first, second, shift
    set\first %r8b
    set\second %r9b
    movzbl %r8b, %r8d
    movzbl %r9b, %r9d
    shll $(\shift + 1), %r9d
    shll $\shift, %r8d
    orl %r8d, %eax
    orl %r9d, %eax
.endm
leaf predicates
    xorl %eax, %eax
    cmpq %rdx, %rcx
    pair o, no, 0
    cmpq %rdx, %rcx
    pair b, ae, 2
    cmpq %rdx, %rcx
    pair e, ne, 4
    cmpq %rdx, %rcx
    pair be, a, 6
    cmpq %rdx, %rcx
    pair s, ns, 8
    cmpq %rdx, %rcx
    pair p, np, 10
    cmpq %rdx, %rcx
    pair l, ge, 12
    cmpq %rdx, %rcx
    pair le, g, 14
    finish

leaf conditional_moves
    movq %rcx, %rax
    cmpq %rdx, %rcx
    cmovlw %dx, %ax
    cmovbl %edx, %eax
    cmovpq %rdx, %rax
    finish

# Preserve a defined incoming flag on a masked-zero count.
leaf shift_flags
    cmpq %rcx, %rdx
    sarb %cl, %dl
    setp %al
    setc %ah
    setz %r8b
    sets %r9b
    movzwl %ax, %eax
    movzbl %r8b, %r8d
    movzbl %r9b, %r9d
    shll $16, %r8d
    shll $17, %r9d
    orl %r8d, %eax
    orl %r9d, %eax
    movzbl %dl, %edx
    shll $24, %edx
    orl %edx, %eax
    finish

leaf shift_widths
    movq %rdx, %rax
    shrw %cl, %ax
    shlb %cl, %dh
    shrq %cl, %rdx
    xorq %rdx, %rax
    finish

leaf shift_one
    shlb %dl
    seto %al
    setc %ah
    movzwl %ax, %eax
    shrw %cx
    seto %dl
    setc %dh
    movzwl %dx, %edx
    shll $16, %edx
    orl %edx, %eax
    finish

leaf joined_flags
    cmpq %rdx, %rcx
    jbe 1f
    subq %rcx, %rdx
    jmp 2f
1:
    addq %rcx, %rdx
2:
    snapshot
    finish
