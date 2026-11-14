.text
.macro leaf name
    .globl cfg_\name
    .seh_proc cfg_\name
cfg_\name:
    .seh_endprologue
    .section .drectve
    .ascii " -export:cfg_\name"
    .text
.endm

# Both arms update different bytes of the same incoming register.
leaf diamond
    movq %rdx, %rax
    cmpq %rdx, %rcx
    jl 1f
    movb %cl, %al
    jmp 2f
1:
    movb %cl, %ah
2:
    movzwl %ax, %eax
    ret
    .seh_endproc

# Preserve different carry values across a join until the conditional jump.
leaf flag_join
    testq %rcx, %rcx
    js 1f
    addq %rcx, %rdx
    jmp 2f
1:
    subq %rcx, %rdx
2:
    movl $17, %eax
    jb 3f
    movl $42, %eax
3:
    ret
    .seh_endproc

# ADC reads the previous iteration's carry. DEC and JNE preserve it.
leaf carry_loop
    movq %rdx, %rax
    andl $7, %ecx
    je 2f
    cmpq $1, %rdx
1:
    adcq %rax, %rax
    decl %ecx
    jne 1b
2:
    ret
    .seh_endproc

# LEA adds a unique bit without changing the comparison flags.
.macro predicate cc,bit
    j\cc 1f
    jmp 2f
1:
    leal (1 << \bit)(%rax), %eax
2:
.endm
leaf jcc
    movl $0, %eax
    cmpb %dl, %cl
    predicate o,0
    predicate no,1
    predicate b,2
    predicate ae,3
    predicate e,4
    predicate ne,5
    predicate be,6
    predicate a,7
    predicate s,8
    predicate ns,9
    predicate p,10
    predicate np,11
    predicate l,12
    predicate ge,13
    predicate le,14
    predicate g,15
    ret
    .seh_endproc

# Re-enter the first instruction with the decremented count and updated sum.
leaf entry_backedge
1:
    andl $7, %ecx
    incq %rdx
    testl %ecx, %ecx
    je 2f
    decl %ecx
    jmp 1b
2:
    movq %rdx, %rax
    ret
    .seh_endproc

# Both edges carry the same flags, including CMP's flags for a masked-zero shift.
leaf identical_successors
    cmpq %rdx, %rcx
    sarq %cl, %rdx
    je 1f
1:
    setz %al
    setc %ah
    movzwl %ax, %eax
    ret
    .seh_endproc

# Define exactly AX on both arms. TEST must preserve the word returned at the join.
leaf partial_join
    cmpq %rdx, %rcx
    jl 1f
    sete %al
    lahf
    jmp 2f
1:
    movw %cx, %ax
    testw %dx, %ax
2:
    movzwl %ax, %eax
    ret
    .seh_endproc
