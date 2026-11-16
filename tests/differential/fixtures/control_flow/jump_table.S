.text
.globl cfg_jump_table
.seh_proc cfg_jump_table
cfg_jump_table:
    .seh_endprologue
    movq %rdx, %rax
.Lcheck:
    cmpq $4, %rcx
    ja .Ldefault
    leaq .Ltable(%rip), %r8
    movslq (%r8,%rcx,4), %r9
    addq %r8, %r9
    jmp *%r9
.Lshared:
    xorq $9, %rax
    jmp .Ldone
.Lloop:
    incq %rax
    decq %rcx
    jmp .Lcheck
.Lthree:
    negq %rax
.Ldone:
    ret
.Lfour:
    movq $41, %rax
    ret
.Ldefault:
    movq $-17, %rax
    ret
.seh_endproc
.section .rdata,"dr"
.p2align 2
.Ltable:
    .long .Lshared-.Ltable, .Lshared-.Ltable, .Lloop-.Ltable, .Lthree-.Ltable, .Lfour-.Ltable
.section .drectve
.ascii " -export:cfg_jump_table"
