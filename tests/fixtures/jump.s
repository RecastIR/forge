.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    cmpl $2, %ecx
    ja .Loutside
    movl %ecx, %eax
    leaq .Lsmall(%rip), %r8
    movslq (%r8,%rax,4), %rax
    addq %r8, %rax
    jmp *%rax
.Lcarry:
    movq %rdx, %rax
    adcq $0, %rax
    ret
.Lother:
    ret  # RAX is the actual runtime target VA.
.Loutside:
    movq $-91, %rax
    ret
    .byte 0x0f  # Unreachable truncated encoding for the invalid table-entry test.
.seh_endproc
.section .jtab,"dr"
.Lsmall:
    .long .Lcarry-.Lsmall, .Lother-.Lsmall, .Lcarry-.Lsmall
.section .jtfix,"dr"
.quad entry

.text
.globl width_paths
.seh_proc width_paths
width_paths:
    .seh_endprologue
    testq %rdx, %rdx
    je .Lwidth_guard
    cmpl $1, %ecx
    ja .Lwidth_default
    jmp .Lwidth_guard  # The negative fixture redirects only this edge to .Lwidth_base.
.Lwidth_guard:
    cmpl $1, %ecx
    ja .Lwidth_default
    movl %ecx, %ecx
.Lwidth_base:
    leaq .Lwidth_table(%rip), %r8
    movslq (%r8,%rcx,4), %rax
    addq %r8, %rax
    jmp *%rax
.Lwidth_zero:
    movl $11, %eax
    ret
.Lwidth_one:
    movl $22, %eax
    ret
.Lwidth_default:
    movl $33, %eax
    ret
.seh_endproc
.section .rdata,"dr"
.Lwidth_table:
    .long .Lwidth_zero-.Lwidth_table, .Lwidth_one-.Lwidth_table

.text
.globl table_caller
.seh_proc table_caller
table_caller:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq entry
    addq $40, %rsp
    ret
.seh_endproc

.text
.globl two_tables
.seh_proc two_tables
two_tables:
    .seh_endprologue
    cmpq $1, %rcx
    ja .Ldone_two
    leaq .Lfirst(%rip), %r8
    movslq (%r8,%rcx,4), %rax
    addq %r8, %rax
    jmp *%rax
.Lsecond_guard:
    cmpq $1, %rdx
    ja .Ldone_two
    leaq .Lsecond(%rip), %r8
    movslq (%r8,%rdx,4), %rax
    addq %r8, %rax
    jmp *%rax
.Lresult:
    movq $77, %rax
    ret
.Ldone_two:
    movq $-19, %rax
    ret
.seh_endproc
.section .jtnest,"dr"
.Lfirst:
    .long .Lsecond_guard-.Lfirst, .Ldone_two-.Lfirst
.Lsecond:
    .long .Lresult-.Lsecond, .Ldone_two-.Lsecond

# Four full tables exhaust the function budget. A test redirects one entry
# in the fourth table to a fifth otherwise unreachable dispatch.
.macro stage n, destination
.text
.Lstage\n:
    cmpq $1023, %rcx
    ja .Lbudget_ret
    leaq .Lbudget\n(%rip), %r8
    movslq (%r8,%rcx,4), %rax
    addq %r8, %rax
    jmp *%rax
.section .jtmax,"dr"
.Lbudget\n:
    .rept 1024
    .long \destination-.Lbudget\n
    .endr
.endm

.text
.globl table_budget
.seh_proc table_budget
table_budget:
    .seh_endprologue
    stage 1, .Lstage2
    stage 2, .Lstage3
    stage 3, .Lstage4
    stage 4, .Lbudget_ret
    stage 5, .Lbudget_ret
.text
.Lbudget_ret:
    movq $53, %rax
    ret
.seh_endproc

.text
.globl case_caller
.seh_proc case_caller
case_caller:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    cmpl $1, %ecx
    ja .Lcase_done
    movl %ecx, %eax
    leaq .Lcase_table(%rip), %r8
    movslq (%r8,%rax,4), %rax
    addq %r8, %rax
    jmp *%rax
.Lcase_call:
    callq .Lcase_leaf
.Lcase_done:
    movl $1, %eax
    addq $40, %rsp
    ret
.seh_endproc
.Lcase_leaf:
    addq %r10, %rax             # R10 is undefined at the only call site.
    ret
.section .jtcall,"dr"
.Lcase_table:
    .long .Lcase_call-.Lcase_table, .Lcase_done-.Lcase_table
