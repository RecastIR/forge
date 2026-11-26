.text
.globl entry, run_count, run_one, run_empty, run_mixed
.globl count_site, after_count, one, two, writer, terminal, bad_return, bad_nonvolatile
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    cmpl $0, trace(%rip)
    jne failed
    call run_empty
    call run_count
    call run_one
.ifdef with_cleanup
    cmpl $0, cleanup_marker(%rip)
    jne failed
    call *__imp__cexit(%rip)
    cmpl $1, cleanup_marker(%rip)
    jne failed
.endif
    movl trace(%rip), %eax
    cmpl $310, %eax
    jne failed
    movl $42, %eax
    jmp done
failed:
    movl $1, %eax
done:
    addq $40, %rsp
    retq
.seh_endproc

.macro runner name, table, site, after
.seh_proc \name
\name:
    pushq %rsi
    .seh_pushreg %rsi
    pushq %rbx
    .seh_pushreg %rbx
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    leaq \table(%rip), %rdx
    movq (%rdx), %rax
    movl %eax, %ecx
    cmpl $-1, %eax
    je .Lscan\@
.Lcount\@:
    testl %ecx, %ecx
    je .Ldone\@
    movl %ecx, %eax
    subl $1, %ecx
    leaq (%rdx,%rax,8), %rbx
    subq %rcx, %rax
    leaq -8(%rdx,%rax,8), %rsi
\site:
    callq *(%rbx)
\after:
    subq $8, %rbx
    cmpq %rsi, %rbx
    jne \site
.Ldone\@:
    addq $40, %rsp
    popq %rbx
    popq %rsi
    movl $42, %eax
    retq
.Lscan\@:
    xorl %eax, %eax
.Lnext\@:
    leal 1(%rax), %r8d
    movl %eax, %ecx
    cmpq $0, (%rdx,%r8,8)
    movq %r8, %rax
    jne .Lnext\@
    jmp .Lcount\@
.seh_endproc
.endm

runner run_count, count_table, count_site, after_count
runner run_one, one_table, one_site, after_one
runner run_empty, empty_table, empty_site, after_empty
runner run_mixed, mixed_table, mixed_site, after_mixed

# The inferred leaf and recorded body both update shared guest data.
one:
    movl trace(%rip), %eax
    leal 1(%rax,%rax,2), %eax
    movl %eax, trace(%rip)
    retq
.seh_proc two
two:
    .seh_endprologue
    movl trace(%rip), %eax
    leal 2(%rax,%rax,2), %eax
    movl %eax, trace(%rip)
    retq
.seh_endproc

.seh_proc writer
writer:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq 40(%rsp), %rax
    leaq after_count(%rip), %rdx
    cmpq %rdx, %rax
    jne .Lbad
    call nested
    jne .Lbad
.ifdef with_cleanup
    leaq on_cleanup(%rip), %rcx
    call *__imp__onexit(%rip)
    testq %rax, %rax
    je .Lbad
.endif
    movq replacement(%rip), %rax
    movq %rax, count_table+8(%rip)
    addq $40, %rsp
    retq
.Lbad:
    movl $100, trace(%rip)
    addq $40, %rsp
    retq
.seh_endproc

nested:
    movl $3, trace(%rip)
    movl $3, %eax
    cmpl $3, %eax
    retq
.seh_proc terminal
terminal:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $57, %ecx
    call *__imp_ExitProcess(%rip)
.seh_endproc
.seh_proc bad_nonvolatile
bad_nonvolatile:
    .seh_endprologue
    xorl %ebx, %ebx
    retq
.seh_endproc
.seh_proc bad_return
bad_return:
    .seh_endprologue
    addq $8, %rsp
    retq
.seh_endproc

.ifdef with_cleanup
.seh_proc on_cleanup
on_cleanup:
    .seh_endprologue
    movl $1, cleanup_marker(%rip)
    retq
.seh_endproc
.endif

.globl shorten_mixed
.seh_proc shorten_mixed
shorten_mixed:
    .seh_endprologue
    movl $1, mixed_table(%rip)
    jmp run_mixed
.seh_endproc

.globl tamper_count, tamper_scan
.seh_proc tamper_count
tamper_count:
    .seh_endprologue
    movl $5, count_table(%rip)
    jmp run_count
.seh_endproc
.seh_proc tamper_scan
tamper_scan:
    .seh_endprologue
    movl $1, empty_table+8(%rip)
    jmp run_empty
.seh_endproc

.globl exclusive
.seh_proc exclusive
exclusive:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    call one
    addq $40, %rsp
    retq
.seh_endproc

.globl one_table, empty_table, count_table, replacement, mixed_table
# An unrelated executable-section fixup keeps its protected-hole policy.
.globl unrelated_cell
.p2align 3
unrelated_cell:
    .quad two
# Put the sentinel terminator at a raw-section alignment boundary. A fixture
# variant supplies these final eight zero bytes through the loader's virtual tail.
.p2align 9
.space 496, 0
one_table:
    .quad -1, exclusive, 0
.data
.p2align 3
count_table:
    .quad 4, two, one, two, writer
replacement:
    .quad one
empty_table:
    .quad -1, 0
mixed_table:
    .quad 2, two, terminal
trace:
    .long 0
.ifdef with_cleanup
cleanup_marker:
    .long 0
.endif
