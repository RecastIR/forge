# CRT code calls the outer function directly, with the Windows callback arguments.
# Ordinary guest CALLs inside it take no arguments. This PE has no TLS directory.
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rsi
    .seh_pushreg %rsi
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $211, %ebx
    movl $212, %esi
    movq %rsp, 32(%rsp)
    call run_empty
    call run_one
    call run_null
    xorl %edx, %edx
    movl $17, %ecx
    movl $19, %r8d
    call outer
    movl $3, %edx
    movl $17, %ecx
    movl $19, %r8d
    call outer
    movl $1, %edx
    movl $17, %ecx
    movl $19, %r8d
    call outer
    cmpl $1, process_attaches(%rip)
    jne .Lfailed
    cmpl $2, crt_mt(%rip)
    jne .Lfailed
    cmpl $0, trace(%rip)
    jne .Lfailed
    movl $2, %edx
    movl $17, %ecx
    movl $19, %r8d
    call outer
    cmpl $1, %eax
    jne .Lfailed
    call *__imp_GetLastError(%rip)
    cmpl $59, %eax
    jne .Lfailed
    cmpl $122, trace(%rip)
    jne .Lfailed
    cmpl $1, single_count(%rip)
    jne .Lfailed
    cmpl $211, %ebx
    jne .Lfailed
    cmpl $212, %esi
    jne .Lfailed
    movq 32(%rsp), %rax
    cmpq %rsp, %rax
    jne .Lfailed
    movl $42, %eax
    jmp .Ldone
.Lfailed:
    movl $5, %eax
.Ldone:
    addq $40, %rsp
    popq %rsi
    popq %rbx
    retq
.seh_endproc

.macro frame
    pushq %rsi
    .seh_pushreg %rsi
    pushq %rbx
    .seh_pushreg %rbx
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
.endm

.macro finish
    movl $1, %eax
    addq $40, %rsp
    popq %rbx
    popq %rsi
    retq
.endm

.macro walk start, end, name, clear=0
\name\()_bounds:
    leaq \start(%rip), %rbx
    leaq \end(%rip), %rsi
    cmpq %rbx, %rsi
    je .Ldone\@
\name\()_load:
    movq (%rbx), %rax
    testq %rax, %rax
    je .Lnext\@
.if \clear
    # The call must still see the already-loaded pointer.
    movq $0, (%rbx)
.endif
\name\()_site:
    callq *%rax
.Lnext\@:
    addq $8, %rbx
    cmpq %rbx, %rsi
    jne \name\()_load
.Ldone\@:
.endm

.seh_proc run_empty
run_empty:
    frame
    walk empty, empty, empty
    finish
.seh_endproc

.seh_proc run_one
run_one:
    frame
    walk single, single+8, single
    finish
.seh_endproc

.globl run_null, null_site, null_only, tamper_null
.seh_proc run_null
run_null:
    frame
    walk null_only, null_only+8, null
    finish
.seh_endproc

.seh_proc tamper_null
tamper_null:
    .seh_endprologue
    leaq single_callback(%rip), %rax
    movq %rax, null_only(%rip)
    jmp run_null
.seh_endproc

.globl outer, many_bounds, many_load, many_site, late_edge
.seh_proc outer
outer:
    frame
    movl $2, crt_mt(%rip)
    cmpl $2, %edx
    je many_bounds
    cmpl $1, %edx
    jne .Lreturn
    call process_attach
    jmp .Lreturn
    walk slots, slots_end, many, 1
late_edge:
    nop
    nop
.Lreturn:
    finish
.seh_endproc

process_attach:
    cmpl $17, %ecx
    jne .Lbad
    cmpl $19, %r8d
    jne .Lbad
    addl $1, process_attaches(%rip)
    retq
.Lbad:
    movl $99, process_attaches(%rip)
    retq

.globl single_callback, writer, tail_callback, replacement, bad_return, bad_save, terminal
.seh_proc single_callback
single_callback:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $0, (%rsp)
    call single_helper
    cmpl $8, %eax
    jne .Lsingle_done
    movl (%rsp), %eax
    addl %eax, single_count(%rip)
.Lsingle_done:
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc single_helper
single_helper:
    .seh_endprologue
    # Record the visit in the caller-provided home slot and return the entry alignment.
    movl $1, 8(%rsp)
    movq %rsp, %rax
    andl $15, %eax
    retq
.seh_endproc

.seh_proc writer
writer:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $1, trace(%rip)
    movq replacement(%rip), %rax
    movq %rax, slots+24(%rip)
    movq $0, slots+32(%rip)
    movl $59, %ecx
    call *__imp_SetLastError(%rip)
    addq $40, %rsp
    retq
.seh_endproc

.seh_proc tail_callback
tail_callback:
    .seh_endprologue
    jmp append_two
.seh_endproc
.seh_proc append_two
append_two:
    .seh_endprologue
    movq %rsp, %rax
    andl $15, %eax
    cmpl $8, %eax
    jne .Lalignment
    movq $19, 8(%rsp)
    movl trace(%rip), %eax
    leal (%rax,%rax,4), %eax
    addl %eax, %eax
    addl $2, %eax
    movl %eax, trace(%rip)
    retq
.Lalignment:
    movl $99, trace(%rip)
    retq
.seh_endproc

.seh_proc bad_return
bad_return:
    .seh_endprologue
    addq $8, %rsp
    retq
.seh_endproc
.seh_proc bad_save
bad_save:
    .seh_endprologue
    xorl %esi, %esi
    retq
.seh_endproc

.seh_proc terminal
terminal:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movl $57, %ecx
    call *__imp_ExitProcess(%rip)
.seh_endproc

.data
.p2align 3
.globl slots, slots_end, empty
single:
    .quad single_callback
empty:
slots:
    .quad writer, 0, tail_callback, writer, tail_callback
slots_end:
replacement:
    .quad tail_callback
trace: .long 0
single_count: .long 0
process_attaches: .long 0
crt_mt: .long 0
# Reserve a mapped range for the over-budget endpoint and zero-tail tests.
.space 8 * 1026, 0

.section .ztail,"bw"
.p2align 3
null_only: .space 8
