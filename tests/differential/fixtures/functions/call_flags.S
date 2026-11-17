.text
.globl call_flags
.seh_proc call_flags
call_flags:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    cmpq $100, %rcx
    je .Lcompare
    cmpq $101, %rcx
    je .Ltest
    cmpq %rdx, %rcx
    call add_carry
    setb %dl
    movzbl %dl, %edx
    leaq (%rdx,%rax,2), %rcx
    call inspect_return
.Lresume:
    addq $40, %rsp
    ret
.Lcompare:
    call compare_caller
    lahf
    movzbl %ah, %eax
    jmp .Lresume
.Ltest:
    call test_caller
    setz %al
    movzbl %al, %eax
    jmp .Lresume
.seh_endproc
.section .drectve
.ascii " -export:call_flags -export:shared_flags"
.text

.seh_proc add_carry
add_carry:
    pushq %rbx
    .seh_pushreg %rbx
    .seh_endprologue
    movq %rdx, %rbx
    movq %rcx, %rax
    adcq %rbx, %rax
    popq %rbx
    ret
.seh_endproc

.seh_proc inspect_return
inspect_return:
    .seh_endprologue
    movq (%rsp), %rax
    leaq .Lresume(%rip), %rdx
    subq %rdx, %rax
    addq %rcx, %rax
    ret
.seh_endproc

# CMP defines AF and TEST does not. Both callers return the shared leaf's flags
# through a frame-pointer epilogue so the root can consume them after two RETs.
.macro flag_caller name
    .seh_proc \name
\name:
    pushq %rbp
    .seh_pushreg %rbp
    subq $32, %rsp
    .seh_stackalloc 32
    leaq 32(%rsp), %rbp
    .seh_setframe %rbp, 32
    .seh_endprologue
.endm

.macro return_shared_flags
    call shared_flags
    leaq (%rbp), %rsp
    popq %rbp
    ret
    .seh_endproc
.endm

flag_caller compare_caller
    cmpb $1, %dl
    return_shared_flags

flag_caller test_caller
    testb %dl, %dl
    return_shared_flags

.globl shared_flags
.seh_proc shared_flags
shared_flags:
    .seh_endprologue
    nop                     # Replaced by LAHF in the negative lift test.
    js .Lkeep
    cmpb %dl, %dl
.Lkeep:
    ret
.seh_endproc
