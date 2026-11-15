.text
.globl call_flags
.seh_proc call_flags
call_flags:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    cmpq %rdx, %rcx
    call add_carry
    setb %dl
    movzbl %dl, %edx
    leaq (%rdx,%rax,2), %rcx
    call inspect_return
.Lresume:
    addq $40, %rsp
    ret
.seh_endproc
.section .drectve
.ascii " -export:call_flags"
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
