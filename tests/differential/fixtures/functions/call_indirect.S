# All calls are ordinary Win64 calls, with one outgoing shadow area per activation.
.text
.globl call_indirect
.seh_proc call_indirect
call_indirect:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq %rdx, 32(%rsp)
    movl %ecx, %r8d
    andl $3, %r8d
    cmpq %rdx, %rcx
    leaq indirect_preserve(%rip), %rax
    call *%rax
    jb .Lshared
    leaq indirect_preserve(%rip), %r11
    nop
    nopl (%rax)
    call *%r11
.Lshared:
    call indirect_preserve
    leaq 32(%rsp), %rcx
    leaq indirect_leaf(%rip), %r10
    call *%r10
    addq 32(%rsp), %rax
    movl %r8d, %ecx
    leaq indirect_recurse(%rip), %r11
    call *%r11
    addq $40, %rsp
    ret
.seh_endproc

.globl indirect_preserve
.seh_proc indirect_preserve
indirect_preserve:
    .seh_endprologue
    movl $13, %r9d
    leaq 1(%rdx), %rdx
    ret
.seh_endproc

# Deliberately omit unwind metadata. The caller observes both writes.
.globl indirect_leaf
indirect_leaf:
    addq %rdx, (%rcx)
    incq indirect_counter(%rip)
    movq indirect_counter(%rip), %rax
    ret

.globl indirect_recurse
.seh_proc indirect_recurse
indirect_recurse:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    testl %ecx, %ecx
    je .Ldone
    decl %ecx
    leaq indirect_recurse(%rip), %r11
    call *%r11
    addq $3, %rax
.Ldone:
    addq $40, %rsp
    ret
.seh_endproc

.data
.p2align 3
indirect_counter:
    .quad 0
.section .drectve
.ascii " -export:call_indirect"
