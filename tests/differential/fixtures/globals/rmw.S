.section .cells,"dw"
.Lstate:
    .quad 0xfffe
.text
.globl global_rmw
.seh_proc global_rmw
global_rmw:
    .seh_endprologue
    addb %cl, .Lstate(%rip)
    seto %r9b
    incw .Lstate+1(%rip)
    decb .Lstate+2(%rip)
    setc %r8b
    subl %edx, .Lstate+3(%rip)
    setc %r10b
    movzbl %r8b, %eax
    movzbl %r9b, %r9d
    movzbl %r10b, %r10d
    shlq $56, %rax
    shlq $57, %r9
    shlq $58, %r10
    orq %r9, %rax
    orq %r10, %rax
    movq .Lstate(%rip), %r8
    orq %r8, %rax
    ret
    .seh_endproc
.section .drectve
.ascii " -export:global_rmw"
