.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    movq %gs:0x30, %r10
    movq 0x30(%r10), %rax
    cmpq %r10, %rax
    jne .Lbad
    movq 8(%r10), %rax
    cmpq %rsp, %rax
    jbe .Lbad
    movq 16(%r10), %rax
    cmpq %rsp, %rax
    ja .Lbad
    movl $42, %eax
    ret
.Lbad:
    movl $1, %eax
    ret
.seh_endproc
