.text
.globl entry
.seh_proc entry
entry:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq __iob_func
    leaq 96(%rax), %r9
    leaq first+4094(%rip), %rcx
    movq width(%rip), %rdx
    movl $2, %r8d
    callq fwrite
    cmpq $2, %rax
    jne .Lbad
    movl $42, %eax
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    addq $40, %rsp
    retq
.seh_endproc
.data
width: .quad 2
.section .sra,"dr"
first: .space 4094
.ascii "AB"
.section .srb,"dr"
.ascii "CD"
