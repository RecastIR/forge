.text
.globl call_continuations
.seh_proc call_continuations
call_continuations:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    cmpq $2, %rdx
    je .Lreturned
    .irp site,0,1,2,3,4,5,6,7
        cmpl $\site, %ecx
        je .Lsite\site
    .endr
    jmp .Lsite8

    # The first instruction after each CALL encodes 0x1200 + site at offset two.
    .irp site,0,1,2,3,4,5,6,7,8
.Lsite\site:
        call read_continuation
        movl $(0x1200 + \site), %r9d
        jmp .Ldone
    .endr

.Lreturned:
    call return_continuation
    movl $0xabcdef11, %r9d
    movq %rax, 32(%rsp)
    movq 32(%rsp), %r8
    movzwl 2(%r8), %eax
.Ldone:
    addq $56, %rsp
    ret
.seh_endproc
.section .drectve
.ascii " -export:call_continuations"
.text

.seh_proc read_continuation
read_continuation:
    .seh_endprologue
    movq (%rsp), %r8
    testq %rdx, %rdx
    je .Lword
    cmpq $3, %rdx
    je .Lunmapped
    cmpq $4, %rdx
    je .Lreadonly
    movzbl 2(%r8), %eax
    ret
.Lword:
    movzwl 2(%r8), %eax
    ret
.Lunmapped:
    # A noncanonical VA on Windows x64, independently of the PE load base.
    movabsq $0x4000000000000000, %r10
    addq %r8, %r10
    movzbl (%r10), %eax
    ret
.Lreadonly:
    movb $0, 2(%r8)
    xorl %eax, %eax
    ret
.seh_endproc

.seh_proc return_continuation
return_continuation:
    .seh_endprologue
    movq (%rsp), %rax
    ret
.seh_endproc
