.text
.globl string_length
.seh_proc string_length
string_length:
    pushq %rbx
    .seh_pushreg %rbx
    subq $64, %rsp
    .seh_stackalloc 64
    .seh_endprologue
    movq %rcx, %rbx
    movq %rdx, 48(%rsp)
    movq $0, 56(%rsp)
    movl $0xfedcba98, %ecx
    call *__imp_SetLastError(%rip)
    cmpq $0, %rbx
    je .Lnull
    cmpq $1, %rbx
    je .Lempty
    cmpq $2, %rbx
    je .Lshort
    cmpq $3, %rbx
    je .Llong
    cmpq $4, %rbx
    je .Lmutable
    cmpq $5, %rbx
    je .Lstack
    cmpq $6, %rbx
    je .Ltwice
    cmpq $7, %rbx
    je .Lalternatives
    cmpq $8, %rbx
    je .Lnested
    # Native-only negative: the local bytes at RSP+40 were never initialized.
    leaq 40(%rsp), %rcx
    jmp .Lcall
.Lnull:
    xorl %ecx, %ecx
    jmp .Lcall
.Lempty:
    leaq lstrlen_empty(%rip), %rcx
    jmp .Lcall
.Lshort:
    leaq lstrlen_short(%rip), %rcx
    jmp .Lcall
.Llong:
    leaq lstrlen_long(%rip), %rcx
    jmp .Lcall
.Lmutable:
    movb $'a', lstrlen_mutable(%rip)
    movb $'b', lstrlen_mutable+1(%rip)
    movb $'c', lstrlen_mutable+2(%rip)
    movb $0, lstrlen_mutable+3(%rip)
    leaq lstrlen_mutable(%rip), %rcx
    jmp .Lcall
.Lstack:
    movl $0x63617473, 40(%rsp)
    movw $0x006b, 44(%rsp)
    leaq 40(%rsp), %rcx
    jmp .Lcall
.Ltwice:
    movb $'a', lstrlen_mutable(%rip)
    movb $0, lstrlen_mutable+1(%rip)
    leaq lstrlen_mutable(%rip), %rcx
    call *__imp_lstrlenA(%rip)
    shlq $4, %rax
    movq %rax, 56(%rsp)
    movl $0x64636261, lstrlen_mutable(%rip)
    movl $0x00006665, lstrlen_mutable+4(%rip)
    leaq lstrlen_mutable(%rip), %rcx
    jmp .Lcall
.Lalternatives:
    leaq lstrlen_empty(%rip), %rcx
    cmpq $0, 48(%rsp)
    je .Lcall
    leaq lstrlen_short(%rip), %rcx
    jmp .Lcall
.Lnested:
    leaq lstrlen_short(%rip), %rcx
    call string_length_helper
    jmp .Lresult
.Lcall:
    call *__imp_lstrlenA(%rip)
.Lresult:
    # Observe all RAX bits and continue with translated arithmetic after the API.
    addq 56(%rsp), %rax
    addq $1, %rax
    # Wine 8 returns zero for NULL but changes last error to ERROR_INVALID_PARAMETER.
    # Compare the documented NULL result; native contract tests require preservation.
    testq %rbx, %rbx
    je .Ldone
    movq %rax, 32(%rsp)
    call *__imp_GetLastError(%rip)
    cmpl $0xfedcba98, %eax
    jne .Lfailed
    movq 32(%rsp), %rax
    jmp .Ldone
.Lfailed:
    movq $-1, %rax
.Ldone:
    addq $64, %rsp
    popq %rbx
    ret
.seh_endproc

.globl string_length_helper
.seh_proc string_length_helper
string_length_helper:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    call *__imp_lstrlenA(%rip)
    addq $40, %rsp
    ret
.seh_endproc

.section .rdata,"dr"
.globl lstrlen_empty, lstrlen_short, lstrlen_long
lstrlen_empty:
    .byte 0
lstrlen_short:
    .asciz "Forge"
lstrlen_long:
    .fill 700, 1, 0x61
    .byte 0

.data
.globl lstrlen_mutable
lstrlen_mutable:
    .asciz "a"
    .space 14
    # Retain relocation evidence for selected-base integration tests.
    .quad lstrlen_short

.section .drectve
.ascii " -export:string_length -export:string_length_helper -export:lstrlen_empty,data -export:lstrlen_short,data -export:lstrlen_long,data -export:lstrlen_mutable,data"
