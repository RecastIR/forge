# A CRT-free Windows console program. Its only observable output comes from the
# imported WriteFile reading message from the PE's read-only data section.
.text
.globl entry
.seh_proc entry
entry:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    # The DWORD selector is valid even with all upper RCX bits set.
    movq $-11, %rcx
    call *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
    leaq message(%rip), %rdx
    movl $message_end-message, %r8d
    leaq 40(%rsp), %r9
    movl $-1, 40(%rsp)
    movq $0, 32(%rsp)
    call *__imp_WriteFile(%rip)
    movl $1, %ecx
    testl %eax, %eax
    jz .Lexit
    movl $2, %ecx
    cmpl $message_end-message, 40(%rsp)
    jne .Lexit
    xorl %ecx, %ecx
.Lexit:
    call *__imp_ExitProcess(%rip)
.seh_endproc

.section .rdata,"dr"
message:
    .ascii "Hello from Windows!\n"
message_end:
