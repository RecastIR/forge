# emit is compiled from C. Arguments after R9 occupy the caller's stack slots.
.text
.globl entry
.seh_proc entry
entry:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rsi
    .seh_pushreg %rsi
    subq $104, %rsp
    .seh_stackalloc 104
    .seh_endprologue
    callq __iob_func
    leaq 48(%rax), %rbx
    callq _errno
    movq %rax, %rsi
.if mixed
    leaq prefix(%rip), %rcx
    movl $1, %edx
    movl $1, %r8d
    movq %rbx, %r9
    callq fwrite
.endif
    movl $37, (%rsi)
    movl $91, %ecx
    callq SetLastError
    leaq fmt(%rip), %rdx
    movq %rbx, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
.if mixed
    movl $0x80000000, %r8d
    movl $0xffffffff, %r9d
    movl $0xabcdef, 32(%rsp)
    movl $0, 40(%rsp)
    movq $-1, 48(%rsp)
    leaq mutable(%rip), %rax
    movq %rax, 56(%rsp)
    movb $77, (%rax)
    leaq text(%rip), %rax
    movq %rax, 64(%rsp)
.elseif numbers
    movl $42, %r8d
    movl $23, %r9d
    movl $0xab, 32(%rsp)
    movl $0, 40(%rsp)
    movl $-1, 48(%rsp)
    movabsq $0x8000000000000000, %rax
    movq %rax, 56(%rsp)
    movq $-1, 64(%rsp)
    movq $-1, 72(%rsp)
.elseif pointer
    leaq mutable(%rip), %r8
    movabsq $0xfedcba9876543210, %rax
    movq %rax, 32(%rsp)
.elseif large
    leaq long_text(%rip), %r8
.elseif null_format
    xorl %edx, %edx
.endif
    callq emit
    movl %eax, record(%rip)
    movl (%rsi), %eax
    movl %eax, record+4(%rip)
    callq GetLastError
    movl %eax, record+8(%rip)
    movl 24(%rbx), %eax
    movl %eax, record+12(%rip)
    movq (%rbx), %rax
    subq 16(%rbx), %rax
    movl %eax, record+16(%rip)
    movl 8(%rbx), %eax
    movl %eax, record+20(%rip)
    movl $-12, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq record(%rip), %rdx
    movl $24, %r8d
    leaq 88(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
.if mixed
    leaq suffix(%rip), %rcx
    callq puts
    leaq 48(%rbx), %rcx
    leaq literal(%rip), %rdx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    callq emit
    callq _cexit
    movl $-11, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq marker(%rip), %rdx
    movl $1, %r8d
    leaq 88(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
.endif
    movl $42, %eax
    addq $104, %rsp
    popq %rsi
    popq %rbx
    retq
.seh_endproc

.section .rdata,"dr"
fmt:
.if mixed
    .asciz "%d|%u|%X|%%|%p|%x|%s|%s\n"
.elseif numbers
    .asciz "%+07d|% -6i|%#08x|%#.0X|%ld|%I64d|%I64u|%.18I64X"
.elseif pointer
    .asciz "%p|%p|%p"
.elseif large
    .asciz "%s"
.elseif boundary
    .asciz "%4096dZ"
.elseif unknown
    .asciz "before%qafter"
.elseif null_string
    .asciz "[%s]"
.else
    .byte 0
.endif
.if large
long_text: .fill 4094,1,65
    .ascii "\nBX"
    .byte 0
.endif
prefix: .ascii "["
suffix: .asciz "]"
literal: .asciz "stderr"
marker: .ascii "#"
text: .asciz "immutable"
.data
mutable: .asciz "mutable"
record: .space 24
