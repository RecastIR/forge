# emit is compiled from C. Arguments after R9 occupy the caller's stack slots.
.text
.globl entry
.seh_proc entry
entry:
.if literal_empty || literal_text
    # Isolate the format's image requirements from the observer's indirect FILE reads.
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    callq __iob_func
    leaq 48(%rax), %rcx
    leaq fmt(%rip), %rdx
    movq $-1, %r8
    callq *__imp_vfprintf(%rip)
    addq $40, %rsp
    retq
.else
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
.if errno_string
    movl $0x4141, (%rsi)
.elseif eilseq
    movl $42, (%rsi)
.else
    movl $37, (%rsi)
.endif
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
    movq $0, 40(%rsp)
    movq $-1, 48(%rsp)
    leaq mutable(%rip), %rax
    movq %rax, 56(%rsp)
    movb $77, (%rax)
    leaq text(%rip), %rax
    movq %rax, 64(%rsp)
.elseif precision
    movl $42, %r8d
    movl $42, %r9d
    movl $42, 32(%rsp)
    movl $42, 40(%rsp)
.elseif padding || sign || field_body || trailing || zero_pad
    movl $42, %r8d
    movl $23, %r9d
.elseif errno_string || errno_slot
    movq %rsi, %r8
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
.elseif large || eilseq
    leaq long_text(%rip), %r8
.elseif null_format
    xorl %edx, %edx
.elseif null_stream
    xorl %ecx, %ecx
.elseif edges
    movl $0x7fffffff, %r8d
    movl $-1, %r9d
    movl $0, 32(%rsp)
    movl $42, 40(%rsp)
    movl $0xab, 48(%rsp)
    movl $-42, 56(%rsp)
    movl $-1, 64(%rsp)
.endif
.if mapped
    leaq dynamic_fmt(%rip), %rdx
    movb $115, 1(%rdx)
    leaq slots(%rip), %r8
    callq *__imp_vfprintf(%rip)
.elseif errno_slot
    callq *__imp_vfprintf(%rip)
.else
    callq emit
.endif
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
.endif
.seh_endproc

.section .rdata,"dr"
fmt:
.if mixed
    .asciz "%d|%u|%X|%%|%p|%x|%s|%s\n"
.elseif edges
    .asciz "%i|%08u|%.0d|%-8.5d|%#X|%+08.5i|%lx"
.elseif numbers
    .asciz "%+07d|% -6i|%#08x|%#.0X|%ld|%I64d|%I64u|%.18I64X"
.elseif pointer
    .asciz "%p|%p|%p"
.elseif large || eilseq
    .asciz "%s"
.elseif precision
    .asciz "%.512u|%.513u|%.4096u|%4096.513u"
.elseif padding
    .asciz "%4096u%4d"
.elseif sign
    .asciz "%4096u%+d"
.elseif field_body
    .asciz "%4095u%-.4dZ"
.elseif trailing
    .asciz "%4093u%-6dZ"
.elseif zero_pad
    .asciz "%4095u%+05dZ"
.elseif errno_string
    .asciz "%s"
.elseif errno_slot
    .asciz "%d"
.elseif literal_text
    .asciz "plain text"
.elseif boundary
    .asciz "%4096dZ"
.elseif unknown
    .asciz "before%qafter"
.elseif null_string
    .asciz "[%s]"
.else
    .byte 0
.endif
.if eilseq
# One complete 5119-byte CRLF transfer, then a failed flush inside the %s body.
long_text: .byte 65
    .fill 4095,1,10
    .asciz "BC"
.elseif large
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
.if mapped
.balign 8
slots: .quad text
    .quad 0xaaaaaaaa80000000
dynamic_fmt: .asciz "%?|%d"
.endif
