.ifndef direct
direct = 0
.endif
.ifndef newline_flush
newline_flush = 0
.endif
.ifndef null_input
null_input = 0
.endif
# Each entry is linked without CRT startup and calls the system import directly.
.text
.globl entry
.seh_proc entry
entry:
.ifdef hello
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    leaq greeting(%rip), %rcx
    callq puts
    addq $40, %rsp
    retq
.else
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rsi
    .seh_pushreg %rsi
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
    callq __iob_func
    movq %rax, %rbx
    callq _errno
    movq %rax, %rsi
    movl $37, (%rsi)
    movl $91, %ecx
    callq SetLastError

.macro write_byte slot
    leaq bracket(%rip), %rcx
    movl $1, %edx
    movl $1, %r8d
    leaq \slot(%rbx), %r9
    callq fwrite
.endm
.macro line source
    leaq \source(%rip), %rcx
    callq *__imp_puts(%rip)
    testl %eax, %eax
    jne .Lbad
.endm
.ifdef mixed
    write_byte 48
    line empty
    line one
    line newlines
    write_byte 48
    movb $77, mutable(%rip)
    line mutable
    write_byte 96
    leaq first+4094(%rip), %rcx
.elseif newline_flush
    write_byte 48
    leaq full(%rip), %rcx
.elseif direct
    leaq large(%rip), %rcx
.elseif null_input
    xorl %ecx, %ecx
.else
    line one
    movl $1, %ecx
.endif
    callq puts
    movl %eax, record(%rip)
    movl (%rsi), %eax
    movl %eax, record+4(%rip)
    callq GetLastError
    movl %eax, record+8(%rip)
    movl 72(%rbx), %eax
    movl %eax, record+12(%rip)
    movq 48(%rbx), %rax
    subq 64(%rbx), %rax
    movq %rax, record+16(%rip)
    movl 56(%rbx), %eax
    movl %eax, record+24(%rip)
    movl 76(%rbx), %eax
    movl %eax, record+28(%rip)
    movl $-12, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq record(%rip), %rdx
    movl $32, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
.ifdef mixed
    callq _cexit
    movl $-11, %ecx
    callq GetStdHandle
    movq %rax, %rcx
    leaq marker(%rip), %rdx
    movl $1, %r8d
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
    callq WriteFile
.endif
    movl $42, %eax
.ifdef crt_exit
    movl %eax, %ecx
    callq exit
.endif
.ifdef win_exit
    movl %eax, %ecx
    callq ExitProcess
.endif
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    addq $56, %rsp
    popq %rsi
    popq %rbx
    retq
.endif
.seh_endproc

.section .rdata,"dr"
greeting: .asciz "Hello from C!"
empty: .byte 0
one: .asciz "Q"
newlines: .asciz "A\r\nB\n"
bracket: .ascii "["
marker: .ascii "#"
.if direct
large: .ascii "A\nB\r\nZ"
.fill 8186,1,65
.byte 0
.endif
.if newline_flush
full: .fill 4095,1,78
.byte 0
.endif
.data
record: .space 32
mutable: .asciz "m\0!"
.ifdef mixed
.section .sra,"dr"
first: .space 4094
.ascii "AB"
.section .srb,"dr"
.asciz "CD"
.endif
