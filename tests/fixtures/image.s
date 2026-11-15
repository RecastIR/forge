.text
.globl entry
entry:
    ret

.macro probe name
    .globl \name
    .seh_proc \name
\name:
    .seh_endprologue
    .section .drectve
    .ascii " -export:\name"
    .text
.endm

probe load32
    movl (%rcx), %eax
    ret
    .seh_endproc

probe maybe_read
    testq %rcx, %rcx
    je 1f
    movq (%rdx), %rax
1:
    xorl %eax, %eax
    ret
    .seh_endproc

probe write32
    movl %edx, (%rcx)
    movl %edx, %eax
    ret
    .seh_endproc

probe lea32
    leal literal(%rip), %eax
    ret
    .seh_endproc

probe address_only
    leaq literal+0x100000(%rip), %rax
    ret
    .seh_endproc

probe direct32
    movl literal+1(%rip), %eax
    ret
    .seh_endproc

probe direct_rx
    movzwl code_data(%rip), %eax
    ret
    .seh_endproc

probe select_rx
    leaq code_data(%rip), %rax
    movzwl (%rax,%rcx), %eax
    ret
    .seh_endproc

probe image_flags
    cmpq %rdx, %rcx
    leaq literal(%rip), %r8
    movzwl (%r8), %eax
    adcq $0, %rax
    ret
    .seh_endproc

probe update
    addl $1, (%rcx)
    movl (%rcx), %eax
    ret
    .seh_endproc

probe bad_write
    movl %edx, literal(%rip)
    ret
    .seh_endproc

probe bad_relocation
    movl pointer-1(%rip), %eax
    ret
    .seh_endproc

probe bad_end
    movl pointer+6(%rip), %eax
    ret
    .seh_endproc

probe high_byte
    movq %rdx, %rax
    movb literal+2(%rip), %ah
    movw literal(%rip), %cx
    addq %rcx, %rax
    ret
    .seh_endproc

.section .literal,"dr"
literal:
    .byte 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0
pointer:
    .quad literal

.section .pool,"xr"
code_data:
    .byte 0x81,0x72,0x63,0x54

.section .mutable,"dw"
    .quad 0x1234

.text
probe frame_join
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movq %rdx, -8(%rbp)
    testq %rcx, %rcx
    je 1f
    movq %rbp, %r8
    subq $8, %r8
    jmp 2f
1:
    movl $2, %eax
    leaq (%rsp,%rax,4), %r8
2:
    movq (%r8), %rax
    leave
    ret
    .seh_endproc

probe mixed_join
    movq %rdx, 8(%rsp)
    leaq 8(%rsp), %r8
    testq %rcx, %rcx
    je 1f
    movq %rcx, %r8
1:
    movl (%r8), %eax
    ret
    .seh_endproc

probe loop_pointer
    movq %rdx, 8(%rsp)
    leaq 8(%rsp), %r8
1:
    movl (%r8), %eax
    testq %rcx, %rcx
    je 2f
    movq %rcx, %r8
    xorl %ecx, %ecx
    jmp 1b
2:
    ret
    .seh_endproc

probe new_rsp
    movq %rsp, %r9
    movq %rcx, %rsp
    movl (%rsp), %eax
    movq %r9, %rsp
    ret
    .seh_endproc

probe lost_origin
    movq %rsp, %r8
    movl %edx, %r8d
    leaq literal(%rip), %rax
    addq %r8, %rax
    movl (%rax), %eax
    ret
    .seh_endproc

probe stack_fault
    movq %rsp, %r8
    movq (%r8), %rax
    ret
    .seh_endproc

probe implicit_push
    pushq %rsp
    popq %rax
    ret
    .seh_endproc

probe implicit_pop
    popq %rax
    ret
    .seh_endproc

probe implicit_leave
    leave
    ret
    .seh_endproc

probe different_offsets
    movq %rdx, 8(%rsp)
    movq %rcx, 16(%rsp)
    leaq 8(%rsp), %r8
    testq %rcx, %rcx
    je 1f
    addq $8, %r8
1:
    movq (%r8), %rax
    ret
    .seh_endproc

probe escape_stack
    # The test supplies the distance from entry RSP to an actual PE constant.
    movabsq $0x123456789abcdef0, %r8
    addq %rsp, %r8
    movl (%rcx), %eax
    testq %rdx, %rdx
    je 1f
    movl (%r8), %eax
1:
    ret
    .seh_endproc
