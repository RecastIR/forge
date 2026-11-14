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
