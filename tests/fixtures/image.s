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

probe partial_relocation
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
counter:
    .quad 0x1234
counter_ptr:
    .quad counter

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

probe pointer_va
    movq counter_ptr(%rip), %rax
    ret
    .seh_endproc

probe update_alias
    movq counter_ptr(%rip), %r8
    movq %r8, 8(%rsp)
    movq 8(%rsp), %r9
    addq %rcx, (%r9)
    movq counter(%rip), %rax
    ret
    .seh_endproc

probe increment_counter
    incq counter(%rip)
    movq counter(%rip), %rax
    ret
    .seh_endproc

probe exchange_byte
    movzbl (%rcx), %eax
    movb %dl, (%rcx)
    ret
    .seh_endproc

probe load64
    movq (%rcx), %rax
    ret
    .seh_endproc

probe opaque_store
    movq %rbx, (%rcx)
    xorl %eax, %eax
    ret
    .seh_endproc

probe store_middle
    movw %dx, 3(%rcx)
    movq (%rcx), %rax
    ret
    .seh_endproc

probe maybe_write
    testq %rdx, %rdx
    je 1f
    movl $1, (%rcx)
1:
    xorl %eax, %eax
    ret
    .seh_endproc

probe increment_counter_reg
    leaq counter(%rip), %r8
    incq (%r8)
    movq (%r8), %rax
    ret
    .seh_endproc

probe maybe_write_literal
    leaq literal(%rip), %r8
    testq %rcx, %rcx
    je 1f
    movb %dl, (%r8)
1:
    movzbl (%r8), %eax
    ret
    .seh_endproc

# A local and an immutable field reach the same load through CMOV and a stack save.
probe choose_local_or_image
    movq %rdx, 8(%rsp)
    leaq 8(%rsp), %r8
    leaq literal+1(%rip), %r9
    testq %rcx, %rcx
    cmovneq %r9, %r8
    pushq %r8
    popq %r9
    movl (%r9), %eax
    ret
    .seh_endproc

probe partial_spill
    leaq literal(%rip), %r8
    movq %r8, 8(%rsp)
    movb %cl, 9(%rsp)
    movq 8(%rsp), %r9
    movl (%r9), %eax
    ret
    .seh_endproc

probe spill_numeric_alias
    leaq literal(%rip), %r8
    movq %r8, 8(%rsp)
    # A numeric guest VA aliases the first shadow slot.
    movl $0x70000fe0, %r9d
    addl $4, (%r9)
    movq 8(%rsp), %rax
    movl (%rax), %eax
    ret
    .seh_endproc

probe indirect_spill_store
    leaq literal(%rip), %r8
    movq %r8, 8(%rsp)
    movq %rdx, (%rcx)
    movq 8(%rsp), %rax
    movl (%rax), %eax
    ret
    .seh_endproc

probe incomplete_spill_join
    movq %rdx, 8(%rsp)
    testq %rcx, %rcx
    je 1f
    leaq literal(%rip), %r8
    movq %r8, 8(%rsp)
1:
    movq 8(%rsp), %rax
    movl (%rax), %eax
    ret
    .seh_endproc

probe walk_image
    leaq literal(%rip), %r8
    testq %rcx, %rcx
    je 2f
1:
    addq $1, %r8
    subq $1, %rcx
    jne 1b
2:
    movl (%r8), %eax
    ret
    .seh_endproc

probe wide_mask
    andl $15, %ecx
    leaq literal(%rip), %r8
    movzbl (%r8,%rcx), %eax
    ret
    .seh_endproc

probe reloaded_stack_va
    movq %rsp, 8(%rsp)
    movq 8(%rsp), %r8
    movabsq $0x123456789abcdef0, %rax
    addq %rax, %r8
    movl (%r8), %eax
    ret
    .seh_endproc

probe joined_stack_va
    movq %rdx, 8(%rsp)
    leaq 8(%rsp), %r8
    testq %rcx, %rcx
    je 1f
    movabsq $0x123456789abcdef0, %rax
    leaq (%rsp,%rax), %r8
1:
    movl (%r8), %eax
    ret
    .seh_endproc
