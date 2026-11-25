# Native fault and signatureless ABI probes. Each entry is lifted independently.
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

.macro boundary suffix,src,dst
probe access_\suffix
    mov\suffix %\src, (%rcx)
    movl $0, %eax
    mov\suffix (%rcx), %\dst
    ret
    .seh_endproc
.endm

boundary b,dl,al
boundary w,dx,ax
boundary l,edx,eax
boundary q,rdx,rax

probe checked_read
    movq %rdx, 8(%rsp)
    movq (%rcx), %rax
    ret
    .seh_endproc

probe conditional_read
    movb %dl, 8(%rsp)
    testq %rcx, %rcx
    je 1f
    movb %dl, 9(%rsp)
1:
    movzwl 8(%rsp), %eax
    ret
    .seh_endproc

probe shifted_rsp
    movq %rdx, %rax
    leaq (%rsp,%rcx), %rsp
    ret
    .seh_endproc

probe restore_rsp
    subq $24, %rsp
    movq %rcx, (%rsp)
    movq (%rsp), %rax
    addq $24, %rsp
    ret
    .seh_endproc

probe moved_rsp_slot
    subq $16, %rsp
    movq %rdx, (%rsp,%rcx)
    movq (%rsp,%rcx), %rax
    addq $16, %rsp
    ret
    .seh_endproc

probe wrap_index
    # Large index products can wrap into a legal address.
    movq %rdx, 8(%rsp,%rcx,8)
    movq 8(%rsp), %rax
    ret
    .seh_endproc

probe entry_memory_loop
1:
    testq %rcx, %rcx
    je 2f
    movq %rdx, 8(%rsp)
    xorq %rcx, %rcx
    jmp 1b
2:
    movq 8(%rsp), %rax
    ret
    .seh_endproc

probe parallel_memory_edges
    cmpq %rdx, %rcx
    movq %rcx, 8(%rsp)
    je 1f
1:
    movq 8(%rsp), %rax
    adcq %rdx, %rax
    ret
    .seh_endproc

# Save valid RSP while testing every view, including SPL. Observe the parent
# after narrow writes and again after its doubleword write via legacy slots.
.macro aliases name,wide,dword,word,low,scratch
probe alias_\name
    movq %rsp, %\scratch
    movabsq $0x123456789abcdef0, %\wide
    movw $0xcdef, %\word
    movb $0x21, %\low
    movq %\wide, 8(%\scratch)
    movl $0x87654321, %\dword
    movq %\wide, %r9
    movq 8(%\scratch), %r8
    movq %\scratch, %rsp
    ret
    .seh_endproc
.endm

aliases ax,rax,eax,ax,al,rsi
aliases cx,rcx,ecx,cx,cl,rsi
aliases dx,rdx,edx,dx,dl,rsi
aliases r8,r8,r8d,r8w,r8b,rsi
aliases r9,r9,r9d,r9w,r9b,rsi
aliases r10,r10,r10d,r10w,r10b,rsi
aliases r11,r11,r11d,r11w,r11b,rsi
aliases sp,rsp,esp,sp,spl,rsi
aliases bp,rbp,ebp,bp,bpl,rsi
aliases bx,rbx,ebx,bx,bl,rsi
aliases si,rsi,esi,si,sil,rdi
aliases di,rdi,edi,di,dil,rsi
aliases r12,r12,r12d,r12w,r12b,rsi
aliases r13,r13,r13d,r13w,r13b,rsi
aliases r14,r14,r14d,r14w,r14b,rsi
aliases r15,r15,r15d,r15w,r15b,rsi

probe high_bytes
    movl $0x76543210, %ebx
    movb %ah, %bh
    movb %ch, %al
    movb %dh, %ah
    movzwl %ax, %r11d
    movq %rbx, %rax
    ret
    .seh_endproc

probe store_immediates
    movq $-1, 8(%rsp)
    movl $0x12345678, 10(%rsp)
    movw $0x5678, 11(%rsp)
    movb $0x34, 12(%rsp)
    movq 8(%rsp), %rax
    ret
    .seh_endproc

# The alternate FF /6 and 8F /0 register encodings also exercise ordering
# when the destination of POP is RSP itself.
probe push_pop_order
    pushq %rbp
    movq %rsp, %rbp
    cmpq %rdx, %rcx
    .byte 0xff, 0xf4   # push rsp
    pushq %rcx
    .byte 0x8f, 0xc0   # pop rax
    popq %rsp
    pushq $-128
    popq %r9
    pushq $-2147483648
    popq %r10
    movq (%rbp), %r11
    movq %r11, (%rbp)
    leave
    adcq %r9, %rax
    addq %r10, %rax
    ret
    .seh_endproc

probe push_rsp_value
    pushq %rsp
    popq %rax
    ret
    .seh_endproc

probe push_rsp_value_modrm
    .byte 0xff, 0xf4   # push rsp (FF /6)
    popq %rax
    ret
    .seh_endproc

probe rsp_pop_destination
    movq %rsp, %r8
    subq $32, %rsp
    pushq %r8
    .byte 0x8f, 0xc4   # pop rsp: the value from the stack wins
    movq %rcx, %rax
    ret
    .seh_endproc

probe frame_layout
    movq %rsp, %r8
    andl $15, %r8d
    pushq %rbp
    movq %rsp, %rbp
    movq %rbp, %rax
    andl $15, %eax
    addq %r8, %rax
    movq %rcx, 16(%rbp)
    movq %rdx, 40(%rbp)
    movq 16(%rbp), %r8
    movq 40(%rbp), %r9
    addq %r8, %rax
    subq %r9, %rax
    leave
    ret
    .seh_endproc

probe saved_registers
    pushq %r12
    movq %r13, %r12
    movq %rbx, 8(%rsp,%rcx)   # rcx=8 selects the first home slot
    movq %rdx, %rbx
    movq %rbx, %rax
    movq 8(%rsp,%rcx), %rbx
    popq %r12
    ret
    .seh_endproc

probe register_save
    movq %rbx, %r10
    movq %rcx, %rbx
    movq %r10, %rbx
    xorl %r10d, %r10d
    movq %rdx, %rax
    ret
    .seh_endproc

probe opaque_scratch
    movq %rbx, %r10
    movq %rdx, %rax
    ret
    .seh_endproc

probe opaque_arithmetic
    movq %rbx, %rax
    addq %rdx, %rax
    ret
    .seh_endproc

probe partial_opaque_return
    movb $1, %r13b
    movq %r13, %rax
    ret
    .seh_endproc

probe swapped_saves
    pushq %rsi
    pushq %rdi
    popq %rsi
    popq %rdi
    movq %rcx, %rax
    ret
    .seh_endproc

probe corrupt_save
    pushq %rbp
    movb $0, (%rsp,%rcx)
    popq %rbp
    movq %rdx, %rax
    ret
    .seh_endproc

probe reordered_save
    pushq %rbp
    movb 1(%rsp), %al
    movb %al, (%rsp)
    popq %rbp
    movq %rdx, %rax
    ret
    .seh_endproc

probe early_clobber
    pushq %rbx
    xorl %ebx, %ebx
    testq %rcx, %rcx
    je 1f
    popq %rbx
    jmp 2f
1:
    addq $8, %rsp
2:
    movq %rdx, %rax
    ret
    .seh_endproc

probe leak_return
    pushq %rbp
    movq (%rsp), %rax
    popq %rbp
    ret
    .seh_endproc

probe leak_address
    pushq %rbp
    popq %r8
    movq (%r8), %rax
    ret
    .seh_endproc

probe frame_loop
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movq %rdx, -8(%rbp)
    andl $7, %ecx
    je 2f
1:
    subq %rcx, %rsp
    movq -8(%rbp), %rax
    addq %rcx, %rax
    movq %rax, -8(%rbp)
    decl %ecx
    jne 1b
2:
    movq -8(%rbp), %rax
    leave
    ret
    .seh_endproc

probe pop_uninitialized
    subq $8, %rsp
    popq %rax
    ret
    .seh_endproc

probe bad_teardown
    pushq %rcx
    movq %rcx, %rax
    ret
    .seh_endproc

probe reserved_pop
    popq %rax
    pushq %rax
    ret
    .seh_endproc

probe push_boundary
    movq %rsp, %r8
    movq %rcx, %rsp
    pushq %rdx
    movq (%rsp), %rax
    popq %rdx
    movq %r8, %rsp
    ret
    .seh_endproc

probe save_all_nonvolatiles
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rcx, %rbx
    movq %rcx, %rbp
    movq %rcx, %rsi
    movq %rcx, %rdi
    movq %rcx, %r12
    movq %rcx, %r13
    movq %rcx, %r14
    movq %rcx, %r15
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    movq %rdx, %rax
    ret
    .seh_endproc

probe read_modify_uninitialized
    subq $8, %rsp
    movw %cx, (%rsp)
    addl $1, (%rsp)
    movl (%rsp), %eax
    addq $8, %rsp
    ret
    .seh_endproc

probe implicit_extensions
    movq %rcx, %rax
    cmpq %rdx, %rcx
    cwde
    cdqe
    adcq $0, %rax
    ret
    .seh_endproc

.macro direct_caller name, target
probe \name
    subq $40, %rsp
    callq \target
    addq $40, %rsp
    ret
    .seh_endproc
.endm

# Each caller resumes nine bytes after its entry. Both active nested return
# slots have initialized neighbors to distinguish overlap checks from validity.
.macro call_boundary suffix, src, dst
direct_caller call_slot_\suffix, call_bridge_\suffix
direct_caller call_bridge_\suffix, call_access_\suffix
probe call_access_\suffix
    movq $-1, -8(%rsp)
    movq $-1, 8(%rsp)
    movq $-1, 40(%rsp)
    movq $-1, 56(%rsp)
    testq %rdx, %rdx
    je 1f
    cmpq $2, %rdx
    je 2f
    mov\suffix %\src, (%rcx)
    jmp 1f
2:
    inc\suffix (%rcx)
1:
    xorl %eax, %eax
    mov\suffix (%rcx), %\dst
    ret
    .seh_endproc
.endm

call_boundary b, dl, al
call_boundary w, dx, ax
call_boundary l, edx, eax
call_boundary q, rdx, rax

probe call_released
    subq $40, %rsp
    callq call_result
1:
    movq -8(%rsp), %r10
    movq %rdx, -8(%rsp)
    movq -8(%rsp), %rax
    leaq 1b(%rip), %rdx
    subq %rdx, %r10
    addq %r10, %rax
    addq $40, %rsp
    ret
    .seh_endproc

probe call_result
    movq %rcx, %rax
    ret
    .seh_endproc

direct_caller call_bad_teardown, bad_teardown

probe call_bad_shadow
    subq $8, %rsp
    callq call_result
    addq $8, %rsp
    ret
    .seh_endproc

probe call_misaligned
    subq $32, %rsp
    callq call_result
    addq $32, %rsp
    ret
    .seh_endproc

probe call_depth
    testq %rcx, %rcx
    je 1f
    subq $40, %rsp
    decq %rcx
    callq call_depth
    addq $40, %rsp
    incq %rax
    ret
1:
    xorl %eax, %eax
    ret
    .seh_endproc

probe call_nonvolatile
    pushq %rbx
    subq $32, %rsp
    movq %rcx, %rbx
    callq call_clobber
    addq $32, %rsp
    popq %rbx
    ret
    .seh_endproc

probe call_clobber
    movq %rdx, %rbx
    movq %rcx, %rax
    ret
    .seh_endproc

probe call_stack_argument
    subq $56, %rsp
    testq %rcx, %rcx
    je 1f
    movq %rdx, 32(%rsp)
1:
    callq call_fifth
    addq $56, %rsp
    ret
    .seh_endproc

probe call_fifth
    movq 40(%rsp), %rax
    ret
    .seh_endproc

probe call_carry
    leaq -40(%rsp), %rsp
    cmpq %rdx, %rcx
    callq call_add_carry
    leaq 40(%rsp), %rsp
    adcq $0, %rax
    ret
    .seh_endproc

probe call_add_carry
    movq %rcx, %rax
    adcq %rdx, %rax
    ret
    .seh_endproc

probe call_preserves_carry
    leaq -40(%rsp), %rsp
    callq call_result
    cmpq %rdx, %rcx
    callq call_result
    leaq 40(%rsp), %rsp
    adcq $0, %rax
    ret
    .seh_endproc

probe call_narrow
    subq $40, %rsp
    callq call_byte
    movzbl %al, %eax
    addq $40, %rsp
    ret
    .seh_endproc

probe call_byte
    movb %cl, %al
    ret
    .seh_endproc

direct_caller call_missing_register, call_fourth

probe call_fourth
    movq %r9, %rax
    ret
    .seh_endproc

probe call_missing_flag
    subq $40, %rsp
    cmpq %rdx, %rcx
    callq call_clear_af
    lahf
    addq $40, %rsp
    ret
    .seh_endproc

probe call_clear_af
    movq %rcx, %rax
    andq %rdx, %rax
    ret
    .seh_endproc

probe opaque_return_rsp
    movq %rcx, %rax
    movq %rbx, %rsp
    ret
    .seh_endproc

# The first call can enter with no defined CF; the second has a known CF.
# One return path preserves it and the other produces a different value.
probe call_join
    leaq -40(%rsp), %rsp
    movq %rcx, %r9
    callq call_join_helper
    movq %r9, %rcx
    cmpq %rdx, %rcx
    callq call_join_helper
    setb %al
    movzbl %al, %eax
    leaq 40(%rsp), %rsp
    ret
    .seh_endproc

probe call_undefined_join
    leaq -40(%rsp), %rsp
    callq call_join_helper
    setb %al
    movzbl %al, %eax
    leaq 40(%rsp), %rsp
    ret
    .seh_endproc

probe call_join_helper
    decq %rcx
    je 1f
    cmpq $3, %rdx
    movq %rdx, 8(%rsp)
1:
    ret
    .seh_endproc

direct_caller call_return_copy, call_copy_slot

probe call_copy_slot
    pushq %rbx
    movq 8(%rsp), %rbx
    movq %rbx, 16(%rsp)
    xorl %eax, %eax
    addq 16(%rsp), %rax
    popq %rbx
    ret
    .seh_endproc

# A callee can replace both a volatile register and a caller's saved pointer
# through an alias. Neither access after CALL may retain its old stack routing.
probe call_pointer_alias
    subq $56, %rsp
    leaq 48(%rsp), %r8
    movq %r8, 40(%rsp)
    leaq 40(%rsp), %rcx
    leaq call_constant(%rip), %rdx
    callq call_redirect
    movq 40(%rsp), %r10
    movq (%r8), %rax
    addq (%r10), %rax
    addq $56, %rsp
    ret
    .seh_endproc

probe call_redirect
    movq %rdx, (%rcx)
    movq %rdx, %r8
    ret
    .seh_endproc

# These entries exercise recovery without executing the recursive or invalid calls.
direct_caller recovery_mutual_a, recovery_mutual_b
probe recovery_mutual_b
    subq $40, %rsp
    testl %ecx, %ecx
    jz .Lmutual_return
    callq recovery_mutual_a
    callq recovery_mutual_b
.Lmutual_return:
    addq $40, %rsp
    ret
    .seh_endproc

probe recovery_no_base
    subq $40, %rsp
    callq recovery_no_base
    callq recovery_invalid_callee
    .seh_endproc

direct_caller recovery_invalid_entry, recovery_invalid_callee
direct_caller recovery_invalid_callee, recovery_invalid_callee+1
direct_caller recovery_unrecorded, entry

direct_caller recovery_mov_source, mov_source
direct_caller recovery_cmp_input, cmp_input
direct_caller recovery_store_source, store_source
direct_caller recovery_extend_source, extend_source
direct_caller recovery_cmov_source, cmov_source
direct_caller recovery_saved_input, saved_input

mov_source:
    movq %r16, %rax
    ret
cmp_input:
    cmpq %rax, %r16
    ret
store_source:
    movq %r16, (%rcx)
    ret
extend_source:
    movzbl %r16b, %eax
    ret
cmov_source:
    cmoveq %r16, %rax
    ret
saved_input:
    movzbl %bl, %eax
    ret

.section .rdata,"dr"
call_constant:
    .quad 0x12345678

.text
# Leave the remaining bytes untouched before a read that will cross a stack boundary.
probe scalar_boundary_prefix
    testq %rdx, %rdx
    jne 1f
    movb $1, (%rcx)
    xorl %eax, %eax
    addl (%rcx), %eax
    ret
1:
    movb %bl, (%rcx)
    cmpq $1, %rdx
    jne 2f
    # A plain MOV may copy the opaque saved byte, even though arithmetic cannot use it.
    movw (%rcx), %r8w
    xorl %eax, %eax
    ret
2:
    movzwl (%rcx), %eax
    ret
    .seh_endproc

# Preserve the Windows nonvolatile destination register. Exercise count, final
# destination, incoming carry, and a qword pattern with distinct bytes.
probe repeat_qword
    pushq %rdi
    subq $32, %rsp
    movq %rsp, %rdi
    testq %rcx, %rcx
    jz 1f
    std
    addq $16, %rdi
1:
    movq %rdx, %rax
    cmpq $1, %rdx
    movl $3, %ecx
    rep stosq
    cld
    setb %r9b
    movzbl %r9b, %r9d
    movq (%rsp), %rax
    addq 8(%rsp), %rax
    addq 16(%rsp), %rax
    addq %rcx, %rax
    addq %r9, %rax
    subq %rsp, %rdi
    addq %rdi, %rax
    addq $32, %rsp
    popq %rdi
    ret
    .seh_endproc

probe repeat_unconsumed
    rep stosq
    movl $42, %eax
    ret
    .seh_endproc

probe repeat_opaque_destination
    movq %rdi, %r11
    movl $17, %eax
    rep stosq
    movq %r11, %rdi
    ret
    .seh_endproc

# The zero-count predecessor defines neither RDI nor RAX.
probe repeat_join
    pushq %rdi
    subq $8, %rsp
    movq $17, (%rsp)
    testq %rcx, %rcx
    je 1f
    movq %rsp, %rdi
    movq %rdx, %rax
    movl $1, %ecx
1:
    rep stosq
    movq (%rsp), %rax
    addq $8, %rsp
    popq %rdi
    ret
    .seh_endproc

# Saving an opaque nonvolatile through RAX requires preserving its byte origins.
probe repeat_join_opaque
    pushq %rdi
    pushq %rbx
    testq %rcx, %rcx
    je 1f
    movq %rbx, %rax
    movq $0, (%rsp)
    movq %rsp, %rdi
    movl $19, %ebx
1:
    rep stosq
    popq %rbx
    popq %rdi
    movl $42, %eax
    ret
    .seh_endproc

probe repeat_to_address
    movq %rdi, %r11
    movq %rcx, %rdi
    movq %rdx, %rcx
    movabsq $0x123456789abcdef0, %rax
    rep stosq
    movq %r11, %rdi
    ret
    .seh_endproc

probe atomic_lock
    subq $24, %rsp
    movq %rdx, (%rsp)
    movq %rcx, %rax
    movabsq $0x123456789abcdef0, %r9
    lock cmpxchgq %r9, (%rsp)
    movl $0x42, %r8d
    xchgq %r8, (%rsp)
    setb %cl
    sete %r10b
    movzbl %cl, %ecx
    movzbl %r10b, %r10d
    addq %r8, %rax
    addq (%rsp), %rax
    addq %rcx, %rax
    leaq (%rax,%r10,2), %rax
    addq $24, %rsp
    ret
    .seh_endproc

probe atomic_readonly
    movq (%rcx), %r8
    movq $-1, %rax
    lock cmpxchgq %rdx, (%rcx)
    ret
    .seh_endproc

probe atomic_unaligned
    movq %rdx, 8(%rsp)
    movq %rdx, 16(%rsp)
    xchgq %rcx, 9(%rsp)
    movq %rcx, %rax
    ret
    .seh_endproc

# Only the original CALL continuation authorizes reading these executable bytes.
probe tail_caller
    subq $40, %rsp
    callq tail_only
    nop
    addq $40, %rsp
    ret
    .seh_endproc

probe tail_only
    jmp tail_reader
    .seh_endproc

probe tail_reader
    movq (%rsp), %r10
    movzbl (%r10), %eax
    ret
    .seh_endproc

# Check every continuation, including the first one after the fan-in exceeds eight.
.macro fan_in name, count
probe \name
    subq $40, %rsp
    .irp n,1,2,3,4,5,6,7,8,9
        .if \n <= \count
            callq tail_wrapper_\n
            nop
            cmpl $0x90, %eax
            jne 1f
        .endif
    .endr
    jmp 2f
1:
    xorl %eax, %eax
2:
    addq $40, %rsp
    ret
    .seh_endproc
.endm

fan_in tail_eight, 8
fan_in tail_nine, 9

.irp n,1,2,3,4,5,6,7,8,9
    .seh_proc tail_wrapper_\n
tail_wrapper_\n:
    .seh_endprologue
    jmp tail_reader
    .seh_endproc
.endr
