.text
.globl entry
.seh_proc entry
entry:
    .seh_endprologue
    cmpq $1, %rcx
    ja .Ldirect
    leaq .Ltable(%rip), %r8
    movslq (%r8,%rcx,4), %rax
    addq %r8, %rax
.Ljump:
    jmp *%rax
    .fill 3, 1, 0xcc
.Lother_jump:
    jmp *%rax
    .fill 3, 1, 0xcc
.Ldirect:
    movl $1, %eax
    ret
.seh_endproc

.globl direct_only
.seh_proc direct_only
direct_only:
    .seh_endprologue
    movl $2, %eax
    ret
.seh_endproc

.section .rdata,"dr"
.Ltable:
    .long .Ldirect-.Ltable, .Ldirect-.Ltable
.p2align 3
.globl _load_config_used
_load_config_used:
    .long 232
    .org _load_config_used + 144
    .long 0x100000              # IMAGE_GUARD_RETPOLINE_PRESENT
    .org _load_config_used + 224
    .secrel32 .Ldvrt
    .secidx .Ldvrt
    .short 0

.section .dvrt,"dr"
.Ldvrt:
    .long 1, 24                 # Version, payload size.
    .quad 5                     # IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH
    .long 12                    # Size of the page block.
    .rva entry                  # Entry is at the beginning of the first code page.
    .long 12
    .short .Ljump-entry, .Lother_jump-entry
