.text
.globl call_leaves
.seh_proc call_leaves
call_leaves:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    call leaf_add
    movq %rax, %rcx
    call leaf_add
    movq %rax, %rcx
    call leaf_abs
    call leaf_count
    movq %rax, 32(%rsp)
    leaq 32(%rsp), %rcx
    call leaf_store
    movq 32(%rsp), %rax
    addq $40, %rsp
    ret
.seh_endproc

# These helpers deliberately have no SEH directives.
leaf_add:
    leaq (%rcx,%rdx), %rax
    ret

leaf_abs:
    movq %rcx, %rax
    testq %rax, %rax
    js .Lnegative
    ret
.Lnegative:
    negq %rax
    ret

leaf_count:
    andl $3, %edx
    je .Ldone
.Lagain:
    incq %rax
    decl %edx
    jne .Lagain
.Ldone:
    ret

leaf_store:
    addq $7, (%rcx)
    ret

.section .drectve
.ascii " -export:call_leaves"
