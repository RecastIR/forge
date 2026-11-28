# Assemble with the same traversal used by executable-bounded-call.s.
.text
.globl budget_runner, budget_tail_site, budget_table, budget_tail
.seh_proc budget_runner
budget_runner:
    runner_frame
    .rept 4
        table_loop budget_table
    .endr
    table_loop budget_tail, budget_tail_site
    runner_return
.seh_endproc

.data
.p2align 3
budget_table:
    .quad -1
    .rept 1024
        .quad two
    .endr
    .quad 0
budget_tail:
    .quad -1, 0
