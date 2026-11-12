# Append to the compiler output for a single leaf named entry.
# Only metadata is added. The label marks the exact end of its .text.
.text
end_entry:
.section .xdata,"dr"
.p2align 2
leaf_info:
.byte 1, 0, 0, 0
.section .pdata,"dr"
.rva entry, end_entry, leaf_info
