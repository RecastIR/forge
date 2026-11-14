.text
# A literal pool before the export exercises negative disp32 and computed RX reads.
.Lbytes:
    .byte 0x80, 0xff
    .short 0x8001
    .long 0x80000001
    .quad 0x8000000000000003
.globl image_widths
.seh_proc image_widths
image_widths:
    .seh_endprologue
    leaq .Lbytes(%rip), %r8
    andl $1, %ecx
    movsbq (%r8,%rcx), %rax
    movzwl .Lbytes+2(%rip), %r9d
    addq %r9, %rax
    movslq .Lbytes+4(%rip), %r9
    addq %r9, %rax
    movq .Lbytes+8(%rip), %r9
    xorq %r9, %rax
    ret
    .seh_endproc
.section .drectve
.ascii " -export:image_widths"
