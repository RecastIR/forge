# Freestanding AMD64 function, unwind record, TLS template and callback.
.text
.globl entry
.seh_proc entry
entry:
  subq $40, %rsp
  .seh_stackalloc 40
  .seh_endprologue
  addq $40, %rsp
  retq
.seh_endproc

.section .tls,"dw"
tls_start:
  .long 42
tls_end:

.data
tls_index:
  .long 0

.section .rdata,"dr"
.p2align 3
callbacks:
  .quad entry, 0
.globl _tls_used
_tls_used:
  .quad tls_start, tls_end, tls_index, callbacks
  .long 4, 0
