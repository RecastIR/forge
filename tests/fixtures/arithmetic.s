.text
.macro function name
  .globl \name
  .seh_proc \name
\name:
  .seh_endprologue
.endm
.macro finish
  retq
  .seh_endproc
.endm

function entry
  movq %rcx, %rax
  subq %rdx, %rax
  finish

function product
  movq %rcx, %rax
  imulq %rdx, %rax
  finish

function expr
  leaq -7(%rcx,%rdx,4), %rax
  addq $-128, %rax
  finish

function low_product
  movl %ecx, %eax
  imull %edx, %eax
  subl $1, %eax
  finish

function select_signed
  cmpq %rdx, %rcx
  jge 1f
  movq %rcx, %rax
  jmp 2f
1:
  movq %rdx, %rax
2:
  finish

function select_unsigned
  cmpl %edx, %ecx
  jb 1f
  xorl %eax, %eax
  retq
1:
  movq $-1, %rax
  finish

function equal
  cmpq %rdx, %rcx
  jne 1f
  movl $1, %eax
  retq
1:
  xorq %rax, %rax
  finish

# Exercise a volatile scratch register, 32-bit LEA, and immediate encodings.
function immediates
  leal -3(%rcx,%rdx,8), %r8d
  movl %r8d, %eax
  subl $0x12345678, %eax
  addq $-100000, %rax
  finish

function zero64
  subq %rax, %rax
  finish

function zero32
  subl %ecx, %ecx
  movq %rcx, %rax
  finish

.globl uncovered
uncovered:
  retq
