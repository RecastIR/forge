# The fixture generator selects a different PE header entry for each standalone test.
.text
.macro begin name
.globl \name
.seh_proc \name
\name:
    subq $56, %rsp
    .seh_stackalloc 56
    .seh_endprologue
.endm

.macro finish
    addq $56, %rsp
    ret
.seh_endproc
.endm

.macro handle selector
    movl $\selector, %ecx
    call *__imp_GetStdHandle(%rip)
    movq %rax, %rcx
.endm

.macro write_args buffer=payload, count=4
    leaq \buffer(%rip), %rdx
    movl $\count, %r8d
    movl $-1, 40(%rsp)
    leaq 40(%rsp), %r9
    movq $0, 32(%rsp)
.endm

.macro write
    call *__imp_WriteFile(%rip)
.endm

# Return the guest-observed Win32 error only if WriteFile returned FALSE and,
# for synchronous writes with a writable count, initialized that DWORD.
.macro report_error expected_count=0
    testl %eax, %eax
    jnz .Lunexpected\@
    .if \expected_count >= 0
    cmpl $\expected_count, 40(%rsp)
    jne .Lunexpected\@
    .endif
    call *__imp_GetLastError(%rip)
    jmp .Ldone\@
.Lunexpected\@:
    movl $254, %eax
.Ldone\@:
.endm

.macro binary_write name, selector
begin \name
    handle \selector
    write_args
    # The upper half of the count register must be ignored for a Windows DWORD.
    movabsq $0x8765432100000004, %r8
    write
    testl %eax, %eax
    jz .Lfailed\@
    movl 40(%rsp), %eax
    jmp .Ldone\@
.Lfailed\@:
    call *__imp_GetLastError(%rip)
.Ldone\@:
finish
.endm

binary_write binary_stdout, -11
binary_write binary_stderr, -12

begin bad_handle
    movl $1, %ecx
    write_args
    write
    report_error
finish

begin stdin_write
    handle -10
    write_args
    write
    report_error
finish

begin bad_selector
    handle -13
    cmpq $-1, %rax
    jne .Lselector_failed
    call *__imp_GetLastError(%rip)
    jmp .Lselector_done
.Lselector_failed:
    movl $254, %eax
.Lselector_done:
finish

begin stdin_handle
    handle -10
    cmpq $2, %rax
    jbe .Lstdin_failed
    cmpq $-1, %rax
    je .Lstdin_failed
    xorl %eax, %eax
    jmp .Lstdin_done
.Lstdin_failed:
    movl $254, %eax
.Lstdin_done:
finish

begin bad_buffer
    handle -11
    write_args long_prefix, 65538
    write
finish

begin large_output
    handle -11
    write_args long_prefix, 65537
    write
    testl %eax, %eax
    jz .Llarge_failed
    movl 40(%rsp), %eax
    subl $65537, %eax
    jz .Llarge_done
.Llarge_failed:
    movl $254, %eax
.Llarge_done:
finish

begin bad_count
    handle -12
    write_args
    # One valid writable byte followed by the protected PE entry return slot.
    leaq 55(%rsp), %r9
    write
finish

begin null_count
    handle -11
    write_args
    xorl %r9d, %r9d
    write
    report_error -1
finish

begin overlapped
    handle -11
    write_args
    movq $1, 32(%rsp)
    write
    report_error -1
finish

begin zero_length
    handle -12
    write_args
    xorl %r8d, %r8d
    xorl %edx, %edx
    write
    testl %eax, %eax
    jz .Lzero_failed
    movl 40(%rsp), %eax
    jmp .Lzero_done
.Lzero_failed:
    movl $254, %eax
.Lzero_done:
finish

.macro failed_write name, selector, count
begin \name
    handle \selector
    write_args payload, \count
    write
    report_error
finish
.endm

failed_write host_failure, -11, 4
failed_write stderr_failure, -12, 4
failed_write zero_stdout_failure, -11, 0
failed_write zero_stderr_failure, -12, 0

begin limited_file
    handle -11
    write_args
    write
    report_error 2
finish

begin direct_exit
    movl $42, %ecx
    call *__imp_ExitProcess(%rip)
    handle -11
    write_args
    write
finish

begin exit_or_write
    testl %ecx, %ecx
    jz .Lmarker
    movl $0xcafe002a, %ecx
    call *__imp_ExitProcess(%rip)
.Lmarker:
    handle -12
    write_args
    write
finish

begin nested_exit
    movl $1, %ecx
    call exit_or_write
    handle -11
    write_args
    write
finish

begin alternate_edge
    xorl %ecx, %ecx
    call exit_or_write
    movl $9, %eax
finish

# A guest call can also be the last instruction of its unwind-backed extent.
begin call_at_end
    call exit_42
.seh_endproc

begin exit_42
    movl $42, %ecx
    call *__imp_ExitProcess(%rip)
.seh_endproc

# The post-call PC has an independent branch entry.
begin branch_past_call
    xorl %eax, %eax
    testl %eax, %eax
    jz .Lafter_exit
    call call_at_end
.Lafter_exit:
    movl $23, %eax
finish

begin recursive_return
    movl $3, %ecx
    call count_returns
    addl $10, %eax
finish

begin count_returns
    testl %ecx, %ecx
    jz .Lbase
    subl $1, %ecx
    call count_returns
    addl $1, %eax
    jmp .Lreturn
.Lbase:
    xorl %eax, %eax
.Lreturn:
finish

# The mutually recursive helpers can exit the process but neither can return to its caller.
begin recursive_exit
    movl $2, %ecx
    call count_to_exit
    int3
.seh_endproc

begin count_to_exit
    testl %ecx, %ecx
    jz .Lexit_now
    call next_count
    int3
.Lexit_now:
    call exit_42
.seh_endproc

begin next_count
    subl $1, %ecx
    call count_to_exit
.seh_endproc

begin isolation
    call *__imp_GetLastError(%rip)
    testl %eax, %eax
    jnz .Lisolation_failed
    addl $1, counter(%rip)
    cmpl $1, counter(%rip)
    jne .Lisolation_failed
    movl $0x23456789, %ecx
    call *__imp_SetLastError(%rip)
    handle -12
    write_args
    write
    testl %eax, %eax
    jz .Lisolation_failed
    cmpl $4, 40(%rsp)
    jne .Lisolation_failed
    call *__imp_GetLastError(%rip)
    cmpl $0x23456789, %eax
    jne .Lisolation_failed
    movl $0xcafe002a, %ecx
    call *__imp_ExitProcess(%rip)
.Lisolation_failed:
    movl $254, %eax
finish

.section .rdata,"dr"
payload:
    .byte 0x41, 0, 0xff, 0x0a
.section .badbuf,"dr"
long_prefix:
    .space 65537, 0x61
.data
counter:
    .long 0
