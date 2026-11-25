# Conventional Windows C startup fixtures

These executables use the default console entry and startup objects of `x86_64-w64-mingw32-gcc-win32`. The repository pins the Win32-thread GCC package `12.2.0-14+25.2`, GNU ld 2.40 and MinGW-w64 10.0.0. The C11 fixture build uses `-O0 -g` for Debug and `-O2 -DNDEBUG` for Release. The linker options `-static -Wl,--no-insert-timestamp` retain the default MSVCRT DLL imports. The build checks that two clean builds of each configuration produce identical PE bytes. [Toolchain and complete build flags](../../README.md#build-and-inspect)

| Fixture | Pinned Wine 8 reference |
| --- | --- |
| `startup/return` | Normal return from `main` yields status 42. |
| `startup/argc`, `startup/argc_none` | The same C source returns 42 with two arguments and 1 with none beyond the executable name. |
| `startup/argv` | Status 42 requires both expected strings, the initialized global and the initial zero in writable storage. |
| `startup/argv_edges` | Status 42 checks the guest PE basename, a null pointer after the last element, empty strings, a tab, embedded quotes, runs of backslashes before a quote and trailing backslashes. |
| `startup/globals` | Status 42 requires the initial values in `.data` and `.bss`, followed by a write and readback. The globals are volatile to preserve these accesses in Release. |
| `startup/cleanup` | The C constructor writes `I`, `main` writes `M`, then the registered handlers write `BA`. The four stdout bytes and exit status 42 test normal CRT termination. The markers use Win32 output directly. |
| `startup/puts` | The application calls the imported `msvcrt.dll!puts` and returns 0. Default text mode emits exactly 15 stdout bytes, `Hello from C!\r\n`, including the carriage return. |

All cases produced empty stderr in both configurations. The fixtures with no output in the table produced empty stdout.

## Reproduce

Run from the repository root with the documented build dependencies. The Windows build and reference steps use the prepared Docker images. The native comparison runs directly on an ARM64 Mac.

```sh
make provision-fixtures
./tools/build-windows-fixtures.sh --all
for config in debug release; do
    for fixture in argc argc_none return argv argv_edges globals puts cleanup; do
        ./tools/run-windows-references.sh --config "$config" --fixture "startup/$fixture" || exit 1
    done
done
make
python3 -B tests/differential/startup.py
```

Select one comparison with `python3 -B tests/differential/startup.py --fixture startup/argv --config debug`. The runner verifies the exported binary and Wine publication, passes the PE to `forge lift --executable`, checks the output’s Mach-O architecture, file type and linked dependencies, and executes it with the manifest argument vector. The source PE snapshot expires before execution. Each run has its own directory under `build/differential/startup/`. Its per-case `result.json` records stage outcomes. A failed translation exits the comparison with status 1 and leaves native execution and byte comparison pending. Compiler output and available stream files sit next to the report. [Source files](.) · [Reference invocations](../../manifests/startup)

The report retains the compiler's structured diagnostic, including the original stage, code and readiness context. For a native link failure it records successful translation and a failed native build. A publication error can also come from the output-path preflight, so earlier stages show `unknown` when the diagnostic cannot establish their outcome. A missing or malformed diagnostic fails the compiler invocation.

## Startup inventory

The following RVAs describe the canonical Debug `crt_argc.exe` (SHA-256 `e2192c63caae30f8dfe5697c3bec3888abcb7831cd7fe33a0f07c09309b0bfb6`). They are inspection evidence for this build. Compiler recovery must derive targets from the input image.

- **Loading.** This AMD64 PE32+ console image has preferred base `0x140000000`, 45 DIR64 relocations and 45 unwind entries. `.text` is executable/readable. `.data`, `.bss`, `.idata`, `.CRT` and `.tls` are readable/writable. `.rdata`, `.pdata`, `.xdata` and `.reloc` are readable. The TLS directory at `0x4020` supplies eight template bytes, index RVA `0x708c`, and a null-terminated callback array at `0x9038`. The loader calls `0x1690` and `0x1660` in that order on process attach. The first initializes a critical section.
- **CRT initialization.** The PE entry `mainCRTStartup` at `0x14d0` calls `__tmainCRTStartup` at `0x1180`. Startup uses `rep stosq`, `gs:[0x30]` to read the NT_TIB and its stack base, and an interlocked startup lock. It invokes the C and C++-named initialization tables through MSVCRT `_initterm`. One guest initializer calls `__getmainargs`. The CRT then calls its own TLS initializer with `DLL_THREAD_ATTACH`, executes its runtime relocator, registers the guest top-level exception filter and initializes x87 state. A stack probe executes before the relocator tests the empty pseudo-relocation list. The linked executable’s ordinary base relocations are separate.
- **Application and termination.** Startup duplicates the argument strings through imported `malloc`, `strlen` and `memcpy`, calls `__main` to run the linked constructor machinery, writes the CRT environment pointer, calls the application at `0x1530` from `0x13a9`, then calls MSVCRT `exit` at `0x14a8`. The application itself checks the count. Two startup wrappers have C exception scopes. The console scope covers `[0x14d4, 0x14e7)` and uses `__C_specific_handler` at thunk `0x1560`, guest filter `0x1dd0`, and continuation `0x14e7`. Exception dispatch requires a separate test from a successfully observed normal return.

| Imported DLL | Required ordinary load-time symbols in the primary fixture |
| --- | --- |
| KERNEL32.dll | DeleteCriticalSection, EnterCriticalSection, GetLastError, GetStartupInfoA, InitializeCriticalSection, LeaveCriticalSection, SetUnhandledExceptionFilter, Sleep, TlsGetValue, VirtualProtect, VirtualQuery, __C_specific_handler |
| msvcrt.dll | __getmainargs, __initenv, __iob_func, __set_app_type, __setusermatherr, _acmdln, _amsg_exit, _cexit, _commode, _fmode, _initterm, _onexit, abort, calloc, exit, fprintf, free, fwrite, malloc, memcpy, signal, strlen, strncmp, vfprintf |

MSVCRT exports `__initenv`, `_acmdln`, `_commode` and `_fmode` as data. The argument comparison programs add `msvcrt.dll!strcmp`, the cleanup markers add KERNEL32 `GetStdHandle`, `WriteFile` and `ExitProcess`, and the text output program adds `msvcrt.dll!puts`. Load-time binding includes imports used only on exceptional or inactive paths. [MinGW-w64 startup source](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/crt/crtexe.c) · [PE TLS callback rules](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#tls-callback-functions)

## Native recovery boundary

Forge recovers the guest startup call at `0x124a` by validating both immutable, relocated pointer cells feeding RAX and the intervening null guard. The regression executable returns 42 through that call. Mutations exercise a branch back into the call, a clobbered target register, a reversed null guard, writable cells, an out-of-image target, and a missing relocation on either field. [Recovery tests](../../../integration/test_functions.py)

The Debug `startup/argc` PE loads `KERNEL32.dll!Sleep` into R12 at `0x11c8` from IAT slot `0x81a8`. The contention path passes 1000 milliseconds in ECX at the register call `0x11e6` and retries the startup lock. On the uncontended path, the runtime relocator still saves R12 on the guest stack. Forge now proves the binding across the loop. A separately linked PE exercises `Sleep(0)`, runs a register-held `SetLastError` call twice and zero times, and checks the imported address after a nested callee saves and restores R12. Its Windows PE under pinned Wine and its standalone ARM64 translation both returned 42 with empty streams. [Regression source](../../../fixtures/executable-import-register.s) · [Imported call recovery](../../../../docs/program-architecture.md#imported-call-recovery)

All 16 original inputs now resolve the registration call at `0x1258` to `KERNEL32.dll!SetUnhandledExceptionFilter`. In the primary PE, `0x1251` loads RCX from the DIR64 pointer cell at `0x44c0`. Its target is the guest filter at RVA `0x1dd0` in Debug and `0x1da0` in Release. The call uses IAT slot `0x81a0`, then `0x126c` stores RAX as the previous filter. The original diagnostic occurred during lifting, before guest execution. [Readiness regression](../../test_native_differential.py) · [Registration contract](../../../../docs/runtime-architecture.md#top-level-exception-filter-registration)

The focused PE installs two distinct filters, restores a previous filter from guest storage, clears it, and verifies each returned address. Its SHA-256 is `9919f98845de11676dc6767f39935ebf77b80dabb2f4deeb1ea4aefc2067235b`. Pinned Wine 8 and the standalone ARM64 executable returned 42 with empty stdout and stderr. The ARM64 result also matched at a guest base offset by `0x30000000`. A separate native test installs a filter and reads unmapped guest address 1. It exits 125 with the original memory fault. [Fixture source](../../../fixtures/executable-top-level-filter.s) · [ARM64 integration tests](../../../integration/test_executable.py)

The PE also uses this guest function for its entry's C-specific exception scope. The protected call at `0x14e1` enters the CRT and its callees. On exception delivery the Debug filter could read the guest exception record, call a signal handler at `0x1e5b`, request continued execution at `0x1e5d`, or chain to a previous handler at `0x1e83`. Forge supports registering the address. A subsequent guest fault still ends the invocation with its original result. [Process result ABI](../../../../runtime/include/forge/process.h) · [Windows filter contract](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)

Argument duplication exposes a later boundary. The compiler accepts `strlen` on a proved heap allocation. For `strlen(argv[1])` after `__getmainargs`, both the output slot and vector element are writable guest memory. The compiler currently lacks the pointer provenance required at that service call and reports `LIFT_IMAGE_MEMORY`. A separate fixture isolates this dependency from the earlier startup lock. [Fixture](../../../fixtures/crt-argv-strlen.s)

## Compatibility boundary

For the primary PE, Forge recognizes 20 of 36 load-time symbols. These are KERNEL32 `GetLastError`, `GetStartupInfoA`, `SetUnhandledExceptionFilter` and `Sleep`, the twelve MSVCRT functions `__getmainargs`, `_amsg_exit`, `_cexit`, `_initterm`, `_onexit`, `calloc`, `exit`, `free`, `malloc`, `memcpy`, `strlen` and `strncmp`, and the four MSVCRT data exports. Eight KERNEL32 symbols and eight MSVCRT symbols still lack bindings. The argument fixture’s additional `strcmp` import has a binding.

In `__tmainCRTStartup`, the startup conflict branch loads error 31 at `0x1407`. Forge recovers the terminating call at `0x140c` to **`msvcrt.dll!_amsg_exit`**. In the primary PE the thunk is at `0x26b0` in Debug and `0x2680` in Release, both jumping through IAT slot `0x8208`. Separate focused PEs execute `_amsg_exit(31)` through the same import-thunk shape and exercise an unused import. [Original Windows, Wine and ARM64 observations](amsg-exit/) · [Lifted tests](../../../integration/test_executable.py)

Forge now resolves the direct call to **`msvcrt.dll!_initterm` at `0x142a`**. In the primary PE the Debug thunk at `0x26c0` and Release thunk at `0x2690` both jump through IAT slot `0x8228`. RCX and RDX obtain relocated `__xc_a` and `__xc_z`. The initializer evidence records the range `[0x9000, 0x9010)` and guest target `pre_cpp_init` at `0x1130`. The first qword is null. An isolated copy of the Debug PE follows this initializer to `__getmainargs`. A second isolated copy follows the original call at `0x1494` through the range `[0x9018, 0x9028)` to `pre_c_init` at `0x1010`, where recovery passes the DOS signature comparison at `0x1044` and stops at the application-type call at `0x1072`. The diagnostic identifies the callback and its originating call at `0x1494`. The import fields identify the failing callee’s IAT slot. Both probes validate the original argument setup, import and table. [Conventional PE regressions](../../test_native_differential.py)

The focused executable imports the real legacy MSVCRT function. One initializer replaces a later slot in writable `.CRT`, and the caller checks the resulting order (21222), heap value (42), guest stack state and last error (73). Its SHA-256 is `fad082d17485aff8adf965d5168c85c92f748cbe6b0141f3ed5f1da82bd0ba58`. Pinned Wine 8 and standalone ARM64 both return 42 with empty streams. ARM64 also returns 42 at a guest base offset by `0x30000000` and in each of two independent processes registered from one artifact. The nested-table executable returns 42 with stdout `MMM`. The terminal variant exits 57 with empty streams before the next initializer or the caller can write a marker. [Fixture source](../../../fixtures/crt-initterm.s) · [Failure and isolation tests](../../../integration/test_executable.py) · [Initializer calling contract](../../../../docs/runtime-architecture.md#crt-initializer-callback-design)

The spill regression reloads a caller-local string pointer after an empty table and again after an all-NULL table. The test shortens the raw extent of a read-only section so four bytes of its eight-byte endpoint pointer come from the PE loader’s zero fill. That PE returned 2 with empty streams under pinned Wine and on ARM64 at guest bases `0x400000` and `0x180000000`. [Fixture source](../../../fixtures/crt-initterm-spill.s) · [PE layout and execution tests](../../../integration/test_executable.py)

Forge resolves the `GetStartupInfoA` IAT call at RVA `0x1453` and both termination thunks in `__tmainCRTStartup`. The managed path calls `_cexit` at `0x1460`, while the ordinary path calls `exit(mainret)` at `0x14a8`. Recovery reaches the C initializer `pre_c_init`. Its operand-size-prefixed comparison checks the PE’s DOS signature at RVA `0x1044`. [MinGW startup](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/crt/crtexe.c) · [Runtime termination contract](../../../../docs/runtime-architecture.md#legacy-msvcrt-termination-handlers)

The original A-only, W-only and combined probes returned 1 on Windows Server 2022 because they assumed a null reserved pointer. Forge now matches that outcome. The field probe checks the observed padding and all three handle slots. With startup flags clear it returns 42 on Windows and Forge, and 44 on pinned Wine 8. With the captured standard handles it returns 43 on Windows and Wine. The ARM64 fault variant places the last byte on the protected outer return address and reports a write fault at `0x70000fd8`. The companion raw records cover both A/W views before and after replacing stdout with stderr. [Compared fields and original bytes](termination/) · [Executable tests](../../../integration/test_executable.py)

Run `./tools/test-forge.sh --executable-reference` for the captured case. To reproduce the direct Wine 8 observation after `make fixtures`, run from the repository root:

```sh
reference=$(python3 -B tests/differential/fixture_images.py --id reference)
docker run --rm --platform linux/amd64 --network none --cap-drop ALL \
    --security-opt no-new-privileges -v "$PWD/build/dev/fixtures/Debug:/input:ro" \
    --entrypoint /bin/sh "$reference" -c '
        for variant in a w aw; do
            /usr/lib/wine/wine64 "/input/executable-startup-info-$variant.exe"
            test "$?" -eq 44 || exit 1
        done'
```

### Startup comparison results

Task 13.3J reran all eight original fixtures in Debug and Release. Every pinned Wine reference passed validation. Every recovery reached the `_initterm` initializer from `0x1494`, passed `CMP16mi` at `0x1044` and stopped in `pre_c_init` (function RVA `0x1010`) at instruction RVA `0x1072`. The diagnostic in all 16 cases was `LIFT_UNSUPPORTED_CONTROL_FLOW` for `CALL64pcrel32` to the unbound `msvcrt.dll!__set_app_type` import. The table gives the complete instruction bytes in each original PE.

| Fixture | Debug bytes | Release bytes | IAT slot RVA (both) |
| --- | --- | --- | --- |
| argc | `e8 29 16 00 00` | `e8 f9 15 00 00` | `0x81f0` |
| argc_none | `e8 29 16 00 00` | `e8 f9 15 00 00` | `0x81f0` |
| argv | `e8 99 16 00 00` | `e8 f9 15 00 00` | `0x81f8` |
| argv_edges | `e8 49 17 00 00` | `e8 f9 15 00 00` | `0x81f8` |
| cleanup | `e8 19 17 00 00` | `e8 99 16 00 00` | `0x8220` |
| globals | `e8 49 16 00 00` | `e8 f9 15 00 00` | `0x81f0` |
| puts | `e8 29 16 00 00` | `e8 f9 15 00 00` | `0x81f8` |
| return | `e8 19 16 00 00` | `e8 f9 15 00 00` | `0x81f0` |

For each table cell the comparator exited 1. Recovery and translation failed. Native compilation, publication, execution and byte comparison were never reached, so native exit status and streams are unavailable. The next startup task is to measure and implement the legacy MSVCRT application-type service. Recovery can encounter that dependency before lifting the later module. The PE also contains a full-width `CMP32mi` at `0x1052`.

### CMP16mi acceptance and remaining compatibility work

The SDK-free executable reads the DOS header via a relocated pointer, an unaligned writable word through an indexed address, an unaligned stack word and two immutable words. Its branches consume comparison flags. Stdout records five pairs of SETO and LAHF bytes, including AF, and status 42 requires the register and memory sentinels to survive. The standalone native test repeats the run at an alternate base. Windows Server 2022 and the pinned Linux amd64 Wine job exercise the macOS producer’s PE. [Assembly](../../../fixtures/executable-cmp16mi.s) · [Executable regression](../../../integration/test_executable.py)

The ARM64 observations were `00 46 01 12 01 87 00 12 00 86`, empty stderr and exit 42. Running the same PE under pinned Wine 8 on Apple Silicon Docker returned `00 46 01 02 01 87 00 02 00 86`. The differing bit is AF for `0x8000 - 0x7fff` and `0x1330 - 0x1201`. Keep this host result distinct in reference reports and use the native Linux amd64 Wine producer for the regression gate. [Wine reference environments](../../README.md#troubleshooting-and-ci)

A successful scalar read requires both bytes to fit one readable mapping. Two readable adjacent mappings yield terminal `FORGE_RT_UNSUPPORTED`, status `FORGE_RT_OK` and an empty fault payload. An inaccessible second byte yields a read fault at that guest address. The managed test observes a service marker on each successful branch and its absence on both terminal paths. Successful cross-mapping access belongs in the shared guest-memory implementation for all applicable scalar operations. [Memory contract](../../../../docs/runtime-architecture.md) · [Boundary regression](../../../integration/test_process.py)

| Outstanding item | Disposition |
| --- | --- |
| Startup metadata triggering standard-handle capture (P3) | Defer until the launcher exposes richer configuration. |
| Full Unicode startup titles and Windows ANSI code pages | Defer conversion support and retain call-time rejection of unsupported input. |
| CRT-managed buffered streams and flushing | Defer. |
| Wine `_onexit` allocation exhaustion | Parity remains unverified. |
| PE TLS initialization and callbacks | Separate loader task. |
| Missing Windows and CRT services | Separate compatibility tasks, beginning with `__set_app_type`. |
| Guest exception delivery and SEH | Separate exception-delivery task. |
| Scalar reads across adjacent readable mappings | Separate shared guest-memory task. |

### Conventional startup responsibilities

| Responsibility | Current result for the selected configuration |
| --- | --- |
| Translate instructions in the executable | Forge lifts the observed repeat store, direction flag operations, aligned 64-bit interlocked operations and primary-thread TIB self read. Recovery also handles a direct linker import thunk and the proved guarded callback load. Managed executable artifacts preserve the imported-function address in R12 and guard its call through the loop. |
| Initialize the PE and its primary thread | The runtime provides process parameters, guest stack bounds and isolated mappings. The PE additionally needs a TLS template and index, followed by the two process-attach callbacks before entry. The callbacks enter a critical-section lifecycle. A successful dry recovery of a callback target does not execute a loader callback. |
| Call the external Windows CRT | There are typed adapters for a bounded argument/heap/byte subset and four writable data exports. MSVCRT can call recovered guest initializers from bounded tables. The exit path can run admitted guest termination handlers in the managed process. The full CRT still has unrecovered dependencies. |
| Deliver guest exceptions | The compiler reports validated entry scope, filter, handler import and continuation evidence. Running the filter on a guest exception requires the guest fault PC, exception context, guest stack unwinding and continuation. The current process fault result terminates the run. |
| Print through stdio | `puts` remains a required external MSVCRT symbol in its own fixture. The primary fixture already imports `__iob_func`, `fprintf`, `fwrite` and `vfprintf` for CRT paths. These need Windows stream objects, the applicable guest calling conventions and exit-time flushing. |

Exception delivery would require preserving the faulting guest instruction, registers and stack across nested calls. TLS initialization and CRT lifetime services remain separate prerequisites. Task 13.4 stays gated on all 16 native comparisons.

These commands inspect the exact primary input and attempt a native build from the repository root on Apple Silicon.

```sh
build/dev/forge inspect build/fixtures/windows-x64/debug/crt_argc.exe --format json
build/dev/forge analyze build/fixtures/windows-x64/debug/crt_argc.exe --functions --format json
build/dev/forge lift build/fixtures/windows-x64/debug/crt_argc.exe --executable \
    --diagnostics-format json --output build/dev/crt-argc
```

The standalone comparator supplies `"hello world"` and `forge` as the two arguments to the published `translated` executable and captures both output streams. It exits unsuccessfully when any stage fails. [Comparator](../../startup.py)

To reproduce the portion that executes natively, build the SDK-free register-call fixture from the Forge root. With the pinned LLVM 23.1.5 tools its PE SHA-256 is `cb23619ce1f1c3205f7aad174bd90697699d364630635ea0b0b3b66d57fa61e6`.

```sh
make fixtures
build/dev/forge lift build/dev/fixtures/Debug/executable-import-register.exe --executable \
    --diagnostics-format json --output build/dev/import-register
build/dev/import-register
test "$?" -eq 42
```

To reproduce the initializer and filter registration comparisons on an ARM64 Mac with the pinned Wine image and the dev build, run the executable reference suite and the native executable tests. The native tests also cover rebasing and fault behavior.

```sh
make fixtures
./tools/test-forge.sh --executable-reference
ctest --test-dir build/dev -C Debug -R '^native_executable$' --output-on-failure
```
