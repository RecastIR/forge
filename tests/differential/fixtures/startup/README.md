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

For the primary PE, Forge recognizes 23 of 36 load-time symbols. These are KERNEL32 `GetLastError`, `GetStartupInfoA`, `SetUnhandledExceptionFilter`, `Sleep` and `VirtualProtect`, the fourteen MSVCRT functions `__iob_func`, `fwrite`, `__getmainargs`, `_amsg_exit`, `_cexit`, `_initterm`, `_onexit`, `calloc`, `exit`, `free`, `malloc`, `memcpy`, `strlen` and `strncmp`, and the four MSVCRT data exports. Seven KERNEL32 symbols and six MSVCRT symbols still lack bindings. The argument fixture’s additional `strcmp` import has a binding.

In `__tmainCRTStartup`, the startup conflict branch loads error 31 at `0x1407`. Forge recovers the terminating call at `0x140c` to **`msvcrt.dll!_amsg_exit`**. In the primary PE the thunk is at `0x26b0` in Debug and `0x2680` in Release, both jumping through IAT slot `0x8208`. Separate focused PEs execute `_amsg_exit(31)` through the same import-thunk shape and exercise an unused import. [Original Windows, Wine and ARM64 observations](amsg-exit/) · [Lifted tests](../../../integration/test_executable.py)

Forge now resolves the direct call to **`msvcrt.dll!_initterm` at `0x142a`**. In the primary PE the Debug thunk at `0x26c0` and Release thunk at `0x2690` both jump through IAT slot `0x8228`. RCX and RDX obtain relocated `__xc_a` and `__xc_z`. The initializer evidence records the range `[0x9000, 0x9010)` and guest target `pre_cpp_init` at `0x1130`. The first qword is null. An isolated copy of the Debug PE follows this initializer to `__getmainargs`. A second isolated copy follows the original call at `0x1494` through the range `[0x9018, 0x9028)` to `pre_c_init` at `0x1010`, where recovery passes the DOS signature comparison at `0x1044` and resolves the application-type call at `0x1072`. This isolated initializer next reaches the cross-function jump from `__mingw_setusermatherr` at `0x1dc7` to the `__setusermatherr` thunk at `0x26a8`. Both probes validate the original argument setup, import and table. [Conventional PE regressions](../../test_native_differential.py)

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

### Legacy CRT application type observations

The SDK-free fixture calls the system DLL through a linker thunk and directly through its IAT inside an `_initterm` initializer. In order, the six low DWORDs are 1, 2, 0, −7, −2147483648 and 1. Each call receives nonzero high RCX bits. The probe obtains the errno address once, seeds both error cells, then records their values immediately after each call. Status 42 also checks continuation, saved RBX, a stack sentinel and the guest `__mingw_app_type` canary. Both console and GUI PE variants write six little-endian DWORD pairs to stdout. The expected (last error, errno) pairs are (700,100), (708,108), (716,116), (724,124), (732,132) and (740,140). [Probe source](../../../fixtures/crt-app-type.s)

**Observed on Windows Server 2022.** The console and GUI PEs both returned 42 with the six expected pairs and empty stderr. A console PE that selected type 2 immediately before `_amsg_exit(8)` returned 255 and wrote the same 57 stderr bytes as the explicit-console and no-setter controls. All three had empty stdout. A call with a GUI argument therefore preserves the console program’s observed fatal route on this DLL. The Windows test omits GUI-subsystem R6008, which can display a modal dialog. [Windows observations and PE hashes](https://github.com/RecastIR/forge/actions/runs/45532412809/job/138935486883)

**Static evidence from the same Windows DLL.** The runner’s `System32/msvcrt.dll` and the Microsoft symbol image have SHA-256 `dde047f12a6b954773284e058631d9939ed1ef1d0f853d4343c320774129ab6e`. The DWORD at RVA `0x99424` starts at zero in the file. Initialization at `0x7dcc` and the exported setter at `0x2df30` call the same selector at `0x335b8`. It saves ECX, reads the main module’s PE subsystem and returns 2 for Windows GUI or 1 for Windows CUI. It returns the original 32-bit argument when it cannot select either subsystem. The setter stores the selected DWORD. Under default error mode the fatal path tests that cell for console type at `0x3f369` and `0x3f3ef`. Its message lookup at `0x3f394` returns early for unknown identifiers. The GUI path also skips the newline fragment (252). The bounded Windows test exercises both silent paths with GUI-subsystem PEs. The caller-value fallback is a disassembly finding. No private storage was queried by the probe. Interactive dialog contents and responses remain unmeasured. [Microsoft symbol image](https://msdl.microsoft.com/download/symbols/msvcrt.dll/EE390ECBa3000/msvcrt.dll)

Pinned Wine 8 and Forge ARM64 returned 42 with these 48 stdout bytes and empty stderr for both variants. Wine source initializes the state to 0 and assigns the supplied integer. Its default-mode fatal diagnostic chooses a message box for type 2. The pinned, headless Wine observer returned 255 with empty redirected streams for the fatal probes. A silent headless run does not establish what appeared on a desktop. MinGW-w64 uses the setter in startup and separately supplies a local stub. The fixture’s import table names the legacy DLL export. [Wine state](https://github.com/wine-mirror/wine/blob/wine-8.0/dlls/msvcrt/data.c) · [Wine fatal routing](https://github.com/wine-mirror/wine/blob/wine-8.0/dlls/msvcrt/exit.c) · [MinGW startup](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/crt/crtexe.c) · [MinGW local setter](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/misc/__set_app_type.c)

The hosted Windows test verifies the producer manifest and prints each PE hash, full exit status and raw stream bytes. The Wine consumer verifies the same manifest before execution. The macOS producer runs the standalone translation of each supported case and checks Forge’s unsupported result for the GUI fatal route. [Reference inputs](../../reference/executable-inputs.txt) · [Executable tests](../../../integration/test_executable.py)

### Legacy standard-stream observations

The SDK-free observer snapshots all three x64 FILE records, calls `fwrite` and records its complete-element result, errno, last error and stream fields. A direct Win32 marker before and after returning `_cexit` distinguishes pending bytes from bytes already written. Each case starts in a fresh process and redirects each output independently to a pipe or a regular file. Focused assembly inputs exercise the same DLL calls through import thunks and IAT slots on Windows, pinned Wine and translated ARM64, including callback output, independent stdout/stderr, alternate guest bases, and a dynamic source crossing two read-only sections. [C observer](../../../fixtures/crt-stream-reference.c) · [Guest calls and callback](../../../fixtures/crt-streams.s) · [FILE snapshots](../../../fixtures/crt-stream-state.s)

Both Windows Server 2022 and pinned Wine keep a six-byte write pending on either output with cursor displacement 6, count 4090, flags 10 and capacity 4096. Direct markers precede that data. A 4096-byte first write bypasses the buffer. A 4097-byte write leaves one byte pending. Both translate LF, including in existing CRLF, and preserve embedded NUL. With separate stdout and stderr, the callback fixture exits 42 with stdout hex `2341000d0a420d0d0a5a` and stderr hex `0d0d0a5a23`. A shared descriptor receives the concatenation in stdout-then-stderr cleanup order.

Windows preallocates stdin's buffer and sets flags 257. Wine starts with flags 1 and no buffer. Windows reports errno 22 with unchanged last error for both overflowing products. Wine wraps the size product. Windows allows empty transfers with invalid stream pointers. Wine can fault in those cases. The native runtime follows Windows for these differences. Both references distinguish a buffered write after closing an output handle from an immediate failed full-block write. The latter returns zero and sets the stream-error flag, errno 9 and last error 6. [Windows Server 2022 measurement](https://github.com/RecastIR/forge/actions/runs/45918949331/job/140248746507) · [Reference driver](../../reference/crt_streams.py)

Windows Server 2022 used MSVCRT 7.0.20348.5756 (SHA-256 `dde047f12a6b954773284e058631d9939ed1ef1d0f853d4343c320774129ab6e`). The extended cases preserve seeded last error 91 for null parameters and overflow. A small stdin write sets errno 9 and its error flag. An invalid non-null source on this path faults when the CRT fetches the first byte. A full-block write to read-only stdin also sets last error 5. A buffered write to missing stdout returns three elements with errno 9, while a full-block write returns zero. A disconnected pipe reports errno 22 and last error 232 on a direct write. After `_amsg_exit(8)` the pending stderr bytes follow the raw R6008 diagnostic. The separate regular-file and pipe records include the full process status and all observed legacy scalar fields. For Wine crashes the direct Linux launcher reports the low exit byte and writes debugger diagnostics containing volatile state. The Wine capture parent checks the full access-violation status on the invalid-stream and invalid-source probes. [Windows failure measurements](https://github.com/RecastIR/forge/actions/runs/45920431752/job/140252513978) · [Windows reference rows](../../reference/crt-stream-windows.json) · [Wine reference rows](../../reference/crt-stream-wine.json)

### Startup comparison results

All 16 original PEs have a writable `.CRT` section with `__xd_a` at RVA `0x9050` and `__xd_z` at `0x9058`. Both RIP-relative LEAs resolve to `0x9058`. The half-open initializer range contains zero slots. In primary Debug, the empty branch at `0x16d1` skips the loop. The qword load at `0x16d8` feeds the NULL guard and the call at `0x16e0`. The NULL path and a successful return rejoin at `0x16e2`, where RBX advances by eight. The backedge at `0x16e9` returns to the load. The older outer function sets `_CRT_MT` to 2 and calls `__mingw_TLScallback` for process attach. Thread attach traverses the range of no-argument functions. The newer MinGW implementation has a different outer function. [Linked CRT source](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/crt/tlssup.c) · [Later implementation](https://github.com/mingw-w64/mingw-w64/blob/9c44fc5d65f515470dbb6febac91c33c2b58edbc/mingw-w64-crt/crt/tlsdyn.c)

Fifteen inputs recover the direct `msvcrt.dll!fwrite` call and stop at the following `msvcrt.dll!vfprintf` thunk in MinGW’s error reporter. All fifteen use `CALL64pcrel32`. The instruction bytes are `e8 8d 0e 00 00` in argv, argv_edges and Release puts, and `e8 85 0e 00 00` in the other affected inputs. Debug `puts` stops earlier at `msvcrt.dll!puts` (`e8 c4 11 00 00`). All 16 Windows Server 2022 and pinned Wine references validate with empty stderr. Recovery and translation fail for each Forge input with `LIFT_UNSUPPORTED_CONTROL_FLOW`. Native build, publication, artifact verification, execution and stream comparison are unrun for every row. Each exit and stdout below belongs to the reference process.

The producer hashes, stored pointers for both pseudo-relocation list bounds, and the signed early-return branch were checked in each original PE. Both pointers hold the same VA in every case. Their common RVA is `0x48d0` for argv and puts, `0x4910` for argv_edges, and `0x48b0` for the other fixtures. On this startup path the relocator exits before a relocation write, `VirtualQuery`, protection change or restoration. Recovery still walks those call sites. In primary Debug, the load at `0x1bee` reads RSI from IAT slot `0x81b8` before the call at `0x1c1d`. [MinGW source](https://github.com/mingw-w64/mingw-w64/blob/v10.0.0/mingw-w64-crt/crt/pseudo-reloc.c)

| Fixture | PE | Function / block RVA | Call RVA | File offset | Thunk RVA | IAT RVA | Reference exit, stdout |
| --- | --- | --- | --- | --- | --- | --- | --- |
| argc | Debug | 0x1840 | 0x189e | 0xe9e | 0x2728 | 0x8290 | 42, empty |
| argc_none | Debug | 0x1840 | 0x189e | 0xe9e | 0x2728 | 0x8290 | 1, empty |
| argv | Debug | 0x18b0 | 0x190e | 0xf0e | 0x27a0 | 0x82a0 | 42, empty |
| argv_edges | Debug | 0x1960 | 0x19be | 0xfbe | 0x2850 | 0x82a0 | 42, empty |
| cleanup | Debug | 0x1930 | 0x198e | 0xf8e | 0x2818 | 0x82c0 | 42, `IMBA` |
| globals | Debug | 0x1860 | 0x18be | 0xebe | 0x2748 | 0x8290 | 42, empty |
| puts | Debug | 0x1530 | 0x1547 | 0xb47 | 0x2710 | 0x8280 | 0, `Hello from C!\r\n` |
| return | Debug | 0x1830 | 0x188e | 0xe8e | 0x2718 | 0x8290 | 42, empty |
| argc | Release | 0x1810 | 0x186e | 0xe6e | 0x26f8 | 0x8290 | 42, empty |
| argc_none | Release | 0x1810 | 0x186e | 0xe6e | 0x26f8 | 0x8290 | 1, empty |
| argv | Release | 0x1810 | 0x186e | 0xe6e | 0x2700 | 0x82a0 | 42, empty |
| argv_edges | Release | 0x1810 | 0x186e | 0xe6e | 0x2700 | 0x82a0 | 42, empty |
| cleanup | Release | 0x18b0 | 0x190e | 0xf0e | 0x2798 | 0x82c0 | 42, `IMBA` |
| globals | Release | 0x1810 | 0x186e | 0xe6e | 0x26f8 | 0x8290 | 42, empty |
| puts | Release | 0x1810 | 0x186e | 0xe6e | 0x2700 | 0x82a0 | 0, `Hello from C!\r\n` |
| return | Release | 0x1810 | 0x186e | 0xe6e | 0x26f8 | 0x8290 | 42, empty |

The comparator's per-row `result.json` retains the complete structured diagnostic, including imports, call edges, unwind metadata, file offset, bytes and table evidence. The primary Debug constructor runner calls at RVA `0x15f0` and returns to `0x15f2`. The Release RVAs are `0x15c0` and `0x15c2`. The original constructor lists use a sentinel header in immutable `.text`, DIR64 entries for `register_frame_ctor` and, for cleanup, `setup`. [Regression assertions](../../test_native_differential.py)

The SDK-free forward-call fixture changes the current slot after the load and later slots before their loads. Its single-entry initializer calls a guest helper that writes the first home slot and returns the low four bits of its entry RSP. The initializer resumes, checks for the expected value of eight and adds the marker from its home slot to the visit count. Exit 42 requires that count to be one. The fixture also checks callback order, a tail transfer, register and stack sentinels, last error and the outer attach reason. [Focused PE](../../../fixtures/executable-forward-call.s) · [Bounded call design](../../../../docs/program-architecture.md#bounded-indirect-calls-through-pointer-tables)

Windows Server 2022, pinned Wine 8 and the standalone ARM64 translation returned 42 with empty stdout and stderr for PE SHA-256 `075cc462472df820b34a960c00f890d855c17411c670014bcf24f9402aa09452`. ARM64 produced the same result at a guest base offset by `0x30000000`. Two managed processes using the same artifact at base `0x10000000` each returned 42 in both the unoptimized and O2 runs. [Windows reference observation](https://github.com/RecastIR/forge/actions/runs/45879006669/job/140118342619) · [Rebased executable test](../../../integration/test_executable.py) · [Managed-process test](../../../integration/test_process.py)

### VirtualProtect reference comparisons

The SDK-free observer runs 45 independent processes per reference backend. Each writes seven little-endian DWORDs covering page size, initial protection, BOOL, old protection, last error and two post-call page protections. In case 44 the final field records the old protection from a second call on the first call’s pristine output page. Windows preserves the DWORD and reports error 87 for the zero-length request. The second call returns old protection 4. Wine succeeds on the first call and reports old protection 8 on the second. Rejected requests distinguish a preserved sentinel from a published `PAGE_NOACCESS`. Windows and Wine both measure a 4096-byte page. The Windows captures establish the initial copy-on-write protection and the effects of writing a page or probing an aliased output DWORD. The runtime uses the Windows results for the cases where Wine differs. The C observer itself stops at Forge entry discovery and imports separate allocation and query services for its setup. [Probe source](../../../fixtures/virtual-protect-reference.c) · [All reference values](../../reference/virtual-protect.json) · [Windows observation log](https://github.com/RecastIR/forge/actions/runs/45911091982/job/140222678936)

| Focused PE | Producer SHA-256 | Observed behavior |
| --- | --- | --- |
| `virtual-protect-reference` | `2ac360041e9b05bfa5f6294b5088c02bc2430935aa9e2b7f312227d3ceb19b42` | Windows and Wine return 42 with 28 bytes on stdout and empty stderr for each case. |
| `executable-virtual-protect` | `d1587e321c54d8ded4efffe05322370a492bccdf03229841a645954f7cf4dfd5` | Stack output, unaligned request spanning two pages, independent neighboring access, writable restoration and preserved registers. Exit 42 with empty streams. |
| `executable-virtual-protect-fresh` | `672f22c70e7049dae862fe2ff1c642f584ae7c3c028f547e8140433fba9921a5` | A pristine writable image page reports old 8. Restoration reports old 2, and the subsequent write succeeds. Exit 42 with empty streams. |
| `executable-virtual-protect-origin` | `aa8f3ba912620ae6da153ed1d505d34421db036eb4d8523350667296aeb06038` | After a guest write, the encoded old protection yields exit 42 on Windows and ARM64, 46 on Wine. Empty streams. |
| `executable-virtual-protect-errors` | `d10286a68bc542ce8d0dcabec21a5a8ba7351235278a716e0c5426aacc451b85` | Ten cases emit 124 stdout bytes, with exit 42 and empty stderr. ARM64 matches the Windows records, including successful protection of the output itself. |
| `executable-virtual-protect-denied` | `739c4ac1fa0ea00281d8ea74a80e0a6d60823a283bb9e39dd02090c563a05804` | Store after read-only protection. Windows exits with access violation `0xc0000005` and empty streams. Wine reports the fault through its debugger. ARM64 exits 125 with a guest write-permission fault on stderr. |
| `executable-virtual-protect-sections` | `8e45ff46a5c492b48523858ea7c468e45d0459b72dca67844744298673a62b2d` | A two-byte request crosses adjacent writable PE sections. |
| `executable-virtual-protect-dynamic` | `0063a9cb5f93f628b0cb9a0a46a8799762e82c520333ee38209c374c192b004c` | The same request reads its size from writable guest data. |
| `executable-virtual-protect-split` | `021665696ddcd7eaf2e0297338b5436b1a326ddc6ae57f25abd97c9108c87ac2` | The old-protection DWORD crosses the section boundary. Only the first section is referenced by guest instructions. |

The focused native regressions additionally cover checked adapter output, read-modify-write, atomic exchange, protected IAT, immutable data, executable promotion, guard requests and a second guest load base. The managed harness executes two independent occurrences from one artifact at O0 and O2. The Windows and Wine jobs validate the same producer manifest before execution. [ARM64 executable tests](../../../integration/test_executable.py) · [Process isolation tests](../../../integration/test_process.py) · [Supported transitions and ownership](../../../../docs/runtime-architecture.md#managed-guest-page-protection)

### CMP16mi acceptance and remaining compatibility work

The SDK-free executable reads the DOS header via a relocated pointer, an unaligned writable word through an indexed address, an unaligned stack word and two immutable words. Its branches consume comparison flags. Stdout records five pairs of SETO and LAHF bytes, including AF, and status 42 requires the register and memory sentinels to survive. The standalone native test repeats the run at an alternate base. Windows Server 2022 and the pinned Linux amd64 Wine job exercise the macOS producer’s PE. [Assembly](../../../fixtures/executable-cmp16mi.s) · [Executable regression](../../../integration/test_executable.py)

The ARM64 observations were `00 46 01 12 01 87 00 12 00 86`, empty stderr and exit 42. Running the same PE under pinned Wine 8 on Apple Silicon Docker returned `00 46 01 02 01 87 00 02 00 86`. The differing bit is AF for `0x8000 - 0x7fff` and `0x1330 - 0x1201`. Keep this host result distinct in reference reports and use the native Linux amd64 Wine producer for the regression gate. [Wine reference environments](../../README.md#troubleshooting-and-ci)

A successful scalar read requires both bytes to fit one readable mapping. Two readable adjacent mappings yield terminal `FORGE_RT_UNSUPPORTED`, status `FORGE_RT_OK` and an empty fault payload. An inaccessible second byte yields a read fault at that guest address. The managed test observes a service marker on each successful branch and its absence on both terminal paths. Successful cross-mapping access belongs in the shared guest-memory implementation for all applicable scalar operations. [Memory contract](../../../../docs/runtime-architecture.md) · [Boundary regression](../../../integration/test_process.py)

| Outstanding item | Disposition |
| --- | --- |
| Startup metadata triggering standard-handle capture (P3) | Defer until the launcher exposes richer configuration. |
| Full Unicode startup titles and Windows ANSI code pages | Defer conversion support and retain call-time rejection of unsupported input. |
| General FILE allocation, stream modes and explicit flush services | Deferred beyond the redirected legacy stdout/stderr subset. |
| Wine `_onexit` allocation exhaustion | Parity remains unverified. |
| PE TLS initialization and callbacks | Separate loader task covering template copying, index publication and pre-entry callbacks. |
| TLS storage, thread attach/detach and destructors | Deferred with TEB/TLS lifecycle support. |
| Missing Windows and CRT services | Future compatibility tasks, including `puts` (Debug puts), `vfprintf` (15 startup inputs), `fprintf` and `__setusermatherr`. |
| GUI CRT error reporting | Detect required GUI routing at `_amsg_exit`. The message-box backend is deferred. |
| Guest exception delivery and SEH | Separate exception-delivery task. |
| Scalar reads across adjacent readable mappings | Separate shared guest-memory task. |
| Dynamic code modification, JIT and self-modifying code | Future compiler/runtime research. |
| Guard pages and full copy-on-write memory | Deferred pending exception delivery and shared/private backing semantics. |
| Nonempty pseudo-relocation lists | Add a future integrated execution case. The original sixteen all take the empty-list path. |
| Immutable and executable page protection changes | Deferred. Retain the reviewed boundary, allocation/retry and access-order tests when extending coverage. Measure repeated checked-write walks before optimizing page tracking. |
| VirtualQuery | Separate service consuming the original and effective page state. |
| General dynamic indirect calls | Future compiler research. Arbitrary register calls still require target and path evidence. |

### Conventional startup responsibilities

| Responsibility | Current result for the selected configuration |
| --- | --- |
| Translate instructions in the executable | Forge lifts the observed repeat store, direction flag operations, aligned 64-bit interlocked operations and primary-thread TIB self read. Recovery also handles a direct linker import thunk and the proved guarded callback load. Managed executable artifacts preserve the imported-function address in R12 and guard its call through the loop. |
| Initialize the PE and its primary thread | The runtime provides process parameters, guest stack bounds and isolated mappings. The PE additionally needs a TLS template and index, followed by the two process-attach callbacks before entry. The callbacks enter a critical-section lifecycle. A successful dry recovery of a callback target does not execute a loader callback. |
| Call the external Windows CRT | There are typed adapters for a bounded argument/heap/byte subset and four writable data exports. MSVCRT can call recovered guest initializers from bounded tables. The exit path can run admitted guest termination handlers in the managed process. The full CRT still has unrecovered dependencies. |
| Deliver guest exceptions | The compiler reports validated entry scope, filter, handler import and continuation evidence. Running the filter on a guest exception requires the guest fault PC, exception context, guest stack unwinding and continuation. The current process fault result terminates the run. |
| Print through stdio | `puts` remains a required external MSVCRT symbol in its own fixture. The primary fixture already imports `__iob_func`, `fprintf`, `fwrite` and `vfprintf` for CRT paths. Legacy stream identity, redirected `fwrite` and terminal flushing now have bindings. The two formatted-output imports still require varargs and formatting support. |

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
