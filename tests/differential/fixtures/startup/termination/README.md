# Legacy MSVCRT termination and Win32 startup reference

The SDK-free, x64 console PEs are built once with LLVM 23.1.5 and LLD. The Windows job downloads the producer’s PE files and verifies their individual hashes and the manifest digest before running them with the system DLLs. The archives include the environment, fixture hashes, raw records and observed streams. Captured children inherit redirected handles. Clear-mode children inherit the runner’s normal launch settings and write their structure record to a file. [Probe inventory](../../../reference/termination/inputs.txt) · [Observer](../../../reference/termination/observe.py) · [Assembly](../../../../fixtures/crt-termination.s) · [System DLL probes](../../../../fixtures/crt-termination-reference.c)

The matched producer manifest SHA-256 was `9139198f527bf7e69792e246a1281a99d01c9c47bf0ba257f2af86bd92c08053`. The pinned Wine 8 image ID was `sha256:d85b416176aed6da31df88d5ee68d561180d48c799d8173d1b8e8d4af2de8d5d`.

## Termination

| Probe | Windows Server 2022 | Pinned Wine 8 | Status (DWORD) |
| --- | --- | --- | --- |
| Duplicate A, then B, return from cleanup and clean again | BAAM | BAAM | 42 |
| Normal CRT exit | BAA | BAA | 0xcafe002a |
| B calls Win32 ExitProcess | B | B | 57 |
| B registers C | BCAAM | BAAMC | 42 |
| B registers C and recursively calls _cexit | BCAAM | BCAAM | 42 |
| Same recursive call, then B writes D | BCAADM | BCDAAM | 42 |
| B registers C and calls exit(67) | BCAA | BC | 67 |

Every captured stderr stream was empty. A, B and C identify guest handlers. M is the caller’s continuation after returning cleanup. The probes exercise the guest MinGW-style `atexit` wrapper, ordinary IAT calls and import thunks. The return value also checks callback-written last error. Forge compares the translated executables with the Windows column. Its separate embedded process harness observes the full native process result after rebasing and running two separate occurrences. [Windows captures](windows-raw.zip) · [Wine captures](wine-raw.zip) · [Executable regressions](../../../../integration/test_executable.py)

On Windows Server 2022 build 20348, system MSVCRT 7.0.20348.5756, successful registration returned the callback pointer. Null registration returned NULL. Both preserved last error 91 and errno 37. A 32 MiB job limit induced a real allocation failure after 2,006,514 registrations. The call returned NULL with last error 8 and errno 12. Cleanup ran every accepted handler once. Under the same bounded test, Wine 8 accepted and ran all four million registrations. Wine allocation failure remains unobserved. Its source implements registration and cleanup using an on-exit table that detaches the current entries for execution. Forge uses a live process-owned stack and reproduces the Windows failure signals at its smaller resource bound. [Windows job](https://github.com/RecastIR/forge/actions/runs/44539179217) · [Wine 8 exit implementation](https://github.com/wine-mirror/wine/blob/wine-8.0/dlls/msvcrt/exit.c)

Microsoft documents normal termination including flushing and closing CRT streams. On both measured legacy DLLs a fully buffered disk file had size zero before and after returning `_cexit`, and its OS handle still identified a disk file. After the child subsequently called Win32 `ExitProcess`, the file contained byte 0x58. The independent `exit(42)` case also left 0x58. The process-end file therefore cannot establish that returning `_cexit` flushed or closed the stream. Forge supports termination for its existing CRT subset. Reachable `fopen` and related stream operations are explicit unsupported imports. [Microsoft termination contract](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/cexit-c-exit) · [Supported cleanup contract](../../../../../docs/runtime-architecture.md#legacy-msvcrt-termination-handlers)

## GetStartupInfoA and GetStartupInfoW (P2)

The three original Task 13.3H PEs returned 1 on native Windows in both launch modes because their reserved-pointer assertion expected NULL. They returned 43 under the Wine capture parent and 44 in the flag-clear Wine launch. Forge reproduces Windows’ reserved-pointer behavior. The additional A/W probe checks the measured padding together with the original standard-handle checks. Its exit code distinguishes the launcher’s handle policy. [Assembly probes](../../../../fixtures/executable-startup-info.s)

| Observation | Windows Server 2022 | Pinned Wine 8 |
| --- | --- | --- |
| Structure size and both calls’ last error | 104, 91 | 104, 91 |
| Padding at offsets 4–7 and 68–71 | Both preserved the 0xbc sentinel | Both zeroed the padding |
| STARTF_USESTDHANDLES set, before changing stdout | A and W reported all original handles | Same |
| Flag set, after changing stdout to stderr | A reported creation stdout, W reported current stdout | Both continued to report creation stdout |
| Flag clear | A wrote INVALID_HANDLE_VALUE in all three slots, W left all three untouched | A and W returned cached handles |
| String pointers | All three present in both views, with an empty shell string, `winsta0\default`, full guest PE path | Null reserved pointer, launch-dependent desktop, title identified the PE |
| Reserved byte buffer | Zero size and null pointer | Zero size and null pointer |

Forge validates the entire output before writing the named fields. Unit tests compare all 104 bytes with sentinels, read the guest strings through checked memory, exercise seeded flags and handle changes, and check that an invalid final byte leaves the writable prefix untouched. The public launcher supplies zero flags. Its defined creation metadata is described in the runtime contract. [Win32 state and deferred launcher work (P3)](../../../../../docs/runtime-architecture.md#win32-startup-information) · [Runtime tests](../../../../unit/runtime_startup_info.cpp)

## Reproduction

Run `make fixtures` and `./tools/test-forge.sh --executable-reference` for the pinned Wine executable comparisons. On ARM64, `ctest --test-dir build/dev -C Debug -R '^(native_executable|runtime_contract)$' --output-on-failure` exercises the translated executables and runtime. The focused Windows CI job also captures the C-only system DLL probes. Its producer inventory and SHA-256 manifest must match the actual PE files. The observer accepts `--wine` for a prepared pinned prefix with the repository’s capture helper. [CI definition](../../../../../.github/workflows/ci.yml) · [Pinned reference environment](../../../README.md)
