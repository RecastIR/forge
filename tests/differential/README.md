# Windows whole-executable fixtures

These C11 and C++20 console programs provide Windows x64 inputs for whole-executable reference runs. Each manifest records a single invocation and its expected output. The programs build independently of Forge.

| Fixture | What the invocation exercises |
| --- | --- |
| `arithmetic/add_i64` | Two signed 64-bit sums, one positive and one negative, computed by the exported two-argument leaf. Enabled for function-level differential testing. |
| `arithmetic/basic` | Two digits supply bounded signed operands, a nonzero divisor, and the shift count for a 32-bit unsigned rotation. |
| `arithmetic/weighted_pair_i64` | A signed 64-bit branch selects addition or subtraction after tripling the left operand’s low 32 bits. Enabled for function-level differential testing. |
| `control_flow/branches` | One pass covers the early return, even and odd digits, three switch arms, and the default. Each input byte has its own output line. |
| `functions/calls` | Recursive calls return into a six-argument call that uses four Windows x64 argument registers and two stack slots. |
| `memory/arrays` | Stack struct fields supply products written through a pointer into a heap allocation. The program sums the products and frees the allocation. |
| `globals/state` | An initialized global, a zero-initialized global, and a static local change across iterations. Input bytes select weights from read-only data. |
| `imports/kernel32` | Process and module validity and a last-error round trip yield three Boolean results. |
| `cpp/lifetime` | The input selects both derived types. The program prints the result of virtual dispatch and the order of construction and destruction after each scope ends. |
| `runner/stderr_only` | Writes exactly `runner-error\n` to stderr and exits zero. |
| `runner/exit_nonzero` | Exits 7 with both streams empty. |
| `runner/exit_and_stderr` | Writes the same 13 stderr bytes and calls `ExitProcess(0x1234)`. |

## Build and inspect

From the repository root, use Docker with Linux amd64 container support. Apple Silicon uses Docker Desktop's amd64 emulation. The first build needs access to the Debian image registry and package snapshot. Fixture compilation and inspection run with networking disabled. The normal Forge build and native CTest suite require only their existing tools.

```sh
./tools/build-windows-fixtures.sh --all
./tools/build-windows-fixtures.sh --config debug
./tools/build-windows-fixtures.sh --config release
```

The wrapper configures the standalone fixture CMake project with Ninja and the Windows x64 toolchain. Each selected configuration builds twice in clean directories. The wrapper checks the exact set of executables, compares the bytes, and uses MinGW objdump to check PE32+, AMD64, executable characteristics, the zero timestamp, and the kernel32 case's four named imports. It then replaces that configuration's export directory. Each directory contains the executables and a filename-sorted `SHA256SUMS` file.

```sh
(cd build/fixtures/windows-x64/debug && shasum -a 256 -c SHA256SUMS)
build/forge inspect build/fixtures/windows-x64/release/imports_kernel32.exe --format json
```

The Dockerfile pins the amd64 Debian Bookworm image by digest and installs packages from the signed 2025-02-24 snapshot. The cross compiler uses the Win32 threading model. The exact package revisions are GCC/G++ `12.2.0-14+25.2`, MinGW-w64 headers and libraries `10.0.0-3`, binutils `2.40-2+10.4`, CMake `3.25.1-1`, and Ninja `1.11.1-2~deb12u1`. The build fixes the locale, timezone, source and debug directory mappings, and PE timestamp. Debug uses `-O0 -g` and Release uses `-O2`. Compiler support libraries are linked statically. [Toolchain definition](toolchain/Dockerfile) · [Compiler and linker flags](fixtures/CMakeLists.txt)

## Manifest v1

Each UTF-8 JSON file under `manifests/` declares one executable. For example:

```json
{
  "schema_version": 1,
  "id": "memory/arrays",
  "description": "Sum weighted bytes copied from stack records to a heap array.",
  "source": "fixtures/memory/arrays.c",
  "binary": "memory_arrays.exe",
  "args": ["Forge"],
  "expected": {"exit_code": 0, "stdout": "sum=1551\n", "stderr": ""}
}
```

Use a unique lowercase `category/name` ID and a portable, case-insensitively unique `.exe` basename. Source paths are relative to this guide's directory and must resolve inside `fixtures/`. Binary names resolve inside the selected configuration's export directory. The ordered `args` list excludes the executable name. Use `[]` for an invocation without arguments.

Both expected streams are required, including empty strings. Their UTF-8 encoding specifies the exact bytes and ordering within each stream. Fixtures use ASCII and set stdout and stderr to binary mode so LF remains LF in redirected Windows output. The exit code is an unsigned 32-bit process status. The contract preserves whitespace and trailing newlines and uses literal strings throughout.

## Add a fixture

1. Add a small source under `fixtures/<category>/`. Include `streams.h` and call `open_binary_streams()` before output. Make the result depend on arguments or an observable API operation. Bound arithmetic, shifts, memory accesses, and recursion for every accepted input. Convert environment-dependent values into deterministic checks inside the program.
2. Add the manifest under `manifests/` or a category subdirectory. Derive the expected exit status and streams from the declared input. CMake discovers targets from the validated manifests.
3. Run `python3 -B tests/differential/manifests.py`, `make format-check`, and the Docker build from the repository root. Inspect optimized code when a particular call, memory access, or branch is essential to the case. Commit source and metadata. Git ignores the generated binaries and checksums under `build/`.

## Capture Wine references

Use Python 3.9 or newer and a local Docker engine with Linux amd64 support. Run these commands from the repository root after building the corresponding configurations.

```sh
./tools/run-windows-references.sh --all
./tools/run-windows-references.sh --config release
./tools/run-windows-references.sh --fixture runner/exit_and_stderr --config debug
```

The runner locks the publication directory, withdraws the selected previous results, and loads the same validated catalog as the builder. For each invocation it checks a private binary snapshot against the export's `SHA256SUMS` and mounts that file read-only in a fresh container. MinGW objdump checks the snapshot's PE format. The container runs as an unprivileged user with a fixed hostname, UTC, `C.UTF-8`, a private initialized 64-bit Wine prefix, and networking disabled. The Windows working directory is `C:\work`, stdin reads from `NUL`, and the fixture starts with the ordered manifest arguments. Container removal discards the working directory, registry, and remaining processes.

The reference image extends the pinned toolchain with Debian Wine and libwine `8.0~repack-4`. A Windows parent starts the PE with separate inheritable pipe handles and drains both concurrently. On this Wine version the initial ntdll breakpoint follows DLL initialization. The parent detaches there, waits for termination and both pipe readers, and reads the full unsigned status with `GetExitCodeProcess`. A separate control record carries that value to the host. Wine runs with `WINEDEBUG=-all`; its launcher diagnostics have a separate channel with a bounded 64 KiB diagnostic tail.

The startup deadline is 120 seconds and the execution deadline is 10 seconds. Each fixture stream can contain up to 1 MiB. Exceeding a limit fails the invocation and the supervisor removes the container, including descendants holding a pipe open. The deadlines cover fixture execution after image preparation. The runner is intended for repository-owned console fixtures. GUI, interactive input, external services, and arbitrary untrusted programs fall outside this workflow.

### Result layout and interpretation

```text
build/reference/windows-x64/wine/debug/runner/exit_and_stderr/
  result.json
  stdout.bin
  stderr.bin
```

Manifest expectations describe intended behavior. A passing reference records the observed Wine behavior for one exact binary and manifest. The publisher compares each byte with the UTF-8 encoding of the expected stream, including whitespace, CR, LF, and trailing newlines. It also checks the full exit code. Expected stderr may contain data and an expected nonzero status may pass.

The version 1 JSON names both raw files and records their lengths and SHA-256 hashes, fixture ID, configuration, pass status, exit code, binary SHA-256, relative manifest path and SHA-256, runner version, Wine version, immutable image ID, container platform, and Docker host architecture. The runner version fingerprints the host implementation and the image ID identifies the guest implementation. All three files appear together by directory rename after validation. Git ignores the output tree. A rerun of one fixture withdraws only that fixture's selected configuration.

For the combined regression, `stdout.bin` is empty, `stderr.bin` contains the 13 bytes ending in hex `0a`, and `result.json` records `4660`.

### Troubleshooting and CI

- **Missing executable or checksum mismatch.** Rebuild with `./tools/build-windows-fixtures.sh --config debug` or `--config release`. An unsupported PE fails inspection before Wine launches it.
- **Wine startup or dependency failure.** Check the fixture/configuration label, loader status, and diagnostic tail. Use the pinned toolchain's `x86_64-w64-mingw32-objdump -p` to inspect imported DLL names. A missing imported DLL can yield `0xc0000135`; a fixture that deliberately exits with that value after startup has an observable exit code.
- **Output or exit mismatch.** Rerun the individual fixture. Diagnostics identify every differing field, the first differing byte offset, both lengths, and escaped byte context. Check binary stream mode, arguments, and flushes before explicit process termination.
- **Timeout, overflow, or artifact write failure.** Check fixture termination, descendants inheriting handles, output volume, and permissions or free space under `build/reference/`. Correct the cause and rerun to publish a fresh result.

The existing `windows-fixtures` job on native Linux amd64 builds both configurations, runs this CLI, reopens the entire artifact matrix, exercises real Wine failure cases, and uploads the references and matching PE exports together in `windows-x64-inputs` on success. Run `python3 -B tests/differential/reference/test_runner.py` for Wine-free tests and `python3 -B tests/differential/reference/test_wine.py` after a complete capture for integration tests. The native Forge CTest suite includes the Wine-free runner tests.

Linux amd64 CI is the canonical Wine environment. Apple Silicon results record the ARM64 Docker host separately. The image disables Rosetta AVX advertisement because the emulator can otherwise abort while restoring Wine's breakpoint signal context. Wine implements Windows APIs with its own loader and runtime. Equivalence with native Windows requires separate evidence and backend provenance.

## Related Forge tests

The initial suite produced seven Debug and seven Release PEs with byte-identical clean rebuilds for each configuration. Native Forge inspection identified all fourteen as AMD64 PE32+ executables importing `KERNEL32.dll` and `msvcrt.dll`. On macOS, Forge reports `DLL_NOT_FOUND` for `msvcrt.dll` when inspecting without Windows DLL search paths. Release disassembly confirmed recursive calls, stack-passed arguments, stack-to-heap copies, and indirect virtual dispatch.

The SDK-free parser and lifter samples live in `tests/fixtures/`. The existing `differential` CTest uses Unicorn to compare an individual x86-64 function with the ARM64 harness.

## Compare a lifted function with Wine

On Apple Silicon, build Forge with LLVM 17. Prepare matching Windows binaries and references with the commands above, or extract the successful Linux job’s `windows-x64-inputs` artifact into `build/`. The native comparison runs offline using those files.

```sh
make CONFIG=Debug
./tools/run-differential.sh --fixture arithmetic/add_i64 --config debug
./tools/run-differential.sh --fixture arithmetic/weighted_pair_i64 --config debug
./tools/run-differential.sh --all --config release
# Downloaded roots each contain debug/ and release/.
./tools/run-differential.sh --all --config debug \
  --binary-root /path/to/windows-x64-fixtures \
  --reference-root /path/to/windows-x64-wine-references
```

Use `--forge PATH` to select the executable for inspection, analysis, and lifting. Relative paths resolve from the directory where you invoke the runner. The default is the repository’s `build/forge`. The report records the SHA-256 of the selected executable. To use Xcode with a custom build directory, run both commands from the repository root.

```sh
CMAKE_GENERATOR=Xcode make BUILD_DIR=build-xcode CONFIG=Debug
CMAKE_GENERATOR=Xcode ./tools/run-differential.sh --all --config debug --forge build-xcode/Debug/forge
```

The manifest supplies the binary, arguments and expected Windows behavior. [cases.json](cases.json) associates an enabled fixture ID with its function export, explicit ABI signature, scope and CMake harness. Each invocation snapshots the selected PE against its configuration’s `SHA256SUMS`. The consumer checks the v1 reference’s validated status, IDs, configuration, binary and manifest hashes, publisher fingerprint, and Wine provenance. It requires the designated regular stream files, verifies sizes and hashes, and independently checks the recorded bytes and full exit code against the manifest. It compares native behavior with the verified observation held in memory. A local override must point to a trusted producer’s artifacts. Hashes detect changes relative to the publication. CI obtains producer identity from its same-run artifact transfer.

For both enabled arithmetic fixtures, the runner resolves the named PE export and checks that Forge discovered an eligible function at that RVA. The Windows driver calls the exported leaf for each decimal pair. MinGW’s `noipa` preserves the call, and function-local `optimize("O2")` keeps the leaf register-only in both builds. Forge lifts the leaf with `i64(i64,i64)`. The generated native wrapper initializes the guest RCX and RDX slots, calls the lifted body, and reads its result from the guest RAX slot. CMake verifies the IR, emits a Mach-O ARM64 object with `llc`, and links it with the C++20 harness. The harness calls `forge_lifted` for each manifest pair and prints its return value. Each configuration uses its own resolved RVA, PE, and Windows reference.

The `weighted_pair_i64` export compares its original signed 64-bit inputs. It triples the left operand’s unsigned low 32 bits, then subtracts the right operand’s unsigned low 32 bits when the left input is smaller and adds them otherwise. Every intermediate fits in `int64_t`. The function disables MinGW if-conversion to exercise a forward conditional jump. Its 13 pairs include equality, both branch directions, negative results, truncation at 2³², and the decimal parser limits. In particular, `(-1, 1)` and `(4294967295, 1)` have identical low words and take different branches. The manifest expectation comes from the Wine capture. The ARM64 comparison uses the validated Windows process observations.

**Coverage is function-level.** The Windows reference exercises the entire console program. The native run exercises the lifted arithmetic and the harness’s formatting. Ten other fixtures remain in the Wine suite. Current lifting requires an eligible register-only function with an explicit supported ABI. The existing arithmetic, branching and call fixtures need additional instruction, stack or call support to reproduce their observations. The remaining fixtures exercise memory, globals, imports, C++ lifetime, or process behavior. In particular, Windows status 4660 in `runner/exit_and_stderr` requires a future full-width guest termination channel. The current harness provides a normal zero completion. Its nonzero statuses and signals indicate execution failure.

### Reports and diagnosis

Each selected fixture has a `result.json` below `build/differential/windows-x64/<config>/<fixture-id>/`. For enabled cases, the same directory holds the PE snapshot, inspection and analysis JSON, stage logs, `generated/lifted.ll`, the `native/` build, and captured `stdout.bin` and `stderr.bin`. The result records the Forge executable digest, original PE digest, reference identity, function RVA and scope, native architecture, each stage outcome, and any mismatch details. The configuration’s `suite.json` records the latest selection, case report paths, and counts. Reruns replace selected artifacts under a configuration lock.

| Report | Where to look |
| --- | --- |
| Reference validation failure | Check the manifest, export checksum, producer identity, streams and downloaded configuration. Rebuild or recapture explicitly when the inputs change. |
| Analysis failure | Inspect `inspect.json`, `analysis.json` and their logs for missing, forwarded or ambiguous exports and conflicting ranges. |
| Unsupported instruction in an enabled case | Check the selected range and the opcode/RVA in `lifting.log`. This stage error fails the suite. |
| Lifting failure | Inspect `lifting.log` for verifier or IR publication errors. |
| Native compilation failure | The diagnostic identifies configuration, object compilation, or linking. The labelled phase in `compilation.log` contains the underlying CMake, LLVM, compiler, or linker output. |
| Native execution failure | Inspect the captured bytes and diagnostic for launch errors, signals, harness exit, the 10-second deadline or the 1 MiB per-stream limit. The supervisor runs with closed stdin in a fresh directory and terminates the process group on failure. |
| Behavioral failure | The report lists every differing field. For stream differences it includes both lengths, the first differing byte offset and escaped byte context. For decimal-pair stdout it also identifies the operands for the first differing expected line. Extra bytes after the last line have no associated pair. For exit-code differences it includes both semantic values. |
| Uncovered | The manifest has no enabled function-level case. Selecting only uncovered fixtures fails with zero executions. |

To add coverage, first obtain passing Debug and Release Wine references through the fixture catalog. Identify a genuine callable export with a source-declared signature, add its entry in `cases.json`, and reuse the decimal-pairs harness when its invocation fits. A new harness belongs in `tests/support/` with a corresponding CMake target. Harness code may parse inputs and format observations. The computation comes from the linked Forge output.

Use `python3 -B tests/differential/test_differential.py` for the Wine-free comparator, validator, supervisor and runner tests. With the full local artifacts available, `python3 -B tests/differential/test_native_differential.py` lifts and runs the weighted case twice in fresh directories and compares the generated IR and process observations. It also changes a return, injects invalid IR, and renames the callable wrapper in private IR copies to exercise mismatch, compilation, and link failures. It checks a failed harness invocation and a mismatched PE. The negative reports live under `build/differential/negative-tests/`.

## Regression CI and local reproduction

From a clean Apple Silicon checkout, install Xcode, LLVM 17.0.6, CMake 3.21+ (for CTest JUnit), and a Docker engine capable of running Linux amd64 containers. Select a Python environment with the pinned Unicorn oracle.

```sh
python3.12 -m venv /tmp/forge-oracle
/tmp/forge-oracle/bin/python -m pip install --only-binary=:all: unicorn==2.1.4
export CMAKE_ARGS="-DPython3_EXECUTABLE=/tmp/forge-oracle/bin/python"
export LLVM_CONFIG="$(brew --prefix llvm@17)/bin/llvm-config"
export LLVM_DIR="$("$LLVM_CONFIG" --cmakedir)"
./tools/test-forge.sh --all
```

The stage commands also work individually. Run `--native` for formatting, clang-tidy, Debug CTest, and ASan/UBSan CTest. This stage requires the native and Unicorn tests to execute and needs no Docker. Run `--references` to build both PE configurations twice, inspect them, capture Wine behavior, and exercise the real capture boundaries. Run `--differential` after those stages, or after extracting the matching CI inputs. It consumes the existing exports, checks every reference, runs both configurations and the negative integrations, and writes local coverage. Use the individual fixture commands above to investigate a failure. A single-fixture run replaces that configuration’s suite index. Rerun the full differential stage to produce complete evidence.

On PRs into `main` and pushes to `main`, `windows-fixtures` on Linux amd64 and `macos` on macOS 26 arm64 run in parallel. The former publishes validated PEs, checksums, per-configuration toolchain/reproducibility records, and captured references. The latter archives the two tested Forge executables. The `differential` job downloads those same-run artifacts on macOS 26 arm64, uses sanitized Forge with Xcode for Debug and ordinary Forge with the default generator for Release to lift and compile the selected functions, and runs the harnesses. Linux `regression-gate` checks prerequisite stage outcomes and the digests of the two tested Forge executables, reopens the exports and references, and compares the saved native observations again. Hosted references require an amd64 Docker host. Local reports record the actual backend and are labeled local.

The gate publishes a job summary and schema-v1 `build/coverage/coverage.json`. Each row identifies its configuration, target, scope, reference and case report. Read the category totals and passing scopes separately for Debug and Release. A missing prerequisite, case report, or successful execution fails the gate. The JSON and diagnostic artifacts are available from the workflow run for seven days. Extract `macos-arm64-differential` under `build/differential/` to follow report paths. The native harness in the downloaded diagnostics can be made executable with `chmod +x`. Failed Windows captures are kept separately in `windows-diagnostics` and are ineligible as CI reference inputs.

| Coverage status | Evidence |
| --- | --- |
| `passed` | A completed native execution matched the validated Windows observation in all fields. |
| `failed` | A completed execution differed in stdout, stderr, or full exit status. |
| `error` | Required evidence was missing, inconsistent, or invalid, or an enabled stage failed. Inspect the stage diagnostics first. |
| `reference_only` | The PE has a validated Windows reference and no differential case enabled for this configuration. |
| `blocked` | A validated fixture has a predeclared capability limitation for this configuration. The row records the reason. |

For a new enabled case, add its function contract to `cases.json` and add a matching `id`, `config`, `target` obligation to `coverage-baseline.json` for each supported configuration. Cases default to Debug and Release. Use the optional nonempty `configs` list for a narrower contract. A known blocker may be declared as a fixture ID with `blocked_reason` and optional `configs`. A fixture can have an enabled entry for Debug and a blocked entry for Release when their configurations are disjoint. CI never converts an enabled failure into a blocker. An intentional coverage reduction requires matching definition and baseline edits plus an explanation in the PR, preferably with a replacement test or tracking issue. The baseline is maintained by hand.

Repository administrators should require the GitHub Actions check `regression-gate` on `main`, require pull requests and code-owner review, and retain other required checks. The baseline and ownership file designate `@ziflex`. Add a second owner with write access before enforcing owner reviews on baseline changes authored by `@ziflex`. Verify the status check after the first hosted run.
