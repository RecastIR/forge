# Forge

Forge inspects Windows PE32+ AMD64 executables and DLLs on macOS. It reports the image layout, imported and exported symbols, base relocations, TLS, AMD64 exception metadata, and the static dependency graph. Function analysis identifies unwind-backed code ranges. The experimental lifter translates individual register-only functions into LLVM IR for native ARM64 compilation. Inspection and lifting both read the PE as a file.

## Repository layout

The root CMake project builds one executable, `forge`. Its headers are private to the project.

| Location | Responsibility |
| --- | --- |
| `src/cli/` | Command dispatch, argument validation, and inspection report rendering |
| `src/pe/` | File input, PE parsing, image metadata, and DLL dependency resolution |
| `src/analysis/` | Function discovery, debug information, and analysis reports |
| `src/lift/` | Translation of supported function instructions to LLVM IR |
| `cmake/` | Formatting and static-analysis commands |
| `tests/integration/` | Build, CLI, code generation, and native execution suites and their Python helpers |
| `tests/fixtures/` | SDK-free PE fixture sources and their generator |
| `tests/support/` | C++ harness for calling a lifted function from a test |
| `tests/differential/` | Windows x64 fixtures, manifests, cross-build tooling, and Wine reference capture |

Add new production code to the component that owns it. Create `runtime/` when generated code first needs a shared native implementation, and `tests/unit/` with the first isolated unit suite. Register tests in `tests/CMakeLists.txt`. Build the whole-executable fixtures with `./tools/build-windows-fixtures.sh --all`, then capture their Wine references with `./tools/run-windows-references.sh --all`. On Apple Silicon, compare enabled lifted functions with `./tools/run-differential.sh --all --config debug` or `--config release`. See the [fixture guide](tests/differential/README.md).

## Build and run

The verified baseline is Apple Silicon, Apple Clang with C++20, CMake 3.20 or later, and Homebrew LLVM 17.0.6. Tests also use Python 3.9+, LLVM Clang, `llvm-mc`, `llvm-dlltool`, `lld-link`, `llvm-readobj`, `opt`, and `llc`.

```sh
brew install cmake llvm@17
make
build/forge inspect path/to/game.exe
build/forge inspect path/to/game.exe --verbose
build/forge inspect path/to/game.exe --dll-path ./bin --dll-path ./plugins --format json
build/forge inspect path/to/game.exe --strict --format json > report.json
```

`make` configures and builds Forge in `build/`. On first configuration, CMake looks for Homebrew's `llvm@17`. To select another installation, run `make LLVM_DIR=/path/to/lib/cmake/llvm`. CMake remembers that selection and rediscovers the fixture tools when you change it. For a CLI-only build, use `make BUILD_TESTING=OFF`. Use `BUILD_TESTING=ON` to re-enable the tests.

Set `BUILD_DIR` to choose an out-of-source build directory. With Unix Makefiles, `CONFIG=Release` sets the cached build type and later calls reuse it. With Xcode, pass `CONFIG` on each invocation to select the configuration for that command. Its default is `Debug`.

```sh
CMAKE_GENERATOR=Xcode make test BUILD_DIR=build-xcode CONFIG=Release
make fixtures BUILD_DIR=build-xcode CONFIG=Release
make clean BUILD_DIR=build-xcode CONFIG=Release
```

## Development checks

Install Apple's developer tools with `xcode-select --install`. The Homebrew LLVM package in the build instructions also provides `clang-format`, `clang-tidy`, and `llvm-config`. Formatting and linting are opt-in locally. The GitHub Actions workflow checks formatting, runs clang-tidy, and tests Debug and sanitizer builds on macOS 26 ARM64 for pull requests and pushes to `main`. It uses LLVM 17.0.6 and a Python environment with Unicorn 2.1.4 for the function-level oracle.

```sh
make format-check   # Verify Forge, harness, and Windows fixture formatting
make format         # Apply the same formatting
make lint           # Analyze Forge and the native C++ test harness
make test CONFIG=Debug
make sanitize       # Run CTest in a separate Debug build with ASan and UBSan
```

`make lint` configures `<BUILD_DIR>-lint/` with Unix Makefiles and refreshes its `compile_commands.json` on each invocation. On macOS it pairs the selected LLVM compiler and clang-tidy with the macOS SDK. This also works alongside an Xcode build. Discovery uses `llvm-config` on `PATH`, then Homebrew's unversioned LLVM or the newest installed versioned formula. Set `LLVM_CONFIG` to choose the tools and `LLVM_DIR` to select a different LLVM library package.

```sh
make lint LLVM_CONFIG=/path/to/bin/llvm-config
make configure CMAKE_ARGS=-DCMAKE_EXPORT_COMPILE_COMMANDS=ON
make lint LINT_DATABASE=build/compile_commands.json
```

The last two commands regenerate and use a Unix Makefiles or Ninja build's own database. Choose a clang-tidy version compatible with that build's compiler and C++ headers. An external database must include the harness and every Forge translation unit. Analyzer findings and selected bug-prone checks fail lint. Other diagnostics are advisory.

## Dependency policy

Discovery reads the direct and RVA-based delay import tables and preserves DLL spelling, symbol names, and ordinals. Resolution matches filenames using ASCII lowercase. For each physical DLL, Forge checks the importing module’s directory, then each explicit `--dll-path` in order. Relative command-line paths use the invocation directory. Each lookup considers only immediate directory entries.

The first matching directory wins. Case variants in the same directory produce `ambiguous`. An incompatible file in the winning directory produces `incompatible`. Forge parses each compatible DLL once by file identity. If hard links expose it in two directories, Forge resolves its imports separately from each directory. Aliases within one directory share a traversal. Symlinks use the target’s canonical directory for that module’s imports.

| Kind | Forge policy |
| --- | --- |
| Windows system | `advapi32`, `combase`, `gdi32`, `kernel32`, `kernelbase`, `ntdll`, `ole32`, `shell32`, `shlwapi`, `user32`, and `ws2_32` (each with `.dll`) are recorded as `external_api`. |
| API set | Names beginning with `api-ms-`, `ext-ms-`, `api-win-`, or `ext-win-` are recorded as `unresolved_contract`. Mapping a contract to its host requires a Windows-version-specific mapping. |
| Third-party runtime | `msvcp140`, `msvcp140_1`, `msvcp140_2`, `vcruntime140`, and `vcruntime140_1` (each with `.dll`) require a compatible physical DLL. |
| Other | A compatible match is classified as `application`. A missing file remains `unknown`. |

Forge applies this static policy independently of the Windows loader. Dynamic loads, export-forwarder resolution, API implementations, and symbol binding are outside the dependency resolver. A resolved edge means Forge found and inspected a compatible DLL. Exception results contain runtime-function metadata. Legacy VA-based delay descriptors produce an unsupported-form diagnostic. Metadata tables must fit in file-backed section data. Variable-length tables and names have per-image expansion limits of one million records and 64 MiB of name data.

## Reports and exit codes

Default text shows section layouts and counts for each metadata table and dependency status. Use `--verbose` for individual symbols, relocation entries, exception ranges, callbacks, resolution edges, and search paths. With `--format json`, stdout contains one schema-v1 document for a completed inspection. Human-readable diagnostics go to stderr.

- `schema_version` is the integer `1`. `inspection.root_module` indexes `modules`. Each physical module records its first-discovered canonical path, binary metadata, sections, imports, exports, relocations, TLS, and exceptions. Absent TLS and exception directories are `null`. Empty tables use arrays.
- Fields ending in `_rva` are relative virtual addresses. VA and RVA fields are hexadecimal strings. File offsets and sizes are integers in bytes. Relocation types use PE numeric codes.
- `dependencies` retains one edge per import descriptor for each distinct importing directory. `importer` and `importer_directory` identify the source, and `import_index` indexes that module’s `imports`. A resolved edge’s `target_module` and `target_directory` identify the source of its outgoing edges. `path` preserves the selected filename, and `search_directory` records where Forge found it.
- `diagnostics` associates stable codes with dependency indices. `summary` counts edges by status across all importing directories. Paths are absolute. The same files, locations, and search order produce byte-identical JSON.

| Exit | Meaning |
| --- | --- |
| `0` | Inspection completed, including any dependency findings. |
| `1` | Input read, PE inspection, or internal failure. |
| `2` | Invalid command line or search-directory configuration. |
| `3` | Inspection completed and `--strict` found a required edge with status `missing`, `ambiguous`, `incompatible`, `inaccessible`, or `unresolved_contract`. |

A required edge is reachable from the root via direct imports alone. Requiredness follows the module and directory together. A DLL’s direct imports can therefore be required through one hard link and optional through another. Delay-only subgraphs remain in the report. Strict mode uses the same report and accepts `external_api` as a declared external provider.

## Test and reproduce fixtures

```sh
make test
make fixtures
build/forge inspect build/fixtures/metadata.exe --strict
```

CTest runs `tests/fixtures/generate.py` to assemble and link SDK-free sources with fixed PE timestamps into the build directory. Tests compare metadata to `llvm-readobj` and create malformed copies in temporary directories. To exercise same-directory case collisions on a case-insensitive Mac, point `TMPDIR` at a writable directory on a case-sensitive volume.

`make fixtures` regenerates just the test images. `make sanitize` builds and runs the suite in Debug with AddressSanitizer and UndefinedBehaviorSanitizer in `<BUILD_DIR>-sanitize/`. It forwards `CMAKE_ARGS`, including compiler and deployment-target settings. Direct CMake builds can enable the same instrumentation with `-DFORGE_ENABLE_SANITIZERS=ON`. `make clean` removes compiled targets from the selected configuration and keeps the CMake cache.

## Discover functions

```sh
build/forge analyze fastgron.exe --functions
build/forge analyze fastgron.exe --functions --format json --strict
```

Analysis reads the root image's PE exception directory, conventionally stored in `.pdata`. Each record reports a half-open interval `[start_rva, end_rva)`, byte count, unwind RVA, original zero-based record indices, and entry-point/TLS-callback membership. Where embedded DWARF is usable, LLVM supplies the enclosing function's linkage name and source location, including when its first instruction comes from an inlined call. Gaps in executable sections remain `unknown_executable_ranges`. These may include leaf functions, padding, or embedded data.

Exact duplicate triples share one row with all their indices. Overlapping, nested, and same-range/different-unwind records share an overlap diagnostic identifying the connected group of records. Each participating row is ineligible for lifting. Invalid bounds, ranges outside file-backed executable sections, and zero, unaligned, or unmapped unwind references produce warnings.

For AMD64 unwind versions 1 and 2, Forge checks the four-byte header and the extent of the declared unwind codes. A record with `UNW_FLAG_CHAININFO` describes a continuation of another function. Forge checks that its aligned chain trailer fits and reports `chained_fragment: true`. A valid disjoint fragment counts as covered code, passes strict analysis, and has `liftable: false`. Both lift interfaces reject that start. An unrecognized version produces `status: "unsupported"` and the numeric `unwind_version`. Its range stays unknown. Strict analysis returns 0 when the only issue is an unrecognized version.

The analysis JSON has its own schema version 1. Rows are sorted by start, end, unwind RVA, and original record index. `liftable` means discovery accepts the range. Instruction and ABI checks run during `lift`. Analysis exits with 0 upon completion, 3 for record findings under `--strict`, 1 for unreadable input or tables, and 2 for usage errors. A trailing partial record produces a finding and preserves the complete records before it.

## Lift and run a native function

The following example builds a Windows EXE from `tests/fixtures/add.c`. Clang compiles its arithmetic and the generator adds a PE unwind record for the leaf. Forge reads the resulting five bytes at RVA `0x1000`. The native C++ harness reads pairs of hexadecimal integers and prints each result in hexadecimal.

```sh
make test
llvm_bin="$(brew --prefix llvm@17)/bin"
build/forge analyze build/fixtures/add.exe --functions
build/forge lift build/fixtures/add.exe --rva 0x1000 \
  --signature 'i64(i64,i64)' --output build/add.ll
"$llvm_bin/opt" -passes=verify -disable-output build/add.ll
"$llvm_bin/llc" -filetype=obj build/add.ll -o build/add.o
"$llvm_bin/llvm-readobj" --file-headers build/add.o
xcrun clang++ -arch arm64 -std=c++20 tests/support/native_harness.cpp build/add.o -o build/add-harness
printf 'a 14\nffffffffffffffff 1\n' | build/add-harness
```

The object reports `Mach-O arm64`. The harness prints `1e` and `0` for 10 + 20 and −1 + 1.

Both IR interfaces retain the internal `forge_lifted_<hex RVA>` function through optimization. Its pointer addresses seven 64-bit slots in this order — RAX, RCX, RDX, R8, R9, R10, R11. Reads use their incoming values. Writes update those slots. Condition flags are local to the supported compare/branch pair. Plain `ret` ends the isolated call. Guest stack state, return addresses, and flags across calls are outside this interface.

The sole supported signature adds `extern "C" int64_t forge_lifted(int64_t, int64_t)`. The caller declares this contract. The wrapper places its native arguments in the RCX and RDX slots, calls the lifted body, and returns RAX. Every reachable path must define any additional register before reading it and must define RAX before returning. Forge verifies the module, writes and closes a sibling temporary file, then publishes it with one rename. A failed lift preserves an existing output file.

| Supported x86-64 forms | Semantics |
| --- | --- |
| 32/64-bit register and immediate moves, same-register XOR and SUB | A 32-bit write clears the upper register half. Same-register XOR and SUB define zero independently of the previous value. |
| ADD, SUB, two-register IMUL | Arithmetic wraps at the operand width. Immediate forms use the decoder's sign extension. IMUL retains the low half. |
| LEA with a 64-bit base/index address expression | Scaled index and displacement use integer arithmetic. The destination can be 32 or 64 bits. |
| CMP immediately followed by Jcc | Equality, inequality, and signed and unsigned order comparisons at the CMP operand width. Each incoming path to Jcc must supply that comparison. |
| Short/near forward direct jumps and ordinary RET | Targets must lie on decoded instruction boundaries within the discovered range. Every reachable path ends in a return. |

The experiment accepts exact discovered starts in PE32+ AMD64 EXEs, with a 64 KiB per-function limit. The whole range must decode linearly. Reachable instructions must satisfy the allowlist. Unsupported cases include 8/16-bit operands, legacy prefixes, nonvolatile registers, guest memory, explicit stack operations, RIP-relative addressing, calls, loops, indirect branches, SIMD, and code bytes subject to base relocations. Diagnostics include the RVA and failing form or bytes.

### Lifting approach

Forge uses LLVM 17 MC for instruction decoding, an explicit translation for each supported form, and LLVM's AArch64 backend via `llc`. The same installed toolchain builds on Apple Silicon, verifies the IR, and produces Mach-O objects. The opcode names and operand layouts follow LLVM 17.0.6. Upgrading LLVM requires rerunning the decoder and behavioral tests.

Remill provides maintained x86-64 semantics and tests LLVM 17 and newer in CI, with macOS builds in its Nix matrix. Using its IR for this native interface would also require adapting its state, memory, and control-flow intrinsics. Its broader instruction coverage is relevant when Forge grows beyond register-only functions. [Remill build matrix](https://github.com/lifting-bits/remill/blob/master/.github/workflows/build.yml) · [Remill intrinsics](https://github.com/lifting-bits/remill/blob/master/docs/INTRINSICS.md)

RetDec lifts x86-64 for decompilation and documents macOS support. Its modified LLVM 8 dependency and limited maintenance make direct integration into Forge's LLVM 17 ARM64 build a larger undertaking. Native Apple Silicon integration and executable equivalence were unverified for that option. [RetDec](https://github.com/avast/retdec) · [RetDec LLVM fork](https://github.com/avast/llvm)

### Verification and fastgron

The `codegen` suite checks the exact RVA-named function in both optimized IR interfaces and emits ARM64 objects. On Apple Silicon, `native` compares the C++ harness with arithmetic references before and after IR optimization. It exercises 272 boundary and seeded random input pairs per case. All ten predicates run at both 32 and 64 bits. Their two paths return distinct constants so equal operands reveal a strict/inclusive comparison error. A separate fixture changes SUB to ADD in the linked PE.

The optional `differential` suite uses Unicorn when its Python package is available to CTest's interpreter. It executes the fixture's original x86-64 code bytes with a Windows x64 call frame and compares the resulting RAX with the native harness. This is isolated machine-code differential execution. The standard native run and the generated functions have no emulator dependency. CTest reports a skip when the optional oracle or native host is unavailable.

```sh
ctest --test-dir build -C Debug -R '^differential$' --output-on-failure
```

On Apple Silicon, 30 fixture cases passed all 8,160 source-reference comparisons before optimization and all 8,160 after optimization. The optimized native functions also matched all 8,160 independent Unicorn 2.1.4 results. As a negative check, substituting JL for JLE in the linked PE failed on input `(0, 0)` under both normal Python and `PYTHONOPTIMIZE=1`.

The pinned Windows fastgron v0.7.7 executable (SHA-256 `1c18064f88804a0519fa51d9a4755bd25b7b73d16e28bddf24e3e1688480eb47`) produced 235 valid ranges and no analysis findings. LLVM resolved `0x29c50` to `std::ctype<char>::do_widen(char) const` at `locale_facets.h:1092`. Its bytes `89 d0 c3` lifted and compiled to ARM64. The signatureless form models the EDX-to-EAX move and zero-extension. That C++ member function has a different prototype from the fixture wrapper. At `0x18670`, lifting stopped at `0x18673` on `CMP8ri [80f909]`. The subsequent `setbe %al` also requires unsupported byte semantics. [fastgron v0.7.7 release](https://github.com/adamritter/fastgron/releases/tag/v0.7.7)

```sh
build/forge lift fastgron.exe --rva 0x29c50 --output build/fastgron.ll
"$llvm_bin/llc" -filetype=obj build/fastgron.ll -o build/fastgron.o
"$llvm_bin/llvm-objdump" -d build/fastgron.o
```
