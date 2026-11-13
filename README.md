# Forge

Forge inspects Windows PE32+ AMD64 executables and DLLs on macOS. It reports the image layout, imported and exported symbols, base relocations, TLS, AMD64 exception metadata, and the static dependency graph. Function analysis identifies unwind-backed code ranges. The experimental lifter translates individual register-only functions into LLVM IR for native ARM64 compilation. Inspection and lifting both read the PE as a file.

## Repository layout

The root CMake project builds the `forge` CLI on a private `forge_core` library. Core contract tests link the same production code. All headers are internal to the repository.

| Location | Responsibility |
| --- | --- |
| `src/cli/` | Command dispatch, argument validation, report and diagnostic rendering, and exit status |
| `src/pe/` | File input, PE parsing, image metadata, and DLL dependency resolution |
| `src/analysis/` | Function discovery, range validation, findings, and optional debug enrichment |
| `src/lift/` | Translation of supported function instructions to LLVM IR |
| `src/output/` | Publication of completed LLVM modules |
| `cmake/` | Formatting and static-analysis commands |
| `tests/integration/` | Build, CLI, code generation, and native execution suites and their Python helpers |
| `tests/fixtures/` | SDK-free PE fixture sources and their generator |
| `tests/unit/` | Core contracts for input lifetime, lifting, verification, publication, integer semantics, and LLVM target setup |
| `tests/support/` | C++ harness for calling a lifted function from a test |
| `tests/differential/` | Windows x64 fixtures, manifests, cross-build tooling, and Wine reference capture |

Add new production code to the component that owns it. Create `runtime/` when generated code first needs a shared native implementation. Register tests in `tests/CMakeLists.txt`. Build the whole-executable fixtures with `./tools/build-windows-fixtures.sh --all`, then capture their Wine references with `./tools/run-windows-references.sh --all`. On Apple Silicon, compare enabled lifted functions with `./tools/run-differential.sh --all --config debug` or `--config release`. See the [fixture guide](tests/differential/README.md).

### Image ownership and stage contracts

`InputFile` validates the opened descriptor and copies its bytes into an owned buffer. `ParsedImage` keeps the physical file identity, that snapshot, its borrowing LLVM COFF object, and the validated PE metadata together. A checked RVA mapping borrows both a section and bytes for the lifetime of the image. The CLI releases the descriptor after acquisition. Replacing the file on disk after that point cannot change what discovery or lifting sees.

Dependency inspection reads import and export tables and retains detached module metadata in its report. Function analysis validates the file-backed extents of the directories it consumes. It skips the import, delay-import and export directories, reads relocations and TLS, and turns recoverable exception-record defects into findings. An `AnalyzedImage` owns its parsed image and the discovered ranges. The analysis command asks for optional DWARF enrichment. The lifter uses the same checked ranges and bytes without opening the path again.

## Build and run

Forge uses Apple Silicon, Apple Clang with C++20, CMake, and a stable **LLVM 23.x** installation. CI pins **23.1.5**. The test suite also uses Python 3.9+, LLVM Clang, `llvm-mc`, `llvm-dlltool`, `lld-link`, `llvm-readobj`, `opt`, and `llc`. Use the complete [LLVM release archive for macOS ARM64](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.5) to obtain these tools together.

```sh
# From a directory containing the release archive, extract to a new directory.
echo '503de30ef90311e0b143623801b19af2250adac6d69faed65ad0051170202e3b  LLVM-23.1.5-macOS-ARM64.tar.zst' | shasum -a 256 -c -
mkdir -p "$HOME/toolchains/llvm-23.1.5"
zstd --long=30 -dc LLVM-23.1.5-macOS-ARM64.tar.zst | tar -xf - --strip-components=1 -C "$HOME/toolchains/llvm-23.1.5"
export LLVM_CONFIG="$HOME/toolchains/llvm-23.1.5/bin/llvm-config"
export LLVM_DIR="$("$LLVM_CONFIG" --cmakedir)"
# In the Forge checkout:
make
build/forge inspect path/to/game.exe
build/forge inspect path/to/game.exe --verbose
build/forge inspect path/to/game.exe --dll-path ./bin --dll-path ./plugins --format json
build/forge inspect path/to/game.exe --strict --format json > report.json
```

`make` configures and builds Forge in `build/`. Set `LLVM_DIR` to the directory containing `LLVMConfig.cmake`, or select its `bin/llvm-config` with `LLVM_CONFIG`. If both are set they must select the same installation. Export your selection when using separate Make, quality, and differential commands. Automatic discovery checks Homebrew’s versioned and unversioned LLVM prefixes on macOS and then the directories on `PATH` for a stable 23.x release. Configuration prints the package version, directory, and paths to the tools needed by that build. For a CLI-only build, use `make BUILD_TESTING=OFF`. Use `BUILD_TESTING=ON` to re-enable the tests.

For a checkout with an LLVM 17 cache, use `make test BUILD_DIR=build-llvm23 CONFIG=Debug`. For the full workflow, which uses fixed directory names, start from a clean checkout or move the old build, lint and sanitizer directories aside after saving any PE and reference artifacts. `make clean` retains the old selection.

Set `BUILD_DIR` to choose an out-of-source build directory. With Unix Makefiles, `CONFIG=Release` sets the cached build type and later calls reuse it. With Xcode, pass `CONFIG` on each invocation to select the configuration for that command. Its default is `Debug`.

```sh
CMAKE_GENERATOR=Xcode make test BUILD_DIR=build-xcode CONFIG=Release
make fixtures BUILD_DIR=build-xcode CONFIG=Release
make clean BUILD_DIR=build-xcode CONFIG=Release
```

## Development checks

Run `./tools/test-forge.sh --all` on Apple Silicon for the complete native, Wine, and differential regression workflow. Stage commands, dependencies, CI artifacts, and the coverage policy are in the [regression guide](tests/differential/README.md#regression-ci-and-local-reproduction).

Install Apple's developer tools with `xcode-select --install`. The LLVM release package also provides `clang-format`, `clang-tidy`, and `llvm-config`. Formatting and linting are opt-in locally. The GitHub Actions workflow checks formatting, runs clang-tidy, and tests Debug and sanitizer builds on macOS 26 ARM64 for pull requests and pushes to `main`. It uses LLVM 23.1.5 and a Python environment with Unicorn 2.1.4 for the function-level oracle.

Forge uses four-space indentation and checks formatting and braces across its C and C++ sources. For naming, readability, IDE setup, and lint scope, see the [C++ style guide](docs/cpp-style.md).

```sh
make format-check   # Check all owned files for formatting and fixtures for braces
make format         # Apply formatting across the same tree
make format-audit   # Run the whole-tree check without writing
make lint           # Check native safety and braces, report whole-function and changed-line advisories
make test CONFIG=Debug
make sanitize       # Run CTest in a separate Debug build with ASan and UBSan
```

`make lint` configures `<BUILD_DIR>-lint/` with Unix Makefiles and refreshes its `compile_commands.json` on each invocation. On macOS it pairs the selected LLVM compiler and clang-tidy with the macOS SDK. This also works alongside an Xcode build. All quality targets use the same LLVM selection as the build. The native build uses Apple’s compiler, SDK and linker. When linking LLVM libraries, the Apple linker loads the selected package’s libLTO to read its ThinLTO bitcode.

```sh
make lint LLVM_CONFIG=/path/to/bin/llvm-config
make configure CMAKE_ARGS=-DCMAKE_EXPORT_COMPILE_COMMANDS=ON
make lint LINT_DATABASE=build/compile_commands.json
```

The last two commands regenerate and use a Unix Makefiles or Ninja build's own database. An external database must include the harness, unit tests, and every Forge translation unit. Lint requires Python 3 and uses a temporary clang-tidy overlay for four expressions in LLVM’s operand-storage headers. LLVM allocates these operands before its C++ objects, which the bounds checker models as separate allocations. The overlay annotates only those upstream expressions for that check. The style guide lists blocking and advisory diagnostics.

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
llvm_bin="$("$LLVM_CONFIG" --bindir)"
build/forge analyze build/fixtures/add.exe --functions
build/forge lift build/fixtures/add.exe --rva 0x1000 \
  --signature 'i64(i64,i64)' --output build/add.ll
"$llvm_bin/opt" -passes=verify -disable-output build/add.ll
"$llvm_bin/llc" -filetype=obj build/add.ll -o build/add.o
"$llvm_bin/llvm-readobj" --file-headers build/add.o
xcrun clang++ -arch arm64 -std=c++20 tests/support/native_harness.cpp build/add.o -o build/add-harness
printf 'a 14\nffffffffffffffff 1\n' | build/add-harness
```

The object reports `Mach-O arm64`. The harness prints `1e` and `0` for 10 + 20 and −1 + 1. It accepts empty input and reports failure for an incomplete pair or an input or output error.

Both IR interfaces retain the internal `forge_lifted_<hex RVA>` function through optimization. Its state pointer requires four-byte alignment and addresses seven 64-bit slots in this order — RAX, RCX, RDX, R8, R9, R10, R11. Reads use their incoming values. Writes update those slots. Condition flags are local to each lifted invocation and start undefined. Plain `ret` ends the isolated call. Guest stack state, return addresses, and flags across calls are outside this interface.

The sole supported signature adds `extern "C" int64_t forge_lifted(int64_t, int64_t)`. The caller declares this contract. The wrapper places its native arguments in the RCX and RDX slots, calls the lifted body, and returns RAX. On every incoming path, a read requires the bits it observes to be defined. Returning requires all 64 bits of RAX. Forge verifies the module, writes and closes a sibling temporary file, then publishes it with one rename. A failed lift preserves an existing output file.

| Supported x86-64 forms | Semantics |
| --- | --- |
| MOV, MOVZX, MOVSX, MOVSXD | Register views share their 64-bit parent. Byte and word writes preserve the other bits, including writes to AH, CH and DH. Doubleword writes clear the upper half. Extension instructions read the encoded source width. |
| ADD, ADC, SUB, SBB, CMP, INC, DEC, NEG | Arithmetic wraps at 8, 16, 32 or 64 bits. CF represents unsigned carry or borrow, OF signed overflow, and AF carry or borrow between bits 3 and 4. INC and DEC preserve CF. CMP only updates flags. Comparing a scratch register with itself sets ZF and PF and clears CF, SF, OF and AF even on first use. SBB of a register with itself produces zero or all ones according to incoming CF. Both idioms require identical register views. |
| AND, OR, XOR, TEST, NOT | Logical results define ZF, SF and even low-byte parity, clear CF and OF, and leave AF undefined. TEST only updates flags. NOT preserves all flags. Same-register XOR and SUB can define zero even on first use of a scratch register. |
| Two-register IMUL | At 16, 32 and 64 bits the low product is stored. CF and OF indicate whether the signed product fits. The other four flags become undefined. |
| SHL/SAL, SHR, SAR | Counts of one, an immediate byte or CL use the x86 five-bit mask (six for 64-bit operands). Effective zero preserves flags. Nonzero counts define ZF, SF and PF and invalidate AF. Only a single-bit shift defines OF. SHL and SHR invalidate CF at or beyond the operand width. |
| SETcc, CMOVcc, LAHF | All sixteen conditions use the architectural flags. SETcc writes a byte. Register-source CMOVcc selects at 16, 32 or 64 bits. A 32-bit CMOVcc clears the upper half on either outcome. LAHF packs SF, ZF, AF, PF and CF into AH. |
| LEA, forward direct JMP/Jcc, plain RET | LEA accepts a 64-bit base/index expression and a 32/64-bit destination. Short and near forward branches target decoded instruction boundaries. Every reachable path ends in a return. |

Register and applicable immediate arithmetic forms use LLVM MC's decoded operands. Forge tracks each flag independently and merges incoming definitions at forward joins. A consumer whose required flag lacks a definition on any incoming path fails during lifting, with its RVA, opcode, bytes and flag name. This proof is conservative for CL shifts. For example, SETO after a CL shift is rejected because a possible count exceeds one. An overwritten or unused undefined flag is harmless.

The supported operand-size prefix selects verified 16-bit forms. Other legacy prefixes, nonvolatile register parents, guest memory, stack operations, RIP-relative addressing, calls, loops, indirect branches, division, other multiply forms, rotates, and SIMD remain unsupported. Lifting requires an exact discovered start in a PE32+ AMD64 EXE, a linearly decodable range of at most 64 KiB, and code bytes free of base relocations. [Intel instruction reference](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf)

### Lifting interface and targets

`generateIR(analyzedImage, request, context)` takes an exact discovered start RVA and an entry mode, `RegisterState` or `WindowsX64I64Pair`. It validates the selected range, unwind and relocation constraints, translates the function, verifies the LLVM module, and returns exclusive ownership of that module. Declare the caller-owned `LLVMContext` before the returned module so the context survives its destruction. Publication serializes the completed module to a sibling temporary, checks writing and closing, and replaces the destination by rename. Publication protects the input directory entry as opened and the captured physical file identity, including when a caller changes working directories. Diagnostics retain the supplied path spelling.

The PE machine identifies the guest. Today's decoder uses `x86_64-pc-windows-msvc`, discovery understands AMD64 unwind metadata, and the wrapper uses the Windows x64 register convention. The output module independently selects `arm64-apple-macosx11.0.0` and its data layout. RVAs are 32-bit image-relative quantities, guest virtual addresses and file offsets retain their own widths, and LLVM pointers belong to the generated program. Future x86 work would need PE32 validation and address handling, an appropriate discovery mechanism, 32-bit decoding and state, and a defined guest calling convention. AMD64 is the only implemented guest.

### Lift diagnostics

`forge lift … --diagnostics-format json` writes one UTF-8 JSON object followed by LF to stderr for a handled execution failure (exit 1). Success leaves both streams empty. The default `text` format retains the human diagnostic. Invalid arguments, including an output alias, produce text and usage with exit 2 in either mode. Inspection and analysis keep their existing report formats.

```json
{"schema_version":1,"stage":"lifting","category":"unsupported","code":"LIFT_UNSUPPORTED_INSTRUCTION","message":"0x1003: PUSH64r [50]: unsupported instruction or operand form","context":{"input":"example.exe","entry_rva":"0x1000","end_rva":"0x1007","instruction_rva":"0x1003","opcode":"PUSH64r","bytes":"50","file_offset":1027}}
```

The version is the integer `1`. The stage, category, code, and human-readable message are strings. Every lift diagnostic carries a context object with the input path as supplied and the requested `entry_rva`. Optional fields include the exclusive `end_rva`, failing `instruction_rva`, LLVM MC `opcode`, and lowercase hex `bytes` (the available prefix for a decode error). RVAs are lowercase hexadecimal strings with a `0x` prefix. A `file_offset` is an integer byte offset. Unsupported guest diagnostics identify the detected `architecture`; publication failures include `output`. Paths and messages are rendered as valid UTF-8. Consumers classify the stage, category and code together.

| Stage | Category | Codes and meaning |
| --- | --- | --- |
| `input` | `io` | `INPUT_OPEN` for opening or validating the descriptor, `INPUT_READ` for acquiring the snapshot |
| `pe` | `invalid_input` | `INVALID_PE` for malformed or unmappable container metadata |
| `pe` | `unsupported` | `UNSUPPORTED_ARCHITECTURE` for the PE machine or hybrid image |
| `entry` | `invalid_input` | `ENTRY_INVALID_START` for missing, invalid or ambiguous starts, `ENTRY_UNMAPPED_CODE` for a unique, non-overlapping exact record whose code bytes lack file backing |
| `entry` | `unsupported` | `ENTRY_DLL`, `ENTRY_UNWIND_VERSION`, `ENTRY_CHAINED_FRAGMENT`, `ENTRY_RELOCATION_OVERLAP` |
| `lifting` | `invalid_input` | `LIFT_INVALID_ENCODING` for undecodable or truncated instructions |
| `lifting` | `unsupported` | `LIFT_FUNCTION_SIZE`, `LIFT_UNSUPPORTED_INSTRUCTION` (including operand forms), `LIFT_UNSUPPORTED_REGISTER`, `LIFT_UNSUPPORTED_PREFIX`, `LIFT_UNSUPPORTED_CONTROL_FLOW`, `LIFT_UNDEFINED_REGISTER`, `LIFT_UNDEFINED_FLAG` |
| `lifting` | `internal` | `LIFT_BACKEND_SETUP` for LLVM decoder setup |
| `verification` | `internal` | `IR_VERIFICATION_FAILED` for LLVM's rejection of generated IR |
| `publication` | `io` | `OUTPUT_CREATE`, `OUTPUT_DESCRIPTOR`, `OUTPUT_WRITE`, `OUTPUT_CLOSE`, `OUTPUT_REPLACE` identify the failed operation |
| Respective stage | `internal` | `INPUT_INTERNAL`, `PE_INTERNAL`, `ANALYSIS_INTERNAL`, `ENTRY_INTERNAL`, `LIFTING_INTERNAL`, `VERIFICATION_INTERNAL`, `PUBLICATION_INTERNAL` cover unexpected handled exceptions |

### Lifting approach

Forge uses LLVM 23 MC for instruction decoding, an explicit translation for each supported form, and LLVM's AArch64 backend via `llc`. The same installed toolchain builds on Apple Silicon, verifies the IR, and produces Mach-O objects. The opcode names and operand layouts follow LLVM 23. Upgrading LLVM requires rerunning the decoder and behavioral tests.

The [binary lifting evaluation](docs/binary-lifting-evaluation.md) compares six projects, follows a Windows x64 carry-flag fixture through Remill and Forge, and explains the recommendation to keep Forge’s LLVM lifter and reuse upstream test and recovery techniques.

RetDec lifts x86-64 for decompilation and documents macOS support. Its modified LLVM 8 dependency and limited maintenance make direct integration into the LLVM 17 ARM64 build used in the evaluation a larger undertaking. Native Apple Silicon integration and executable equivalence were unverified for that option. [RetDec](https://github.com/avast/retdec) · [RetDec LLVM fork](https://github.com/avast/llvm)

### Verification and fastgron

The `codegen` suite checks the exact RVA-named function in both optimized IR interfaces and emits ARM64 objects. On Apple Silicon, `native` compares the C++ harness with arithmetic references before and after IR optimization. It exercises 272 boundary and seeded random input pairs per case. All ten predicates run at both 32 and 64 bits. Their two paths return distinct constants so equal operands reveal a strict/inclusive comparison error. A separate fixture changes SUB to ADD in the linked PE.

The optional `differential` suite uses Unicorn when its Python package is available to CTest's interpreter. It executes the fixture's original x86-64 code bytes with a Windows x64 call frame and compares the resulting RAX with the native harness. This is isolated machine-code differential execution. The standard native run and the generated functions have no emulator dependency. CTest reports a skip when the optional oracle or native host is unavailable.

```sh
ctest --test-dir build -C Debug -R '^differential$' --output-on-failure
```

On Apple Silicon, 30 fixture cases passed all 8,160 source-reference comparisons before optimization and all 8,160 after optimization. The optimized native functions also matched all 8,160 independent Unicorn 2.1.4 results. As a negative check, substituting JL for JLE in the linked PE failed on input `(0, 0)` under both normal Python and `PYTHONOPTIMIZE=1`.

The pinned Windows fastgron v0.7.7 executable (SHA-256 `1c18064f88804a0519fa51d9a4755bd25b7b73d16e28bddf24e3e1688480eb47`) produced 235 valid ranges and no analysis findings. LLVM resolved `0x29c50` to `std::ctype<char>::do_widen(char) const` at `locale_facets.h:1092`. Its bytes `89 d0 c3` lifted and compiled to ARM64. The signatureless form models the EDX-to-EAX move and zero-extension. That C++ member function has a different prototype from the fixture wrapper. [fastgron v0.7.7 release](https://github.com/adamritter/fastgron/releases/tag/v0.7.7)

```sh
build/forge lift fastgron.exe --rva 0x29c50 --output build/fastgron.ll
"$llvm_bin/llc" -filetype=obj build/fastgron.ll -o build/fastgron.o
"$llvm_bin/llvm-objdump" -d build/fastgron.o
```
