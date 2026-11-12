# Windows whole-executable fixtures

These seven small C11 and C++20 console programs provide Windows x64 inputs for future whole-executable comparisons. Each manifest records a single invocation and its expected output. The programs build independently of Forge.

| Fixture | What the invocation exercises |
| --- | --- |
| `arithmetic/basic` | Two digits supply bounded signed operands, a nonzero divisor, and the shift count for a 32-bit unsigned rotation. |
| `control_flow/branches` | One pass covers the early return, even and odd digits, three switch arms, and the default. Each input byte has its own output line. |
| `functions/calls` | Recursive calls return into a six-argument call that uses four Windows x64 argument registers and two stack slots. |
| `memory/arrays` | Stack struct fields supply products written through a pointer into a heap allocation. The program sums the products and frees the allocation. |
| `globals/state` | An initialized global, a zero-initialized global, and a static local change across iterations. Input bytes select weights from read-only data. |
| `imports/kernel32` | Process and module validity and a last-error round trip yield three Boolean results. |
| `cpp/lifetime` | The input selects both derived types. The program prints the result of virtual dispatch and the order of construction and destruction after each scope ends. |

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
2. Add the manifest. Derive the expected exit status and streams from the declared input. CMake discovers targets from the validated manifests.
3. Run `python3 -B tests/differential/manifests.py`, `make format-check`, and the Docker build from the repository root. Inspect optimized code when a particular call, memory access, or branch is essential to the case. Commit source and metadata. Git ignores the generated binaries and checksums under `build/`.

## Verification and remaining work

The initial suite produced seven Debug and seven Release PEs with byte-identical clean rebuilds for each configuration. Native Forge inspection identified all fourteen as AMD64 PE32+ executables importing `KERNEL32.dll` and `msvcrt.dll`. On macOS, Forge reports `DLL_NOT_FOUND` for `msvcrt.dll` when inspecting without Windows DLL search paths. Release disassembly confirmed recursive calls, stack-passed arguments, stack-to-heap copies, and indirect virtual dispatch.

The existing SDK-free parser and lifter samples live in `tests/fixtures/`. The existing `differential` CTest uses Unicorn to compare an individual x86-64 function with the ARM64 harness. Whole-executable execution is pending. Task 3 will run the original PEs in a controlled Windows environment, capture raw stdout, stderr, and exit status, verify the manifest expectations, and store validated reference results with the executable identity. A later harness will compare the translated programs against those captures.

The planned `reference/` runner and native `harness/` will start each invocation in a fresh working directory with the same inputs. CI will transfer reference artifacts between hosts. Native comparison tests will use a CTest setup fixture and `FIXTURES_REQUIRED` to prepare those artifacts when a case is selected.
