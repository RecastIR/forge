# Forge

Forge inspects Windows PE32+ AMD64 executables and DLLs on macOS. It reports the image layout, imported and exported symbols, base relocations, TLS, AMD64 exception metadata, and the static dependency graph. All inspection reads files without executing their code.

## Build and run

The verified baseline is Apple Silicon, Apple Clang with C++20, CMake 3.20 or later, and Homebrew LLVM 17.0.6. Tests also use Python 3.9+, `llvm-mc`, `llvm-dlltool`, `lld-link`, and `llvm-readobj`.

```sh
brew install cmake llvm@17
make
build/forge inspect path/to/game.exe
build/forge inspect path/to/game.exe --dll-path ./bin --dll-path ./plugins --format json
build/forge inspect path/to/game.exe --strict --format json > report.json
```

`make` configures and builds Forge in `build/`. It discovers Homebrew's `llvm@17` automatically. For another installation, use `make LLVM_DIR=/path/to/lib/cmake/llvm`. For a CLI-only build, use `make BUILD_TESTING=OFF`. Set `BUILD_DIR` to choose a different build directory.

## Dependency policy

Discovery reads the direct and RVA-based delay import tables and preserves DLL spelling, symbol names, and ordinals. Resolution matches filenames using ASCII lowercase. For each physical DLL, Forge checks the importing module’s directory, then each explicit `--dll-path` in order. Relative command-line paths use the invocation directory. Each lookup considers only immediate directory entries.

The first matching directory wins. Case variants in the same directory produce `ambiguous`. An incompatible file in the winning directory produces `incompatible`. Each compatible DLL is inspected once by file identity. Symlinks use the target’s canonical directory for that module’s imports. Dependencies retain the selected filename and the directory that supplied it.

| Kind | Forge policy |
| --- | --- |
| Windows system | `advapi32`, `combase`, `gdi32`, `kernel32`, `kernelbase`, `ntdll`, `ole32`, `shell32`, `shlwapi`, `user32`, and `ws2_32` (each with `.dll`) are recorded as `external_api`. |
| API set | Names beginning with `api-ms-`, `ext-ms-`, `api-win-`, or `ext-win-` are recorded as `unresolved_contract`. Mapping a contract to its host requires a Windows-version-specific mapping. |
| Third-party runtime | `msvcp140`, `msvcp140_1`, `msvcp140_2`, `vcruntime140`, and `vcruntime140_1` (each with `.dll`) require a compatible physical DLL. |
| Other | A compatible match is classified as `application`. A missing file remains `unknown`. |

Forge applies this static policy independently of the Windows loader. Dynamic loads, export-forwarder resolution, API implementations, symbol binding, and native code generation are outside this stage. A resolved edge means Forge found and inspected a compatible DLL. Exception results contain runtime-function metadata. Legacy VA-based delay descriptors produce an unsupported-form diagnostic. Metadata tables must fit in file-backed section data. Variable-length tables and names have per-image expansion limits of one million records and 64 MiB of name data.

## Reports and exit codes

Text is the default. With `--format json`, stdout contains one schema-v1 document for a completed inspection. Human-readable diagnostics go to stderr.

- `schema_version` is the integer `1`. `inspection.root_module` indexes `modules`. Each module records its canonical path, binary metadata, sections, imports, exports, relocations, TLS, and exceptions. Absent TLS and exception directories are `null`. Empty tables use arrays.
- Fields ending in `_rva` are relative virtual addresses. VA and RVA fields are hexadecimal strings. File offsets and sizes are integers in bytes. Relocation types use PE numeric codes.
- `dependencies` retains one edge per import descriptor. `importer` and `target_module` index `modules`, and `import_index` indexes the importer’s `imports`. Each edge records its load type, requiredness, classification, and status. Physical lookup records searched directories in priority order.
- `diagnostics` associates stable codes with dependency indices. `summary` counts edges by observed status. Paths are absolute. The same files, locations, and search order produce byte-identical JSON.

| Exit | Meaning |
| --- | --- |
| `0` | Inspection completed, including any dependency findings. |
| `1` | Input read, PE inspection, or internal failure. |
| `2` | Invalid command line or search-directory configuration. |
| `3` | Inspection completed and `--strict` found a required edge with status `missing`, `ambiguous`, `incompatible`, `inaccessible`, or `unresolved_contract`. |

A required edge is reachable from the root via direct imports alone. A DLL reached by direct and delay paths is required through the direct path. Delay-only subgraphs remain in the report. Strict mode uses the same report and accepts `external_api` as a declared external provider.

## Test and reproduce fixtures

```sh
make test
make fixtures
build/forge inspect build/fixtures/metadata.exe --strict
```

CTest runs `tests/fixtures/generate.py` to assemble and link SDK-free sources with fixed PE timestamps into the build directory. Tests compare metadata to `llvm-readobj` and create malformed copies in temporary directories. To exercise same-directory case collisions on a case-insensitive Mac, point `TMPDIR` at a writable directory on a case-sensitive volume.

`make fixtures` regenerates just the test images. `make sanitize` builds and runs the suite with AddressSanitizer and UndefinedBehaviorSanitizer in `build-sanitize/`. `make clean` removes compiled targets from the selected build directory and keeps its CMake configuration.
