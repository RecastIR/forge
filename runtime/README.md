# Forge Runtime

`forge_runtime` is a native static library for macOS ARM64. A host creates a runtime instance and guest thread tokens, then uses the tokens to set and read 32-bit last-error values. With `forge lift --checked-memory`, synchronous native services can also validate, read and write guest buffers using the active invocation. [Checked guest buffers](../docs/runtime-architecture.md#checked-guest-buffers)

Hosts using compiler-generated process artifacts can register the same artifact in independent processes, invoke its lifted entry once per process, and inspect a tagged return, explicit exit, or fault. Managed programs can write guest bytes to inherited stdout and stderr. Embedders using pipes or finite file-size limits configure output signal handling before the run. [Standard streams and process exit](../docs/runtime-architecture.md#standard-streams-and-process-exit) · [Process C ABI](include/forge/process.h) · [Host lifecycle](../docs/runtime-architecture.md#12f--process-lifecycle-integration)

Native C, C++ and generated ARM64 code share the same [public C ABI](include/forge/runtime.h). The runtime links independently of the Forge compiler, CLI and Wine.

The separate `forge_startup` archive supplies the native `main` for executables linked by `forge lift --executable`. Existing C and C++ hosts link `forge_runtime` directly and supply their own entry. [Compile and run a native executable](../README.md#compile-and-run-a-native-executable)

Process artifacts can publish read-only function IAT slots containing stable guest addresses for imported services. Registration checks their backing and reserves their addresses for the process lifetime. [Imported function addresses](../docs/runtime-architecture.md#imported-function-addresses)

## Build and test

From the repository root on Apple Silicon, use CMake and the native C/C++ toolchain in a build directory separate from any Forge-managed preset.

```sh
cmake -S . -B build/tmp/runtime-only -G "Unix Makefiles" -DFORGE_RUNTIME_ONLY=ON
cmake --build build/tmp/runtime-only
ctest --test-dir build/tmp/runtime-only --output-on-failure
```

This configuration produces `build/tmp/runtime-only/libforge_runtime.a`. For a manual build, compile C callers as C and use the native C++ linker driver to link their objects with the archive and the platform C++ runtime.

The full Apple Silicon development build requires the C and LLVM IR smoke tests. A compiler-only build includes the IR smoke when its selected LLVM installation provides matching LLVM 23 `opt` and ARM64-capable `llc` binaries. A runtime-only build accepts the same pair through `-DFORGE_RUNTIME_IR_TOOLS_DIR=/path/to/llvm/bin`. Both configurations run the native tests when the pair is unavailable. Configure the runtime-only build with `-DFORGE_ENABLE_SANITIZERS=ON` for sanitizer coverage.

To check formatting from this configuration, put version 23.1.5 of `clang-format-23` or `clang-format` on `PATH` and build the `format-check` target. The [benchmark instructions and measurements](../docs/runtime-architecture.md#reproduce-the-native-call-benchmark) provide Debug and Release commands.

## Link a CMake host

Enable both C and C++ in the parent project so CMake can compile the host's `main.c` as C and choose the native C++ linker driver for the runtime archive. Set `FORGE_SOURCE_DIR` to the Forge checkout when configuring the host. The `forge_runtime` target publishes the include path for `<forge/runtime.h>`.

```cmake
cmake_minimum_required(VERSION 3.20)
project(native_host LANGUAGES C CXX)
set(FORGE_RUNTIME_ONLY ON)
add_subdirectory("${FORGE_SOURCE_DIR}" forge-build)

add_executable(native_host main.c)
target_link_libraries(native_host PRIVATE forge_runtime)
```

The [runtime architecture](../docs/runtime-architecture.md) covers lifetimes, status codes, guest calling and memory contracts, Wine reuse, and lifted last-error services. The runtime's Forge-authored source uses [Apache-2.0](../LICENSE).

## Link a lifted Windows function

`KERNEL32.dll!lstrlenA` uses the same typed native entry and runtime archive, with explicit `--checked-memory` instead of plain `--runtime`. It reads proven image/stack buffers through checked guest-VA operations and returns a 32-bit length without changing last error. The initial implementation requires a NUL within the first 1 MiB; faults and limit exhaustion trap at the generated boundary. This temporary service limit does not restrict other checked copies. See the [Windows x64 service ABI](../docs/runtime-architecture.md#12e--windows-x64-abi-bridge) for memory planning and failure behavior.

Build the runtime-only archive above, build the Windows fixtures, and select the exported `last_error` RVA from `forge inspect`. With LLVM 23 selected, run these commands from the repository root.

```sh
pe=build/fixtures/windows-x64/release/last_error.exe
rva=$(build/dev/forge inspect "$pe" --format json | python3 -c 'import json,sys; print(next(e["rva"] for e in json.load(sys.stdin)["modules"][0]["exports"] if "last_error" in e["names"]))')
build/dev/forge lift "$pe" --rva "$rva" --signature 'i64(i64,i64)' --runtime --output build/tmp/last_error.ll
llvm_bin=$("$LLVM_CONFIG" --bindir)
"$llvm_bin/opt" -passes=verify -disable-output build/tmp/last_error.ll
"$llvm_bin/llc" -filetype=obj build/tmp/last_error.ll -o build/tmp/last_error.o
xcrun clang++ -std=c++20 -arch arm64 -Iruntime/include tests/support/runtime_pairs.cpp \
    build/tmp/last_error.o build/tmp/runtime-only/libforge_runtime.a -o build/tmp/last_error
build/tmp/last_error 4275878552 0 0 1
```

Both invocations print `4275878552`. The driver creates an ABI v1 instance and guest thread before the first invocation. It retains both through the second invocation and then releases them. Its linked entry has this C ABI.

```cpp
extern "C" int64_t forge_lifted_with_runtime(forge_rt_instance *, forge_rt_thread_token,
                                              int64_t arg1, int64_t arg2);
```
