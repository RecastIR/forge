# Forge Runtime

`forge_runtime` is a native static library for macOS ARM64. A host creates a runtime instance and guest thread tokens, then uses the tokens to set and read 32-bit last-error values. Native C, C++ and generated ARM64 code share the same [public C ABI](include/forge/runtime.h). The runtime links independently of the Forge compiler, CLI and Wine.

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

The [runtime architecture](../docs/runtime-architecture.md) covers lifetimes, status codes, guest calling and memory contracts, Wine reuse, and the proposed first imported service. The runtime's Forge-authored source uses [Apache-2.0](../LICENSE).
