# Forge Runtime

`forge_runtime` is a native static library for macOS ARM64. A host creates a runtime instance and guest thread tokens, then uses the tokens to set and read 32-bit last-error values. Native C, C++ and generated ARM64 code share the same [public C ABI](include/forge/runtime.h). The runtime links independently of the Forge compiler, CLI and Wine.

## Build and test

From the repository root on Apple Silicon with CMake and the native C/C++ toolchain:

```sh
cmake -S . -B build/tmp/runtime-only -DFORGE_RUNTIME_ONLY=ON
cmake --build build/tmp/runtime-only
ctest --test-dir build/tmp/runtime-only --output-on-failure
```

This configuration produces `build/tmp/runtime-only/libforge_runtime.a` with a single-configuration generator. CMake consumers link the `forge_runtime` target, which publishes the include path for `<forge/runtime.h>`. For a manual build, compile C callers as C and use the native C++ linker driver to link their objects with the archive and the platform C++ runtime.

The full Apple Silicon development build runs the C and LLVM IR smoke tests. To include the IR smoke in a runtime-only build, configure with `-DFORGE_RUNTIME_IR_TOOLS_DIR=/path/to/llvm/bin` pointing to matching LLVM 23 `opt` and ARM64-capable `llc` binaries. If this pair is unavailable, the native tests still run. Only the test needs these tools. Configure with `-DFORGE_ENABLE_SANITIZERS=ON` for sanitizer coverage.

To check formatting from this configuration, put the repository’s pinned `clang-format` on `PATH` and build the `format-check` target. The [benchmark instructions and measurements](../docs/runtime-architecture.md#reproduce-the-native-call-benchmark) provide Debug and Release commands.

The [runtime architecture](../docs/runtime-architecture.md) covers lifetimes, status codes, guest calling and memory contracts, Wine reuse, and the proposed first imported service. The runtime's Forge-authored source uses [Apache-2.0](../LICENSE).
