# Forge runtime

The future native macOS ARM64 runtime will own guest process and thread state, guest memory, Windows x64 ABI and import bridging, Windows-compatible services, and host OS integration. Task 12A will define the ABI used by compiler-generated code and introduce the first runtime build target. The runtime will execute that code independently of LLVM and compiler internals. See [compiler and runtime responsibilities](../docs/design-guide.md#compiler-and-runtime).

Forge currently uses Wine for [differential reference tests](../tests/differential/README.md). Forge's own sources are licensed under [Apache-2.0](../LICENSE). Future Wine-derived sources may require separate LGPL licensing and attribution. Task 12A will determine how to track those sources and their obligations.
