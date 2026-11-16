# Forge runtime

This directory reserves the future native macOS ARM64 execution environment and Windows compatibility layer. Task 12A will define its interface to compiler-generated code and introduce the first build target. See [compiler and runtime responsibilities](../docs/design-guide.md#compiler-and-runtime).

Forge currently uses Wine for [differential reference tests](../tests/differential/README.md). Forge's own sources are licensed under [Apache-2.0](../LICENSE). Future Wine-derived sources may require separate LGPL licensing and attribution. Task 12A will determine how to track those sources and their obligations.
