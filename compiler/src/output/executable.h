#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace llvm {
    class Module;
}

namespace forge {
    class ParsedImage;

    struct ExecutableToolchain {
        std::filesystem::path opt, llc, xcrun, startup, runtime;
        std::string sdk = "macosx";
        std::vector<std::string> linkFlags;
    };

    // Emit the thin ARM64 Mach-O object without requiring a macOS host or linker.
    void publishNativeObject(const llvm::Module &module, const ParsedImage &input,
                             const std::filesystem::path &output, const ExecutableToolchain &tools,
                             bool optimize);

    // Link a verified PE-entry process module and atomically publish the ARM64 Mach-O.
    void publishExecutable(const llvm::Module &module, const ParsedImage &input,
                           const std::filesystem::path &output, const ExecutableToolchain &tools,
                           bool optimize);
} // namespace forge
