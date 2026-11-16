#pragma once

#include <filesystem>

namespace llvm {
    class Module;
}

namespace forge {
    class ParsedImage;

    std::filesystem::path checkedOutputDestination(const ParsedImage &input,
                                                   const std::filesystem::path &output);
    void publishIR(const llvm::Module &module, const ParsedImage &input,
                   const std::filesystem::path &output);
} // namespace forge
