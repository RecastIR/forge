#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>

namespace llvm {
    class LLVMContext;
    class Module;
} // namespace llvm

namespace forge {
    class AnalyzedImage;

    enum class EntryMode { RegisterState, WindowsX64I64Pair };

    struct LiftRequest {
        uint32_t startRva;
        EntryMode mode;
    };

    // The module is independent of the image after generation. The caller's context
    // must outlive the module and all of its IR.
    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context);

    void verifyLiftedIR(const llvm::Module &module, const std::filesystem::path &input,
                        uint32_t entryRva);
} // namespace forge
