#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>

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
        // Guest VAs default to the PE's preferred base. Native storage has its own address.
        std::optional<uint64_t> guestLoadBase = std::nullopt;
    };

    // The module is independent of the image after generation. The caller's context
    // must outlive the module and all of its IR.
    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context);

    void verifyLiftedIR(const llvm::Module &module, const std::filesystem::path &input,
                        uint32_t entryRva);
} // namespace forge
