#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>

namespace llvm {
    class LLVMContext;
    class Module;
} // namespace llvm

namespace forge {
    class AnalyzedImage;

    namespace win64 {
        struct ServiceBinding;
    }

    enum class EntryMode { RegisterState, WindowsX64I64Pair };

    enum class LiftOutput { Function, ProcessArtifact };

    struct LiftRequest {
        uint32_t startRva;
        EntryMode mode;
        // Guest VAs default to the PE's preferred base. Native storage has its own address.
        std::optional<uint64_t> guestLoadBase = std::nullopt;
        bool runtime = false;
        // Publish the selected image and live stack to the runtime at the typed entry.
        bool checkedMemory = false;
        // Process artifacts are an explicit compiler output with their own checked entry ABI.
        LiftOutput output = LiftOutput::Function;
    };

    // The module is independent of the image after generation. The caller's context
    // must outlive the module and all of its IR.
    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context);

    // Explicit catalogue for native hosts supplying their own statically linked adapters.
    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context,
                                             std::span<const win64::ServiceBinding> services);

    void verifyLiftedIR(const llvm::Module &module, const std::filesystem::path &input,
                        uint32_t entryRva);
} // namespace forge
