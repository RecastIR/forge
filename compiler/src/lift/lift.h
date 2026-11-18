#pragma once

#include "analysis/exception_scope.h"
#include "pe/image.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace llvm {
    class LLVMContext;
    class Module;
} // namespace llvm

namespace forge {
    class AnalyzedImage;

    namespace win64 {
        struct ServiceBinding;
    }

    enum class EntryMode { RegisterState, WindowsX64I64Pair, PeEntry };

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

    struct ExecutableCall {
        uint32_t callerRva, instructionRva, targetRva;
    };

    struct ExecutableUnresolvedCall {
        uint32_t callerRva, instructionRva;
        std::optional<int64_t> targetRva;
    };

    struct ExecutableImport {
        std::string dll, name;
    };

    struct ExecutableImportSlot {
        std::string name;
        uint32_t iatRva;
        bool hasService, hasDataExport;
    };

    struct ExecutableImportDirectory {
        std::string dll;
        uint32_t descriptorRva;
        bool delayed, bound;
        std::vector<ExecutableImportSlot> slots;
    };

    // Owned facts, including progress up to the first failing dependency. Entry recovery
    // identifies an exact function start. Group recovery includes all reachable callees.
    struct ExecutableReadiness {
        std::string architecture;
        std::optional<uint32_t> entryRva;
        bool entryRecovered = false, recoveryComplete = false;
        std::vector<ExecutableCall> calls;
        std::vector<ExecutableImport> imports;
        std::vector<ExecutableUnresolvedCall> unresolvedCalls;
        // Image declarations are independent of the calls recovered before a failure.
        std::vector<ExecutableImportDirectory> loadImports;
        std::string importInventoryError;
        std::optional<TLS> tls;
        std::optional<uint32_t> entryHandlerUnwindRva, entryHandlerRva;
        std::optional<CSpecificHandler> entryCHandler;
        std::string entryHandlerError;
    };

    // Selects the PE header entry and emits a checked process artifact. The entry
    // receives no guest arguments and must return a defined result. Readiness is
    // populated on success and on an InspectionError.
    std::unique_ptr<llvm::Module> generateExecutableIR(const AnalyzedImage &analysis,
                                                       std::optional<uint64_t> guestLoadBase,
                                                       llvm::LLVMContext &context,
                                                       ExecutableReadiness &readiness);

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
