#pragma once

#include "lift/cfg.h"
#include "pe/image.h"

#include <variant>

namespace llvm {
    class MCRegisterInfo;
}

namespace forge {
    class AnalyzedImage;
}

namespace forge::x86 {
    struct ValidatedEntry {
        ValidatedEntry(const ValidatedEntry &) = delete;
        ValidatedEntry &operator=(const ValidatedEntry &) = delete;

        const AnalyzedImage &analysis;
        const uint32_t rva;
        const MappedRange code;
        const RelocationIndex relocations;

      private:
        // The range and relocation index must come from validation of the same snapshot.
        friend ValidatedEntry validateEntry(const AnalyzedImage &analysis, uint32_t rva);
        ValidatedEntry(const AnalyzedImage &analysis, uint32_t rva, MappedRange code,
                       RelocationIndex &&relocations);
    };

    ValidatedEntry validateEntry(const AnalyzedImage &analysis, uint32_t rva);
    ValidatedEntry validateEntry(const AnalyzedImage &&analysis, uint32_t rva) = delete;
    uint64_t validateGuestBase(const ValidatedEntry &entry, std::optional<uint64_t> requested);

    enum class CallKind : uint8_t { Direct, RipRelativeRegister };

    struct GuestCallTarget {
        uint32_t rva;
        CallKind kind;
        uint32_t evidenceRva;
    };

    enum class ServiceSignature { DwordToVoid, VoidToDword };

    struct ServiceBinding {
        llvm::StringLiteral name, nativeSymbol;
        ServiceSignature signature;
    };

    struct ExternalCallTarget {
        uint32_t slot;
        const Import &descriptor;
        const ServiceBinding &binding;
    };

    // All RVAs in a recovered group belong to its one immutable source snapshot.
    struct ResolvedCallSite {
        uint32_t caller, block, instruction, continuation;
        std::variant<GuestCallTarget, ExternalCallTarget> target;

        const GuestCallTarget &guest() const { return std::get<GuestCallTarget>(target); }

        const ExternalCallTarget *external() const {
            return std::get_if<ExternalCallTarget>(&target);
        }
    };

    enum class RecoveryOrigin { UnwindBacked, InferredLeaf };

    struct RecoveredFunction {
        RecoveredFunction(uint32_t entry, RecoveryOrigin origin, MappedRange code)
            : entry(entry), origin(origin), code(code) {}

        RecoveredFunction(const RecoveredFunction &) = delete;
        RecoveredFunction &operator=(const RecoveredFunction &) = delete;

        const uint32_t entry;
        const RecoveryOrigin origin;
        // For an inferred leaf this is the bounded decode window. Only graph steps claim bytes.
        MappedRange code;
        ControlFlowGraph graph;
        std::map<uint32_t, ResolvedCallSite> calls;
        // References the callers' records in caller, block and instruction order.
        std::vector<const ResolvedCallSite *> incoming;
        const Step *instructionContaining(uint32_t rva) const;
        const ResolvedCallSite *callAt(uint32_t instructionRva) const;
    };

    // The caller keeps the analyzed image alive for all byte and section views.
    // The group owns decoder metadata and CFG storage through every consumer.
    class RecoveredFunctionGroup {
      public:
        RecoveredFunctionGroup(const AnalyzedImage &analysis, uint32_t rva);
        RecoveredFunctionGroup(const AnalyzedImage &&analysis, uint32_t rva) = delete;
        explicit RecoveredFunctionGroup(const ValidatedEntry &entry);
        ~RecoveredFunctionGroup();
        RecoveredFunctionGroup(const RecoveredFunctionGroup &) = delete;
        RecoveredFunctionGroup &operator=(const RecoveredFunctionGroup &) = delete;

        uint32_t root() const { return entryRva; }

        const ParsedImage &image() const { return source; }

        const llvm::MCRegisterInfo &registers() const &;
        const llvm::MCRegisterInfo &registers() const && = delete;

        const std::map<uint32_t, RecoveredFunction> &functions() const & { return recovered; }

        const std::map<uint32_t, RecoveredFunction> &functions() const && = delete;

        const RecoveredFunction &function(uint32_t rva) const & { return recovered.at(rva); }

        const RecoveredFunction &function(uint32_t rva) const && = delete;

        void annotateFailure(InspectionError &failure) const;

      private:
        struct Decoder;
        const ParsedImage &source;
        uint32_t entryRva;
        // Destroy steps and call indices before the MC objects backing the decoded instructions.
        std::unique_ptr<Decoder> decoder;
        std::map<uint32_t, RecoveredFunction> recovered;
    };
} // namespace forge::x86
