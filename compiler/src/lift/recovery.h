#pragma once

#include "forge/service_signature.h"
#include "lift/cfg.h"
#include "pe/image.h"

#include <set>
#include <span>
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

    enum class CallKind : uint8_t { Direct, RipRelativeRegister, TailJump };

    struct GuestCallTarget {
        uint32_t rva;
        CallKind kind;
        uint32_t evidenceRva;
        bool recursiveTail = false; // Rejected by recovery, retained for failure reporting.
    };

    struct ReverseTableProof {
        uint32_t header, baseDefinition, countLoad, zeroGuard, scanRead;
        unsigned cursor;
        bool sentinel;
    };

    struct ForwardTableProof {
        uint32_t firstDefinition, lastDefinition, entryCompare, emptyBranch;
        uint32_t pointerLoad, nullTest, nullBranch, increment, latchCompare, backedge;
        unsigned cursor, limit, target;
        std::optional<uint32_t> slotStore;
    };

    struct BoundedTableCall {
        uint32_t first, last;
        std::vector<uint32_t> targets;
        std::variant<ReverseTableProof, ForwardTableProof> proof;

        const ReverseTableProof *reverse() const { return std::get_if<ReverseTableProof>(&proof); }

        const ForwardTableProof *forward() const { return std::get_if<ForwardTableProof>(&proof); }

        uint32_t originRva() const {
            const auto *layout = reverse();
            return layout ? layout->header : first;
        }

        void annotate(FailureContext &context, std::optional<uint32_t> target = {}) const {
            // The failing call records its own proof before an incoming call supplies context.
            if (context.tableFirstRva || context.tableHeaderRva) {
                return;
            }

            context.tableTargetRva = target;

            if (const auto *loop = forward()) {
                context.tableFirstRva = first;
                context.tableLastRva = last;
                context.pointerLoadRva = loop->pointerLoad;
            } else {
                context.tableHeaderRva = std::get<ReverseTableProof>(proof).header;
            }
        }

        RvaRange extent() const {
            const auto *layout = reverse();
            return {layout ? layout->header : first,
                    uint64_t(last) + (layout && layout->sentinel ? 8 : 0)};
        }
    };

    struct InitializerTable {
        uint32_t first, last;
        // Sorted, unique RVAs admitted for this call. The runtime reads the live table.
        std::vector<uint32_t> targets;
    };

    struct TerminationRegistration {
        // A zero origin denotes a locally proved argument. Forwarded RCX keeps a separate
        // proof for each direct caller instruction. A zero target denotes a literal NULL.
        bool forwarded = false;
        std::map<uint32_t, uint32_t> targets;
    };

    struct ExternalCallTarget {
        uint32_t slot;
        const Import &descriptor;
        const win64::ServiceBinding &binding;
        std::optional<InitializerTable> initializers = {};
        std::optional<TerminationRegistration> registration = {};
    };

    const win64::ServiceBinding *findService(std::span<const win64::ServiceBinding> services,
                                             const Import &descriptor, const Symbol &symbol);

    // All RVAs in a recovered group belong to its one immutable source snapshot.
    struct ResolvedCallSite {
        uint32_t caller, block, instruction;
        std::optional<uint32_t> continuation; // Only CALL pushes a continuation.
        std::variant<GuestCallTarget, ExternalCallTarget, BoundedTableCall> target;

        const BoundedTableCall *table() const { return std::get_if<BoundedTableCall>(&target); }

        std::span<const uint32_t> guestTargets() const & {
            if (const auto *single = std::get_if<GuestCallTarget>(&target)) {
                return {&single->rva, 1};
            }
            if (const auto *bounded = table()) {
                return bounded->targets;
            }
            return {};
        }

        void annotateTableFailure(FailureContext &context, uint32_t targetRva) const {
            context.sourceCall = CallLocation{caller, instruction};
            table()->annotate(context, targetRva);
        }

        void annotateCallbackFailure(FailureContext &context,
                                     std::optional<uint32_t> targetRva) const;

        bool isTailJump() const { return !continuation; }

        const GuestCallTarget &guest() const { return std::get<GuestCallTarget>(target); }

        const ExternalCallTarget *external() const {
            return std::get_if<ExternalCallTarget>(&target);
        }
    };

    enum class RecoveryOrigin { UnwindBacked, InferredLeaf };
    // A complete group includes table-discovered entries. A PE entry additionally
    // admits register-held imports; a standalone function cannot call managed initializers.
    enum class RecoveryMode { CompleteGroup, FunctionLift, PeEntry };

    struct RecoveredFunction {
        RecoveredFunction(uint32_t entry, RecoveryOrigin origin, MappedRange code)
            : entry(entry), origin(origin), code(code) {}

        RecoveredFunction(const RecoveredFunction &) = delete;
        RecoveredFunction &operator=(const RecoveredFunction &) = delete;

        const uint32_t entry;
        const RecoveryOrigin origin;
        // Borrows the first admitting callback registration or initializer call in a group-owned
        // caller.
        const ResolvedCallSite *callbackSource = nullptr;
        bool mayReturn = false;
        bool receivesRegistrationOrigin = false;
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
        // Catalogue storage and its strings must outlive this group.
        explicit RecoveredFunctionGroup(
            const ValidatedEntry &entry,
            std::span<const win64::ServiceBinding> services = win64::services,
            llvm::function_ref<void(const RecoveredFunctionGroup &, const InspectionError &)>
                onFailure = nullptr,
            RecoveryMode mode = RecoveryMode::CompleteGroup);
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
        std::set<std::pair<std::string_view, std::string_view>> requiredImports() const &;
        std::set<std::pair<std::string_view, std::string_view>> requiredImports() const && = delete;

      private:
        struct Decoder;
        const ParsedImage &source;
        uint32_t entryRva;
        // Destroy steps and call indices before the MC objects backing the decoded instructions.
        std::unique_ptr<Decoder> decoder;
        std::map<uint32_t, RecoveredFunction> recovered;
    };
} // namespace forge::x86
