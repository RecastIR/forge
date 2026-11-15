#pragma once

#include "lift/cfg.h"
#include "pe/image.h"

namespace llvm {
    class MCRegisterInfo;
}

namespace forge {
    class AnalyzedImage;
}

namespace forge::x86 {
    struct ValidatedEntry {
        const AnalyzedImage &analysis;
        uint32_t rva;
        MappedRange code;
        RelocationIndex relocations;
    };

    ValidatedEntry validateEntry(const AnalyzedImage &analysis, uint32_t rva);
    ValidatedEntry validateEntry(const AnalyzedImage &&analysis, uint32_t rva) = delete;
    uint64_t validateGuestBase(const ValidatedEntry &entry, std::optional<uint64_t> requested);

    // All RVAs in a recovered group belong to its one immutable source snapshot.
    struct DirectCall {
        uint32_t caller, block, instruction, callee, continuation;
    };

    struct RecoveredFunction {
        explicit RecoveredFunction(MappedRange mapped) : code(mapped) {}

        RecoveredFunction(const RecoveredFunction &) = delete;
        RecoveredFunction &operator=(const RecoveredFunction &) = delete;

        MappedRange code;
        ControlFlowGraph graph;
        std::map<uint32_t, DirectCall> calls;
        // References the callers' records in caller, block and instruction order.
        std::vector<const DirectCall *> incoming;
        const DirectCall *callAt(uint32_t instructionRva) const;
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

        const llvm::MCRegisterInfo &registers() const;

        const std::map<uint32_t, RecoveredFunction> &functions() const { return recovered; }

        const RecoveredFunction &function(uint32_t rva) const { return recovered.at(rva); }

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
