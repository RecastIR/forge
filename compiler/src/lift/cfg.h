#pragma once

#include "diagnostic.h"

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/MC/MCInst.h"

#include <map>
#include <vector>

namespace llvm {
    class MCDisassembler;
    class MCInstrInfo;
} // namespace llvm

namespace forge::x86 {
    class JumpTableReader;

    struct Step {
        uint32_t rva, next;
        llvm::MCInst inst;
        llvm::StringRef opcode; // Borrows the decoder's instruction-name table.
        llvm::StringRef bytes;  // Borrows the analyzed image.

        bool isDirectCall() const { return opcode == "CALL64pcrel32"; }

        bool isMemoryCall() const { return opcode == "CALL64m"; }

        bool isRegisterCall() const { return opcode == "CALL64r"; }

        [[noreturn]] void reject(FailureCode kind, const llvm::Twine &reason,
                                 std::optional<int64_t> target = {},
                                 std::optional<uint32_t> importSlot = {}) const;
    };

    enum class Flow : uint8_t { Fallthrough, Jump, Conditional, Indirect, Return, FallOff };

    struct RelativeTable {
        uint32_t compareRva, guardRva, loadRva, tableRva;
        // Entries correspond one-for-one to the owning block's ordered successors.
        unsigned count;

        std::string describe() const;
        [[noreturn]] void rejectEntry(const Step &jump, unsigned index, FailureCode kind,
                                      const llvm::Twine &reason,
                                      std::optional<int64_t> target = {}) const;
    };

    struct GuestBlock {
        std::vector<Step> steps;
        Flow exit;
        // Jcc: taken then fallthrough. Indirect: one edge per index, including duplicates.
        llvm::SmallVector<uint32_t, 2> successors;
        std::optional<RelativeTable> table;
    };

    using ControlFlowGraph = std::map<uint32_t, GuestBlock>;

    inline constexpr unsigned maxFunctionBytes = 64 * 1024;

    using LeafStepCheck = llvm::function_ref<void(const Step &, Flow)>;

    ControlFlowGraph discoverCFG(llvm::StringRef bytes, uint32_t begin,
                                 const llvm::MCDisassembler &dis, const llvm::MCInstrInfo &info,
                                 LeafStepCheck validateLeaf);
    ControlFlowGraph discoverCFG(llvm::StringRef bytes, uint32_t begin,
                                 const llvm::MCDisassembler &dis, const llvm::MCInstrInfo &info,
                                 JumpTableReader &tables);
} // namespace forge::x86
