#pragma once

#include "diagnostic.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/MC/MCInst.h"

#include <map>
#include <vector>

namespace llvm {
    class MCDisassembler;
    class MCInstrInfo;
} // namespace llvm

namespace forge::x86 {
    struct Step {
        uint32_t rva, next;
        llvm::MCInst inst;
        llvm::StringRef opcode; // Borrows the decoder's instruction-name table.
        llvm::StringRef bytes;  // Borrows the analyzed image.

        [[noreturn]] void reject(FailureCode kind, const llvm::Twine &reason,
                                 std::optional<int64_t> target = {}) const;
    };

    enum class Flow : uint8_t { Fallthrough, Jump, Conditional, Return, FallOff };

    struct GuestBlock {
        std::vector<Step> steps;
        Flow exit;
        // For Jcc the taken edge comes first. Parallel edges are retained for LLVM PHIs.
        llvm::SmallVector<uint32_t, 2> successors;
    };

    using ControlFlowGraph = std::map<uint32_t, GuestBlock>;

    ControlFlowGraph discoverCFG(llvm::StringRef bytes, uint32_t begin,
                                 const llvm::MCDisassembler &dis, const llvm::MCInstrInfo &info);
} // namespace forge::x86
