#pragma once

#include "diagnostic.h"

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/MC/MCInst.h"

#include <map>
#include <memory>
#include <vector>

namespace llvm {
    class MCDisassembler;
    class MCInstrInfo;
} // namespace llvm

namespace forge::x86 {
    class JumpTableReader;

    enum class Flow : uint8_t {
        Fallthrough,
        Jump,
        TailJump,
        Conditional,
        Indirect,
        Return,
        TerminalCall,
        FallOff
    };

    struct GuardedPointerCall {
        uint32_t producer, slot;
    };

    struct Step {
        uint32_t rva, next;
        llvm::MCInst inst;
        llvm::StringRef opcode; // Borrows the decoder's instruction-name table.
        llvm::StringRef bytes;  // Borrows the analyzed image.
        Flow flow = Flow::Fallthrough;
        std::optional<GuardedPointerCall> guardedPointerCall = {};
        // A full-width RIP-relative load reaches this register on every incoming path.
        // Recovery separately validates ownership and binds the indicated IAT slot.
        std::optional<uint32_t> registerImportSlot = {};

        // Provisional until the complete loop and every incoming edge validate.
        bool forwardTableCandidate = false;

        bool isDirectCall() const { return opcode == "CALL64pcrel32"; }

        std::optional<int64_t> directCallTarget() const {
            if (!isDirectCall()) {
                return {};
            }
            return relativeTarget();
        }

        int64_t relativeTarget() const { return int64_t(next) + inst.getOperand(0).getImm(); }

        bool isMemoryCall() const { return opcode == "CALL64m"; }

        bool isRegisterCall() const { return opcode == "CALL64r"; }

        bool isRepeatedQwordStore() const { return opcode == "STOSQ" && bytes == "\xf3\x48\xab"; }

        bool isLockedCompareExchange() const {
            return opcode == "CMPXCHG64rm" && bytes.starts_with("\xf0");
        }

        bool isAtomicExchange() const { return isLockedCompareExchange() || opcode == "XCHG64rm"; }

        InspectionError errorAtInstruction(FailureCode kind, const llvm::Twine &reason,
                                           FailureContext context = {}) const;
        [[noreturn]] void reject(FailureCode kind, const llvm::Twine &reason,
                                 std::optional<int64_t> target = {},
                                 std::optional<uint32_t> importSlot = {},
                                 const std::optional<ImportOwnershipFailure> &ownership = {}) const;
    };

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
    // A recorded call may initially have no proven return. Recovery resumes its next PC
    // when the target acquires a reachable RET. The callback lives only during advance().
    using CallFlow = llvm::function_ref<Flow(const Step &, std::optional<int64_t> guestTarget)>;

    ControlFlowGraph discoverCFG(llvm::StringRef bytes, uint32_t begin,
                                 const llvm::MCDisassembler &dis, const llvm::MCInstrInfo &info,
                                 LeafStepCheck validateLeaf);

    class RecordedCFG {
      public:
        RecordedCFG(llvm::StringRef bytes, uint32_t begin, const llvm::MCDisassembler &dis,
                    const llvm::MCInstrInfo &info, JumpTableReader &tables, bool registerImports);
        ~RecordedCFG();
        bool advance(CallFlow classify);
        void resume(uint32_t instruction);
        const std::map<uint32_t, Step> &steps() const &;
        const std::map<uint32_t, Step> &steps() const && = delete;
        bool hasBypassedProof() const;
        ControlFlowGraph finish();

      private:
        struct State;
        std::unique_ptr<State> state;
    };
} // namespace forge::x86
