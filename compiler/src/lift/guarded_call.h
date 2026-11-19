#pragma once

#include "lift/operands.h"
#include "pe/image.h"

namespace forge::x86 {
    bool clobbersRegister(const Step &step, llvm::MCRegister reg, RegisterView view,
                          const llvm::MCInstrInfo &info, const llvm::MCRegisterInfo &registers);
    uint32_t relocatedPointerRva(const Step &call, const Module &module,
                                 const ImageInitialization &init, uint32_t slot, uint64_t value,
                                 bool allowImageEnd = false);
    uint32_t readImmutableImagePointer(const Step &call, const ParsedImage &image,
                                       const ImageInitialization &init, uint32_t slot,
                                       bool allowImageEnd = false);
    // Explicit branch/table edges are indexed by destination. Sequential predecessors
    // are derived from the decoded extents and their current return behavior.
    std::optional<uint32_t>
    reachingImportSlot(const std::map<uint32_t, Step> &decoded,
                       const std::multimap<uint32_t, uint32_t> &branchPredecessors,
                       const Step &call, const llvm::MCInstrInfo &info,
                       const llvm::MCRegisterInfo &registers);
    std::optional<GuardedPointerCall>
    recognizeGuardedPointerCall(const std::map<uint32_t, Step> &decoded, const Step &call,
                                const InstructionOperands &operands);
    uint32_t guardedCallTarget(const Step &call, uint32_t slot, const ParsedImage &image,
                               const ImageInitialization &init);
} // namespace forge::x86
