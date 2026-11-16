#pragma once

#include "lift/recovery.h"

namespace forge::x86 {
    void recoverLeaves(const ValidatedEntry &entry,
                       std::map<uint32_t, RecoveredFunction> &functions,
                       const std::map<uint32_t, const ResolvedCallSite *> &deferred,
                       llvm::ArrayRef<RvaRange> loaderWrites, const llvm::MCDisassembler &dis,
                       const llvm::MCInstrInfo &instructions, const llvm::MCRegisterInfo &regs);
} // namespace forge::x86
