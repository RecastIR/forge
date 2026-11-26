#pragma once

#include "lift/operands.h"
#include "lift/recovery.h"

namespace forge::x86 {
    BoundedTableCall recoverTableCall(const std::map<uint32_t, Step> &steps, const Step &call,
                                      const InstructionOperands &operands, const ParsedImage &image,
                                      const ImageInitialization &init,
                                      llvm::ArrayRef<RvaRange> functions,
                                      unsigned &remainingEntries);

    void validateTableLoop(const RecoveredFunction &function, const Step &call,
                           const BoundedTableCall &table, const InstructionOperands &operands);
} // namespace forge::x86
