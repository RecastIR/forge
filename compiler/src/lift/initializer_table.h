#pragma once

#include "lift/recovery.h"

namespace forge::x86 {
    // Shared only while scanning one finished caller CFG. Same-block proofs need no index.
    struct InitializerRecovery {
        using Predecessors = std::map<uint32_t, std::vector<const GuestBlock *>>;
        std::optional<Predecessors> predecessors;
        unsigned entries = 0;
    };

    InitializerTable
    recoverInitializerTable(const RecoveredFunction &caller, const GuestBlock &block,
                            const Step &call, const win64::ServiceBinding &binding,
                            const ParsedImage &image, const ImageInitialization &init,
                            const llvm::MCInstrInfo &instructions,
                            const llvm::MCRegisterInfo &registers, InitializerRecovery &recovery);
} // namespace forge::x86
