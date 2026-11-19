#pragma once

#include "diagnostic.h"

namespace forge {
    struct CExceptionScope {
        uint32_t beginRva, endRva, filterRva, jumpRva;
    };

    // Copied evidence for the AMD64 __C_specific_handler scope table. A declared
    // count is retained even if its rows cannot be validated.
    struct CSpecificHandler {
        std::string dll;
        uint32_t iatSlotRva, tableRva;
        std::optional<uint32_t> count;
        std::optional<CExceptionScope> scope;
        FailureCode failure = FailureCode::ExecutableStartup;
        std::string limitation;
    };
} // namespace forge
