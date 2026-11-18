#pragma once

#include "forge/process.h"

#include <array>
#include <string>

namespace forge::runtime {
    // The managed occurrence keeps these bytes stable while its parameter mapping is live.
    struct ProcessParameters {
        std::string narrow;
        std::u16string wide;
        std::array<uint64_t, 2> stackBounds{FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE,
                                            FORGE_RT_STACK_BASE};
        uint64_t self = 0, tibClaim = 0;

        forge_rt_status buildCommandLine(const forge_rt_artifact &artifact,
                                         const forge_rt_process_startup &startup);
    };
} // namespace forge::runtime
