#pragma once

#include "crt_parameters.h"
#include "forge/process.h"

#include <array>
#include <optional>
#include <string>

namespace forge::runtime {
    // The instance owns the strings and the stable descriptors registered against those bytes.
    struct ProcessParameters {
        std::string narrow;
        std::u16string wide;
        std::array<uint64_t, 2> stackBounds{FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE,
                                            FORGE_RT_STACK_BASE};
        uint64_t self = 0, tibClaim = 0;
        int32_t crtErrno = 0;
        std::optional<CrtParameters> crt;
        std::array<forge_rt_image_region, 6> rows{};
        forge_rt_image mapping{};

        forge_rt_status initialize(forge_rt_instance &instance, const forge_rt_artifact &artifact,
                                   const forge_rt_process_startup &startup, bool osCommandLine,
                                   CrtImports imports);

      private:
        forge_rt_status buildCommandLine(const forge_rt_artifact &artifact,
                                         const forge_rt_process_startup &startup);
    };
} // namespace forge::runtime
