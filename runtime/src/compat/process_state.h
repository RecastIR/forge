#pragma once

#include "crt/crt_parameters.h"
#include "win32/process_parameters.h"
#include "win32/standard_handles.h"

#include <array>
#include <optional>
#include <vector>

namespace forge::runtime {
    struct TerminationRegistry {
        struct Handler {
            uint64_t site, target;
        };

        static constexpr size_t limit = 4096;

        static constexpr unsigned maxDepth = 16;
        unsigned depth = 0;
        size_t dispatched = 0;
        bool completed = false;
        std::vector<Handler> entries;
    };

    // Owned at a stable address by the managed occurrence. Its core reservations borrow
    // the combined parameter mapping until registration rollback or process close.
    struct WindowsProcessState {
        ProcessParameters parameters;
        std::optional<StandardHandles> standardHandles;
        uint64_t topLevelExceptionFilter = 0;

        std::optional<CrtParameters> crt;
        int32_t crtErrno = 0;
        size_t heapUsage = 0;
        TerminationRegistry termination;

        static constexpr size_t errnoRow = 2, narrowCommandRow = 3, wideCommandRow = 4;
        std::array<forge_rt_image_region, 6 + StartupInfo::maxRows> rows{};
        forge_rt_image mapping{};

        forge_rt_status initializeParameters(forge_rt_instance &instance,
                                             const forge_rt_artifact &artifact,
                                             const forge_rt_process_startup &startup,
                                             bool osCommandLine, CrtImports imports);

      private:
        forge_rt_status mapParameters(forge_rt_instance &instance,
                                      const forge_rt_artifact &artifact, bool osCommandLine,
                                      size_t startupPayloadSize);
    };
} // namespace forge::runtime
