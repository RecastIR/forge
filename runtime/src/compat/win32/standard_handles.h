#pragma once

#include "../../platform/darwin/io.h"
#include "forge/runtime.h"

#include <array>
#include <optional>

namespace forge::runtime {
    struct StandardStream {
        uint64_t handle = 0;
        std::optional<darwin::Descriptor> descriptor;
    };

    class StandardHandles {
      public:
        StandardHandles() = default;
        StandardHandles(const StandardHandles &) = delete;
        StandardHandles &operator=(const StandardHandles &) = delete;
        ~StandardHandles();

        // Called once on an unpublished process. Destruction also releases a partial capture.
        forge_rt_status capture() noexcept;

        std::array<uint64_t, 3> values() const {
            return {streams[0].handle, streams[1].handle, streams[2].handle};
        }

        std::array<StandardStream, 3> streams{};
        bool hostHandlesOutputSignals = false;
    };
} // namespace forge::runtime
