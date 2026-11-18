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
        std::array<StandardStream, 3> streams{};
        bool hostHandlesOutputSignals = false;
    };
} // namespace forge::runtime
