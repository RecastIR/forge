#pragma once

#include <cstdint>

namespace forge::runtime::darwin {
    // Return zero on completion or the native error. An indefinite wait returns only on failure.
    int yieldThread() noexcept;
    int waitForMilliseconds(uint32_t milliseconds) noexcept;
    int waitIndefinitely() noexcept;
} // namespace forge::runtime::darwin
