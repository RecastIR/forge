#pragma once

#include <cstddef>
#include <cstdint>

namespace forge::x86 {
    // Positional slots are independent of the Darwin ABI and of the declared width.
    struct ServiceLocation {
        size_t position;

        bool inRegister() const { return position < 4; }

        unsigned registerIndex() const { return static_cast<unsigned>(position + 1); }

        uint64_t callerOffset() const { return position * 8; }

        uint64_t entryOffset() const { return callerOffset() + 8; }
    };
} // namespace forge::x86
