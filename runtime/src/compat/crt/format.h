#pragma once

#include "forge/service_memory.h"

namespace forge::runtime {
    // Staged logical bytes belong to one synchronous call. Parsing has no stream effects.
    struct FormattedOutput {
        std::array<char, 16384> bytes;
        size_t length = 0;

        // The writer rejects inputs overlapping its live FILE or buffer before committing.
        size_t formatBytes = 0, slotBytes = 0;

        struct StringRead {
            uint64_t address;
            size_t size;
        };

        std::array<StringRead, win64::crtFormatConversions> strings;
        size_t stringCount = 0;
    };

    forge_rt_status
    formatOutput(const win64::GuestBuffer<win64::crtVfprintf.arguments[1]> &format,
                 const win64::GuestBuffer<win64::crtVfprintf.arguments[2]> &arguments,
                 FormattedOutput &out);
} // namespace forge::runtime
