#pragma once

#include "forge/service_memory.h"

namespace forge::runtime {
    // Staged logical bytes belong to one synchronous call. Parsing has no stream effects.
    struct FormattedOutput {
        std::array<char, 16384> bytes;
        size_t length = 0;

        // A failed character write stops one part. Only literal text between fields
        // and left-aligned trailing padding require a nonnegative count on entry.
        enum class Part : uint8_t { Boundary, Padding, Text };

        struct Write {
            uint16_t end;
            Part part;
        };

        // One intervening literal and at most five parts per field, then a final literal.
        std::array<Write, 6 * win64::crtFormatConversions + 1> writes;
        size_t writeCount = 0;

        void finishPart(Part part) {
            static_assert(std::tuple_size_v<decltype(bytes)> <= UINT16_MAX);
            writes[writeCount++] = {static_cast<uint16_t>(length), part};
        }

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
