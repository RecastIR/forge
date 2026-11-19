#pragma once

#include "forge/service_memory.h"

#include <algorithm>
#include <array>

namespace forge::runtime {
    template <win64::Argument arg>
    forge_rt_status scanString(const win64::GuestBuffer<arg> &string, uint64_t limit,
                               uint64_t &length) {
        std::array<uint8_t, 256> bytes{};
        for (uint64_t offset = 0; offset < limit;) {
            const auto count =
                static_cast<size_t>(std::min<uint64_t>(bytes.size(), limit - offset));
            const auto chunk = std::span(bytes).first(count);
            const auto status = string.read(offset, chunk);
            if (status == FORGE_RT_OK) {
                const auto end = std::ranges::find(chunk, uint8_t{0});
                if (end != chunk.end()) {
                    length = offset + static_cast<size_t>(end - chunk.begin());
                    return FORGE_RT_OK;
                }
            } else if (status == FORGE_RT_GUEST_FAULT ||
                       status == FORGE_RT_UNSUPPORTED_CALLBACK_RETURN ||
                       status == FORGE_RT_UNSUPPORTED_CALLBACK_ARGUMENT) {
                // A speculative chunk can extend past the NUL into inaccessible bytes.
                for (size_t i = 0; i < count; ++i) {
                    uint8_t byte;
                    const auto single = string.readScalar(offset + i, byte);
                    if (single != FORGE_RT_OK) {
                        return single;
                    }

                    if (!byte) {
                        length = offset + i;
                        return FORGE_RT_OK;
                    }
                }
            } else {
                return status;
            }

            offset += count;
        }
        return FORGE_RT_RESOURCE_EXHAUSTED;
    }
} // namespace forge::runtime
