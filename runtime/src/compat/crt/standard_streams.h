#pragma once

#include "forge/runtime.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace forge::runtime {
    class StandardHandles;

    // Legacy MSVCRT's x64 _iobuf. Every address in this record is a guest VA.
    struct LegacyFile {
        uint64_t ptr = 0;
        int32_t count = 0;
        uint32_t padding = 0;
        uint64_t base = 0;
        uint32_t flags = 0;
        int32_t file = 0, charbuf = 0, capacity = 0;
        uint64_t tmpname = 0;
    };

    static_assert(sizeof(LegacyFile) == 48 && alignof(LegacyFile) == 8 &&
                  offsetof(LegacyFile, base) == 16 && offsetof(LegacyFile, file) == 28 &&
                  offsetof(LegacyFile, tmpname) == 40);

    struct CrtStandardStreams {
        static constexpr size_t capacity = 4096;
        std::array<LegacyFile, 3> files{};
        std::array<uint8_t, capacity> stdinBytes{};
        std::array<forge_rt_image_region, 2> rows{};
        forge_rt_image mapping{};

        struct Buffer {
            std::array<uint8_t, capacity> bytes{};
            forge_rt_image_region row{};
            forge_rt_image mapping{};
        };

        std::array<std::unique_ptr<Buffer>, 3> buffers{};
        bool preserveAbortResult = false;

        forge_rt_status initialize(forge_rt_instance &instance, const StandardHandles &handles);
        forge_rt_status prepareBuffer(forge_rt_instance &instance, size_t index);
        forge_rt_status finish(const StandardHandles &handles) noexcept;
    };
} // namespace forge::runtime
