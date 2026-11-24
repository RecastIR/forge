#pragma once

#include "forge/process.h"

#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace forge::runtime {
    class StandardHandles;

    struct StartupWindow {
        uint32_t x = 0, y = 0, width = 0, height = 0;
        uint32_t columns = 0, lines = 0, fill = 0, flags = 0;
    };

    struct StartupText {
        std::string narrow;
        // A missing wide view after preparation means the source title cannot be encoded.
        std::optional<std::u16string> wide;
        uint64_t narrowAddress = 0, wideAddress = 0;
    };

    // Creation metadata belongs to the occurrence. Registration derives the UTF-16
    // views and maps only supplied data. Standard stream descriptors have a separate owner.
    struct StartupInfo {
        static constexpr size_t maxRows = 7; // Three A/W strings and the reserved byte buffer.
        static constexpr uint32_t useStdHandles = 0x100;
        StartupWindow window;
        uint16_t show = 0;
        std::array<uint64_t, 3> creationHandles{};
        std::optional<StartupText> shell, desktop, title;
        std::vector<uint8_t> reserved;
        uint64_t reservedAddress = 0;

        forge_rt_status setDefaultStrings(const forge_rt_artifact &artifact,
                                          const forge_rt_process_startup &startup);
        forge_rt_status prepare(const StandardHandles *handles, size_t &size);
        size_t map(uint64_t base, std::span<forge_rt_image_region, maxRows> rows);
    };

    // The managed occurrence keeps these bytes stable while its parameter mapping is live.
    struct ProcessParameters {
        StartupInfo startupInfo;
        std::string narrow;
        std::u16string wide;
        std::array<uint64_t, 2> stackBounds{FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE,
                                            FORGE_RT_STACK_BASE};
        uint64_t self = 0, tibClaim = 0;

        forge_rt_status buildCommandLine(const forge_rt_artifact &artifact,
                                         const forge_rt_process_startup &startup);
    };
} // namespace forge::runtime
