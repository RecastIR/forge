#pragma once

#include "../../core/page_protection.h"

namespace forge::runtime::win32 {
    inline constexpr uint64_t lowestUser = 0x10000, highestUser = UINT64_C(0x7ffffffeffff);
    inline constexpr uint32_t noAccess = 1, readOnly = 2, readWrite = 4, writeCopy = 8;
    inline constexpr uint32_t badLength = 24, invalidParameter = 87, invalidAddress = 487,
                              inaccessible = 998;

    constexpr uint32_t windowsProtection(PageAccess access) {
        switch (access) {
        case PageAccess::ReadOnly:
            return readOnly;
        case PageAccess::ReadWrite:
            return readWrite;
        case PageAccess::ImageCopy:
            return writeCopy;
        case PageAccess::ExecuteRead:
            return 0x20;
        case PageAccess::None:
            return 0; // Reserved image pages have no effective protection.
        }
    }
} // namespace forge::runtime::win32
