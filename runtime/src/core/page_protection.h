#pragma once

#include "forge/process.h"

#include <optional>
#include <span>
#include <vector>

namespace forge::runtime {
    struct Reservation;
    struct Thread;

    struct PageInterval {
        uint64_t first, last; // Inclusive guest VAs.
    };

    enum class PageAccess : uint8_t { ReadOnly, ReadWrite, ImageCopy };

    struct PageProtections {
        std::span<const forge_rt_section_protection> original;
        // Effective write restrictions and privately realized SEC_IMAGE pages are independent.
        std::vector<PageInterval> readOnly;
        std::vector<PageInterval> privatePages;

        void recordWrite(PageInterval bytes);
        bool isPrivate(uint64_t address) const noexcept;
        bool permitsMapping(uint64_t imageBase, const forge_rt_region_template &row) const noexcept;
        std::optional<uint64_t> deniedWrite(PageInterval range) const noexcept;
    };

    enum class ProtectionResult : uint8_t { Supported, Unmapped, CrossReservation, Unsupported };

    struct ProtectionUpdate {
        PageProtections *owner = nullptr;
        std::vector<PageInterval> next;
        PageAccess previous = PageAccess::ReadOnly;

        void stage(PageInterval pages, bool writable);
        void commit() noexcept;
    };

    // The caller holds the mapping lock through validation, output transfer and commit.
    ProtectionResult queryProtection(std::span<const Reservation> reservations, uint64_t address,
                                     PageInterval pages, PageInterval output,
                                     ProtectionUpdate &update);
    // A rejected DWORD may name valid Windows storage omitted or sealed by the image plan.
    bool unavailableProtectionOutput(std::span<const Reservation> reservations, uint64_t address);
    forge_rt_status checkProtectionOutput(const forge_rt_instance &instance, const Thread &active,
                                          uint64_t address, forge_rt_memory_fault &fault);
    // Requires a checked DWORD under the same mapping lock. Its write probe realizes
    // private image pages even if the new access subsequently prevents publishing the value.
    void publishProtectionOutput(const forge_rt_instance &instance, uint64_t address,
                                 const uint32_t *value);
} // namespace forge::runtime
