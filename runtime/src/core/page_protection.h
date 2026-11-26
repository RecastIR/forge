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
        bool touchesPrivate(PageInterval bytes) const noexcept;
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

    // One contiguous transfer can intersect the managed image at most once. Hold the
    // invocation through publication. Heap insertion may relocate reservation iterators.
    struct ImageWrite {
        PageProtections *owner = nullptr;
        PageInterval bytes{};

        void record() const {
            if (owner) {
                owner->recordWrite(bytes);
            }
        }
    };

    struct GuestWrite {
        uint64_t address;
        size_t size;
        const void *source; // A null source realizes the write probe without storing bytes.
        ImageWrite image{};
    };

    forge_rt_status checkGuestWrite(const forge_rt_instance &instance, const Thread &active,
                                    GuestWrite &write, forge_rt_memory_fault &fault);
    // Reserve sparse tracking before a multi-output service makes any observable changes.
    forge_rt_status prepareGuestWrites(const forge_rt_instance &instance, const Thread &active,
                                       std::span<GuestWrite> writes, forge_rt_memory_fault &fault);
    void publishGuestWrite(const forge_rt_instance &instance, const GuestWrite &write);
} // namespace forge::runtime
