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

    enum class PageAccess : uint8_t { ReadOnly, ReadWrite, ImageCopy, ExecuteRead, None };
    enum class ImageState : uint8_t { Committed, Reserved };

    struct PageProtections {
        std::span<const forge_rt_section_protection> original;
        // Effective write restrictions and privately realized SEC_IMAGE pages are independent.
        std::vector<PageInterval> readOnly;
        std::vector<PageInterval> privatePages;
        uint32_t sizeOfHeaders = 0; // No explicit header extent in v6.

        std::span<const forge_rt_loader_pages> loaderPages{};

        // Inclusive RVAs of the affected run containing or following rva in this section.
        std::optional<PageInterval> nextLoaderWrite(const forge_rt_section_protection &section,
                                                    uint64_t rva) const noexcept;
        void recordWrite(PageInterval bytes);
        bool touchesPrivate(PageInterval bytes) const noexcept;
        bool isPrivate(uint64_t address) const noexcept;
        bool permitsMapping(uint64_t imageBase, const forge_rt_region_template &row) const noexcept;
        std::optional<uint64_t> deniedWrite(PageInterval range) const noexcept;
    };

    // A metadata query neither resolves a byte pointer nor grants access to the page.
    struct ImageRegion {
        uint64_t base, allocation, allocationLast, size;
        PageAccess access;
        ImageState state;
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

        void include(PageProtections *state, PageInterval range) {
            if (!owner) {
                owner = state;
                bytes.first = range.first;
            }
            bytes.last = range.last;
        }

        void record() const {
            if (owner) {
                owner->recordWrite(bytes);
            }
        }
    };

    std::optional<ImageRegion> queryImageRegion(std::span<const Reservation> reservations,
                                                uint64_t address, const ImageWrite &probe = {});

    bool unavailableQueryOutput(std::span<const Reservation> reservations, const Thread &active,
                                uint64_t address);

    // A page-start probe beyond the result bytes may realize an omitted writable
    // image page. The returned end is bounded by source state and the next published row.
    std::optional<uint64_t> probeOmittedImagePages(std::span<const Reservation> reservations,
                                                   uint64_t address, uint64_t last,
                                                   ImageWrite &probe);

    // Probe the first byte and each subsequent page start. Coalesce admissible
    // runs using existing mapping and access extents. Return only staged effects,
    // including the successful prefix on a later inaccessible page.
    forge_rt_status probeGuestWritePages(const forge_rt_instance &instance, const Thread &active,
                                         uint64_t address, uint64_t length, size_t resultSize,
                                         ImageWrite &probe, forge_rt_memory_fault &fault);

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
