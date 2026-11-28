#include "instance.h"
#include "page_protection.h"

#include <algorithm>

namespace forge::runtime {
    namespace {
        constexpr uint64_t pageMask = FORGE_RT_GUEST_PAGE_SIZE - 1;

        const Reservation *imageAt(std::span<const Reservation> reservations, uint64_t address) {
            const auto after =
                std::ranges::upper_bound(reservations, address, {}, &Reservation::base);
            if (after == reservations.begin()) {
                return nullptr;
            }

            const auto &range = *std::prev(after);
            return range.protections && address - range.base < range.size ? &range : nullptr;
        }

        // Intersect the run with the next change in a sorted, inclusive overlay.
        bool overlayAt(std::span<const PageInterval> spans, uint64_t page, uint64_t &last) {
            const auto it = std::ranges::lower_bound(spans, page, {}, &PageInterval::last);
            if (it == spans.end()) {
                return false;
            }
            if (it->first > page) {
                last = std::min(last, it->first - 1);
                return false;
            }

            last = std::min(last, it->last);
            return true;
        }

        struct Run {
            uint64_t last;
            // An ordinary writable section with loader fixups can be either pristine or private.
            std::optional<PageAccess> access;
            ImageState state = ImageState::Committed;
        };

        std::optional<Run> headerRun(const Reservation &image, uint64_t rva) {
            const auto &state = *image.protections;
            if (state.original.empty() || state.original.front().rva < FORGE_RT_GUEST_PAGE_SIZE) {
                return {};
            }

            if (state.sizeOfHeaders) {
                const auto headersLast = (uint64_t{state.sizeOfHeaders} - 1) | pageMask;
                if (rva <= headersLast) {
                    return Run{image.base + headersLast, PageAccess::ReadOnly};
                }

                return Run{image.base + (state.original.front().rva - 1), PageAccess::None,
                           ImageState::Reserved};
            }

            // v6 establishes the first header page. Its table alone cannot
            // distinguish further header pages from reserved alignment padding.
            if (rva != 0) {
                return {};
            }
            return Run{image.base + pageMask, PageAccess::ReadOnly};
        }

        std::optional<Run> describe(const Reservation &image, uint64_t page,
                                    const ImageWrite &probe) {
            const auto &state = *image.protections;
            const auto rva = page - image.base;
            const auto after = std::ranges::upper_bound(state.original, rva, {},
                                                        &forge_rt_section_protection::rva);
            const uint64_t imageLast = image.size - 1;
            if (after == state.original.begin()) {
                return headerRun(image, rva);
            }

            const auto &section = *std::prev(after);
            const auto end = (uint64_t{section.rva} + section.size - 1) | pageMask;
            if ((section.rva & pageMask) || rva > end || end > imageLast ||
                (after != state.original.end() && after->rva <= end) ||
                (section.attributes & FORGE_RT_FIXED_PROTECTION)) {
                return {};
            }

            auto last = image.base + end;
            const auto access = section.attributes & ~FORGE_RT_LOADER_MAY_WRITE;
            if (access == FORGE_RT_READ) {
                return Run{last, PageAccess::ReadOnly};
            }
            if (access == (FORGE_RT_READ | FORGE_RT_EXECUTE)) {
                return Run{last, PageAccess::ExecuteRead};
            }
            if (access != (FORGE_RT_READ | FORGE_RT_WRITE)) {
                return {};
            }
            if (overlayAt(state.readOnly, page, last)) {
                return Run{last, PageAccess::ReadOnly};
            }
            if (probe.owner == &state) {
                const PageInterval pages{probe.bytes.first & ~pageMask,
                                         probe.bytes.last | pageMask};
                if (overlayAt(std::span(&pages, 1), page, last)) {
                    return Run{last, PageAccess::ReadWrite};
                }
            }
            if (overlayAt(state.privatePages, page, last)) {
                return Run{last, PageAccess::ReadWrite};
            }
            if (section.attributes & FORGE_RT_LOADER_MAY_WRITE) {
                return Run{last, std::nullopt};
            }
            return Run{last, PageAccess::ImageCopy};
        }
    } // namespace

    std::optional<ImageRegion> queryImageRegion(std::span<const Reservation> reservations,
                                                uint64_t address, const ImageWrite &probe) {
        const auto page = address & ~pageMask;
        const auto *image = imageAt(reservations, page);
        if (!image || ((image->base | image->size) & pageMask)) {
            return {};
        }

        auto run = describe(*image, page, probe);
        if (!run || !run->access) {
            return {};
        }

        const auto access = *run->access;
        const auto last = image->base + (image->size - 1);
        while (run->last < last) {
            const auto next = describe(*image, run->last + 1, probe);
            if (!next || (!next->access &&
                          (access == PageAccess::ImageCopy || access == PageAccess::ReadWrite))) {
                return {};
            }
            if (next->access != access || next->state != run->state) {
                break;
            }
            run = next;
        }

        return ImageRegion{page, image->base, run->last - page + 1, access, run->state};
    }

    bool unavailableQueryOutput(std::span<const Reservation> reservations, uint64_t address) {
        const auto *image = imageAt(reservations, address);
        if (!image) {
            return false;
        }

        const auto page = address & ~pageMask;
        if ((image->base | image->size) & pageMask) {
            return true;
        }

        const auto run = describe(*image, page, {});
        return !run || !run->access || run->access == PageAccess::ReadWrite ||
               run->access == PageAccess::ImageCopy;
    }
} // namespace forge::runtime
