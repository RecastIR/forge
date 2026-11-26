#include "page_protection.h"

#include "instance.h"

#include <algorithm>

namespace forge::runtime {
    bool PageProtections::isPrivate(uint64_t address) const noexcept {
        const auto it = std::ranges::lower_bound(privatePages, address, {}, &PageInterval::last);
        return it != privatePages.end() && it->first <= address;
    }

    namespace {
        PageInterval writtenPages(PageInterval bytes) {
            constexpr uint64_t mask = FORGE_RT_GUEST_PAGE_SIZE - 1;
            return {bytes.first & ~mask, bytes.last | mask};
        }

        auto firstTouching(auto &ranges, PageInterval pages) {
            return std::ranges::lower_bound(ranges, pages.first - (pages.first != 0), {},
                                            &PageInterval::last);
        }
    } // namespace

    bool PageProtections::touchesPrivate(PageInterval bytes) const noexcept {
        const auto pages = writtenPages(bytes);
        const auto it = firstTouching(privatePages, pages);
        return it != privatePages.end() && it->first <= pages.last + (pages.last != UINT64_MAX);
    }

    void PageProtections::recordWrite(PageInterval bytes) {
        const auto pages = writtenPages(bytes);
        const auto begin = firstTouching(privatePages, pages);
        const auto end = std::upper_bound(
            begin, privatePages.end(), pages.last + (pages.last != UINT64_MAX),
            [](uint64_t address, PageInterval span) { return address < span.first; });
        if (begin == end) {
            privatePages.insert(begin, pages);
        } else {
            begin->first = std::min(begin->first, pages.first);
            begin->last = std::max(std::prev(end)->last, pages.last);
            privatePages.erase(std::next(begin), end);
        }
    }

    bool PageProtections::permitsMapping(uint64_t imageBase,
                                         const forge_rt_region_template &row) const noexcept {
        if (row.start < imageBase || !row.size) {
            return false;
        }
        const auto rva = row.start - imageBase;
        const auto after =
            std::ranges::upper_bound(original, rva, {}, &forge_rt_section_protection::rva);
        if (after == original.begin()) {
            // Headers precede the first section. They have a fixed read-only backing.
            return row.permissions == FORGE_RT_READ &&
                   (original.empty() || row.size <= original.front().rva - rva);
        }

        const auto &section = *std::prev(after);
        const auto offset = rva - section.rva;
        return offset < section.size && row.size <= section.size - offset &&
               (row.permissions & section.attributes) == row.permissions;
    }

    std::optional<uint64_t> PageProtections::deniedWrite(PageInterval range) const noexcept {
        const auto it = std::ranges::lower_bound(readOnly, range.first, {}, &PageInterval::last);
        if (it != readOnly.end() && it->first <= range.last) {
            return std::max(it->first, range.first);
        }

        return std::nullopt;
    }

    namespace {
        // A committed Windows image page can have bytes the compiler did not materialize.
        // Admit only ranges completely covered by private source data AND by writable rows.
        bool eligible(const Reservation &reservation, PageInterval pages) {
            const auto &image = *reservation.image;
            const auto sections = reservation.protections->original;
            const auto rows = std::span(image.regions, static_cast<size_t>(image.count));
            const auto first = pages.first - image.base;
            const auto last = pages.last - image.base;
            auto section =
                std::ranges::upper_bound(sections, first, {}, &forge_rt_section_protection::rva);
            if (section == sections.begin()) {
                return false;
            }

            uint64_t pos = first;
            constexpr auto rw = FORGE_RT_READ | FORGE_RT_WRITE;
            for (--section; pos <= last; ++section) {
                if (section == sections.end() || section->rva > pos ||
                    (section->attributes & ~FORGE_RT_LOADER_MAY_WRITE) != rw) {
                    return false;
                }

                const auto end = uint64_t{section->rva} + section->size;
                if (end <= pos) {
                    return false;
                }
                pos = end;
            }

            auto row =
                std::ranges::upper_bound(rows, pages.first, {}, &forge_rt_image_region::start);
            if (row == rows.begin()) {
                return false;
            }

            pos = pages.first;
            for (--row; row != rows.end(); ++row) {
                if (row->start > pos || pos - row->start >= row->size || row->permissions != rw ||
                    !row->claim) {
                    return false;
                }

                const auto end = row->start + (row->size - 1);
                if (end >= pages.last) {
                    return true;
                }
                pos = end + 1;
            }

            return false;
        }

        void appendInterval(std::vector<PageInterval> &ranges, PageInterval value) {
            if (!ranges.empty() && value.first - ranges.back().last == 1) {
                ranges.back().last = value.last;
            } else {
                ranges.push_back(value);
            }
        }
    } // namespace

    bool unavailableProtectionOutput(std::span<const Reservation> reservations, uint64_t address) {
        const auto after = std::ranges::upper_bound(reservations, address, {}, &Reservation::base);
        if (after == reservations.begin()) {
            return false;
        }

        const auto &reservation = *std::prev(after);
        const auto offset = address - reservation.base;
        if (!reservation.protections || offset >= reservation.size ||
            reservation.protections->deniedWrite({address, address})) {
            return false;
        }

        const auto sections = reservation.protections->original;
        const auto end =
            std::ranges::upper_bound(sections, offset, {}, &forge_rt_section_protection::rva);
        if (end == sections.begin()) {
            return false;
        }

        const auto &section = *std::prev(end);
        // Windows also backs section tail padding at page granularity.
        return (section.attributes & FORGE_RT_WRITE) &&
               offset / FORGE_RT_GUEST_PAGE_SIZE <=
                   (uint64_t{section.rva} + section.size - 1) / FORGE_RT_GUEST_PAGE_SIZE;
    }

    ProtectionResult queryProtection(std::span<const Reservation> reservations, uint64_t address,
                                     PageInterval pages, PageInterval output,
                                     ProtectionUpdate &update) {
        auto after = std::ranges::upper_bound(reservations, address, {}, &Reservation::base);
        if (after == reservations.begin() ||
            address - std::prev(after)->base >= std::prev(after)->size) {
            // A sub-page heap or parameter block only describes the bytes Forge lends.
            // Padding on either side is on a page of unknown Windows allocation extent.
            const auto pageEnd = pages.first | (FORGE_RT_GUEST_PAGE_SIZE - 1);
            const auto next =
                std::ranges::upper_bound(reservations, pages.first, {}, &Reservation::base);
            auto it = next == reservations.begin() ? next : std::prev(next);
            for (; it != reservations.end() && it->base <= pageEnd; ++it) {
                if (!it->protections && it->base + (it->size - 1) >= pages.first) {
                    return ProtectionResult::Unsupported;
                }
            }

            return ProtectionResult::Unmapped;
        }

        const auto &reservation = *std::prev(after);
        // Synthetic parameter, heap, and active stack extents do not establish a
        // Windows allocation boundary, including when page rounding extends before them.
        if (!reservation.protections) {
            return ProtectionResult::Unsupported;
        }

        if (pages.first < reservation.base || pages.last - reservation.base >= reservation.size) {
            return ProtectionResult::CrossReservation;
        }

        update.owner = reservation.protections;
        if (!eligible(reservation, pages)) {
            return ProtectionResult::Unsupported;
        }

        if (!update.owner->deniedWrite({pages.first, pages.first})) {
            const bool probeWritesFirstPage =
                output.first <= (pages.first | (FORGE_RT_GUEST_PAGE_SIZE - 1)) &&
                output.last >= pages.first;
            if (probeWritesFirstPage || update.owner->isPrivate(pages.first)) {
                update.previous = PageAccess::ReadWrite;
            } else {
                const auto source = std::prev(
                    std::ranges::upper_bound(update.owner->original, pages.first - reservation.base,
                                             {}, &forge_rt_section_protection::rva));
                if (source->attributes & FORGE_RT_LOADER_MAY_WRITE) {
                    return ProtectionResult::Unsupported;
                }
                update.previous = PageAccess::ImageCopy;
            }
        }
        return ProtectionResult::Supported;
    }

    void ProtectionUpdate::stage(PageInterval pages, bool writable) {
        bool inserted = writable;
        for (auto range : owner->readOnly) {
            if (range.last < pages.first) {
                appendInterval(next, range);
                continue;
            }

            if (range.first < pages.first) {
                appendInterval(next, {range.first, pages.first - 1});
            }
            if (!inserted) {
                appendInterval(next, pages);
                inserted = true;
            }
            if (range.last > pages.last) {
                appendInterval(next, {std::max(range.first, pages.last + 1), range.last});
            }
        }

        if (!inserted) {
            appendInterval(next, pages);
        }
    }

    void ProtectionUpdate::commit() noexcept { owner->readOnly.swap(next); }
} // namespace forge::runtime
