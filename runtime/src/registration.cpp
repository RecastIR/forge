#include "instance.h"

#include "forge/guest_range.h"

#include <algorithm>
#include <cassert>
#include <span>

using namespace forge;
using namespace forge::runtime;

namespace {
    // Claims belong to the backing owner and survive instance destruction. This lock
    // orders transactions involving multiple claim words across independent processes.
    std::mutex claimMutex;

    auto guestRange(const auto &mapping) {
        return GuestRange::fromOffset({mapping.base}, 0, mapping.size);
    }

    bool validImage(const forge_rt_image &image) {
        const auto extent = guestRange(image);

        if (!extent || (image.count != 0 && !image.regions) ||
            image.count > PTRDIFF_MAX / sizeof(forge_rt_image_region)) {
            return false;
        }

        std::optional<uint64_t> previousLast;

        for (const auto &row : std::span(image.regions, static_cast<size_t>(image.count))) {
            const auto range = GuestRange::fromOffset({row.start}, 0, row.size);
            constexpr uint32_t permissions = FORGE_RT_READ | FORGE_RT_WRITE | FORGE_RT_EXECUTE;

            if (!range || !row.bytes || row.size > SIZE_MAX || row.permissions == 0 ||
                (row.permissions & ~permissions) != 0 ||
                ((row.permissions & FORGE_RT_WRITE) != 0 && row.claim == nullptr)) {
                return false;
            }

            const auto last = row.start + (row.size - 1);

            if (!extent->contains({row.start}) || !extent->contains({last}) ||
                (previousLast && *previousLast >= row.start)) {
                return false;
            }

            previousLast = last;
        }

        return true;
    }

    bool validStack(const forge_rt_stack &stack) {
        const auto range = guestRange(stack);
        return range && stack.bytes && stack.marks && stack.size <= SIZE_MAX && stack.size >= 8 &&
               stack.outerReturn >= stack.base && stack.outerReturn - stack.base <= stack.size - 8;
    }

    auto position(auto &reservations, uint64_t base) {
        return std::ranges::lower_bound(reservations, base, {}, &Reservation::base);
    }

    bool overlaps(const auto &first, const auto &second) {
        // Publication checks descriptor extents before comparing them with live reservations.
        const auto left = guestRange(first);
        const auto right = guestRange(second);
        assert(left && right);
        return left.value().overlaps(right.value());
    }

    bool occupied(const std::vector<Reservation> &reservations, const auto &mapping) {
        const auto next = position(reservations, mapping.base);

        if (next != reservations.end() && overlaps(mapping, *next)) {
            return true;
        }

        if (next == reservations.begin()) {
            return false;
        }

        return overlaps(mapping, *std::prev(next));
    }

    forge_rt_status claimBacking(const forge_rt_image &image) {
        const std::span rows(image.regions, static_cast<size_t>(image.count));
        const auto hasClaim = [](const auto &row) { return row.claim != nullptr; };

        if (std::ranges::none_of(rows, hasClaim)) {
            return FORGE_RT_OK;
        }

        const std::lock_guard lock(claimMutex);

        for (const auto &row : rows) {
            if (row.claim && *row.claim != 0) {
                return FORGE_RT_MAPPING_CONFLICT;
            }
        }

        const auto occurrence = issueToken();

        if (!occurrence) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        for (const auto &row : rows) {
            if (row.claim) {
                *row.claim = occurrence;
            }
        }

        return FORGE_RT_OK;
    }

    forge_rt_status publishImage(forge_rt_instance &process, const forge_rt_image &image,
                                 const forge_rt_stack *stack) {
        auto &reservations = process.reservations;
        const auto found = position(reservations, image.base);
        const bool attached = found != reservations.end() && found->image == &image;

        if (!attached && !validImage(image)) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        if (!attached && occupied(reservations, image)) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        if (stack && (occupied(reservations, *stack) || overlaps(*stack, image))) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        // No allocation or potentially throwing operation may follow the exclusive claim.
        const size_t additional =
            static_cast<size_t>(!attached) + static_cast<size_t>(stack != nullptr);
        const auto limit = reservations.max_size();

        if (additional > limit - reservations.size()) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        const auto required = reservations.size() + additional;
        const auto capacity = reservations.capacity();

        if (required > capacity) {
            const auto growth = std::min(capacity, limit - capacity);
            reservations.reserve(std::max(required, capacity + growth));
        }

        if (attached) {
            return FORGE_RT_OK;
        }

        const auto status = claimBacking(image);

        if (status != FORGE_RT_OK) {
            return status;
        }

        reservations.insert(position(reservations, image.base),
                            {image.base, image.size, &image, nullptr});
        return FORGE_RT_OK;
    }
} // namespace

extern "C" forge_rt_status forge_rt_register_image(forge_rt_instance *instance,
                                                   const forge_rt_image *image) noexcept {
    if (!image) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance,
                        [&](auto &process) { return publishImage(process, *image, nullptr); });
}

extern "C" forge_rt_status forge_rt_detach_image(forge_rt_instance *instance,
                                                 const forge_rt_image *image) noexcept {
    if (!image) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](auto &process) {
        auto &reservations = process.reservations;
        const auto found = position(reservations, image->base);

        if (found == reservations.end() || found->image != image) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        const bool executing = std::ranges::any_of(
            process.threads, [&](const auto &entry) { return entry.second.image == image; });

        if (executing) {
            return FORGE_RT_BUSY;
        }

        reservations.erase(found);
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_enter(forge_rt_instance *instance, forge_rt_thread_token thread,
                                          const forge_rt_image *image, const forge_rt_stack *stack,
                                          forge_rt_invocation_token *outInvocation) noexcept {
    if (!image || !outInvocation || (stack && !validStack(*stack))) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](auto &process) {
        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        auto &active = entry->second;

        if (active.invocation) {
            return FORGE_RT_BUSY;
        }

        auto &reservations = process.reservations;

        const auto invocation = issueToken();

        if (!invocation) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        const auto status = publishImage(process, *image, stack);

        if (status != FORGE_RT_OK) {
            return status;
        }

        if (stack) {
            active.stack = *stack;
            reservations.insert(position(reservations, stack->base),
                                {stack->base, stack->size, nullptr, &active});
        }

        active.invocation = invocation;
        active.parent = executingInvocation;
        active.image = image;
        executingInvocation = invocation;
        *outInvocation = invocation;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_leave(forge_rt_instance *instance, forge_rt_thread_token thread,
                                          forge_rt_invocation_token invocation) noexcept {
    return withInstance(instance, [&](auto &process) {
        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        auto &active = entry->second;

        if (!invocation || active.invocation != invocation || executingInvocation != invocation) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        if (active.stack.bytes) {
            auto &reservations = process.reservations;
            reservations.erase(position(reservations, active.stack.base));
            active.stack = {};
        }

        executingInvocation = active.parent;
        active.parent = 0;
        active.invocation = 0;
        active.image = nullptr;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status
forge_rt_current_invocation(forge_rt_instance *instance, forge_rt_thread_token thread,
                            forge_rt_invocation_token *outInvocation) noexcept {
    if (!outInvocation) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](const auto &process) {
        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        const auto invocation = entry->second.invocation;

        if (!invocation || executingInvocation != invocation) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        *outInvocation = invocation;
        return FORGE_RT_OK;
    });
}
