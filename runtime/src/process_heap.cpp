#include "forge/msvcrt_process.h"
#include "instance.h"

#include <algorithm>
#include <cstring>

using namespace forge::runtime;

namespace {
    constexpr size_t heapBudget = size_t{64} * 1024 * 1024;
    constexpr size_t allocationCharge = 256;
    constexpr int32_t windowsEnomem = 12;

    forge_rt_status activeHeap(const forge_rt_instance &instance, forge_rt_thread_token thread) {
        if (!instance.managedExecution || !instance.parameters) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto found = instance.threads.find(thread);

        if (found == instance.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (!executingInvocation || found->second.invocation != executingInvocation ||
            instance.managedExecution->thread != thread) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        return FORGE_RT_OK;
    }

    forge_rt_status exhausted(forge_rt_instance &instance, uint64_t &address) {
        instance.parameters->crtErrno = windowsEnomem;
        address = 0;
        return FORGE_RT_OK;
    }

    forge_rt_status allocate(forge_rt_instance &instance, uint64_t size, uint64_t &address) {
        size = std::max<uint64_t>(size, 1);

        if (size > heapBudget - allocationCharge ||
            size + allocationCharge > heapBudget - instance.heapUsage) {
            return exhausted(instance, address);
        }

        auto base = findGuestAllocation(instance.reservations, size, 16, instance.nextHeapAddress);

        if (!base) {
            base = findGuestAllocation(instance.reservations, size, 16);
        }

        if (!base) {
            return exhausted(instance, address);
        }

        try {
            // Make both potentially allocating publications transactional. publishOwnedImage
            // requires one reservation and cannot throw after claiming the backing.
            auto &ranges = instance.reservations;

            if (ranges.capacity() == ranges.size()) {
                ranges.reserve(std::max(ranges.size() + 1, 2 * ranges.size()));
            }

            const auto [entry, inserted] =
                instance.heap.try_emplace(base, base, static_cast<size_t>(size));

            if (!inserted) {
                return FORGE_RT_INTERNAL_ERROR;
            }

            const auto status = publishOwnedImage(instance, entry->second.image);

            if (status != FORGE_RT_OK) {
                instance.heap.erase(entry);
                return status;
            }
        } catch (const std::bad_alloc &) {
            return exhausted(instance, address);
        }

        instance.heapUsage += static_cast<size_t>(size) + allocationCharge;
        instance.nextHeapAddress = (base + size + 15) & ~uint64_t{15};
        address = base;
        return FORGE_RT_OK;
    }
} // namespace

// Legacy __getmainargs creates a fresh writable, null-terminated vector per call.
// Construct the entire allocation under the instance lock before exposing the pointer.
forge_rt_status CrtParameters::copyArguments(forge_rt_instance &owner, uint64_t &address) const {
    size_t cursor = (arguments.size() + 1) * sizeof(uint64_t);
    size_t size = cursor;

    for (const auto &argument : arguments) {
        size += argument.size() + 1;
    }

    const auto status = allocate(owner, size, address);

    if (status != FORGE_RT_OK || !address) {
        return status;
    }

    auto &buffer = owner.heap.at(address).bytes;

    for (size_t i = 0; i < arguments.size(); ++i) {
        const auto pointer = address + cursor;
        const auto &argument = arguments[i];
        std::memcpy(buffer.data() + i * sizeof(pointer), &pointer, sizeof(pointer));
        std::memcpy(buffer.data() + cursor, argument.c_str(), argument.size() + 1);
        cursor += argument.size() + 1;
    }

    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_msvcrt_calloc(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t count,
                                                  uint64_t size, uint64_t *outAddress) noexcept {
    if (!outAddress) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](auto &owner) {
        const auto status = activeHeap(owner, thread);

        if (status != FORGE_RT_OK) {
            return status;
        }

        if (count && size > UINT64_MAX / count) {
            return exhausted(owner, *outAddress);
        }

        return allocate(owner, count * size, *outAddress);
    });
}

extern "C" forge_rt_status forge_rt_msvcrt_malloc(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t size,
                                                  uint64_t *outAddress) noexcept {
    return forge_rt_msvcrt_calloc(instance, thread, 1, size, outAddress);
}

extern "C" forge_rt_status forge_rt_msvcrt_free(forge_rt_instance *instance,
                                                forge_rt_thread_token thread,
                                                uint64_t address) noexcept {
    return withInstance(instance, [&](auto &owner) {
        const auto status = activeHeap(owner, thread);

        if (status != FORGE_RT_OK || !address) {
            return status;
        }

        const auto block = owner.heap.find(address);

        if (block == owner.heap.end()) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        auto &ranges = owner.reservations;
        const auto range = std::ranges::lower_bound(ranges, address, {}, &Reservation::base);

        if (range == ranges.end() || range->image != &block->second.image) {
            return FORGE_RT_INTERNAL_ERROR;
        }

        ranges.erase(range);
        owner.heapUsage -= block->second.bytes.size() + allocationCharge;
        owner.nextHeapAddress = std::min(owner.nextHeapAddress, address);
        owner.heap.erase(block);
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_msvcrt_errno(forge_rt_instance *instance,
                                                 forge_rt_thread_token thread,
                                                 uint64_t *outAddress) noexcept {
    if (!outAddress) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](const auto &owner) {
        const auto status = activeHeap(owner, thread);

        if (status == FORGE_RT_OK) {
            *outAddress = owner.parameters->rows[2].start;
        }

        return status;
    });
}
