#include "instance.h"

#include <algorithm>

namespace forge::runtime {
    forge_rt_status allocateHeapBlock(forge_rt_instance &instance, size_t size,
                                      HeapBlock *&outBlock) {
        constexpr uint64_t alignment = 16;
        auto base =
            findGuestAllocation(instance.reservations, size, alignment, instance.nextHeapAddress);

        if (!base) {
            base = findGuestAllocation(instance.reservations, size, alignment);
        }

        if (!base) {
            outBlock = nullptr;
            return FORGE_RT_OK;
        }

        const auto [entry, inserted] = instance.heap.try_emplace(base, base, size);
        if (!inserted) {
            return FORGE_RT_INTERNAL_ERROR;
        }

        // Publication reserves capacity before claiming the bytes. A failure or exception
        // leaves the reservation table untouched, so the unpublished block can be released.
        try {
            const auto status = publishOwnedImage(instance, entry->second.image);
            if (status != FORGE_RT_OK) {
                instance.heap.erase(entry);
                return status;
            }
        } catch (...) {
            instance.heap.erase(entry);
            throw;
        }

        instance.nextHeapAddress = (base + size + alignment - 1) & ~(alignment - 1);
        outBlock = &entry->second;
        return FORGE_RT_OK;
    }

    forge_rt_status freeHeapBlock(forge_rt_instance &instance, uint64_t address,
                                  size_t &releasedSize) {
        const auto block = instance.heap.find(address);
        if (block == instance.heap.end()) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        auto &ranges = instance.reservations;
        const auto range = std::ranges::lower_bound(ranges, address, {}, &Reservation::base);

        if (range == ranges.end() || range->image != &block->second.image) {
            return FORGE_RT_INTERNAL_ERROR;
        }

        ranges.erase(range);
        releasedSize = block->second.bytes.size();
        instance.nextHeapAddress = std::min(instance.nextHeapAddress, address);
        instance.heap.erase(block);
        return FORGE_RT_OK;
    }
} // namespace forge::runtime
