#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/msvcrt_process.h"

#include <algorithm>
#include <cstring>

using namespace forge::runtime;

namespace {
    constexpr size_t heapBudget = size_t{64} * 1024 * 1024;
    constexpr size_t allocationCharge = 256;
    constexpr int32_t windowsEnomem = 12;

    forge_rt_status exhausted(WindowsProcessState &windows, uint64_t &address) {
        windows.crtErrno = windowsEnomem;
        address = 0;
        return FORGE_RT_OK;
    }

    forge_rt_status allocate(forge_rt_instance &instance, uint64_t size, uint64_t &address,
                             std::span<uint8_t> *bytes = nullptr) {
        auto &windows = *instance.windows;
        size = std::max<uint64_t>(size, 1);

        if (size > heapBudget - allocationCharge ||
            size + allocationCharge > heapBudget - windows.heapUsage) {
            return exhausted(windows, address);
        }

        HeapBlock *block = nullptr;
        try {
            const auto status = allocateHeapBlock(instance, static_cast<size_t>(size), block);
            if (status != FORGE_RT_OK) {
                return status;
            }
        } catch (const std::bad_alloc &) {
            return exhausted(windows, address);
        }

        if (!block) {
            return exhausted(windows, address);
        }

        windows.heapUsage += static_cast<size_t>(size) + allocationCharge;
        address = block->image.base;
        if (bytes) {
            *bytes = block->bytes;
        }

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

    std::span<uint8_t> buffer;
    const auto status = allocate(owner, size, address, &buffer);

    if (status != FORGE_RT_OK || !address) {
        return status;
    }

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
        const auto status = checkManagedInvocation(owner, thread);

        if (status != FORGE_RT_OK) {
            return status;
        }

        if (count && size > UINT64_MAX / count) {
            return exhausted(*owner.windows, *outAddress);
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
        const auto status = checkManagedInvocation(owner, thread);

        if (status != FORGE_RT_OK || !address) {
            return status;
        }

        size_t releasedSize = 0;
        const auto released = freeHeapBlock(owner, address, releasedSize);
        if (released == FORGE_RT_OK) {
            owner.windows->heapUsage -= releasedSize + allocationCharge;
        }

        return released;
    });
}

extern "C" forge_rt_status forge_rt_msvcrt_errno(forge_rt_instance *instance,
                                                 forge_rt_thread_token thread,
                                                 uint64_t *outAddress) noexcept {
    if (!outAddress) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](const auto &owner) {
        const auto status = checkManagedInvocation(owner, thread);

        if (status == FORGE_RT_OK) {
            *outAddress = owner.windows->rows[WindowsProcessState::errnoRow].start;
        }

        return status;
    });
}
