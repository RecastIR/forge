#pragma once

#include "forge/runtime.h"

#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace forge::runtime {
    struct Thread {
        uint32_t lastError = 0;
        forge_rt_invocation_token invocation = 0;
        forge_rt_invocation_token parent = 0;
        const forge_rt_image *image = nullptr;
        forge_rt_stack stack{};
    };

    // A reservation covers the whole image, including holes, or one active stack.
    // Thread references survive table rehash. An active thread cannot be destroyed.
    struct Reservation {
        uint64_t base;
        uint64_t size;
        const forge_rt_image *image;
        const Thread *stackOwner;
    };

    uint64_t issueToken() noexcept;
    extern thread_local forge_rt_invocation_token executingInvocation;
} // namespace forge::runtime

struct forge_rt_instance {
    std::mutex mutex;
    std::unordered_map<forge_rt_thread_token, forge::runtime::Thread> threads;
    std::vector<forge::runtime::Reservation> reservations;
};

namespace forge::runtime {
    template <typename Operation>
    forge_rt_status withInstance(forge_rt_instance *instance, Operation operation) noexcept {
        if (instance == nullptr) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        try {
            const std::lock_guard lock(instance->mutex);
            return operation(*instance);
        } catch (const std::bad_alloc &) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        } catch (const std::length_error &) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        } catch (...) {
            return FORGE_RT_INTERNAL_ERROR;
        }
    }
} // namespace forge::runtime
