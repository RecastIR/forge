#include "forge/runtime.h"

#include <atomic>
#include <limits>
#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_map>

struct forge_rt_instance {
    std::mutex mutex;
    std::unordered_map<forge_rt_thread_token, uint32_t> lastErrors;
};

namespace {
    // Only token issuance is shared between instances. A destroyed token is never reused, even
    // when the host allocator reuses an instance's address.
    std::atomic<forge_rt_thread_token> lastIssuedToken{0};

    forge_rt_thread_token allocateThreadToken() noexcept {
        auto previous = lastIssuedToken.load(std::memory_order_relaxed);

        while (previous != std::numeric_limits<forge_rt_thread_token>::max()) {
            const auto next = previous + 1;

            if (lastIssuedToken.compare_exchange_weak(previous, next, std::memory_order_relaxed)) {
                return next;
            }
        }

        return 0;
    }

    template <typename Operation>
    forge_rt_status withThreadTable(forge_rt_instance *instance, Operation operation) noexcept {
        if (instance == nullptr) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        try {
            const std::lock_guard lock(instance->mutex);
            return operation(instance->lastErrors);
        } catch (const std::bad_alloc &) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        } catch (const std::length_error &) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        } catch (...) {
            return FORGE_RT_INTERNAL_ERROR;
        }
    }
} // namespace

extern "C" forge_rt_status forge_rt_create(uint32_t expectedVersion,
                                           forge_rt_instance **outInstance) noexcept {
    if (outInstance == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    if (expectedVersion != FORGE_RT_ABI_VERSION) {
        return FORGE_RT_ABI_MISMATCH;
    }

    try {
        *outInstance = new forge_rt_instance;
        return FORGE_RT_OK;
    } catch (const std::bad_alloc &) {
        return FORGE_RT_RESOURCE_EXHAUSTED;
    } catch (...) {
        return FORGE_RT_INTERNAL_ERROR;
    }
}

extern "C" forge_rt_status forge_rt_destroy(forge_rt_instance *instance) noexcept {
    if (instance == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    delete instance;
    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_thread_create(forge_rt_instance *instance,
                                                  forge_rt_thread_token *outThread) noexcept {
    if (outThread == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withThreadTable(instance, [outThread](auto &lastErrors) {
        const auto thread = allocateThreadToken();

        if (thread == 0) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        lastErrors.emplace(thread, 0);
        *outThread = thread;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_thread_destroy(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread) noexcept {
    return withThreadTable(instance, [thread](auto &lastErrors) {
        return lastErrors.erase(thread) == 0 ? FORGE_RT_INVALID_THREAD : FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_set_last_error(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread,
                                                   uint32_t value) noexcept {
    return withThreadTable(instance, [thread, value](auto &lastErrors) {
        const auto entry = lastErrors.find(thread);

        if (entry == lastErrors.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        entry->second = value;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_get_last_error(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread,
                                                   uint32_t *outValue) noexcept {
    if (outValue == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withThreadTable(instance, [thread, outValue](const auto &lastErrors) {
        const auto entry = lastErrors.find(thread);

        if (entry == lastErrors.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        *outValue = entry->second;
        return FORGE_RT_OK;
    });
}
