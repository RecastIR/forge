#include "instance.h"

#include <algorithm>
#include <atomic>
#include <limits>

namespace forge::runtime {
    uint64_t issueToken() noexcept {
        // A thread, invocation, or occurrence identity is never recycled, including when
        // the host later reuses an instance or backing address.
        static std::atomic<uint64_t> lastIssuedToken{0};
        auto previous = lastIssuedToken.load(std::memory_order_relaxed);

        while (previous != std::numeric_limits<uint64_t>::max()) {
            const auto next = previous + 1;

            if (lastIssuedToken.compare_exchange_weak(previous, next, std::memory_order_relaxed)) {
                return next;
            }
        }

        return 0;
    }

    thread_local forge_rt_invocation_token executingInvocation = 0;
} // namespace forge::runtime

using namespace forge::runtime;

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

    // Host quiescence prevents new uses between the check and release.
    const auto status = withInstance(instance, [](const auto &process) {
        if (process.managedExecution) {
            return FORGE_RT_INVALID_STATE;
        }

        const bool active = std::ranges::any_of(
            process.threads, [](const auto &entry) { return entry.second.invocation != 0; });
        return active ? FORGE_RT_BUSY : FORGE_RT_OK;
    });

    if (status != FORGE_RT_OK) {
        return status;
    }

    delete instance;
    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_thread_create(forge_rt_instance *instance,
                                                  forge_rt_thread_token *outThread) noexcept {
    if (outThread == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [outThread](auto &process) {
        if (process.managedExecution) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto thread = issueToken();

        if (thread == 0) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        process.threads.try_emplace(thread);
        *outThread = thread;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_thread_destroy(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread) noexcept {
    return withInstance(instance, [thread](auto &process) {
        if (process.managedExecution) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (entry->second.invocation != 0) {
            return FORGE_RT_BUSY;
        }

        process.threads.erase(entry);
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_set_last_error(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread,
                                                   uint32_t value) noexcept {
    return withInstance(instance, [thread, value](auto &process) {
        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (process.managedExecution &&
            (!entry->second.invocation || executingInvocation != entry->second.invocation)) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        entry->second.lastError = value;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_get_last_error(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread,
                                                   uint32_t *outValue) noexcept {
    if (outValue == nullptr) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [thread, outValue](const auto &process) {
        const auto entry = process.threads.find(thread);

        if (entry == process.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (process.managedExecution &&
            (!entry->second.invocation || executingInvocation != entry->second.invocation)) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        *outValue = entry->second.lastError;
        return FORGE_RT_OK;
    });
}
