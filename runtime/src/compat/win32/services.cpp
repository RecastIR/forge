#include "../string_scan.h"

#include <cerrno>
#include <sched.h>
#include <time.h>
#include <unistd.h>

extern "C" forge_rt_status forge_rt_sleep(forge_rt_instance *instance, forge_rt_thread_token thread,
                                          uint32_t milliseconds) noexcept {
    // Use the same live-thread and active-invocation check as GetLastError. No process
    // lock or borrowed thread record may be held while suspending the caller.
    uint32_t lastError;
    const auto status = forge_rt_get_last_error(instance, thread, &lastError);

    if (status != FORGE_RT_OK) {
        return status;
    }

    if (milliseconds == 0) {
        return sched_yield() == 0 ? FORGE_RT_OK : FORGE_RT_INTERNAL_ERROR;
    }

    if (milliseconds == UINT32_MAX) {
        for (;;) {
            pause();
        }
    }

    timespec remaining{static_cast<time_t>(milliseconds / 1000),
                       static_cast<long>(milliseconds % 1000) * 1000000L};

    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno != EINTR) {
            return FORGE_RT_INTERNAL_ERROR;
        }
    }

    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_lstrlen_a(forge_rt_instance *instance,
                                              forge_rt_thread_token thread, uint64_t address,
                                              int32_t *outLength,
                                              forge_rt_memory_fault *fault) noexcept {
    if (!outLength || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_memory_fault detail{};
    forge::win64::ServiceInvocation call{instance, thread, detail};
    const auto status = call.resolveCurrent();
    if (status != FORGE_RT_OK) {
        return status;
    }

    const auto string =
        forge::win64::guestBuffer<forge::win64::stringLength, 0>(call, std::tie(address));
    if (string.absent()) {
        *outLength = 0;
        return FORGE_RT_OK;
    }

    // This service's supported range includes the terminating NUL.
    constexpr uint64_t stringLimit = 1024 * 1024;
    uint64_t length;
    const auto scanned = forge::runtime::scanString(string, stringLimit, length);
    if (scanned == FORGE_RT_OK) {
        *outLength = static_cast<int32_t>(length);
    } else if (scanned == FORGE_RT_GUEST_FAULT) {
        if (detail.reason == FORGE_RT_FAULT_OVERFLOW) {
            detail.address = address;
        }

        *fault = detail;
    }

    return scanned;
}
