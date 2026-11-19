#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/msvcrt_process.h"
#include "forge/process.h"

using namespace forge::runtime;

bool TerminationRegistry::append(Handler handler) noexcept {
    if (entries.size() >= limit) {
        return false;
    }

    try {
        entries.push_back(handler);
    } catch (const std::bad_alloc &) {
        return false;
    }

    completed = false;
    return true;
}

extern "C" forge_rt_status forge_rt_msvcrt_onexit(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t target,
                                                  uint64_t *out, uint64_t site) noexcept {
    if (!out || !site) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](auto &owner) {
        const auto status = checkPendingExecution(owner, thread);

        if (status != FORGE_RT_OK) {
            return status;
        }

        auto &windows = *owner.windows;
        *out = 0;

        if (!target) {
            return FORGE_RT_OK;
        }

        if (windows.termination.append({site, target})) {
            *out = target;
            return FORGE_RT_OK;
        }

        // ERROR_NOT_ENOUGH_MEMORY and ENOMEM from the legacy Windows DLL.
        owner.threads.at(thread).lastError = 8;
        windows.crtErrno = 12;
        return FORGE_RT_OK;
    });
}

namespace {
    forge_rt_status cleanup(forge_rt_instance *instance, forge_rt_thread_token thread,
                            forge_rt_termination_dispatch dispatch) noexcept {
        if (!dispatch) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        const auto status = withInstance(
            instance, [thread](auto &owner) { return checkPendingExecution(owner, thread); });

        if (status != FORGE_RT_OK) {
            return status;
        }

        auto &registry = instance->windows->termination;

        if (registry.completed) {
            return FORGE_RT_OK;
        }

        if (registry.depth == TerminationRegistry::maxDepth) {
            return FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY;
        }

        if (!registry.depth) {
            registry.dispatched = 0;
        }

        ++registry.depth;
        forge_rt_status outcome = FORGE_RT_OK;

        // Remove the entry before re-entry. A newly registered handler joins the live
        // stack. Nested cleanup shares the outer budget and can consume pending entries.
        while (!registry.entries.empty()) {
            if (registry.dispatched == TerminationRegistry::limit) {
                outcome = FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY;
                break;
            }

            ++registry.dispatched;
            const auto handler = registry.entries.back();
            registry.entries.pop_back();
            dispatchGuestCallback(dispatch, instance->managedExecution, handler.site,
                                  handler.target);

            if (instance->managedExecution->result.kind) {
                break;
            }
        }

        --registry.depth;
        if (!registry.depth) {
            registry.completed = outcome == FORGE_RT_OK && !instance->managedExecution->result.kind;
        }

        return outcome;
    }
} // namespace

extern "C" forge_rt_status forge_rt_msvcrt_cexit(forge_rt_instance *instance,
                                                 forge_rt_thread_token thread,
                                                 forge_rt_termination_dispatch dispatch) noexcept {
    return cleanup(instance, thread, dispatch);
}

extern "C" forge_rt_status forge_rt_msvcrt_exit(forge_rt_instance *instance,
                                                forge_rt_thread_token thread, int32_t code,
                                                forge_rt_termination_dispatch dispatch) noexcept {
    const auto status = cleanup(instance, thread, dispatch);
    if (status != FORGE_RT_OK || instance->managedExecution->result.kind) {
        return status;
    }

    return publishTerminalResult(
        instance, thread, {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, static_cast<uint32_t>(code), {}, 0});
}
