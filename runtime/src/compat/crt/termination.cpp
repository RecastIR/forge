#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/msvcrt_process.h"
#include "forge/process.h"

#include <utility>

using namespace forge::runtime;

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
        auto &registry = windows.termination;
        *out = 0;

        if (!target) {
            return FORGE_RT_OK;
        }

        if (registry.entries.size() < TerminationRegistry::limit) {
            try {
                registry.entries.push_back({site, target});
                *out = target;
                return FORGE_RT_OK;
            } catch (const std::bad_alloc &) {
                // The failed append leaves every earlier registration intact.
            }
        }

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

        if (registry.phase == TerminationRegistry::Running) {
            return FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY;
        }

        registry.phase = TerminationRegistry::Running;

        // Remove the entry before re-entry. Never retain a reference into a vector
        // across guest execution. The active invocation owns this synchronous borrow.
        size_t remaining = TerminationRegistry::limit;
        while (!registry.entries.empty()) {
            if (!remaining--) {
                return FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY;
            }

            const auto handler = registry.entries.back();
            registry.entries.pop_back();
            const auto previous = std::exchange(callbackInvocation, executingInvocation);
            dispatch(instance->managedExecution, handler.site, handler.target);
            callbackInvocation = previous;

            if (instance->managedExecution->result.kind) {
                return FORGE_RT_OK;
            }
        }

        registry.phase = TerminationRegistry::Completed;
        return FORGE_RT_OK;
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
