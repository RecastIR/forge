#include "../../core/instance.h"
#include "forge/process.h"
#include "forge/service_memory.h"

#include <utility>

using namespace forge::runtime;
using namespace forge::win64;

extern "C" forge_rt_status
forge_rt_msvcrt_initterm(forge_rt_instance *instance, forge_rt_thread_token thread, uint64_t first,
                         uint64_t last, forge_rt_memory_fault *fault,
                         forge_rt_initializer_dispatch dispatch) noexcept {
    if (!fault || !dispatch) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    const auto active = withInstance(
        instance, [thread](auto &owner) { return checkPendingExecution(owner, thread); });

    if (active != FORGE_RT_OK) {
        return active;
    }

    // Process admission pins the view and its mappings for this synchronous native call.
    // Each checked read acquires and releases its own borrow before dispatch.
    auto *execution = instance->managedExecution;
    ServiceInvocation call{instance, thread, *fault, executingInvocation};
    const auto table = guestBuffer<crtInitterm, 0>(call, std::tie(first, last));

    if (!table) {
        return FORGE_RT_UNSUPPORTED_INITIALIZER_RANGE;
    }

    for (uint64_t offset = 0; offset < table->byteSize(); offset += sizeof(uint64_t)) {
        uint64_t target;
        const auto read = table->readScalar(offset, target);

        if (read != FORGE_RT_OK) {
            return read;
        }

        if (!target) {
            continue;
        }

        const auto previous = std::exchange(callbackInvocation, call.token);
        dispatch(execution, target);
        callbackInvocation = previous;

        if (execution->result.kind) {
            break;
        }
    }

    return FORGE_RT_OK;
}
