#include <forge/runtime.h>
#include <stdbool.h>
#include <stddef.h>

extern const uint32_t RuntimeIrExpectedAbi;
extern forge_rt_status runtimeIrSetLastError(forge_rt_instance *runtime,
                                             const forge_rt_thread_token *thread, uint32_t value);
extern forge_rt_status runtimeIrGetLastError(forge_rt_instance *runtime,
                                             const forge_rt_thread_token *thread, uint32_t *value);

static bool checkLastError(forge_rt_instance *runtime, forge_rt_thread_token thread) {
    const uint32_t expected = UINT32_C(0xfedcba98);
    uint32_t value = 0;

    if (runtimeIrSetLastError(runtime, &thread, expected) != FORGE_RT_OK ||
        runtimeIrGetLastError(runtime, &thread, &value) != FORGE_RT_OK || value != expected) {
        return false;
    }

    // The sole live token and this invalid variant have identical low 32 bits.
    const forge_rt_thread_token invalid = thread ^ UINT64_C(0x8000000000000000);
    uint32_t failedOutput = UINT32_MAX;
    const forge_rt_status setStatus = runtimeIrSetLastError(runtime, &invalid, 0);
    const forge_rt_status getStatus = runtimeIrGetLastError(runtime, &invalid, &failedOutput);

    value = 0;
    return setStatus == FORGE_RT_INVALID_THREAD && getStatus == FORGE_RT_INVALID_THREAD &&
           failedOutput == UINT32_MAX &&
           forge_rt_get_last_error(runtime, thread, &value) == FORGE_RT_OK && value == expected;
}

int main(void) {
    forge_rt_instance *runtime = NULL;

    if (forge_rt_create(RuntimeIrExpectedAbi, &runtime) != FORGE_RT_OK) {
        return 1;
    }

    forge_rt_thread_token thread = 0;
    const bool passed =
        forge_rt_thread_create(runtime, &thread) == FORGE_RT_OK && checkLastError(runtime, thread);
    forge_rt_status cleanup = forge_rt_destroy(runtime);
    return !passed || cleanup != FORGE_RT_OK;
}
