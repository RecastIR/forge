#include <forge/runtime.h>
#include <stddef.h>

extern const uint32_t RuntimeIrExpectedAbi;
extern int32_t runtimeIrRoundtrip(forge_rt_instance *runtime, forge_rt_thread_token thread,
                                  uint32_t expected);

int main(void) {
    forge_rt_instance *runtime = NULL;

    if (forge_rt_create(RuntimeIrExpectedAbi, &runtime) != FORGE_RT_OK) {
        return 1;
    }

    forge_rt_thread_token thread = 0;
    uint32_t value = 0;
    const uint32_t expected = UINT32_C(0xfedcba98);
    int failed = forge_rt_thread_create(runtime, &thread) != FORGE_RT_OK ||
                 runtimeIrRoundtrip(runtime, thread, expected) != 0 ||
                 forge_rt_get_last_error(runtime, thread, &value) != FORGE_RT_OK ||
                 value != expected;
    forge_rt_status cleanup = forge_rt_destroy(runtime);
    return failed || cleanup != FORGE_RT_OK;
}
