#include "runtime_direct.h"

forge_rt_status directSet(uint32_t *cell, forge_rt_thread_token, uint32_t value) {
    *cell = value;
    return FORGE_RT_OK;
}

forge_rt_status directGet(uint32_t *cell, forge_rt_thread_token, uint32_t *value) {
    *value = *cell;
    return FORGE_RT_OK;
}
