#ifndef FORGE_TESTS_RUNTIME_DIRECT_H
#define FORGE_TESTS_RUNTIME_DIRECT_H

#include <forge/runtime.h>

// A caller-owned cell gives the baseline the same scalar argument and result widths.
forge_rt_status directSet(uint32_t *cell, forge_rt_thread_token thread, uint32_t value);
forge_rt_status directGet(uint32_t *cell, forge_rt_thread_token thread, uint32_t *value);

#endif
