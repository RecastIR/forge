#ifndef FORGE_MSVCRT_PROCESS_H
#define FORGE_MSVCRT_PROCESS_H

#include "forge/runtime.h"

#ifdef __cplusplus
#define FORGE_CRT_NOEXCEPT noexcept
extern "C" {
#else
#define FORGE_CRT_NOEXCEPT
#endif

/* The managed process owns its legacy CRT heap. Returned pointers are guest VAs.
 * Resource exhaustion returns NULL and sets the guest thread's errno to ENOMEM. */
forge_rt_status forge_rt_msvcrt_malloc(forge_rt_instance *instance, forge_rt_thread_token thread,
                                       uint64_t size, uint64_t *outAddress) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_calloc(forge_rt_instance *instance, forge_rt_thread_token thread,
                                       uint64_t count, uint64_t size,
                                       uint64_t *outAddress) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_free(forge_rt_instance *instance, forge_rt_thread_token thread,
                                     uint64_t address) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_errno(forge_rt_instance *instance, forge_rt_thread_token thread,
                                      uint64_t *outAddress) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_getmainargs(forge_rt_instance *instance,
                                            forge_rt_thread_token thread, uint64_t argc,
                                            uint64_t argv, uint64_t environment,
                                            int32_t expandWildcards, uint64_t startupInfo,
                                            int32_t *outResult,
                                            forge_rt_memory_fault *fault) FORGE_CRT_NOEXCEPT;

/* Attempt the fatal console diagnostic on the process's captured stderr, then
 * publish guest exit code 255 for the active managed invocation. */
forge_rt_status forge_rt_msvcrt_amsg_exit(forge_rt_instance *instance, forge_rt_thread_token thread,
                                          int32_t errorNumber) FORGE_CRT_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef FORGE_CRT_NOEXCEPT

#endif
