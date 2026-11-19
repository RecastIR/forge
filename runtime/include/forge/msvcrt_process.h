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

/* Compiler-to-CRT linkage. The generated call site supplies its own trusted dispatcher.
 * Guest code supplies only the two table addresses. The borrow expires on return. */
struct forge_rt_execution;
/* Hidden linkage operands come from translated code. Each retained entry stores only
 * the proof identity and guest VA. Cleanup borrows the current artifact dispatcher. */
typedef void (*forge_rt_termination_dispatch)(struct forge_rt_execution *, uint64_t site,
                                              uint64_t target) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_onexit(forge_rt_instance *, forge_rt_thread_token, uint64_t target,
                                       uint64_t *out, uint64_t site) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_cexit(forge_rt_instance *, forge_rt_thread_token,
                                      forge_rt_termination_dispatch) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_exit(forge_rt_instance *, forge_rt_thread_token, int32_t,
                                     forge_rt_termination_dispatch) FORGE_CRT_NOEXCEPT;

typedef void (*forge_rt_initializer_dispatch)(struct forge_rt_execution *,
                                              uint64_t) FORGE_CRT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_initterm(forge_rt_instance *instance, forge_rt_thread_token thread,
                                         uint64_t first, uint64_t last,
                                         forge_rt_memory_fault *fault,
                                         forge_rt_initializer_dispatch dispatch) FORGE_CRT_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef FORGE_CRT_NOEXCEPT

#endif
