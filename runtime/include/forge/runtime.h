#ifndef FORGE_RUNTIME_H
#define FORGE_RUNTIME_H

#include <stdint.h>

#ifdef __cplusplus
#define FORGE_RT_NOEXCEPT noexcept
extern "C" {
#else
#define FORGE_RT_NOEXCEPT
#endif

#define FORGE_RT_ABI_VERSION UINT32_C(1)

/* The public C ABI uses the forge_rt_ prefix for its exported names. */
// NOLINTBEGIN(readability-identifier-naming)
typedef struct forge_rt_instance forge_rt_instance;
typedef uint64_t forge_rt_thread_token;
typedef uint32_t forge_rt_status;

#define FORGE_RT_OK UINT32_C(0)
#define FORGE_RT_INVALID_ARGUMENT UINT32_C(1)
#define FORGE_RT_ABI_MISMATCH UINT32_C(2)
#define FORGE_RT_INVALID_THREAD UINT32_C(3)
#define FORGE_RT_RESOURCE_EXHAUSTED UINT32_C(4)
#define FORGE_RT_INTERNAL_ERROR UINT32_C(5)

/* All output parameters are written only on success. Null pointers are invalid arguments.
 * A successful create transfers ownership to the caller. Pass the ABI version expected by the
 * calling code. Each instance owns its guest thread contexts. */
forge_rt_status forge_rt_create(uint32_t expectedVersion,
                                forge_rt_instance **outInstance) FORGE_RT_NOEXCEPT;

/* The caller must finish all calls on the instance before destroying it. Destroy also releases
 * every remaining guest thread. The instance pointer expires on successful destruction. */
forge_rt_status forge_rt_destroy(forge_rt_instance *instance) FORGE_RT_NOEXCEPT;

/* Thread operations on a live instance may be called concurrently. A token identifies one guest
 * thread in its owning instance. Native callers treat the token as opaque. Guest-visible Windows
 * handles belong to a separate future contract. Zero, destroyed and foreign tokens report
 * FORGE_RT_INVALID_THREAD. A new thread's last-error value is zero. */
forge_rt_status forge_rt_thread_create(forge_rt_instance *instance,
                                       forge_rt_thread_token *outThread) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_thread_destroy(forge_rt_instance *instance,
                                        forge_rt_thread_token thread) FORGE_RT_NOEXCEPT;

forge_rt_status forge_rt_set_last_error(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint32_t value) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_get_last_error(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint32_t *outValue) FORGE_RT_NOEXCEPT;
// NOLINTEND(readability-identifier-naming)

#ifdef __cplusplus
}
#endif
#undef FORGE_RT_NOEXCEPT

#endif
