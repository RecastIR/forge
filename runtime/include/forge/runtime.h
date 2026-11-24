#ifndef FORGE_RUNTIME_H
#define FORGE_RUNTIME_H

#include <stddef.h>
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
#define FORGE_RT_INVALID_INVOCATION UINT32_C(6)
#define FORGE_RT_BUSY UINT32_C(7)
#define FORGE_RT_MAPPING_CONFLICT UINT32_C(8)
#define FORGE_RT_GUEST_FAULT UINT32_C(9)
#define FORGE_RT_INVALID_STATE UINT32_C(10)
#define FORGE_RT_HOST_CONFIGURATION UINT32_C(11)
/* Service status values in this family propagate as an unsupported guest operation. */
#define FORGE_RT_UNSUPPORTED_SERVICE_FLAG UINT32_C(0x10000)
#define FORGE_RT_UNSUPPORTED_CRT_WILDCARDS (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(1))
#define FORGE_RT_UNSUPPORTED_CRT_NEW_MODE (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(2))
#define FORGE_RT_UNSUPPORTED_CALLBACK_RETURN (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(3))
#define FORGE_RT_UNSUPPORTED_INITIALIZER_TARGET (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(4))
#define FORGE_RT_UNSUPPORTED_INITIALIZER_RANGE (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(5))
#define FORGE_RT_UNSUPPORTED_TERMINATION_TARGET (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(7))
#define FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(8))
#define FORGE_RT_UNSUPPORTED_STARTUP_TITLE (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(9))
#define FORGE_RT_UNSUPPORTED_CALLBACK_ARGUMENT (FORGE_RT_UNSUPPORTED_SERVICE_FLAG | UINT32_C(6))

#define FORGE_RT_READ UINT32_C(1)
#define FORGE_RT_WRITE UINT32_C(2)
#define FORGE_RT_EXECUTE UINT32_C(4)

#define FORGE_RT_MARK_UNINITIALIZED UINT8_C(0)
#define FORGE_RT_MARK_CALLBACK_RETURN UINT8_C(0xfd)
/* Offset from the callback entry RSP to the end of its return slot and four home slots. */
#define FORGE_RT_INITIALIZER_HOME_END UINT32_C(40)
#define FORGE_RT_MARK_RETURN UINT8_C(0xfe)
#define FORGE_RT_MARK_CONCRETE UINT8_C(0xff)

#define FORGE_RT_FAULT_OVERFLOW UINT32_C(1)
#define FORGE_RT_FAULT_UNMAPPED UINT32_C(2)
#define FORGE_RT_FAULT_PERMISSION UINT32_C(3)
#define FORGE_RT_FAULT_STACK UINT32_C(4)

typedef uint64_t forge_rt_invocation_token;

/* Generated module descriptors use native C layout. Each row borrows size bytes starting
 * at bytes. The owner provides one initially zero, naturally aligned claim word for each
 * initialized writable backing. All its aliases, including read-only rows, use that word.
 * A row's permissions govern access through its guest address. Immutable backing has a
 * null claim. The owner keeps descriptors, row tables and claim words outside guest-accessible
 * storage. Only the runtime may access the claim word once registration begins. Keep the
 * descriptor and its ordered, disjoint rows immutable and their backing live at stable
 * addresses while borrowed. */
typedef struct forge_rt_image_region {
    uint64_t start;
    uint64_t size;
    const void *bytes;
    uint32_t permissions;
    uint64_t *claim;
} forge_rt_image_region;

typedef struct forge_rt_image {
    uint64_t base;
    uint64_t size;
    const forge_rt_image_region *regions;
    uint64_t count;
} forge_rt_image;

/* The owner lends two disjoint size-byte spans exclusively to this activation until leave.
 * Keep both spans disjoint from image backing, other active stacks and registration metadata
 * across all instances. outerReturn is the guest VA of the eight-byte synthetic return slot.
 * Entries without stack storage pass null. */
typedef struct forge_rt_stack {
    uint64_t base;
    uint64_t size;
    void *bytes;
    uint8_t *marks;
    uint64_t outerReturn;
} forge_rt_stack;

typedef struct forge_rt_memory_fault {
    uint64_t address;
    uint32_t access;
    uint32_t reason;
} forge_rt_memory_fault;

/* Output pointers refer to host storage and are written only on success. Null pointers are
 * invalid arguments. Pass the ABI version expected by the calling code. A successful create
 * transfers ownership of the instance to the caller. The live instance identifies one logical
 * guest process and owns its guest thread records. */
forge_rt_status forge_rt_create(uint32_t expectedVersion,
                                forge_rt_instance **outInstance) FORGE_RT_NOEXCEPT;

/* Before destruction the caller must stop new uses and wait for all runtime calls and lifted
 * invocations using the instance to finish. Destroy releases all remaining guest thread records.
 * The instance pointer expires on successful destruction. */
forge_rt_status forge_rt_destroy(forge_rt_instance *instance) FORGE_RT_NOEXCEPT;

/* Thread operations on a live instance may be called concurrently. A token identifies one guest
 * thread in its owning instance. Native callers treat the token as opaque. Guest-visible Windows
 * handles have a separate representation. Zero, destroyed and foreign tokens report
 * FORGE_RT_INVALID_THREAD. A new thread's last-error value is zero. */
forge_rt_status forge_rt_thread_create(forge_rt_instance *instance,
                                       forge_rt_thread_token *outThread) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_thread_destroy(forge_rt_instance *instance,
                                        forge_rt_thread_token thread) FORGE_RT_NOEXCEPT;

forge_rt_status forge_rt_set_last_error(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint32_t value) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_get_last_error(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint32_t *outValue) FORGE_RT_NOEXCEPT;
/* Wait on the calling host thread. Zero yields and UINT32_MAX waits indefinitely. */
forge_rt_status forge_rt_sleep(forge_rt_instance *instance, forge_rt_thread_token thread,
                               uint32_t milliseconds) FORGE_RT_NOEXCEPT;

/* MSVCRT byte string and memory adapters. All addresses and size_t values are guest
 * 64-bit values. Result storage is written on success, fault storage on a guest fault. */
forge_rt_status forge_rt_msvcrt_strlen(forge_rt_instance *, forge_rt_thread_token, uint64_t address,
                                       uint64_t *result,
                                       forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_strcmp(forge_rt_instance *, forge_rt_thread_token, uint64_t left,
                                       uint64_t right, int32_t *result,
                                       forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_strncmp(forge_rt_instance *, forge_rt_thread_token, uint64_t left,
                                        uint64_t right, uint64_t count, int32_t *result,
                                        forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_msvcrt_memcpy(forge_rt_instance *, forge_rt_thread_token,
                                       uint64_t destination, uint64_t source, uint64_t count,
                                       uint64_t *result,
                                       forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;

/* Current managed process command line in process-owned, read-only guest storage.
 * W returns UTF-16LE. A supports the ASCII subset. Both preserve thread last error. */
forge_rt_status forge_rt_get_command_line_a(forge_rt_instance *instance,
                                            forge_rt_thread_token thread,
                                            uint64_t *outAddress) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_get_command_line_w(forge_rt_instance *instance,
                                            forge_rt_thread_token thread,
                                            uint64_t *outAddress) FORGE_RT_NOEXCEPT;

/* Windows x64 STARTUPINFO output in checked, writable guest memory (104 bytes).
 * Both variants require a managed invocation and preserve the guest thread's last error. */
forge_rt_status forge_rt_get_startup_info_a(forge_rt_instance *instance,
                                            forge_rt_thread_token thread, uint64_t address,
                                            forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_get_startup_info_w(forge_rt_instance *instance,
                                            forge_rt_thread_token thread, uint64_t address,
                                            forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;

/* Console services require the current managed process and a declared console dependency.
 * An active invocation without captured standard handles reports FORGE_RT_INVALID_STATE.
 * Guest handles and addresses are integer bits. Only the native outs are host pointers. A Win32
 * failure delivers the guest failure value with status OK and sets the guest thread's last error.
 */
forge_rt_status forge_rt_get_std_handle(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint32_t selector, uint64_t *outHandle) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_write_file(forge_rt_instance *instance, forge_rt_thread_token thread,
                                    uint64_t handle, uint64_t buffer, uint32_t length,
                                    uint64_t written, uint64_t overlapped, int32_t *outResult,
                                    forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;

/* Completes the current managed guest process with the given Windows DWORD.
 * The generated call site propagates this terminal result to the process runner. */
forge_rt_status forge_rt_exit_process(forge_rt_instance *instance, forge_rt_thread_token thread,
                                      uint32_t exitCode) FORGE_RT_NOEXCEPT;

/* Replace this managed process's top-level exception filter. Both filter values are guest
 * addresses. Zero restores default handling. Writes outPrevious only on success. Registration
 * preserves last error. Guest faults remain terminal. */
forge_rt_status forge_rt_set_unhandled_exception_filter(forge_rt_instance *instance,
                                                        forge_rt_thread_token thread,
                                                        uint64_t guestFilter,
                                                        uint64_t *outPrevious) FORGE_RT_NOEXCEPT;

/* Read a guest NUL-terminated byte string in the current synchronous invocation.
 * A null guest address returns zero after validating the invocation. The initial service
 * scans at most 1 MiB, including the terminator; exhaustion returns RESOURCE_EXHAUSTED.
 * This temporary service limit does not restrict checked copies. outLength changes only
 * on success; fault changes only on GUEST_FAULT (overflow reports the scan's start VA).
 * Both host outputs must be nonnull, disjoint, and outside guest backing and metadata.
 * The input bytes and Windows last error are unchanged on every path. */
forge_rt_status forge_rt_lstrlen_a(forge_rt_instance *instance, forge_rt_thread_token thread,
                                   uint64_t address, int32_t *outLength,
                                   forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
/* A generated descriptor identifies this single-group image while attached. Registration
 * is idempotent while live. Detach drains checked copies in this instance and retires the
 * occurrence on success. An executing image returns BUSY. Writable claims survive retirement.
 * Before releasing descriptor or backing storage, its owner must stop new entries and
 * registrations that use it, wait for outstanding descriptor users, and detach every
 * registration borrowing that storage or destroy each such instance. */
forge_rt_status forge_rt_register_image(forge_rt_instance *instance,
                                        const forge_rt_image *image) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_detach_image(forge_rt_instance *instance,
                                      const forge_rt_image *image) FORGE_RT_NOEXCEPT;

/* Enter atomically registers the image if necessary and publishes this activation.
 * The thread stays live until the matching leave on the entering native thread. */
forge_rt_status forge_rt_enter(forge_rt_instance *instance, forge_rt_thread_token thread,
                               const forge_rt_image *image, const forge_rt_stack *stack,
                               forge_rt_invocation_token *outInvocation) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_leave(forge_rt_instance *instance, forge_rt_thread_token thread,
                               forge_rt_invocation_token invocation) FORGE_RT_NOEXCEPT;
forge_rt_status
forge_rt_current_invocation(forge_rt_instance *instance, forge_rt_thread_token thread,
                            forge_rt_invocation_token *outInvocation) FORGE_RT_NOEXCEPT;

/* Copies validate the live association even for count zero, when buffer may be null.
 * For nonempty copies, buffer is a caller-owned span of capacity usable bytes and must
 * be disjoint from the diagnostic slot. Both host spans must be disjoint from guest
 * backing, stack marks and registered metadata. A stack transfer
 * requires its owning invocation to be innermost on this native thread. Access for
 * validation is READ, WRITE, or both. Only GUEST_FAULT publishes a diagnostic. The data
 * destination and stack marks change only on complete success. Calls leave last error alone. */
forge_rt_status forge_rt_validate_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        forge_rt_invocation_token invocation, uint64_t address,
                                        uint64_t count, uint32_t access,
                                        forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_read_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                                    forge_rt_invocation_token invocation, uint64_t address,
                                    uint64_t count, void *buffer, size_t capacity,
                                    forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
forge_rt_status forge_rt_write_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                                     forge_rt_invocation_token invocation, uint64_t address,
                                     uint64_t count, const void *buffer, size_t capacity,
                                     forge_rt_memory_fault *fault) FORGE_RT_NOEXCEPT;
// NOLINTEND(readability-identifier-naming)

#ifdef __cplusplus
}
#endif
#undef FORGE_RT_NOEXCEPT

#endif
