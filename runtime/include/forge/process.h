#ifndef FORGE_PROCESS_H
#define FORGE_PROCESS_H

#include "forge/runtime.h"

#ifdef __cplusplus
#define FORGE_PROCESS_NOEXCEPT noexcept
extern "C" {
#else
#define FORGE_PROCESS_NOEXCEPT
#endif

// NOLINTBEGIN(readability-identifier-naming)
#define FORGE_RT_ARTIFACT_VERSION UINT32_C(1)
#define FORGE_RT_NAMED_ARTIFACT_VERSION UINT32_C(2)
#define FORGE_RT_CRT_ARTIFACT_VERSION UINT32_C(3)
#define FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION UINT32_C(4)
#define FORGE_RT_PE_ARTIFACT_VERSION UINT32_C(5)
#define FORGE_RT_PROTECTION_ARTIFACT_VERSION UINT32_C(6)
#define FORGE_RT_GUEST_PAGE_SIZE UINT32_C(4096)
#define FORGE_RT_FIXED_PROTECTION UINT32_C(8)
#define FORGE_RT_LOADER_MAY_WRITE UINT32_C(16)
#define FORGE_RT_STACK_BASE UINT64_C(0x70000000)
#define FORGE_RT_STACK_SIZE UINT32_C(4096)
#define FORGE_RT_ENTRY_RSP (FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE - 32 - 8)
#define FORGE_RT_RETURN_MARKER UINT64_C(0x4652474552455401)

typedef struct forge_rt_process forge_rt_process;
typedef uint32_t forge_rt_process_state;
#define FORGE_RT_PROCESS_CREATED UINT32_C(1)
#define FORGE_RT_PROCESS_READY UINT32_C(2)
#define FORGE_RT_PROCESS_RUNNING UINT32_C(3)
#define FORGE_RT_PROCESS_EXITED UINT32_C(4)
#define FORGE_RT_PROCESS_FAULTED UINT32_C(5)
#define FORGE_RT_PROCESS_CLOSED UINT32_C(6)

#define FORGE_RT_RETURNED UINT32_C(1)
#define FORGE_RT_EXECUTION_FAULT UINT32_C(2)
#define FORGE_RT_UNSUPPORTED UINT32_C(3)
#define FORGE_RT_RUNTIME_FAILURE UINT32_C(4)
#define FORGE_RT_EXIT_PROCESS UINT32_C(5)
#define FORGE_RT_FAULT_MEMORY UINT32_C(1)
#define FORGE_RT_FAULT_CONTROL UINT32_C(2)
#define FORGE_RT_FAULT_ABI UINT32_C(3)

/* RETURNED supplies the complete guest RAX in value. EXIT_PROCESS supplies the
 * zero-extended DWORD from a terminal guest service such as ExitProcess, _amsg_exit or abort.
 * EXECUTION_FAULT identifies the fault class. FAULT_MEMORY carries the checked-copy diagnostic.
 * A bounded-call fault carries (call RVA << 32) | table header RVA in value.
 * RUNTIME_FAILURE supplies a nonzero native runtime status. */
typedef struct forge_rt_process_result {
    uint32_t kind;
    forge_rt_status status;
    uint64_t value;
    forge_rt_memory_fault memory;
    uint32_t fault;
} forge_rt_process_result;

typedef struct forge_rt_entry_inputs {
    uint64_t rcx;
    uint64_t rdx;
} forge_rt_entry_inputs;

/* Native compiler/runtime boundary. The entry borrows the view synchronously from run.
 * Its pointers address only this process's storage or immutable artifact storage.
 * Service adapters borrow instance/thread. The process controls their lifecycle.
 * The entry owns initial register/flag setup and publishes its final result before return. */
typedef struct forge_rt_execution {
    forge_rt_instance *instance;
    forge_rt_thread_token thread;
    const forge_rt_image_region *regions;
    uint8_t *stackBytes;
    uint8_t *stackMarks;
    uint64_t rcx;
    uint64_t rdx;
    forge_rt_process_result result;
    uint64_t registers[16];
    uint64_t registerMarks[16];
    uint8_t flags[6];
    uint8_t directionFlag;
} forge_rt_execution;

/* Generated entry slow path for a failed scalar image lookup or stack
 * bounds/outer-return check. Size is in bytes. Stack selects the stack
 * domain (1) or image domain (0). Access uses the checked-copy permission bits
 * or READ_SAVED for a guest load that can copy opaque register-origin marks.
 * Requires the current entry view. Only its tagged result is written. Full
 * accessible coverage across image rows produces UNSUPPORTED with status OK. */
#define FORGE_RT_SCALAR_READ_SAVED UINT32_C(8)
void forge_rt_report_scalar_boundary(forge_rt_execution *execution, uint64_t address, uint32_t size,
                                     uint32_t access, uint32_t stack) FORGE_PROCESS_NOEXCEPT;

typedef struct forge_rt_fragment {
    uint64_t offset;
    uint64_t size;
    const void *bytes;
} forge_rt_fragment;

/* immutableBytes lends size bytes of immutable native storage. A null pointer
 * requests fresh zeroed writable storage with the supplied ordered, disjoint fragments.
 * Fragments contain initialization bytes at this artifact's selected guest load base. */
typedef struct forge_rt_backing {
    uint64_t size;
    const void *immutableBytes;
    const forge_rt_fragment *fragments;
    uint64_t fragmentCount;
} forge_rt_backing;

typedef struct forge_rt_region_template {
    uint64_t start;
    uint64_t size;
    uint64_t backing;
    uint64_t offset;
    uint32_t permissions;
} forge_rt_region_template;

typedef struct forge_rt_import {
    const char *dll;
    const char *name;
} forge_rt_import;

/* An artifact describes one recovered group at a fixed guest load base. Its selected
 * entryRva can differ from the PE header's peEntryRva. The trusted native entry and its
 * layout tables must come from the same translation. All descriptor tables, immutable
 * bytes, names, and native code have stable addresses and outlive every registered use.
 * Imports describe services resolved by the native linker. Include the console imports used by
 * hand-authored entries and their native adapters: registration captures standard streams when
 * the table declares KERNEL32.dll GetStdHandle or WriteFile, or MSVCRT _amsg_exit for
 * a console or unknown subsystem. DLL names are case-insensitive. */
typedef struct forge_rt_artifact {
    uint32_t version;
    uint64_t base;
    uint64_t size;
    uint64_t entryRva;
    uint64_t peEntryRva;
    const forge_rt_backing *backings;
    uint64_t backingCount;
    const forge_rt_region_template *regions;
    uint64_t regionCount;
    const forge_rt_import *imports;
    uint64_t importCount;
    void (*entry)(forge_rt_execution *);
} forge_rt_artifact;

/* Version 2 appends the original PE basename. The prefix is the complete v1 descriptor. */
typedef struct forge_rt_named_artifact {
    forge_rt_artifact artifact;
    const char *executableName;
} forge_rt_named_artifact;

#define FORGE_RT_CRT_ACMDLN UINT32_C(1)
#define FORGE_RT_CRT_INITENV UINT32_C(2)
#define FORGE_RT_CRT_FMODE UINT32_C(3)
#define FORGE_RT_CRT_COMMODE UINT32_C(4)

typedef struct forge_rt_data_import {
    uint32_t slotRva;
    uint32_t kind;
} forge_rt_data_import;

/* Version 3 describes ordered, disjoint 8-byte IAT slots in private image backing.
 * Their backing bytes must also be disjoint and guest write-protected through every
 * mapping. Registration publishes the writable CRT cell's guest VA in each slot. */
typedef struct forge_rt_crt_artifact {
    forge_rt_named_artifact named;
    const forge_rt_data_import *dataImports;
    uint64_t dataImportCount;
} forge_rt_crt_artifact;

typedef struct forge_rt_function_import {
    uint32_t slotRva;
    forge_rt_import target;
} forge_rt_function_import;

/* Version 4 appends the ordinary named function IAT slots observed as guest values.
 * These ordered, disjoint qwords have the same storage protections as data import slots.
 * Each catalogue service has one opaque guest address per process. Those addresses occupy
 * a reserved range with no readable/writable guest bytes and contain no native pointers.
 * Observing a function's identity alone does not declare a call to that service. */
typedef struct forge_rt_function_import_artifact {
    forge_rt_crt_artifact crt;
    const forge_rt_function_import *functionImports;
    uint64_t functionImportCount;
} forge_rt_function_import_artifact;

/* Version 5 appends the source PE32+ optional header's Subsystem, independent of the
 * selected entry and guest-visible header mappings. The complete v4 prefix is required. */
typedef struct forge_rt_pe_artifact {
    forge_rt_function_import_artifact functions;
    uint16_t subsystem;
} forge_rt_pe_artifact;

/* The original section extents and source R/W/X bits are independent of which
 * bytes are materialized. FIXED excludes shared, discardable and noncached data.
 * Only v6 generated entries consult effective protection on every mutable access. */
typedef struct forge_rt_section_protection {
    uint32_t rva, size, attributes;
} forge_rt_section_protection;

typedef struct forge_rt_protection_artifact {
    forge_rt_pe_artifact pe;
    const forge_rt_section_protection *sections;
    uint64_t sectionCount;
} forge_rt_protection_artifact;

/* Borrowed during registration. Arguments exclude argv[0]. A null executablePath defaults to
 * C:\\ plus the original PE basename in a v2 descriptor. Inputs to command-line services are
 * ASCII and the encoded command line is limited to 32767 UTF-16 units including the NUL. */
typedef struct forge_rt_process_startup {
    const char *executablePath;
    size_t argumentCount;
    const char *const *arguments;
    size_t environmentCount;
    const char *const *environment;
} forge_rt_process_startup;

/* Exported by a linked compiler-generated process artifact. */
const forge_rt_artifact *forge_lifted_artifact(void);

forge_rt_status forge_rt_process_create(uint32_t expectedVersion,
                                        forge_rt_process **outProcess) FORGE_PROCESS_NOEXCEPT;
/* One artifact per process. Repeating a successful registration in READY with
 * the identical descriptor succeeds. Failed initial registration leaves CREATED retryable. */
forge_rt_status forge_rt_process_register(forge_rt_process *process,
                                          const forge_rt_artifact *artifact) FORGE_PROCESS_NOEXCEPT;
/* One-shot configuration of a CREATED process. Failure leaves registration retryable.
 * The runtime materializes parameters when the artifact declares a consuming import. */
forge_rt_status forge_rt_process_register_with_startup(
    forge_rt_process *process, const forge_rt_artifact *artifact,
    const forge_rt_process_startup *startup) FORGE_PROCESS_NOEXCEPT;

/* A managed scalar miss may resolve into process-owned memory outside the PE. Protection-enabled
 * v6 entries use this resolver for every nonstack scalar. The native pointer is borrowed by the
 * current guest instruction only. A null result publishes a terminal diagnostic in the execution
 * view. */
void *forge_rt_resolve_process_scalar(forge_rt_execution *execution, uint64_t address,
                                      uint32_t size, uint32_t access) FORGE_PROCESS_NOEXCEPT;
/* Primary guest thread GS base. A zero result publishes a failure on the supplied view. */
uint64_t forge_rt_primary_teb(forge_rt_execution *execution) FORGE_PROCESS_NOEXCEPT;
forge_rt_status forge_rt_process_get_state(forge_rt_process *process,
                                           forge_rt_process_state *outState) FORGE_PROCESS_NOEXCEPT;
/* For READY processes only. Records the host's assurance of safe output signal handling,
 * including SIGPIPE on pipes/devices and SIGXFSZ under a finite file-size limit. Otherwise
 * writes rely on an ignored signal or Darwin F_SETNOSIGPIPE on a pipe/device. Under either
 * policy the host keeps applicable dispositions, descriptor flags and file-size limits safe
 * throughout execution, including across descriptor aliases and blocked writes. */
forge_rt_status
forge_rt_process_allow_host_output_signals(forge_rt_process *process) FORGE_PROCESS_NOEXCEPT;
/* Run enters the selected guest root exactly once. A null inputs pointer sets RCX and
 * RDX to zero. Otherwise run copies the caller's register seeds on admission. OK delivers
 * a tagged result even for execution failure. Captured descriptor duplicates are released
 * before any terminal state becomes visible. Admission errors preserve outResult. The
 * caller supplies live native input/output storage disjoint from each other and guest data. */
forge_rt_status forge_rt_process_run(forge_rt_process *process, const forge_rt_entry_inputs *inputs,
                                     forge_rt_process_result *outResult) FORGE_PROCESS_NOEXCEPT;
/* Close releases the process payload, is idempotent, and returns BUSY during execution.
 * Destroy also closes a live process. Quiesce all other callers before destroying.
 * The handle expires on successful destroy. */
forge_rt_status forge_rt_process_close(forge_rt_process *process) FORGE_PROCESS_NOEXCEPT;
forge_rt_status forge_rt_process_destroy(forge_rt_process *process) FORGE_PROCESS_NOEXCEPT;
// NOLINTEND(readability-identifier-naming)

#ifdef __cplusplus
}
#endif
#undef FORGE_PROCESS_NOEXCEPT

#endif
