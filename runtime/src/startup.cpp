#include "forge/process.h"

#include <cinttypes>
#include <csignal>
#include <cstdio>

namespace {
    constexpr int failureExit = 125;

    int runtimeFailure(const char *stage, forge_rt_status status) {
        if (status == FORGE_RT_HOST_CONFIGURATION) {
            std::fprintf(stderr, "forge: host standard stream configuration failed stage=%s\n",
                         stage);
            return failureExit;
        }

        std::fprintf(stderr, "forge: runtime failure stage=%s status=%" PRIu32 "\n", stage, status);
        return failureExit;
    }

    int exitStatus(const forge_rt_process_result &result) {
        switch (result.kind) {
        case FORGE_RT_EXIT_PROCESS:
        case FORGE_RT_RETURNED: {
            const auto dword = static_cast<uint32_t>(result.value);
            return static_cast<int>(dword & 0xffU);
        }
        case FORGE_RT_EXECUTION_FAULT:
            switch (result.fault) {
            case FORGE_RT_FAULT_MEMORY:
                std::fprintf(stderr,
                             "forge: guest memory fault address=0x%" PRIx64 " access=%" PRIu32
                             " reason=%" PRIu32 "\n",
                             result.memory.address, result.memory.access, result.memory.reason);
                break;
            case FORGE_RT_FAULT_CONTROL:
                std::fputs("forge: guest control fault\n", stderr);
                break;
            case FORGE_RT_FAULT_ABI:
                std::fputs("forge: guest ABI fault\n", stderr);
                break;
            default:
                return runtimeFailure("result", FORGE_RT_INTERNAL_ERROR);
            }

            return failureExit;
        case FORGE_RT_UNSUPPORTED:
            if (result.status == FORGE_RT_UNSUPPORTED_CRT_WILDCARDS) {
                std::fputs("forge: unsupported MSVCRT __getmainargs wildcard expansion\n", stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_CRT_NEW_MODE) {
                std::fputs("forge: unsupported MSVCRT __getmainargs new-handler mode\n", stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_CALLBACK_RETURN) {
                std::fputs("forge: unsupported guest access to a native callback return slot\n",
                           stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_INITIALIZER_TARGET) {
                std::fputs("forge: unsupported MSVCRT initializer target\n", stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_TERMINATION_TARGET) {
                std::fputs("forge: unproven MSVCRT termination callback for registration site\n",
                           stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_TERMINATION_REENTRY) {
                std::fputs("forge: unsupported recursive MSVCRT cleanup or handler limit\n",
                           stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_INITIALIZER_RANGE) {
                std::fputs("forge: unsupported MSVCRT initializer table range\n", stderr);
            } else if (result.status == FORGE_RT_UNSUPPORTED_CALLBACK_ARGUMENT) {
                std::fputs("forge: unsupported guest access above the callback home space\n",
                           stderr);
            } else {
                std::fputs("forge: unsupported guest execution\n", stderr);
            }
            return failureExit;
        case FORGE_RT_RUNTIME_FAILURE:
            return runtimeFailure("execution", result.status);
        default:
            return runtimeFailure("result", FORGE_RT_INTERNAL_ERROR);
        }
    }
} // namespace

int main(int argc, char **argv, char **environment) {
    // This executable owns its host process. A broken pipe or exceeded file-size limit
    // must reach the Windows service as a write error, including after earlier progress.
    struct sigaction action{};
    action.sa_handler = SIG_IGN;

    if (sigemptyset(&action.sa_mask) != 0 || ::sigaction(SIGPIPE, &action, nullptr) != 0 ||
        ::sigaction(SIGXFSZ, &action, nullptr) != 0) {
        return runtimeFailure("output-signals", FORGE_RT_HOST_CONFIGURATION);
    }

    const auto *artifact = forge_lifted_artifact();

    if (!artifact || (artifact->version != FORGE_RT_ARTIFACT_VERSION &&
                      artifact->version != FORGE_RT_NAMED_ARTIFACT_VERSION &&
                      artifact->version != FORGE_RT_CRT_ARTIFACT_VERSION &&
                      artifact->version != FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION)) {
        return runtimeFailure("artifact", FORGE_RT_ABI_MISMATCH);
    }

    if (!artifact->peEntryRva) {
        std::fputs("forge: runtime failure: PE image has no entry point\n", stderr);
        return failureExit;
    }

    if (artifact->entryRva != artifact->peEntryRva) {
        std::fputs("forge: runtime failure: compiled entry differs from PE entry point\n", stderr);
        return failureExit;
    }

    forge_rt_process *process = nullptr;
    auto status = forge_rt_process_create(FORGE_RT_ABI_VERSION, &process);

    if (status != FORGE_RT_OK) {
        return runtimeFailure("create", status);
    }

    forge_rt_process_result result{};
    const char *stage = "register";
    size_t environmentCount = 0;

    while (environment && environment[environmentCount]) {
        ++environmentCount;
    }

    const forge_rt_process_startup startup{nullptr, static_cast<size_t>(argc > 0 ? argc - 1 : 0),
                                           argc > 0 ? argv + 1 : nullptr, environmentCount,
                                           environment};
    status = forge_rt_process_register_with_startup(process, artifact, &startup);

    if (status == FORGE_RT_OK) {
        stage = "run";
        status = forge_rt_process_run(process, nullptr, &result);
    }

    // All admitted runs are synchronous, including faults. Destroy also closes the process.
    const auto destroyed = forge_rt_process_destroy(process);

    if (status != FORGE_RT_OK) {
        return runtimeFailure(stage, status);
    }

    if (destroyed != FORGE_RT_OK) {
        return runtimeFailure("destroy", destroyed);
    }

    return exitStatus(result);
}
