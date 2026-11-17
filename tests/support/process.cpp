#include "../differential/fixtures/arithmetic/operand.h"
#include <forge/process.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <vector>

// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" const forge_rt_artifact *forge_lifted_artifact();

namespace {
    bool failGetter = false;
    using Process = std::unique_ptr<forge_rt_process, decltype(&forge_rt_process_destroy)>;

    void require(bool passed, const char *operation) {
        if (!passed) {
            std::fprintf(stderr, "Process harness failed at %s\n", operation);
            std::abort();
        }
    }

    void report(const forge_rt_process_result &result) {
        switch (result.kind) {
        case FORGE_RT_RETURNED:
            require(result.status == FORGE_RT_OK, "return status");
            std::printf("return %" PRIu64 "\n", result.value);
            break;
        case FORGE_RT_EXECUTION_FAULT:
            require(result.status == FORGE_RT_GUEST_FAULT, "fault status");
            if (result.fault == FORGE_RT_FAULT_MEMORY) {
                std::printf("memory %" PRIu64 " %u %u\n", result.memory.address,
                            result.memory.access, result.memory.reason);
            } else {
                std::printf("guard %u\n", result.fault);
            }

            break;
        case FORGE_RT_RUNTIME_FAILURE:
            std::printf("runtime %u\n", result.status);
            break;
        default:
            require(false, "unexpected outcome");
        }
    }
} // namespace

// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" forge_rt_status probe_process_get(forge_rt_instance *instance,
                                             forge_rt_thread_token thread, uint32_t *out) {
    std::putchar('G');
    return failGetter ? FORGE_RT_RESOURCE_EXHAUSTED
                      : forge_rt_get_last_error(instance, thread, out);
}

int main(int argc, char **argv) {
    require(argc >= 4 && argc % 2 == 0, "arguments");
    failGetter = std::string_view(argv[1]) == "fail-get";
    const auto *artifact = forge_lifted_artifact();
    require(artifact && artifact == forge_lifted_artifact(), "stable artifact");
    std::printf("entry %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", artifact->base, artifact->entryRva,
                artifact->peEntryRva);

    for (uint64_t i = 0; i < artifact->importCount; ++i) {
        std::printf("import %s %s\n", artifact->imports[i].dll, artifact->imports[i].name);
    }

    // All instances register the single linked artifact before any guest writes occur.
    std::vector<Process> processes;
    for (int i = 2; i < argc; i += 2) {
        forge_rt_process *raw = nullptr;
        require(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK, "create");
        processes.emplace_back(raw, forge_rt_process_destroy);
        require(forge_rt_process_register(raw, artifact) == FORGE_RT_OK, "register");
    }

    for (size_t i = 0; i < processes.size(); ++i) {
        int64_t rcx = 0, rdx = 0;
        require(parse_operand(argv[2 + 2 * i], &rcx) && parse_operand(argv[3 + 2 * i], &rdx),
                "input pair");
        const forge_rt_entry_inputs inputs{static_cast<uint64_t>(rcx), static_cast<uint64_t>(rdx)};
        forge_rt_process_result result{};
        require(forge_rt_process_run(processes[i].get(), rcx || rdx ? &inputs : nullptr, &result) ==
                    FORGE_RT_OK,
                "run");
        report(result);
        require(forge_rt_process_close(processes[i].get()) == FORGE_RT_OK, "close");
    }
}
