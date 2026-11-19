#include <forge/process.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
    thread_local bool rejectAllocations = false;

    void require(bool passed, const char *expression, int line) {
        if (!passed) {
            std::fprintf(stderr, "runtime_process_admission.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    void returnToHost(forge_rt_execution *execution) {
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkAdmission(bool importFunction) {
        constexpr uint64_t base = 0x1000;
        const forge_rt_backing backing{8, nullptr, nullptr, 0};
        const forge_rt_region_template slot{base, 8, 0, 0, FORGE_RT_READ};
        const forge_rt_function_import binding{0, {"kernel32.dll", "GetLastError"}};
        const forge_rt_function_import_artifact artifact{
            {{{FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION, base, 16, 8, 8, &backing, 1, &slot, 1,
               nullptr, 0, returnToHost},
              "admission.exe"},
             nullptr,
             0},
            &binding,
            importFunction ? 1U : 0U};
        forge_rt_process *process = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);

        // Verify the allocation gate against the linked runtime and retry the same process.
        rejectAllocations = true;
        const auto failed = forge_rt_process_register(process, &artifact.crt.named.artifact);
        rejectAllocations = false;
        REQUIRE(failed == FORGE_RT_RESOURCE_EXHAUSTED);
        REQUIRE(forge_rt_process_register(process, &artifact.crt.named.artifact) == FORGE_RT_OK);

        forge_rt_process_state state = 0;
        REQUIRE(forge_rt_process_get_state(process, &state) == FORGE_RT_OK &&
                state == FORGE_RT_PROCESS_READY);
        forge_rt_process_result result{};
        rejectAllocations = true;
        const auto status = forge_rt_process_run(process, nullptr, &result);
        rejectAllocations = false;
        REQUIRE(status == FORGE_RT_OK);

        if (result.kind != FORGE_RT_RETURNED) {
            std::fprintf(stderr, "function imports %u, result kind %u, runtime status %u\n",
                         importFunction ? 1U : 0U, result.kind, result.status);
        }

        REQUIRE(result.kind == FORGE_RT_RETURNED && result.status == FORGE_RT_OK &&
                result.value == 42);
        REQUIRE(forge_rt_process_get_state(process, &state) == FORGE_RT_OK &&
                state == FORGE_RT_PROCESS_EXITED);
        REQUIRE(forge_rt_process_destroy(process) == FORGE_RT_OK);
    }
} // namespace

void *operator new(std::size_t size) {
    if (!rejectAllocations) {
        if (void *bytes = std::malloc(size ? size : 1)) {
            return bytes;
        }
    }

    throw std::bad_alloc();
}

void operator delete(void *bytes) noexcept { std::free(bytes); }

void operator delete(void *bytes, std::size_t) noexcept { std::free(bytes); }

int main() {
    checkAdmission(false);
    checkAdmission(true);
}
