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

    void failProtectionAllocation(forge_rt_execution *execution) {
        constexpr auto address = uint64_t{0x400000};
        constexpr auto output = FORGE_RT_STACK_BASE + 128;
        int32_t result = -1;
        forge_rt_memory_fault fault{};
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token invocation{};
        REQUIRE(forge_rt_current_invocation(instance, thread, &invocation) == FORGE_RT_OK);
        const uint32_t sentinel = 73;
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, output, 4, &sentinel, 4,
                                     &fault) == FORGE_RT_OK);
        rejectAllocations = true;
        const auto status =
            forge_rt_virtual_protect(instance, thread, address, 1, 2, output, &result, &fault);
        rejectAllocations = false;
        REQUIRE(status == FORGE_RT_RESOURCE_EXHAUSTED && result == -1);
        uint32_t value{};
        REQUIRE(forge_rt_read_guest(instance, thread, invocation, output, 4, &value, 4, &fault) ==
                FORGE_RT_OK);
        REQUIRE(value == sentinel);
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, address, 4, &sentinel, 4,
                                     &fault) == FORGE_RT_OK);
        REQUIRE(forge_rt_virtual_protect(instance, thread, address, 1, 2, output, &result,
                                         &fault) == FORGE_RT_OK);
        REQUIRE(result == 1);
        returnToHost(execution);
    }

    void checkProtectionAllocation() {
        constexpr auto size = FORGE_RT_GUEST_PAGE_SIZE;
        constexpr auto rw = FORGE_RT_READ | FORGE_RT_WRITE;
        const forge_rt_backing backing{size, nullptr, nullptr, 0};
        const forge_rt_region_template row{0x400000, size, 0, 0, rw};
        const forge_rt_section_protection source{0, size, rw};
        const forge_rt_artifact descriptor{FORGE_RT_PROTECTION_ARTIFACT_VERSION,
                                           0x400000,
                                           size,
                                           0,
                                           0,
                                           &backing,
                                           1,
                                           &row,
                                           1,
                                           nullptr,
                                           0,
                                           failProtectionAllocation};
        const forge_rt_protection_artifact artifact{
            {{{{descriptor, "memory.exe"}, nullptr, 0}, nullptr, 0}, 3}, &source, 1};
        forge_rt_process *process = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_register(process, &artifact.pe.functions.crt.named.artifact) ==
                FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process, nullptr, &result) == FORGE_RT_OK &&
                result.value == 42);
        REQUIRE(forge_rt_process_destroy(process) == FORGE_RT_OK);
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
    checkProtectionAllocation();
}
