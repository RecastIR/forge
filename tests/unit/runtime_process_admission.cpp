#include "../../runtime/src/compat/process_state.h"
#include "../../runtime/src/core/instance.h"
#include <forge/msvcrt_process.h>
#include <forge/process.h>

#include <algorithm>
#include <array>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
    thread_local bool rejectAllocations = false;
    thread_local const uint8_t *publishedCount = nullptr;

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
        const auto probe =
            forge_rt_virtual_protect(instance, thread, address, 0, 2, address, &result, &fault);
        rejectAllocations = false;
        REQUIRE(probe == FORGE_RT_RESOURCE_EXHAUSTED && result == -1);
        uint32_t old{};
        REQUIRE(forge_rt_virtual_protect(instance, thread, address, 1, 4, output, &result,
                                         &fault) == FORGE_RT_OK);
        REQUIRE(forge_rt_read_guest(instance, thread, invocation, output, 4, &old, 4, &fault) ==
                    FORGE_RT_OK &&
                old == 8);
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, output, 4, &sentinel, 4,
                                     &fault) == FORGE_RT_OK);
        result = -1;
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

    constexpr uint64_t imageBase = 0x400000, page = FORGE_RT_GUEST_PAGE_SIZE;
    constexpr uint64_t sentinel = 0xa5a5a5a5a5a5a5a5;

    void mainArgsOutputs(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token{};
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        const auto read = [&](uint64_t address) {
            uint64_t value{};
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, 8, &value, 8, &fault) ==
                    FORGE_RT_OK);
            return value;
        };
        constexpr auto count = FORGE_RT_STACK_BASE + 160;
        constexpr auto argv = imageBase, env = imageBase + 2 * page;
        std::fill_n(execution->stackBytes + 160, 4, 0xa5);
        int32_t result = 71;
        const auto invoke = [&] {
            return forge_rt_msvcrt_getmainargs(instance, thread, count, argv, env, 0, 0, &result,
                                               &fault);
        };
        const auto heapUsage = instance->windows->heapUsage;
        const auto blocks = instance->heap.size();
        rejectAllocations = true;
        const auto failed = invoke();
        rejectAllocations = false;
        REQUIRE(failed == FORGE_RT_RESOURCE_EXHAUSTED && result == 71);
        REQUIRE(instance->windows->heapUsage == heapUsage && instance->heap.size() == blocks);
        for (unsigned i = 160; i < 164; ++i) {
            REQUIRE(execution->stackBytes[i] == 0xa5 &&
                    execution->stackMarks[i] == FORGE_RT_MARK_UNINITIALIZED);
        }

        for (const auto address : {argv, env}) {
            REQUIRE(read(address) == sentinel);
            int32_t changed{};
            REQUIRE(forge_rt_virtual_protect(instance, thread, address, 1, 4, count + 16, &changed,
                                             &fault) == FORGE_RT_OK &&
                    changed == 1);
            uint32_t old{};
            REQUIRE(forge_rt_read_guest(instance, thread, token, count + 16, 4, &old, 4, &fault) ==
                        FORGE_RT_OK &&
                    old == 8);
        }

        // Reject host allocations after the first guest output. All remaining stores
        // must succeed, including the disjoint environment page.
        publishedCount = execution->stackBytes + 160;
        const auto retried = invoke();
        publishedCount = nullptr;
        REQUIRE(retried == FORGE_RT_OK && result == 0 && execution->stackBytes[160] == 1);
        const auto vector = read(argv);
        REQUIRE(vector && read(vector) && read(vector + 8) == 0);
        REQUIRE(read(env) && read(read(env)) == 0);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, vector) == FORGE_RT_OK);
        REQUIRE(instance->windows->heapUsage == heapUsage && instance->heap.size() == blocks);
        returnToHost(execution);
    }

    template <bool ansi> void startupOutputs(forge_rt_execution *execution) {
        constexpr auto tail = FORGE_RT_STACK_SIZE - 4;
        constexpr auto address = FORGE_RT_STACK_BASE + tail;
        const auto query = ansi ? forge_rt_get_startup_info_a : forge_rt_get_startup_info_w;
        forge_rt_memory_fault fault{};
        // cb lies in the last four stack bytes. All later fields lie in the pristine PE.
        auto *count = execution->stackBytes + tail;
        std::fill_n(count, 4, 0xa5);
        const auto *image = static_cast<const uint8_t *>(execution->regions[0].bytes);
        rejectAllocations = true;
        const auto failed = query(execution->instance, execution->thread, address, &fault);
        rejectAllocations = false;
        REQUIRE(failed == FORGE_RT_RESOURCE_EXHAUSTED);
        REQUIRE(std::all_of(count, count + 4, [](auto byte) { return byte == 0xa5; }));
        REQUIRE(execution->stackMarks[tail] == FORGE_RT_MARK_UNINITIALIZED);
        REQUIRE(std::all_of(image, image + 100, [](auto byte) { return byte == 0xa5; }));

        REQUIRE(query(execution->instance, execution->thread, address, &fault) == FORGE_RT_OK);
        REQUIRE(count[0] == 104 && count[1] == 0);
        REQUIRE(execution->stackMarks[tail] == FORGE_RT_MARK_CONCRETE);
        REQUIRE(image[4 - 4] == 0xa5 && image[68 - 4] == 0xa5 && image[79 - 4] == 0);
        REQUIRE(image[80 - 4] == (ansi ? 0xff : 0xa5));
        returnToHost(execution);
    }

    void checkProtectionAllocation(void (*entry)(forge_rt_execution *), uint64_t base = imageBase) {
        constexpr auto size = 3 * page;
        constexpr auto rw = FORGE_RT_READ | FORGE_RT_WRITE;
        std::array<uint8_t, size> initial;
        initial.fill(0xa5);
        const forge_rt_fragment fragment{0, size, initial.data()};
        const forge_rt_backing backing{size, nullptr, &fragment, 1};
        constexpr forge_rt_import imports[]{{"msvcrt.dll", "__getmainargs"},
                                            {"kernel32.dll", "GetStartupInfoA"},
                                            {"kernel32.dll", "GetStartupInfoW"}};
        const forge_rt_region_template row{base, size, 0, 0, rw};
        const forge_rt_section_protection source{0, size, rw};
        const forge_rt_artifact descriptor{FORGE_RT_PROTECTION_ARTIFACT_VERSION,
                                           base,
                                           size,
                                           0,
                                           0,
                                           &backing,
                                           1,
                                           &row,
                                           1,
                                           imports,
                                           std::size(imports),
                                           entry};
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
    if (!rejectAllocations && (!publishedCount || *publishedCount != 1)) {
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
    checkProtectionAllocation(failProtectionAllocation);
    checkProtectionAllocation(mainArgsOutputs);
    constexpr auto aboveStack = FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE;
    checkProtectionAllocation(startupOutputs<true>, aboveStack);
    checkProtectionAllocation(startupOutputs<false>, aboveStack);
}
