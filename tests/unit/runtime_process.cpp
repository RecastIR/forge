#include <forge/process.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <latch>
#include <memory>
#include <thread>

namespace {
    void require(bool passed, const char *expression, int line) {
        if (!passed) {
            std::fprintf(stderr, "runtime_process.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)
    using Process = std::unique_ptr<forge_rt_process, decltype(&forge_rt_process_destroy)>;
    constexpr uint64_t base = 0x2100;
    constexpr uint8_t initial = 37;
    constexpr forge_rt_fragment fragment{2, 1, &initial};
    constexpr forge_rt_backing backings[]{{4, nullptr, &fragment, 1}, {1, &initial, nullptr, 0}};
    constexpr forge_rt_region_template regions[]{
        {base, 4, 0, 0, FORGE_RT_READ | FORGE_RT_WRITE},
        {base + 8, 1, 0, 2, FORGE_RT_READ},
        {base + 9, 1, 1, 0, FORGE_RT_READ},
    };

    forge_rt_artifact artifactWith(void (*entry)(forge_rt_execution *)) {
        return {FORGE_RT_ARTIFACT_VERSION,
                base,
                16,
                14,
                15,
                backings,
                std::size(backings),
                regions,
                std::size(regions),
                nullptr,
                0,
                entry};
    }

    Process create() {
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        return {raw, forge_rt_process_destroy};
    }

    void expectState(forge_rt_process *process, forge_rt_process_state expected) {
        forge_rt_process_state state = 0;
        REQUIRE(forge_rt_process_get_state(process, &state) == FORGE_RT_OK && state == expected);
    }

    void rejectRun(forge_rt_process *process, forge_rt_status expected) {
        forge_rt_process_result result{11, 12, 13, {14, 15, 16}, 17};
        REQUIRE(forge_rt_process_run(process, nullptr, &result) == expected);
        REQUIRE(result.kind == 11 && result.status == 12 && result.value == 13 &&
                result.memory.address == 14 && result.memory.access == 15 &&
                result.memory.reason == 16 && result.fault == 17);
    }

    struct RunningProbe {
        forge_rt_process *process;
        std::latch entered{1}, resume{1};
        forge_rt_instance *instance = nullptr;
        forge_rt_thread_token thread = 0;
        forge_rt_invocation_token invocation = 0;
    };

    thread_local RunningProbe *activeProbe = nullptr;

    void checkInitialMemory(forge_rt_execution &execution, forge_rt_invocation_token invocation) {
        auto *instance = execution.instance;
        const auto thread = execution.thread;
        std::array<uint8_t, 4> bytes{};
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_read_guest(instance, thread, invocation, base, 4, bytes.data(), 4,
                                    &fault) == FORGE_RT_OK);
        REQUIRE((bytes == std::array<uint8_t, 4>{0, 0, initial, 0}));
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, base + 8, 1, bytes.data(), 1,
                                     &fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.address == base + 8 && fault.reason == FORGE_RT_FAULT_PERMISSION);
        REQUIRE(forge_rt_read_guest(instance, thread, invocation, FORGE_RT_ENTRY_RSP, 1,
                                    bytes.data(), 1, &fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.address == FORGE_RT_ENTRY_RSP && fault.reason == FORGE_RT_FAULT_STACK);
        REQUIRE(forge_rt_read_guest(instance, thread, invocation, FORGE_RT_ENTRY_RSP + 8, 1,
                                    bytes.data(), 1, &fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.address == FORGE_RT_ENTRY_RSP + 8 && fault.reason == FORGE_RT_FAULT_STACK);

        // A borrowed read-only alias of private bytes must carry its owner's claim.
        forge_rt_instance *other = nullptr;
        REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &other) == FORGE_RT_OK);
        const forge_rt_image contender{base, 16, execution.regions + 1, 1};
        REQUIRE(forge_rt_register_image(other, &contender) == FORGE_RT_MAPPING_CONFLICT);
        REQUIRE(forge_rt_destroy(other) == FORGE_RT_OK);
    }

    void runIsolated(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token invocation = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &invocation) == FORGE_RT_OK);
        checkInitialMemory(*execution, invocation);
        uint32_t lastError = 999;
        REQUIRE(forge_rt_get_last_error(instance, thread, &lastError) == FORGE_RT_OK &&
                lastError == 0);
        const auto tag = static_cast<uint8_t>(execution->rcx);
        REQUIRE(forge_rt_set_last_error(instance, thread, tag) == FORGE_RT_OK);
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, base + 2, 1, &tag, 1, &fault) ==
                FORGE_RT_OK);
        REQUIRE(forge_rt_write_guest(instance, thread, invocation, FORGE_RT_ENTRY_RSP + 8, 1, &tag,
                                     1, &fault) == FORGE_RT_OK);

        if (activeProbe) {
            auto &probe = *activeProbe;
            expectState(probe.process, FORGE_RT_PROCESS_RUNNING);
            rejectRun(probe.process, FORGE_RT_BUSY);
            REQUIRE(forge_rt_process_close(probe.process) == FORGE_RT_BUSY);
            REQUIRE(forge_rt_leave(instance, thread, invocation) == FORGE_RT_INVALID_STATE);
            probe.instance = instance;
            probe.thread = thread;
            probe.invocation = invocation;
            probe.entered.count_down();
            probe.resume.wait();
        }

        for (const auto address : {base + 8, FORGE_RT_ENTRY_RSP + 8}) {
            uint8_t observed = 0;
            REQUIRE(forge_rt_read_guest(instance, thread, invocation, address, 1, &observed, 1,
                                        &fault) == FORGE_RT_OK &&
                    observed == tag);
        }

        REQUIRE(forge_rt_get_last_error(instance, thread, &lastError) == FORGE_RT_OK &&
                lastError == tag);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, execution->rdx, {}, 0};
    }

    void checkIsolation() {
        const auto artifact = artifactWith(runIsolated);
        const auto first = create(), second = create();
        REQUIRE(forge_rt_process_register(first.get(), &artifact) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_register(second.get(), &artifact) == FORGE_RT_OK);
        RunningProbe probe{first.get()};
        std::thread running([&] {
            activeProbe = &probe;
            const forge_rt_entry_inputs inputs{51, UINT64_MAX};
            forge_rt_process_result result{};
            REQUIRE(forge_rt_process_run(first.get(), &inputs, &result) == FORGE_RT_OK);
            REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == UINT64_MAX);
            activeProbe = nullptr;
        });

        probe.entered.wait();
        expectState(first.get(), FORGE_RT_PROCESS_RUNNING);
        rejectRun(first.get(), FORGE_RT_BUSY);
        REQUIRE(forge_rt_process_close(first.get()) == FORGE_RT_BUSY);
        uint8_t observed = 0;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_read_guest(probe.instance, probe.thread, probe.invocation, base, 1,
                                    &observed, 1, &fault) == FORGE_RT_INVALID_INVOCATION);
        forge_rt_process_result result{};
        const forge_rt_entry_inputs inputs{73, 31};
        REQUIRE(forge_rt_process_run(second.get(), &inputs, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == 31);
        REQUIRE(forge_rt_process_close(second.get()) == FORGE_RT_OK);
        probe.resume.count_down();
        running.join();
        expectState(first.get(), FORGE_RT_PROCESS_EXITED);
        rejectRun(first.get(), FORGE_RT_INVALID_STATE);
    }

    void checkRegistration() {
        const auto artifact = artifactWith(runIsolated);
        const auto process = create();
        expectState(process.get(), FORGE_RT_PROCESS_CREATED);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);
        auto invalid = artifact;
        ++invalid.version;
        REQUIRE(forge_rt_process_register(process.get(), &invalid) == FORGE_RT_ABI_MISMATCH);
        invalid = artifact;
        invalid.base = FORGE_RT_STACK_BASE;
        invalid.regions = nullptr;
        invalid.regionCount = 0;
        REQUIRE(forge_rt_process_register(process.get(), &invalid) == FORGE_RT_MAPPING_CONFLICT);
        invalid = artifact;
        auto broken = std::to_array(regions);
        broken.back().permissions = FORGE_RT_READ | FORGE_RT_WRITE;
        invalid.regions = broken.data();
        REQUIRE(forge_rt_process_register(process.get(), &invalid) == FORGE_RT_INVALID_ARGUMENT);
        expectState(process.get(), FORGE_RT_PROCESS_CREATED);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);

        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        const auto other = artifact;
        REQUIRE(forge_rt_process_register(process.get(), &other) == FORGE_RT_MAPPING_CONFLICT);
        expectState(process.get(), FORGE_RT_PROCESS_READY);
        REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
        expectState(process.get(), FORGE_RT_PROCESS_CLOSED);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_INVALID_STATE);
    }

    void checkFaultCleanup() {
        const auto artifact = artifactWith([](forge_rt_execution *execution) {
            if (execution->rcx) {
                execution->result.kind = FORGE_RT_UNSUPPORTED;
            }
        });

        for (uint64_t i = 0; i < 32; ++i) {
            const auto process = create();
            REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
            forge_rt_process_result result{};
            const forge_rt_entry_inputs inputs{i % 2, 0};
            REQUIRE(forge_rt_process_run(process.get(), &inputs, &result) == FORGE_RT_OK);

            if (i % 2 == 0) {
                REQUIRE(result.kind == FORGE_RT_RUNTIME_FAILURE &&
                        result.status == FORGE_RT_INTERNAL_ERROR);
            } else {
                REQUIRE(result.kind == FORGE_RT_UNSUPPORTED);
            }

            expectState(process.get(), FORGE_RT_PROCESS_FAULTED);
            rejectRun(process.get(), FORGE_RT_INVALID_STATE);
            REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
        }
    }
} // namespace

void testRuntimeProcess() {
    checkRegistration();
    checkIsolation();
    checkFaultCleanup();
}
