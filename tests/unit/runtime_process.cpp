#include <forge/msvcrt_process.h>
#include <forge/process.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <latch>
#include <memory>
#include <string>
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
        const auto filter = UINT64_C(0x180000000) + tag;
        uint64_t previous = UINT64_MAX;
        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, thread, filter, &previous) ==
                    FORGE_RT_OK &&
                previous == 0);
        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, thread, 0, nullptr) ==
                FORGE_RT_INVALID_ARGUMENT);
        previous = UINT64_MAX;
        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, 0, 0, &previous) ==
                    FORGE_RT_INVALID_THREAD &&
                previous == UINT64_MAX);

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

        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, thread, 0, &previous) ==
                    FORGE_RT_OK &&
                previous == filter);
        // Leave a nonzero filter installed through teardown.
        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, thread, filter + 1, &previous) ==
                    FORGE_RT_OK &&
                previous == 0);
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
        uint64_t previous = UINT64_MAX;
        REQUIRE(forge_rt_set_unhandled_exception_filter(probe.instance, probe.thread, 0,
                                                        &previous) == FORGE_RT_INVALID_INVOCATION &&
                previous == UINT64_MAX);
        REQUIRE(forge_rt_exit_process(probe.instance, probe.thread, 17) ==
                FORGE_RT_INVALID_INVOCATION);
        REQUIRE(forge_rt_msvcrt_amsg_exit(probe.instance, probe.thread, 31) ==
                FORGE_RT_INVALID_INVOCATION);
        REQUIRE(forge_rt_sleep(probe.instance, probe.thread, UINT32_MAX) ==
                FORGE_RT_INVALID_INVOCATION);
        REQUIRE(forge_rt_read_guest(probe.instance, probe.thread, probe.invocation, base, 1,
                                    &observed, 1, &fault) == FORGE_RT_INVALID_INVOCATION);
        forge_rt_process_result result{};
        const forge_rt_entry_inputs inputs{73, 31};
        REQUIRE(forge_rt_process_run(second.get(), &inputs, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == 31);
        REQUIRE(forge_rt_process_close(second.get()) == FORGE_RT_OK);
        // Reusing this native thread must start with an empty registration.
        const auto fresh = create();
        REQUIRE(forge_rt_process_register(fresh.get(), &artifact) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_run(fresh.get(), &inputs, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == 31);
        probe.resume.count_down();
        running.join();
        expectState(first.get(), FORGE_RT_PROCESS_EXITED);
        rejectRun(first.get(), FORGE_RT_INVALID_STATE);
    }

    void checkUnmanagedExceptionFilter() {
        forge_rt_instance *instance = nullptr;
        forge_rt_thread_token thread = 0;
        forge_rt_invocation_token invocation = 0;
        const forge_rt_image image{base, 16, nullptr, 0};
        uint64_t previous = UINT64_MAX;
        REQUIRE(forge_rt_set_unhandled_exception_filter(nullptr, 0, 0, &previous) ==
                    FORGE_RT_INVALID_ARGUMENT &&
                previous == UINT64_MAX);
        REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &instance) == FORGE_RT_OK);
        REQUIRE(forge_rt_thread_create(instance, &thread) == FORGE_RT_OK);
        REQUIRE(forge_rt_enter(instance, thread, &image, nullptr, &invocation) == FORGE_RT_OK);
        REQUIRE(forge_rt_set_unhandled_exception_filter(instance, thread, 0, &previous) ==
                    FORGE_RT_INVALID_STATE &&
                previous == UINT64_MAX);
        REQUIRE(forge_rt_leave(instance, thread, invocation) == FORGE_RT_OK);
        REQUIRE(forge_rt_destroy(instance) == FORGE_RT_OK);
    }

    void checkExitProcess() {
        constexpr uint32_t exitCode = UINT32_C(0xf123452a);
        const auto artifact = artifactWith([](forge_rt_execution *execution) {
            REQUIRE(forge_rt_exit_process(execution->instance, 0, 1) == FORGE_RT_INVALID_THREAD);
            REQUIRE(forge_rt_exit_process(execution->instance, execution->thread, exitCode) ==
                    FORGE_RT_OK);
            REQUIRE(forge_rt_exit_process(execution->instance, execution->thread, 2) ==
                    FORGE_RT_INVALID_STATE);
            uint64_t previous = UINT64_MAX;
            REQUIRE(forge_rt_set_unhandled_exception_filter(execution->instance, execution->thread,
                                                            0,
                                                            &previous) == FORGE_RT_INVALID_STATE &&
                    previous == UINT64_MAX);
        });
        const auto process = create();
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_EXIT_PROCESS && result.status == FORGE_RT_OK &&
                result.value == exitCode);
        expectState(process.get(), FORGE_RT_PROCESS_EXITED);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);
    }

    constexpr const char *parameterCases[]{R"("C:\Real Guest.exe" "" "two words" a\"b "sp ace\\")",
                                           R"(Z:\second.exe mutable)"};

    void inspectParameters(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        const auto teb = forge_rt_primary_teb(execution);
        REQUIRE(teb != 0 && teb != FORGE_RT_STACK_BASE);
        // This test's PE occupies the initial parameter base. Inspect its relocated thread anchor.
        REQUIRE(teb >= UINT64_C(0x20000));
        forge_rt_memory_fault fault{};
        uint64_t actual = 0;
        REQUIRE(forge_rt_read_guest(instance, thread, token, teb + 0x30, 8, &actual, 8, &fault) ==
                    FORGE_RT_OK &&
                actual == teb);
        REQUIRE(forge_rt_read_guest(instance, thread, token, teb + 8, 8, &actual, 8, &fault) ==
                    FORGE_RT_OK &&
                actual == FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE);
        const uint64_t tag = 19;
        REQUIRE(forge_rt_write_guest(instance, thread, token, teb + 0x30, 8, &tag, 8, &fault) ==
                FORGE_RT_OK);
        REQUIRE(forge_rt_primary_teb(execution) == teb);
        REQUIRE(forge_rt_read_guest(instance, thread, token, teb + 0x30, 8, &actual, 8, &fault) ==
                    FORGE_RT_OK &&
                actual == tag);
        REQUIRE(forge_rt_read_guest(instance, thread, token, teb + 0x20, 8, &actual, 8, &fault) ==
                    FORGE_RT_GUEST_FAULT &&
                fault.reason == FORGE_RT_FAULT_UNMAPPED);

        uint64_t narrow = 0, wide = 0;
        REQUIRE(forge_rt_set_last_error(instance, thread, 94) == FORGE_RT_OK);
        REQUIRE(forge_rt_get_command_line_a(instance, thread, &narrow) == FORGE_RT_OK);
        REQUIRE(forge_rt_get_command_line_w(instance, thread, &wide) == FORGE_RT_OK);
        uint32_t lastError = 0;
        REQUIRE(forge_rt_get_last_error(instance, thread, &lastError) == FORGE_RT_OK &&
                lastError == 94);
        const std::string expected(parameterCases[execution->rcx]);
        std::string bytes(expected.size() + 1, '?');
        REQUIRE(forge_rt_read_guest(instance, thread, token, narrow, bytes.size(), bytes.data(),
                                    bytes.size(), &fault) == FORGE_RT_OK);
        REQUIRE(bytes == expected + '\0');
        std::u16string chars(bytes.size(), u'?');
        REQUIRE(forge_rt_read_guest(instance, thread, token, wide, chars.size() * 2, chars.data(),
                                    chars.size() * 2, &fault) == FORGE_RT_OK);
        REQUIRE(chars == std::u16string(bytes.begin(), bytes.end()));
        REQUIRE(forge_rt_write_guest(instance, thread, token, narrow, 1, &tag, 1, &fault) ==
                    FORGE_RT_GUEST_FAULT &&
                fault.reason == FORGE_RT_FAULT_PERMISSION);
        REQUIRE(forge_rt_get_command_line_a(instance, thread, &actual) == FORGE_RT_OK &&
                actual == narrow);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, actual, {}, 0};
    }

    void checkParameters() {
        const forge_rt_import bindings[]{{"Kernel32.DLL", "GetCommandLineA"},
                                         {"KERNEL32.dll", "GetCommandLineW"}};
        const forge_rt_named_artifact descriptor{{FORGE_RT_NAMED_ARTIFACT_VERSION, 0x10000, 0x1000,
                                                  16, 16, nullptr, 0, nullptr, 0, bindings, 2,
                                                  inspectParameters},
                                                 "Real Guest.exe"};
        auto first = create(), second = create();
        const char *args[]{"", "two words", "a\"b", "sp ace\\"};
        forge_rt_process_startup invalid{nullptr, std::size(args), nullptr, 0, nullptr};
        REQUIRE(forge_rt_process_register_with_startup(first.get(), &descriptor.artifact,
                                                       &invalid) == FORGE_RT_INVALID_ARGUMENT);
        invalid = {"bad\"name.exe", 0, nullptr, 0, nullptr};
        REQUIRE(forge_rt_process_register_with_startup(first.get(), &descriptor.artifact,
                                                       &invalid) == FORGE_RT_INVALID_ARGUMENT);
        expectState(first.get(), FORGE_RT_PROCESS_CREATED);
        const forge_rt_process_startup startup{nullptr, std::size(args), args, 0, nullptr};
        REQUIRE(forge_rt_process_register_with_startup(first.get(), &descriptor.artifact,
                                                       &startup) == FORGE_RT_OK);
        char owned[] = "mutable";
        const char *overrideArgs[]{owned};
        const forge_rt_process_startup other{R"(Z:\second.exe)", 1, overrideArgs, 0, nullptr};
        REQUIRE(forge_rt_process_register_with_startup(second.get(), &descriptor.artifact,
                                                       &other) == FORGE_RT_OK);
        owned[0] = 'X';
        forge_rt_process_result result{};
        const forge_rt_entry_inputs tag{1, 0};
        REQUIRE(forge_rt_process_run(first.get(), nullptr, &result) == FORGE_RT_OK &&
                result.kind == FORGE_RT_RETURNED);
        REQUIRE(forge_rt_process_run(second.get(), &tag, &result) == FORGE_RT_OK &&
                result.kind == FORGE_RT_RETURNED);
    }

    void inspectHeap(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        uint64_t block = 0, zero = 0, errnoAddress = 0;
        REQUIRE(forge_rt_msvcrt_calloc(instance, thread, 2, 4, &block) == FORGE_RT_OK && block &&
                block % 16 == 0);
        REQUIRE(forge_rt_msvcrt_malloc(instance, thread, 0, &zero) == FORGE_RT_OK && zero &&
                zero != block && zero % 16 == 0);
        REQUIRE(forge_rt_msvcrt_errno(instance, thread, &errnoAddress) == FORGE_RT_OK);
        uint32_t error = UINT32_MAX;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_read_guest(instance, thread, token, errnoAddress, 4, &error, 4, &fault) ==
                    FORGE_RT_OK &&
                error == 0);
        uint64_t bytes = UINT64_MAX;
        REQUIRE(forge_rt_read_guest(instance, thread, token, block, 8, &bytes, 8, &fault) ==
                    FORGE_RT_OK &&
                bytes == 0);
        auto *native = forge_rt_resolve_process_scalar(execution, block, 8, FORGE_RT_WRITE);
        REQUIRE(native != nullptr);
        std::memcpy(native, &zero, 8);
        REQUIRE(forge_rt_read_guest(instance, thread, token, block, 8, &bytes, 8, &fault) ==
                    FORGE_RT_OK &&
                bytes == zero);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, block + 1) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, block) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, block) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_read_guest(instance, thread, token, block, 1, &bytes, 1, &fault) ==
                    FORGE_RT_GUEST_FAULT &&
                fault.reason == FORGE_RT_FAULT_UNMAPPED);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, 0) == FORGE_RT_OK);
        REQUIRE(forge_rt_set_last_error(instance, thread, 4) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_calloc(instance, thread, UINT64_MAX, 2, &block) == FORGE_RT_OK &&
                block == 0);
        REQUIRE(forge_rt_read_guest(instance, thread, token, errnoAddress, 4, &error, 4, &fault) ==
                    FORGE_RT_OK &&
                error == 12);
        REQUIRE(forge_rt_get_last_error(instance, thread, &error) == FORGE_RT_OK && error == 4);
        REQUIRE(forge_rt_msvcrt_malloc(instance, thread, UINT64_MAX, &block) == FORGE_RT_OK &&
                block == 0);
        // Leave the zero-size allocation to process destruction.
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkHeap() {
        const auto descriptor = artifactWith(inspectHeap);
        const auto first = create(), second = create();

        for (const auto *owner : {&first, &second}) {
            REQUIRE(forge_rt_process_register(owner->get(), &descriptor) == FORGE_RT_OK);
            forge_rt_process_result result{};
            REQUIRE(forge_rt_process_run(owner->get(), nullptr, &result) == FORGE_RT_OK &&
                    result.kind == FORGE_RT_RETURNED && result.value == 42);
        }
    }

    void checkHeapBudgetRefund() {
        const auto artifact = artifactWith([](forge_rt_execution *execution) {
            auto *instance = execution->instance;
            const auto thread = execution->thread;
            const auto allocate = [&](uint64_t size) {
                uint64_t address = UINT64_MAX;
                REQUIRE(forge_rt_msvcrt_malloc(instance, thread, size, &address) == FORGE_RT_OK);
                return address;
            };
            constexpr auto budget = uint64_t{64} * 1024 * 1024;
            constexpr uint64_t charge = 256;
            constexpr uint64_t anchorSize = 1;
            constexpr uint64_t remainingPayload = budget - (anchorSize + charge) - charge;
            const auto anchor = allocate(anchorSize);
            const auto probe = allocate(17);
            REQUIRE(anchor && probe && anchor != probe);

            // The live anchor keeps both boundary requests below the per-allocation maximum.
            REQUIRE(forge_rt_msvcrt_free(instance, thread, probe) == FORGE_RT_OK);
            REQUIRE(allocate(remainingPayload + 1) == 0);
            uint64_t errnoAddress = 0;
            forge_rt_invocation_token token = 0;
            forge_rt_memory_fault fault{};
            int32_t error = 0;
            REQUIRE(forge_rt_msvcrt_errno(instance, thread, &errnoAddress) == FORGE_RT_OK);
            REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
            REQUIRE(forge_rt_read_guest(instance, thread, token, errnoAddress, sizeof(error),
                                        &error, sizeof(error), &fault) == FORGE_RT_OK &&
                    error == 12);

            const auto block = allocate(remainingPayload);
            REQUIRE(block != 0);
            REQUIRE(forge_rt_msvcrt_free(instance, thread, block) == FORGE_RT_OK);
            REQUIRE(forge_rt_msvcrt_free(instance, thread, anchor) == FORGE_RT_OK);
            execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 0, {}, 0};
        });
        const auto process = create();
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK &&
                result.kind == FORGE_RT_RETURNED);
    }

    void inspectCrtArguments(forge_rt_execution *execution) {
        const auto thread = execution->thread;
        auto *instance = execution->instance;
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        forge_rt_memory_fault fault{};
        const auto read = [&](uint64_t address, auto &value) {
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, sizeof(value), &value,
                                        sizeof(value), &fault) == FORGE_RT_OK);
        };
        const auto pointer = [&](uint64_t address) {
            uint64_t value = 0;
            read(address, value);
            return value;
        };
        const auto string = [&](uint64_t address, std::string expected) {
            expected.push_back('\0');
            std::string bytes(expected.size(), '?');
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, bytes.size(),
                                        bytes.data(), bytes.size(), &fault) == FORGE_RT_OK &&
                    bytes == expected);
        };
        constexpr uint64_t out = FORGE_RT_ENTRY_RSP - 64;
        int32_t result = 17;
        const int32_t newMode = 1;
        REQUIRE(forge_rt_write_guest(instance, thread, token, out + 32, 4, &newMode, 4, &fault) ==
                FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_getmainargs(instance, thread, out, out + 8, out + 16, 0, out + 32,
                                            &result, &fault) == FORGE_RT_UNSUPPORTED_CRT_NEW_MODE);
        REQUIRE(forge_rt_msvcrt_getmainargs(instance, thread, out, out + 8, out + 16, 1, 0, &result,
                                            &fault) == FORGE_RT_UNSUPPORTED_CRT_WILDCARDS);
        REQUIRE(forge_rt_msvcrt_getmainargs(instance, thread, out, out + 8, 1, 0, 0, &result,
                                            &fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(result == 17 && fault.address == 1);
        uint32_t count = 0;
        REQUIRE(forge_rt_read_guest(instance, thread, token, out, 4, &count, 4, &fault) ==
                FORGE_RT_GUEST_FAULT);
        REQUIRE(forge_rt_msvcrt_getmainargs(instance, thread, out, out + 8, out + 16, 0, 0, &result,
                                            &fault) == FORGE_RT_OK &&
                result == 0);
        read(out, count);
        REQUIRE(count == 5);
        const uint64_t argv = pointer(out + 8);
        string(pointer(argv), R"(C:\Real Guest.exe)");
        string(pointer(argv + 8), "");
        string(pointer(argv + 16), "two words");
        string(pointer(argv + 24), "a\"b");
        string(pointer(argv + 32), "sp ace\\");
        REQUIRE(pointer(argv + 40) == 0);
        const uint64_t env = pointer(out + 16);
        string(pointer(env), "FORGE=a b");
        REQUIRE(pointer(env + 8) == 0);
        const auto cmd = pointer(pointer(base));
        string(cmd, parameterCases[0]);
        const auto initialEnv = pointer(pointer(base + 8));
        REQUIRE(initialEnv == env);
        // The export is writable. The next __getmainargs reads the changed environment
        // pointer and reconstructs independent argument strings from the initial command.
        const uint64_t changedEnv = env + 8;
        REQUIRE(forge_rt_write_guest(instance, thread, token, pointer(base + 8), 8, &changedEnv, 8,
                                     &fault) == FORGE_RT_OK);
        const char changed = '!';
        REQUIRE(forge_rt_write_guest(instance, thread, token, pointer(argv + 16), 1, &changed, 1,
                                     &fault) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_getmainargs(instance, thread, out, out + 8, out + 16, 0, 0, &result,
                                            &fault) == FORGE_RT_OK &&
                result == 0);
        REQUIRE(pointer(out + 16) == changedEnv);
        const uint64_t otherArgs = pointer(out + 8);
        REQUIRE(otherArgs != argv && pointer(otherArgs + 16) != pointer(argv + 16));
        string(pointer(otherArgs + 16), "two words");
        string(pointer(argv + 16), "!wo words");
        uint32_t mode = 0;
        read(pointer(base + 16), mode);
        REQUIRE(mode == 0x4000);
        read(pointer(base + 24), mode);
        REQUIRE(mode == 0);
        REQUIRE(forge_rt_write_guest(instance, thread, token, base, 4, &mode, 4, &fault) ==
                    FORGE_RT_GUEST_FAULT &&
                fault.reason == FORGE_RT_FAULT_PERMISSION);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkCrtArguments() {
        const forge_rt_backing storage{36, nullptr, nullptr, 0};
        forge_rt_region_template rows[]{{base, 16, 0, 0, FORGE_RT_READ},
                                        {base + 16, 16, 0, 16, FORGE_RT_READ},
                                        {base + 40, 1, 0, 31, FORGE_RT_READ},
                                        {base + 48, 4, 0, 32, FORGE_RT_READ | FORGE_RT_WRITE}};
        const forge_rt_import getMainArgs{"msvcrt.dll", "__getmainargs"};
        const forge_rt_data_import imports[]{{0, FORGE_RT_CRT_ACMDLN},
                                             {8, FORGE_RT_CRT_INITENV},
                                             {16, FORGE_RT_CRT_FMODE},
                                             {24, FORGE_RT_CRT_COMMODE}};
        forge_rt_crt_artifact descriptor{
            {{FORGE_RT_CRT_ARTIFACT_VERSION, base, 64, 32, 32, &storage, 1, rows, std::size(rows),
              &getMainArgs, 1, inspectCrtArguments},
             "Real Guest.exe"},
            imports,
            4};
        const auto process = create();
        const char *args[]{"", "two words", "a\"b", "sp ace\\"};
        const char *env[]{"FORGE=a b"};
        const forge_rt_process_startup startup{nullptr, std::size(args), args, std::size(env), env};
        const auto reject = [&] {
            REQUIRE(forge_rt_process_register_with_startup(process.get(),
                                                           &descriptor.named.artifact,
                                                           &startup) == FORGE_RT_INVALID_ARGUMENT);
            expectState(process.get(), FORGE_RT_PROCESS_CREATED);
        };
        const forge_rt_data_import invalid[]{{0, FORGE_RT_CRT_ACMDLN}, {4, FORGE_RT_CRT_COMMODE}};
        descriptor.dataImports = invalid;
        descriptor.dataImportCount = 2;
        reject();
        descriptor.dataImports = imports;
        descriptor.dataImportCount = 4;
        rows[1].offset = 0;
        reject();
        rows[1].offset = 12;
        reject();
        rows[1].offset = 16;
        rows[1].permissions |= FORGE_RT_WRITE;
        reject();
        rows[1].permissions = FORGE_RT_READ;
        rows[2].permissions |= FORGE_RT_WRITE;
        reject();
        rows[2].permissions = FORGE_RT_READ;
        REQUIRE(forge_rt_process_register_with_startup(process.get(), &descriptor.named.artifact,
                                                       &startup) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK &&
                result.kind == FORGE_RT_RETURNED);
    }

    void inspectFunctionImports(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);

        std::array<uint64_t, 4> pointers{};
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_read_guest(instance, thread, token, base, sizeof(pointers),
                                    pointers.data(), sizeof(pointers), &fault) == FORGE_RT_OK);
        REQUIRE(pointers[0] && pointers[0] == pointers[1]);
        REQUIRE(pointers[2] && pointers[2] != pointers[0]);
        REQUIRE(pointers[3] && pointers[3] != pointers[0] && pointers[3] != pointers[2]);
        uint64_t alias = 0;
        REQUIRE(forge_rt_read_guest(instance, thread, token, base + sizeof(pointers), sizeof(alias),
                                    &alias, sizeof(alias), &fault) == FORGE_RT_OK &&
                alias == pointers[1]);

        uint64_t allocation = 0;
        REQUIRE(forge_rt_msvcrt_malloc(instance, thread, 4096, &allocation) == FORGE_RT_OK &&
                allocation);
        uint8_t byte = 0;
        for (const auto address : {pointers[0], pointers[2]}) {
            REQUIRE(address < allocation || address - allocation >= 4096);
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, 1, &byte, 1, &fault) ==
                    FORGE_RT_GUEST_FAULT);
            REQUIRE(fault.reason == FORGE_RT_FAULT_UNMAPPED && fault.address == address);
        }
        REQUIRE(forge_rt_msvcrt_free(instance, thread, allocation) == FORGE_RT_OK);

        REQUIRE(forge_rt_write_guest(instance, thread, token, base, 1, &byte, 1, &fault) ==
                FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.reason == FORGE_RT_FAULT_PERMISSION);
        REQUIRE(forge_rt_read_guest(instance, thread, token, pointers[3], 1, &byte, 1, &fault) ==
                FORGE_RT_OK);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkFunctionImports() {
        const forge_rt_backing storage{32, nullptr, nullptr, 0};
        forge_rt_region_template rows[]{{base, 32, 0, 0, FORGE_RT_READ},
                                        {base + 32, 8, 0, 8, FORGE_RT_READ}};
        forge_rt_function_import functions[]{{0, {"kernel32.dll", "GetLastError"}},
                                             {8, {"KERNEL32.DLL", "GetLastError"}},
                                             {16, {"KERNEL32.dll", "GetCommandLineA"}}};
        const forge_rt_data_import data{24, FORGE_RT_CRT_FMODE};
        const forge_rt_function_import_artifact descriptor{
            {{{FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION, base, 64, 40, 40, &storage, 1, rows,
               std::size(rows), nullptr, 0, inspectFunctionImports},
              "functions.exe"},
             &data,
             1},
            functions,
            std::size(functions)};
        // Merely reading the GetCommandLineA address does not consume process arguments.
        const char *arguments[] = {"café"};
        const forge_rt_process_startup startup{nullptr, 1, arguments, 0, nullptr};
        auto process = create();
        const auto registerArtifact = [&] {
            return forge_rt_process_register_with_startup(process.get(),
                                                          &descriptor.crt.named.artifact, &startup);
        };
        const auto reject = [&] {
            REQUIRE(registerArtifact() == FORGE_RT_INVALID_ARGUMENT);
            expectState(process.get(), FORGE_RT_PROCESS_CREATED);
        };

        functions[2].target.name = "getcommandlinea";
        reject();
        functions[2].target.name = "GetCommandLineA";
        functions[2].slotRva = 24;
        reject();
        functions[2].slotRva = 32;
        reject();
        functions[2].slotRva = 16;
        rows[1].permissions |= FORGE_RT_WRITE;
        reject();
        rows[1].permissions = FORGE_RT_READ;

        for (unsigned i = 0; i < 2; ++i) {
            REQUIRE(registerArtifact() == FORGE_RT_OK);
            forge_rt_process_result result{};
            REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK &&
                    result.kind == FORGE_RT_RETURNED && result.value == 42);
            process = create();
        }
    }

    void checkCrtInputConsumers() {
        const forge_rt_backing storage{8, nullptr, nullptr, 0};
        const forge_rt_region_template slot{base, 8, 0, 0, FORGE_RT_READ};
        forge_rt_data_import binding{0, FORGE_RT_CRT_FMODE};
        const auto dataOnlyEntry = [](forge_rt_execution *execution) {
            int32_t result = 17;
            forge_rt_memory_fault fault{};
            REQUIRE(forge_rt_msvcrt_getmainargs(execution->instance, execution->thread, 0, 0, 0, 0,
                                                0, &result, &fault) == FORGE_RT_INVALID_STATE);
            REQUIRE(result == 17);
            execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
        };
        forge_rt_crt_artifact descriptor{{{FORGE_RT_CRT_ARTIFACT_VERSION, base, 16, 8, 8, &storage,
                                           1, &slot, 1, nullptr, 0, dataOnlyEntry},
                                          "input.exe"},
                                         &binding,
                                         1};
        const char *unicodeArg[]{"café"};
        const char *unicodeEnv[]{"LANG_VALUE=café"};
        forge_rt_process_startup startup{nullptr, 1, unicodeArg, 1, unicodeEnv};
        const auto check = [&](forge_rt_status expected) {
            const auto process = create();
            REQUIRE(forge_rt_process_register_with_startup(
                        process.get(), &descriptor.named.artifact, &startup) == expected);
            expectState(process.get(), expected == FORGE_RT_OK ? FORGE_RT_PROCESS_READY
                                                               : FORGE_RT_PROCESS_CREATED);

            if (expected == FORGE_RT_OK && !descriptor.named.artifact.importCount) {
                forge_rt_process_result result{};
                REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK &&
                        result.kind == FORGE_RT_RETURNED && result.value == 42);
            }
        };

        check(FORGE_RT_OK);
        binding.kind = FORGE_RT_CRT_COMMODE;
        check(FORGE_RT_OK);
        binding.kind = FORGE_RT_CRT_ACMDLN;
        check(FORGE_RT_INVALID_ARGUMENT);
        startup.argumentCount = 0;
        check(FORGE_RT_OK);
        binding.kind = FORGE_RT_CRT_INITENV;
        check(FORGE_RT_INVALID_ARGUMENT);
        startup.argumentCount = 1;
        startup.environmentCount = 0;
        check(FORGE_RT_OK);
        descriptor.dataImportCount = 0;
        startup.environmentCount = 1;
        check(FORGE_RT_OK);

        const forge_rt_import getCommand{"Kernel32.DLL", "GetCommandLineA"};
        descriptor.named.artifact.imports = &getCommand;
        descriptor.named.artifact.importCount = 1;
        check(FORGE_RT_INVALID_ARGUMENT);
        startup.argumentCount = 0;
        check(FORGE_RT_OK);

        const forge_rt_import getMainArgs{"MSVCRT.DLL", "__getmainargs"};
        descriptor.named.artifact.imports = &getMainArgs;
        startup.argumentCount = 1;
        startup.environmentCount = 0;
        check(FORGE_RT_INVALID_ARGUMENT);
        startup.argumentCount = 0;
        startup.environmentCount = 1;
        check(FORGE_RT_INVALID_ARGUMENT);
        startup.environmentCount = 0;
        check(FORGE_RT_OK);
    }

    void checkRegistration() {
        const auto artifact = artifactWith(runIsolated);
        const auto process = create();
        expectState(process.get(), FORGE_RT_PROCESS_CREATED);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);
        auto invalid = artifact;
        invalid.version = UINT32_MAX;
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

    void checkCloseCreated() {
        const auto process = create();
        REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
        expectState(process.get(), FORGE_RT_PROCESS_CLOSED);
        REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_allow_host_output_signals(process.get()) ==
                FORGE_RT_INVALID_STATE);
        rejectRun(process.get(), FORGE_RT_INVALID_STATE);
    }

    void checkInvalidExitCode() {
        const auto artifact = artifactWith([](forge_rt_execution *execution) {
            execution->result = {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, UINT64_C(0x100000000), {}, 0};
        });
        const auto process = create();
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_RUNTIME_FAILURE &&
                result.status == FORGE_RT_INTERNAL_ERROR);
        expectState(process.get(), FORGE_RT_PROCESS_FAULTED);
    }

    void checkScalarBoundaries() {
        const auto artifact = artifactWith([](forge_rt_execution *execution) {
            constexpr auto address = FORGE_RT_ENTRY_RSP - 1;
            execution->stackMarks[address - FORGE_RT_STACK_BASE] = 1; // Opaque saved-register byte.
            auto &result = execution->result;

            forge_rt_report_scalar_boundary(execution, address, 2, FORGE_RT_READ, 1);
            REQUIRE(result.kind == FORGE_RT_EXECUTION_FAULT && result.memory.address == address);
            forge_rt_report_scalar_boundary(execution, address, 2, FORGE_RT_SCALAR_READ_SAVED, 1);
            REQUIRE(result.kind == FORGE_RT_EXECUTION_FAULT &&
                    result.memory.address == FORGE_RT_ENTRY_RSP &&
                    result.memory.access == FORGE_RT_READ &&
                    result.memory.reason == FORGE_RT_FAULT_STACK);

            forge_rt_invocation_token invocation = 0;
            forge_rt_memory_fault fault{};
            REQUIRE(forge_rt_current_invocation(execution->instance, execution->thread,
                                                &invocation) == FORGE_RT_OK);
            REQUIRE(forge_rt_validate_guest(execution->instance, execution->thread, invocation,
                                            address, 2, FORGE_RT_READ,
                                            &fault) == FORGE_RT_GUEST_FAULT);
            REQUIRE(fault.address == address && fault.reason == FORGE_RT_FAULT_STACK);

            forge_rt_report_scalar_boundary(execution, base + 8, 2, FORGE_RT_READ, 0);
            REQUIRE(result.kind == FORGE_RT_UNSUPPORTED);

            // A stale thread must remain a runtime failure even on a failed guest guard.
            auto stale = *execution;
            stale.thread = 0;
            forge_rt_report_scalar_boundary(&stale, address, 2, FORGE_RT_READ, 1);
            REQUIRE(stale.result.kind == FORGE_RT_RUNTIME_FAILURE &&
                    stale.result.status == FORGE_RT_INVALID_THREAD);
        });
        const auto process = create();
        REQUIRE(forge_rt_process_register(process.get(), &artifact) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process.get(), nullptr, &result) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_UNSUPPORTED);
        expectState(process.get(), FORGE_RT_PROCESS_FAULTED);
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
    checkCloseCreated();
    checkRegistration();
    checkParameters();
    checkHeap();
    checkHeapBudgetRefund();
    checkCrtArguments();
    checkFunctionImports();
    checkCrtInputConsumers();
    checkIsolation();
    checkUnmanagedExceptionFilter();
    checkExitProcess();
    checkInvalidExitCode();
    checkScalarBoundaries();
    checkFaultCleanup();
}
