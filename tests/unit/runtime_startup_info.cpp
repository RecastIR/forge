#include "../../runtime/src/compat/process_state.h"
#include "../../runtime/src/core/process_image.h"
#include <forge/service_signature.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>

namespace {
    using namespace forge::runtime;
    constexpr uint64_t base = 0x400000;
    using Bytes = std::array<uint8_t, 104>;

    void require(bool ok, const char *what, int line) {
        if (!ok) {
            std::fprintf(stderr, "runtime_startup_info.cpp:%d: %s\n", line, what);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    struct Caller {
        explicit Caller(forge_rt_execution &execution)
            : instance(execution.instance), thread(execution.thread) {
            REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        }

        forge_rt_instance *instance;
        forge_rt_thread_token thread;
        forge_rt_invocation_token token{};
        forge_rt_memory_fault fault{};

        void write(uint64_t address, const Bytes &bytes) {
            REQUIRE(forge_rt_write_guest(instance, thread, token, address, bytes.size(),
                                         bytes.data(), bytes.size(), &fault) == FORGE_RT_OK);
        }

        template <size_t size> std::array<uint8_t, size> read(uint64_t address) {
            std::array<uint8_t, size> bytes{};
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, size, bytes.data(), size,
                                        &fault) == FORGE_RT_OK);
            return bytes;
        }

        forge_rt_status query(bool ansi, uint64_t address) {
            const auto fn = ansi ? forge_rt_get_startup_info_a : forge_rt_get_startup_info_w;
            return fn(instance, thread, address, &fault);
        }

        std::array<uint64_t, 3> standardHandles() const {
            constexpr uint32_t stdInput = 0xfffffff6, stdOutput = 0xfffffff5, stdError = 0xfffffff4;
            constexpr std::array selectors{stdInput, stdOutput, stdError};
            std::array<uint64_t, 3> handles{};

            for (size_t i = 0; i < selectors.size(); ++i) {
                REQUIRE(forge_rt_get_std_handle(instance, thread, selectors[i], &handles[i]) ==
                        FORGE_RT_OK);
            }

            return handles;
        }
    };

    template <size_t width> uint64_t field(const Bytes &bytes, size_t offset) {
        static_assert(width <= sizeof(uint64_t));
        uint64_t result = 0;

        for (size_t i = 0; i < width; ++i) {
            result |= uint64_t{bytes[offset + i]} << (i * 8);
        }

        return result;
    }

    void checkFaults(Caller &call, bool ansi) {
        Bytes before;
        before.fill(0x69);
        call.write(base, before);

        // The last byte is read-only, including when W would preserve that handle.
        REQUIRE(call.query(ansi, base + 1) == FORGE_RT_GUEST_FAULT);
        REQUIRE(call.fault.address == base + 104 && call.fault.reason == FORGE_RT_FAULT_PERMISSION);
        REQUIRE(call.fault.access == FORGE_RT_WRITE && call.read<104>(base) == before);

        struct FaultCase {
            uint64_t start, firstInvalid;
            uint32_t reason;
        };

        constexpr FaultCase invalid[]{
            {0, 0, FORGE_RT_FAULT_UNMAPPED},
            {base + 128, base + 128, FORGE_RT_FAULT_UNMAPPED},
            {base + 104, base + 104, FORGE_RT_FAULT_PERMISSION},
            {FORGE_RT_ENTRY_RSP - 103, FORGE_RT_ENTRY_RSP, FORGE_RT_FAULT_STACK},
            {UINT64_MAX - 100, UINT64_MAX - 100, FORGE_RT_FAULT_OVERFLOW}};

        for (const auto &test : invalid) {
            REQUIRE(call.query(ansi, test.start) == FORGE_RT_GUEST_FAULT);
            REQUIRE(call.fault.address == test.firstInvalid && call.fault.reason == test.reason);
            REQUIRE(call.fault.access == FORGE_RT_WRITE);
        }

        // A writable prefix followed by a hole also fails atomically.
        REQUIRE(call.query(ansi, base + 106) == FORGE_RT_GUEST_FAULT);
        REQUIRE(call.fault.address == base + 110 && call.fault.reason == FORGE_RT_FAULT_UNMAPPED);
        REQUIRE(call.read<4>(base + 106) == std::array<uint8_t, 4>{});
    }

    void checkText(Caller &call, uint64_t pointer, bool ansi, std::string_view expected) {
        REQUIRE(pointer != 0);
        REQUIRE(ansi || pointer % 2 == 0);
        for (size_t i = 0; i <= expected.size(); ++i) {
            const auto byte = i == expected.size() ? uint8_t{0} : static_cast<uint8_t>(expected[i]);
            if (ansi) {
                REQUIRE(call.read<1>(pointer + i)[0] == byte);
            } else {
                REQUIRE(call.read<2>(pointer + 2 * i) == (std::array<uint8_t, 2>{byte, 0}));
            }
        }
    }

    void checkDefaultView(Caller &call, bool ansi, std::string_view title) {
        Bytes sentinel;
        sentinel.fill(0xbc);
        Bytes expected{};
        expected[0] = 104;

        std::fill_n(expected.begin() + 4, 4, 0xbc);
        std::fill_n(expected.begin() + 68, 4, 0xbc);

        std::fill(expected.begin() + 80, expected.end(), ansi ? 0xff : 0xbc);

        for (const auto address : {base, FORGE_RT_ENTRY_RSP - 104}) {
            call.write(address, sentinel);

            for (size_t attempt = 0; attempt < 2; ++attempt) {
                REQUIRE(call.query(ansi, address) == FORGE_RT_OK);
                auto bytes = call.read<104>(address);
                const std::array<std::string_view, 3> strings{"", "winsta0\\default", title};
                for (size_t i = 0; i < strings.size(); ++i) {
                    const auto offset = 8 + 8 * i;
                    const auto pointer = field<8>(bytes, offset);
                    checkText(call, pointer, ansi, strings[i]);
                    std::ranges::fill(std::span(bytes).subspan(offset, 8), 0);
                }
                REQUIRE(bytes == expected);
            }
        }

        checkFaults(call, ansi);
    }

    void defaultEntry(forge_rt_execution *execution) {
        Caller call(*execution);
        REQUIRE(!call.instance->windows->standardHandles);
        REQUIRE(forge_rt_set_last_error(call.instance, call.thread, 73) == FORGE_RT_OK);

        const std::string_view title = execution->rcx ? "C:\\Guest App.exe" : "";
        checkDefaultView(call, true, title);
        checkDefaultView(call, false, title);

        // W must accept uninitialized stack storage and preserve marks on omitted bytes.
        const auto uninitialized = FORGE_RT_STACK_BASE + 200;
        REQUIRE(call.query(false, uninitialized) == FORGE_RT_OK);
        REQUIRE(execution->stackMarks[200] == FORGE_RT_MARK_CONCRETE);
        REQUIRE(execution->stackMarks[204] == FORGE_RT_MARK_UNINITIALIZED);
        REQUIRE(execution->stackMarks[280] == FORGE_RT_MARK_UNINITIALIZED);

        uint32_t error = 0;
        REQUIRE(forge_rt_get_last_error(call.instance, call.thread, &error) == FORGE_RT_OK &&
                error == 73);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
        REQUIRE(call.query(true, base) == FORGE_RT_INVALID_STATE);
    }

    constexpr uint32_t rw = FORGE_RT_READ | FORGE_RT_WRITE;
    constexpr forge_rt_import imports[]{{"KERNEL32.dll", "GetStartupInfoA"},
                                        {"KERNEL32.dll", "GetStartupInfoW"}};
    constexpr forge_rt_backing backing{128, nullptr, nullptr, 0};
    constexpr forge_rt_region_template regions[]{{base, 37, 0, 0, rw},
                                                 {base + 37, 67, 0, 37, rw},
                                                 {base + 104, 1, 0, 104, FORGE_RT_READ},
                                                 {base + 106, 4, 0, 106, rw}};
    constexpr forge_rt_artifact artifact{
        FORGE_RT_ARTIFACT_VERSION, base,    128, 0,           0, &backing, 1, regions,
        std::size(regions),        imports, 2,   defaultEntry};

    void populatedEntry(forge_rt_execution *execution) {
        Caller call(*execution);
        uint64_t command = 0;
        REQUIRE(forge_rt_get_command_line_a(call.instance, call.thread, &command) == FORGE_RT_OK);
        REQUIRE(call.read<8>(command) ==
                (std::array<uint8_t, 8>{'a', 'p', 'p', '.', 'e', 'x', 'e', 0}));

        const auto tag = static_cast<uint8_t>(execution->rcx);
        auto &streams = call.instance->windows->standardHandles;
        if (!streams) {
            std::abort();
        }

        auto &handles = *streams;
        const auto original = call.standardHandles();
        REQUIRE(original[1] != 0 && original[1] != original[2]);
        std::swap(handles.streams[1].handle, handles.streams[2].handle);
        const auto current = call.standardHandles();

        Bytes sentinel;
        sentinel.fill(0xbc);
        for (bool ansi : {true, false}) {
            call.write(base, sentinel);
            REQUIRE(call.query(ansi, base) == FORGE_RT_OK);
            const auto bytes = call.read<104>(base);
            const auto padding = field<4>(sentinel, 4);
            REQUIRE(field<4>(bytes, 0) == 104);
            REQUIRE(field<4>(bytes, 4) == padding);
            REQUIRE(field<4>(bytes, 68) == padding);

            for (size_t i = 0; i < 7; ++i) {
                REQUIRE(field<4>(bytes, 32 + i * 4) == tag + i);
            }

            REQUIRE(field<4>(bytes, 60) == 0x100 && field<2>(bytes, 64) == 0x1234);
            REQUIRE(field<2>(bytes, 66) == 3 && call.read<1>(field<8>(bytes, 8))[0] == 0);
            const auto desktop = field<8>(bytes, 16), title = field<8>(bytes, 24);
            REQUIRE(call.read<3>(field<8>(bytes, 72)) == (std::array<uint8_t, 3>{tag, 0, 0xff}));

            if (ansi) {
                REQUIRE(call.read<3>(desktop) == (std::array<uint8_t, 3>{'D', tag, 0}));
                REQUIRE(call.read<2>(title) == (std::array<uint8_t, 2>{tag, 0}));
            } else {
                REQUIRE((desktop | title) % 2 == 0);
                REQUIRE(call.read<6>(desktop) == (std::array<uint8_t, 6>{'D', 0, tag, 0, 0, 0}));
                REQUIRE(call.read<4>(title) == (std::array<uint8_t, 4>{tag, 0, 0, 0}));
            }

            for (const auto address : {field<8>(bytes, 8), desktop, title, field<8>(bytes, 72)}) {
                const uint8_t overwrite = 0;
                REQUIRE(forge_rt_write_guest(call.instance, call.thread, call.token, address, 1,
                                             &overwrite, 1, &call.fault) == FORGE_RT_GUEST_FAULT);
                REQUIRE(call.fault.address == address &&
                        call.fault.reason == FORGE_RT_FAULT_PERMISSION);
            }

            for (size_t i = 0; i < original.size(); ++i) {
                REQUIRE(field<8>(bytes, 80 + 8 * i) == (ansi ? original : current)[i]);
            }

            REQUIRE(call.query(ansi, base) == FORGE_RT_OK && call.read<104>(base) == bytes);
        }

        // A can still report creation handles after the live namespace has been retired.
        call.instance->windows->standardHandles.reset();
        REQUIRE(call.query(true, base) == FORGE_RT_OK);
        const auto cached = call.read<104>(base);

        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(field<8>(cached, 80 + i * 8) == original[i]);
        }

        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, tag, {}, 0};
    }

    // Seed internal creation fields before normal parameter mapping. Both occurrences
    // deliberately reuse guest VAs while owning distinct bytes and handle namespaces.
    struct PopulatedProcess {
        PopulatedProcess(const forge_rt_artifact &input, uint8_t tag) : image(input) {
            auto &info = windows.parameters.startupInfo;
            const uint32_t n = tag;
            info.window = {n, n + 1, n + 2, n + 3, n + 4, n + 5, n + 6, StartupInfo::useStdHandles};
            info.show = 0x1234;
            info.shell.emplace();
            info.desktop.emplace().narrow = {'D', static_cast<char>(tag)};
            info.title.emplace().narrow = {static_cast<char>(tag)};
            info.reserved = {tag, 0, 0xff};
            REQUIRE(windows.standardHandles.emplace().capture() == FORGE_RT_OK);
            const forge_rt_process_startup launch{"app.exe", 0, nullptr, 0, nullptr};
            REQUIRE(windows.initializeParameters(image.instance, input, launch, true, {{}, true}) ==
                    FORGE_RT_OK);
            REQUIRE(image.prepare() == FORGE_RT_OK);
            image.reservePrimaryStackSlot();
            image.instance.windows = &windows;
            image.instance.managedExecution = &image.execution.view;
            image.execution.view.rcx = tag;
        }

        ~PopulatedProcess() { image.retire(); }

        WindowsProcessState windows;
        ProcessImage image;
    };
} // namespace

void testRuntimeStartupInfo() {
    using namespace forge::win64;
    static_assert(getStartupInfoA.result == Value::Void &&
                  getStartupInfoW.arguments[0].size == 104);
    forge_rt_instance standalone;
    forge_rt_memory_fault untouched{1, 2, 3};
    REQUIRE(forge_rt_get_startup_info_w(&standalone, 0, base, &untouched) ==
            FORGE_RT_INVALID_STATE);
    REQUIRE(untouched.address == 1 && untouched.access == 2 && untouched.reason == 3);

    forge_rt_process *raw = nullptr;
    REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
    std::unique_ptr<forge_rt_process, decltype(&forge_rt_process_destroy)> owner(
        raw, forge_rt_process_destroy);
    auto bad = artifact;
    const forge_rt_region_template broken{base, 129, 0, 0, rw};
    bad.regions = &broken;
    bad.regionCount = 1;
    REQUIRE(forge_rt_process_register(raw, &bad) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
    forge_rt_process_result result{};
    REQUIRE(forge_rt_process_run(raw, nullptr, &result) == FORGE_RT_OK &&
            result.kind == FORGE_RT_RETURNED && result.value == 42);

    forge_rt_process *named = nullptr;
    REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &named) == FORGE_RT_OK);
    std::unique_ptr<forge_rt_process, decltype(&forge_rt_process_destroy)> namedOwner(
        named, forge_rt_process_destroy);
    const forge_rt_process_startup launch{"C:\\Guest App.exe", 0, nullptr, 0, nullptr};
    const forge_rt_entry_inputs inputs{1, 0};
    REQUIRE(forge_rt_process_register_with_startup(named, &artifact, &launch) == FORGE_RT_OK);
    REQUIRE(forge_rt_process_run(named, &inputs, &result) == FORGE_RT_OK &&
            result.kind == FORGE_RT_RETURNED && result.value == 42);

    auto seeded = artifact;
    seeded.entry = populatedEntry;
    PopulatedProcess first(seeded, 'X'), second(seeded, 'Y');
    REQUIRE(first.windows.parameters.startupInfo.creationHandles !=
            second.windows.parameters.startupInfo.creationHandles);
    REQUIRE(first.image.run().value == 'X');
    REQUIRE(second.image.run().value == 'Y');
}
