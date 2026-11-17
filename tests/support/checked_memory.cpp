#include "../differential/fixtures/arithmetic/operand.h"
#include "forge/runtime.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <latch>
#include <thread>

// Link the two independent artifacts generated from the same input PE.
// NOLINTBEGIN(readability-identifier-naming)
extern "C" const forge_rt_image *forge_lifted_image();
extern "C" const forge_rt_image *second_lifted_image();
extern "C" uint64_t forge_lifted_with_runtime(forge_rt_instance *, forge_rt_thread_token, uint64_t,
                                              uint64_t);
extern "C" uint64_t second_lifted_with_runtime(forge_rt_instance *, forge_rt_thread_token, uint64_t,
                                               uint64_t);
// NOLINTEND(readability-identifier-naming)

namespace {
    constexpr uint64_t entryRsp = 0x70001000 - 40;
    constexpr uint64_t frame = entryRsp - 56;
    constexpr uint64_t local = frame + 32;
    constexpr uint64_t output = frame + 40;

    uint64_t imageValue, imageConstant;
    uint64_t expectedImage, expectedLocal, lastInvocation;

    void require(bool success, const char *message) {
        if (!success) {
            std::fprintf(stderr, "%s\n", message);
            std::abort();
        }
    }

    struct Process {
        forge_rt_instance *instance = nullptr;
        forge_rt_thread_token thread = 0;
        uint64_t image = 11;

        Process() {
            require(forge_rt_create(FORGE_RT_ABI_VERSION, &instance) == FORGE_RT_OK, "create");
            require(forge_rt_thread_create(instance, &thread) == FORGE_RT_OK, "thread create");
        }

        ~Process() { require(forge_rt_destroy(instance) == FORGE_RT_OK, "destroy"); }

        Process(const Process &) = delete;
        Process &operator=(const Process &) = delete;
    };

    void concurrentFirstRegistration(const Process &process) {
        std::array<std::thread, 4> callers;
        std::latch ready(callers.size());
        for (auto &caller : callers) {
            caller = std::thread([&] {
                forge_rt_thread_token thread = 0;
                require(forge_rt_thread_create(process.instance, &thread) == FORGE_RT_OK,
                        "thread create");
                ready.arrive_and_wait();
                auto *descriptor = second_lifted_image();
                forge_rt_invocation_token invocation = 0;
                require(forge_rt_enter(process.instance, thread, descriptor, nullptr,
                                       &invocation) == FORGE_RT_OK,
                        "concurrent first registration");
                uint64_t initial = 0;
                forge_rt_memory_fault fault{};
                require(forge_rt_read_guest(process.instance, thread, invocation, imageValue,
                                            sizeof(initial), &initial, sizeof(initial),
                                            &fault) == FORGE_RT_OK &&
                            initial == 11,
                        "published initialized PE bytes");
                require(forge_rt_leave(process.instance, thread, invocation) == FORGE_RT_OK,
                        "leave");
                require(forge_rt_thread_destroy(process.instance, thread) == FORGE_RT_OK,
                        "thread destroy");
            });
        }

        for (auto &caller : callers) {
            caller.join();
        }
    }

    void invoke(Process &process, decltype(&forge_lifted_with_runtime) entry, uint64_t input) {
        expectedLocal = input;
        expectedImage = process.image + input + 1;
        auto result = entry(process.instance, process.thread, input, input + 1);
        process.image = expectedImage * 3;
        require(result == ((input + 17) ^ process.image) + input * 5 + 41, "guest reload");

        forge_rt_memory_fault fault{};
        uint64_t value = 0;
        require(forge_rt_read_guest(process.instance, process.thread, lastInvocation, local,
                                    sizeof(value), &value, sizeof(value),
                                    &fault) == FORGE_RT_INVALID_INVOCATION,
                "retired activation");
    }
} // namespace

// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" forge_rt_status probe_get_last_error(forge_rt_instance *instance,
                                                forge_rt_thread_token thread, uint32_t *outValue) {
    uint64_t invocation = 0;
    require(forge_rt_current_invocation(instance, thread, &invocation) == FORGE_RT_OK,
            "current invocation");
    require(invocation != lastInvocation, "fresh invocation");
    lastInvocation = invocation;
    forge_rt_memory_fault fault{};
    auto read = [&](uint64_t address, uint64_t &value) {
        return forge_rt_read_guest(instance, thread, invocation, address, sizeof(value), &value,
                                   sizeof(value), &fault);
    };
    auto write = [&](uint64_t address, uint64_t value) {
        return forge_rt_write_guest(instance, thread, invocation, address, sizeof(value), &value,
                                    sizeof(value), &fault);
    };

    uint64_t observed = 0;
    require(read(imageValue, observed) == FORGE_RT_OK && observed == expectedImage, "image read");
    require(read(local, observed) == FORGE_RT_OK && observed == expectedLocal, "stack read");
    require(read(imageConstant, observed) == FORGE_RT_OK && observed == 41, "immutable read");
    require(write(imageConstant, 0) == FORGE_RT_GUEST_FAULT, "immutable write");
    require(read(frame - 8, observed) == FORGE_RT_OK && observed != 0, "guest continuation");
    require(write(frame - 8, 0) == FORGE_RT_GUEST_FAULT, "protected continuation");
    require(read(entryRsp, observed) == FORGE_RT_GUEST_FAULT, "synthetic return");
    require(read(output, observed) == FORGE_RT_GUEST_FAULT, "uninitialized output");

    require(write(imageValue, expectedImage * 3) == FORGE_RT_OK, "image write");
    require(write(local, expectedLocal + 17) == FORGE_RT_OK, "stack write");
    require(write(output, expectedLocal * 5) == FORGE_RT_OK, "stack initialization");
    return forge_rt_get_last_error(instance, thread, outValue);
}

int main(int argc, char **argv) {
    int64_t mutableVA = 0, immutableVA = 0;
    if (argc != 3 || !parse_operand(argv[1], &mutableVA) || !parse_operand(argv[2], &immutableVA)) {
        return 2;
    }

    imageValue = static_cast<uint64_t>(mutableVA);
    imageConstant = static_cast<uint64_t>(immutableVA);
    Process first, second;
    invoke(first, forge_lifted_with_runtime, 37);
    concurrentFirstRegistration(second);
    invoke(second, second_lifted_with_runtime, 203);
    invoke(first, forge_lifted_with_runtime, 73);
    auto *descriptor = forge_lifted_image();
    require(forge_rt_register_image(first.instance, descriptor) == FORGE_RT_OK,
            "live registration");
    require(forge_rt_detach_image(first.instance, descriptor) == FORGE_RT_OK, "detach");
    require(forge_rt_register_image(first.instance, descriptor) == FORGE_RT_MAPPING_CONFLICT,
            "retired writable backing");
    Process fresh;
    require(forge_rt_register_image(fresh.instance, descriptor) == FORGE_RT_MAPPING_CONFLICT,
            "foreign writable backing");
    return 0;
}
