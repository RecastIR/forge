#include <forge/runtime.h>

#include "../../runtime/src/instance.h"
#include "forge/service_memory.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <latch>
#include <memory>
#include <span>
#include <thread>
#include <vector>

extern "C" forge_rt_status forgeTestReadGuest(forge_rt_instance *, forge_rt_thread_token,
                                              forge_rt_invocation_token, uint64_t, uint64_t, void *,
                                              size_t, forge_rt_memory_fault *) noexcept;

namespace {
    struct TransferGate {
        std::latch copyApproved{1};
        std::latch removalAttempted{1};
    };

    thread_local TransferGate *pausedCopy = nullptr;

    void require(bool passed, const char *expression, int line) {
        if (!passed) {
            std::fprintf(stderr, "runtime_memory.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    using Instance = std::unique_ptr<forge_rt_instance, decltype(&forge_rt_destroy)>;

    Instance createInstance() {
        forge_rt_instance *instance = nullptr;
        REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &instance) == FORGE_RT_OK);
        return {instance, forge_rt_destroy};
    }

    forge_rt_thread_token createThread(forge_rt_instance *instance) {
        forge_rt_thread_token token = 0;
        REQUIRE(forge_rt_thread_create(instance, &token) == FORGE_RT_OK);
        return token;
    }

    struct Activation {
        forge_rt_instance *instance;
        forge_rt_thread_token thread;
        forge_rt_invocation_token id = 0;

        forge_rt_status enter(const forge_rt_image &image, const forge_rt_stack *stack = nullptr) {
            return forge_rt_enter(instance, thread, &image, stack, &id);
        }

        forge_rt_status leave() const { return forge_rt_leave(instance, thread, id); }

        forge_rt_status read(uint64_t address, std::span<uint8_t> buffer,
                             forge_rt_memory_fault &fault) const {
            return forge_rt_read_guest(instance, thread, id, address, buffer.size(), buffer.data(),
                                       buffer.size(), &fault);
        }

        forge_rt_status write(uint64_t address, std::span<const uint8_t> buffer,
                              forge_rt_memory_fault &fault) const {
            return forge_rt_write_guest(instance, thread, id, address, buffer.size(), buffer.data(),
                                        buffer.size(), &fault);
        }

        forge_rt_status validate(uint64_t address, uint64_t count, uint32_t access,
                                 forge_rt_memory_fault &fault) const {
            return forge_rt_validate_guest(instance, thread, id, address, count, access, &fault);
        }
    };

    void expectFault(const forge_rt_memory_fault &fault, forge_rt_memory_fault expected) {
        REQUIRE(fault.address == expected.address);
        REQUIRE(fault.access == expected.access);
        REQUIRE(fault.reason == expected.reason);
    }

    constexpr auto readWrite = FORGE_RT_READ | FORGE_RT_WRITE;

    void testSegments() {
        // Two separately owned native allocations abut in the guest address space.
        std::vector<uint8_t> first{10, 11, 12, 13};
        std::vector<uint8_t> second{20, 21, 22};
        const std::array<uint8_t, 2> literal{30, 31};
        std::array<uint8_t, 2> output{40, 41};
        uint64_t firstClaim = 0, secondClaim = 0, outputClaim = 0;
        constexpr uint64_t base = 0x1000;
        const forge_rt_image_region regions[]{
            {base, first.size(), first.data(), readWrite, &firstClaim},
            {base + 4, second.size(), second.data(), readWrite, &secondClaim},
            {base + 7, literal.size(), literal.data(), FORGE_RT_READ | FORGE_RT_EXECUTE, nullptr},
            {base + 10, output.size(), output.data(), FORGE_RT_WRITE, &outputClaim},
        };
        const forge_rt_image image{base, 64, regions, std::size(regions)};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        REQUIRE(forge_rt_register_image(instance.get(), &image) == FORGE_RT_OK);
        REQUIRE(active.enter(image) == FORGE_RT_OK);
        REQUIRE(forge_rt_set_last_error(instance.get(), active.thread, 0xaaff) == FORGE_RT_OK);

        std::array<uint8_t, 4> result{};
        forge_rt_memory_fault fault{17, 18, 19};
        REQUIRE(active.read(base + 2, result, fault) == FORGE_RT_OK);
        REQUIRE(result == std::array<uint8_t, 4>{12, 13, 20, 21});
        expectFault(fault, {17, 18, 19});
        const std::array<uint8_t, 4> input{80, 81, 82, 83};
        REQUIRE(active.write(base + 1, input, fault) == FORGE_RT_OK);
        REQUIRE(first == std::vector<uint8_t>({10, 80, 81, 82}));
        REQUIRE(second == std::vector<uint8_t>({83, 21, 22}));
        REQUIRE(active.read(base + 5, result, fault) == FORGE_RT_OK);
        REQUIRE(result == std::array<uint8_t, 4>{21, 22, 30, 31});
        REQUIRE(active.validate(base + 1, 5, readWrite, fault) == FORGE_RT_OK);

        const auto before = second;
        REQUIRE(active.write(base + 5, input, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 7, FORGE_RT_WRITE, FORGE_RT_FAULT_PERMISSION});
        REQUIRE(second == before);
        REQUIRE(active.validate(base + 5, 4, readWrite, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 7, readWrite, FORGE_RT_FAULT_PERMISSION});

        result.fill(0xcd);
        const auto unchanged = result;
        REQUIRE(active.read(base + 7, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 9, FORGE_RT_READ, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(result == unchanged);
        REQUIRE(active.read(base + 10, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 10, FORGE_RT_READ, FORGE_RT_FAULT_PERMISSION});
        REQUIRE(result == unchanged);
        REQUIRE(active.write(base + 10, input, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 12, FORGE_RT_WRITE, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(output == std::array<uint8_t, 2>{40, 41});

        uint32_t lastError = 0;
        REQUIRE(forge_rt_get_last_error(instance.get(), active.thread, &lastError) == FORGE_RT_OK);
        REQUIRE(lastError == 0xaaff);
        REQUIRE(active.leave() == FORGE_RT_OK);
    }

    void testBoundedServiceBuffer() {
        using namespace forge::win64;
        constexpr Argument buffer{Value::Address, Access::InOut, Extent::CountArgument, 1};
        static constexpr ServiceBinding binding{
            "test.dll",  "Buffer",           "testBuffer", parameters<buffer, Argument{Value::U32}>,
            Value::Void, LastError::Preserve};
        std::array<uint8_t, 8> bytes{};
        uint64_t claim = 0;
        const forge_rt_image_region row{0x1000, bytes.size(), bytes.data(), readWrite, &claim};
        const forge_rt_image image{row.start, row.size, &row, 1};
        const auto process = createInstance();
        Activation active{process.get(), createThread(process.get())};
        REQUIRE(active.enter(image) == FORGE_RT_OK);
        forge_rt_memory_fault fault{17, 18, 19};
        ServiceInvocation call{active.instance, active.thread, fault};
        REQUIRE(call.resolveCurrent() == FORGE_RT_OK);

        const auto view = guestBuffer<binding, 0>(call, std::tuple{row.start, 4u});
        REQUIRE(view.validate() == FORGE_RT_OK);
        const std::array<uint8_t, 4> data{1, 2, 3, 4};
        REQUIRE(view.write(0, data) == FORGE_RT_OK);
        uint32_t value = 0;
        REQUIRE(view.readScalar(0, value) == FORGE_RT_OK && value == 0x04030201);
        // The backing is eight bytes, but this argument lends only the first four.
        REQUIRE(view.writeScalar(1, UINT32_MAX) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(view.readScalar(UINT64_MAX, value) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(value == 0x04030201 && bytes[4] == 0 && bytes[1] == 2);
        expectFault(fault, {17, 18, 19});

        const auto crossing = guestBuffer<binding, 0>(call, std::tuple{row.start + 6, 4u});
        REQUIRE(crossing.write(0, data) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {row.start + 8, FORGE_RT_WRITE, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(bytes[6] == 0 && bytes[7] == 0);
        REQUIRE(active.leave() == FORGE_RT_OK);
        REQUIRE(view.readScalar(0, value) == FORGE_RT_INVALID_INVOCATION);
    }

    void testRangeBoundaries() {
        std::array<uint8_t, 2> last{0xc3, 0x81};
        uint64_t claim = 0;
        constexpr uint64_t top = UINT64_MAX;
        const forge_rt_image_region row{top - 1, 2, last.data(), readWrite, &claim};
        const forge_rt_image image{top - 1, 2, &row, 1};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        REQUIRE(forge_rt_register_image(instance.get(), &image) == FORGE_RT_OK);
        REQUIRE(active.enter(image) == FORGE_RT_OK);

        std::array<uint8_t, 1> byte{};
        std::array<uint8_t, 2> both{};
        forge_rt_memory_fault fault{};
        REQUIRE(active.read(top, byte, fault) == FORGE_RT_OK);
        REQUIRE(byte[0] == 0x81);
        REQUIRE(active.read(top - 1, both, fault) == FORGE_RT_OK);
        REQUIRE(both == last);
        REQUIRE(active.write(top, both, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {top, FORGE_RT_WRITE, FORGE_RT_FAULT_OVERFLOW});
        REQUIRE(last == std::array<uint8_t, 2>{0xc3, 0x81});
        REQUIRE(active.read(top, both, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {top, FORGE_RT_READ, FORGE_RT_FAULT_OVERFLOW});
        REQUIRE(both == last);

        REQUIRE(forge_rt_read_guest(active.instance, active.thread, active.id, 0, 0, nullptr, 0,
                                    &fault) == FORGE_RT_OK);
        REQUIRE(forge_rt_write_guest(active.instance, active.thread, active.id, top, 0, nullptr, 0,
                                     &fault) == FORGE_RT_OK);
        REQUIRE(active.validate(top, 0, readWrite, fault) == FORGE_RT_OK);
        fault = {1, 2, 3};
        REQUIRE(forge_rt_read_guest(active.instance, active.thread, active.id, top - 1, 2,
                                    byte.data(), byte.size(), &fault) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_write_guest(active.instance, active.thread, active.id, top, 1, nullptr, 1,
                                     &fault) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(last == both);
        expectFault(fault, {1, 2, 3});
        REQUIRE(active.leave() == FORGE_RT_OK);
        REQUIRE(active.validate(top, 0, readWrite, fault) == FORGE_RT_INVALID_INVOCATION);
        expectFault(fault, {1, 2, 3});
    }

    void checkReusedStack(const Activation &active, const forge_rt_image &image, uint64_t base) {
        forge_rt_memory_fault fault{};
        std::array<uint8_t, 2> result{};
        const std::array<uint8_t, 2> replacement{0x20, 0x48};
        auto next = active;
        REQUIRE(next.enter(image) == FORGE_RT_OK);
        REQUIRE(next.id != active.id);
        REQUIRE(active.read(base, result, fault) == FORGE_RT_INVALID_INVOCATION);
        REQUIRE(next.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(next.leave() == FORGE_RT_OK);

        std::array<uint8_t, 64> freshBytes{}, freshMarks{};
        const forge_rt_stack fresh{base, freshBytes.size(), freshBytes.data(), freshMarks.data(),
                                   base + 48};
        REQUIRE(next.enter(image, &fresh) == FORGE_RT_OK);
        REQUIRE(active.write(base, replacement, fault) == FORGE_RT_INVALID_INVOCATION);
        REQUIRE(next.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(next.write(base, replacement, fault) == FORGE_RT_OK);
        REQUIRE(freshBytes[0] == replacement[0] && freshMarks[0] == 0xff);
        REQUIRE(next.leave() == FORGE_RT_OK);
    }

    void testStack() {
        constexpr uint64_t base = 0x70000000;
        std::array<uint8_t, 64> bytes{}, marks{};
        const forge_rt_stack stack{base, bytes.size(), bytes.data(), marks.data(), base + 48};
        const forge_rt_image image{0x1000, 8, nullptr, 0};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        REQUIRE(forge_rt_register_image(instance.get(), &image) == FORGE_RT_OK);
        REQUIRE(active.enter(image, &stack) == FORGE_RT_OK);
        bytes.fill(0x5a);
        marks[1] = 17; // Opaque saved register byte.
        marks[2] = 0xff;
        std::fill_n(marks.begin() + 8, 8, 0xfe);  // Nested guest return.
        std::fill_n(marks.begin() + 48, 8, 0xfe); // Synthetic outer return.

        forge_rt_memory_fault fault{};
        std::array<uint8_t, 2> result{1, 2};
        const std::array<uint8_t, 2> replacement{0x19, 0x47};
        REQUIRE(active.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(active.read(base + 1, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 1, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(result == std::array<uint8_t, 2>{1, 2});
        REQUIRE(active.validate(base + 1, 2, readWrite, fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(active.write(base, replacement, fault) == FORGE_RT_OK);
        REQUIRE(active.validate(base, 3, readWrite, fault) == FORGE_RT_OK);
        REQUIRE(marks[0] == 0xff && marks[1] == 0xff && marks[2] == 0xff && marks[3] == 0);
        REQUIRE(active.read(base, result, fault) == FORGE_RT_OK);
        REQUIRE(result == replacement);
        REQUIRE(active.read(base + 8, result, fault) == FORGE_RT_OK);
        REQUIRE(result == std::array<uint8_t, 2>{0x5a, 0x5a});
        REQUIRE(active.validate(base + 8, 1, readWrite, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 8, readWrite, FORGE_RT_FAULT_STACK});

        const auto beforeBytes = bytes;
        const auto beforeMarks = marks;
        REQUIRE(active.write(base + 7, replacement, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 8, FORGE_RT_WRITE, FORGE_RT_FAULT_STACK});
        REQUIRE(active.write(base + 47, replacement, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 48, FORGE_RT_WRITE, FORGE_RT_FAULT_STACK});
        REQUIRE(active.read(base + 48, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 48, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(bytes == beforeBytes && marks == beforeMarks);

        std::thread outsider([&] {
            forge_rt_memory_fault denied{};
            auto copy = replacement;
            REQUIRE(active.read(base, copy, denied) == FORGE_RT_GUEST_FAULT);
            expectFault(denied, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
            REQUIRE(copy == replacement);
        });
        outsider.join();

        Activation inner{instance.get(), createThread(instance.get())};
        REQUIRE(inner.enter(image, &stack) == FORGE_RT_MAPPING_CONFLICT);
        REQUIRE(inner.enter(image) == FORGE_RT_OK);
        REQUIRE(inner.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(active.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(inner.leave() == FORGE_RT_OK);
        REQUIRE(active.read(base, result, fault) == FORGE_RT_OK);
        REQUIRE(result == replacement);
        REQUIRE(forge_rt_thread_destroy(instance.get(), active.thread) == FORGE_RT_BUSY);
        REQUIRE(active.leave() == FORGE_RT_OK);
        checkReusedStack(active, image, base);
    }

    void testClaims() {
        constexpr uint64_t base = 0x3000;
        std::array<uint8_t, 2> backing{1, 2};
        uint64_t claim = 0;
        const forge_rt_image_region firstRows[]{
            {base, 1, backing.data(), readWrite, &claim},
            {base + 2, 1, backing.data(), FORGE_RT_READ, &claim},
            {base + 3, 1, backing.data() + 1, readWrite, &claim},
        };
        const forge_rt_image first{base, 4, firstRows, std::size(firstRows)};
        // A read-only view of A's mutable bytes still requires their exclusive claim.
        uint8_t fresh = 3;
        uint64_t freshClaim = 0;
        const forge_rt_image_region contenderRows[]{
            {base, 1, &fresh, readWrite, &freshClaim},
            {base + 1, 1, backing.data(), FORGE_RT_READ, &claim},
        };
        const forge_rt_image contender{base, 4, contenderRows, std::size(contenderRows)};
        const forge_rt_image clean{base, 4, contenderRows, 1};
        const auto secondProcess = createInstance();
        forge_rt_memory_fault fault{};

        {
            const auto firstProcess = createInstance();
            REQUIRE(forge_rt_register_image(firstProcess.get(), &first) == FORGE_RT_OK);
            REQUIRE(forge_rt_register_image(firstProcess.get(), &first) == FORGE_RT_OK);
            REQUIRE(forge_rt_register_image(secondProcess.get(), &contender) ==
                    FORGE_RT_MAPPING_CONFLICT);
            REQUIRE(forge_rt_register_image(secondProcess.get(), &clean) == FORGE_RT_OK);
            Activation a{firstProcess.get(), createThread(firstProcess.get())};
            Activation b{secondProcess.get(), createThread(secondProcess.get())};
            REQUIRE(a.enter(first) == FORGE_RT_OK);
            REQUIRE(b.enter(clean) == FORGE_RT_OK);

            std::array<uint8_t, 1> byte{0xab};
            REQUIRE(a.write(base, byte, fault) == FORGE_RT_OK);
            byte[0] = 0;
            REQUIRE(a.read(base + 2, byte, fault) == FORGE_RT_OK && byte[0] == 0xab);
            byte[0] = 0xcd;
            REQUIRE(a.write(base + 2, byte, fault) == FORGE_RT_GUEST_FAULT);
            expectFault(fault, {base + 2, FORGE_RT_WRITE, FORGE_RT_FAULT_PERMISSION});
            REQUIRE(a.read(base, byte, fault) == FORGE_RT_OK && byte[0] == 0xab);
            REQUIRE(b.read(base, byte, fault) == FORGE_RT_OK && byte[0] == 3);
            REQUIRE(forge_rt_detach_image(firstProcess.get(), &first) == FORGE_RT_BUSY);
            REQUIRE(b.leave() == FORGE_RT_OK);
            REQUIRE(a.leave() == FORGE_RT_OK);
            REQUIRE(forge_rt_detach_image(firstProcess.get(), &first) == FORGE_RT_OK);
            REQUIRE(forge_rt_register_image(firstProcess.get(), &first) ==
                    FORGE_RT_MAPPING_CONFLICT);
        }

        REQUIRE(forge_rt_detach_image(secondProcess.get(), &clean) == FORGE_RT_OK);
        const forge_rt_image alias{base, 4, &firstRows[1], 1};
        REQUIRE(forge_rt_register_image(secondProcess.get(), &alias) == FORGE_RT_MAPPING_CONFLICT);
        REQUIRE(backing[0] == 0xab);

        // A sole read-only row claims mutable backing even without any writable row.
        uint8_t cell = 7;
        uint64_t attachedClaim = 0;
        const forge_rt_image_region readOnly{base, 1, &cell, FORGE_RT_READ, &attachedClaim};
        const forge_rt_image_region writable{base, 1, &cell, readWrite, &attachedClaim};
        const forge_rt_image attached{base, 1, &readOnly, 1}, other{base, 1, &writable, 1};
        {
            const auto owner = createInstance();
            REQUIRE(forge_rt_register_image(owner.get(), &attached) == FORGE_RT_OK);
            REQUIRE(forge_rt_register_image(secondProcess.get(), &other) ==
                    FORGE_RT_MAPPING_CONFLICT);
        }

        REQUIRE(forge_rt_register_image(secondProcess.get(), &other) == FORGE_RT_MAPPING_CONFLICT);
    }

    void testSharedImmutableBacking() {
        constexpr uint64_t base = 0x3600;
        const std::array<uint8_t, 2> bytes{9, 27};
        const forge_rt_image_region row{base, bytes.size(), bytes.data(), FORGE_RT_READ, nullptr};
        const forge_rt_image shared{base, bytes.size(), &row, 1};
        const forge_rt_image execution{base + 16, 1, nullptr, 0};
        const auto first = createInstance(), second = createInstance();
        Activation remaining{second.get(), createThread(second.get())};
        REQUIRE(forge_rt_register_image(first.get(), &shared) == FORGE_RT_OK);
        REQUIRE(remaining.enter(shared) == FORGE_RT_OK);
        REQUIRE(forge_rt_detach_image(first.get(), &shared) == FORGE_RT_OK);

        forge_rt_memory_fault fault{};
        std::array<uint8_t, 2> result{};
        Activation detached{first.get(), createThread(first.get())};
        REQUIRE(detached.enter(execution) == FORGE_RT_OK);
        REQUIRE(detached.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(detached.leave() == FORGE_RT_OK);
        REQUIRE(remaining.read(base, result, fault) == FORGE_RT_OK && result == bytes);
        REQUIRE(remaining.leave() == FORGE_RT_OK);
        REQUIRE(forge_rt_detach_image(second.get(), &shared) == FORGE_RT_OK);
    }

    void testReservations() {
        const uint8_t byte = 8;
        constexpr uint64_t base = 0x4000;
        const forge_rt_image reserved{base, 16, nullptr, 0};
        const forge_rt_image_region row{base + 3, 1, &byte, FORGE_RT_READ, nullptr};
        const forge_rt_image hole{base + 3, 1, &row, 1};
        const forge_rt_image outside{base + 4, 1, &row, 1};
        const forge_rt_image overflowing{UINT64_MAX, 2, nullptr, 0};
        const forge_rt_image_region repeated[]{row, row};
        const forge_rt_image overlap{base, 16, repeated, std::size(repeated)};
        uint8_t mutableByte = 8;
        const forge_rt_image_region unclaimed{base, 1, &mutableByte, readWrite, nullptr};
        const forge_rt_image missingClaim{base, 1, &unclaimed, 1};
        const auto process = createInstance();
        REQUIRE(forge_rt_register_image(process.get(), &missingClaim) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_register_image(process.get(), &overflowing) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_register_image(process.get(), &outside) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_register_image(process.get(), &overlap) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_register_image(process.get(), &reserved) == FORGE_RT_OK);
        REQUIRE(forge_rt_register_image(process.get(), &hole) == FORGE_RT_MAPPING_CONFLICT);
        REQUIRE(forge_rt_detach_image(process.get(), &reserved) == FORGE_RT_OK);
        REQUIRE(forge_rt_register_image(process.get(), &hole) == FORGE_RT_OK);
    }

    void testCompetingClaims() {
        constexpr uint64_t base = 0x3500;
        std::array<uint8_t, 3> bytes{};
        uint64_t firstClaim = 0, sharedClaim = 0, secondClaim = 0;
        const forge_rt_image_region left[]{
            {base, 1, bytes.data(), readWrite, &firstClaim},
            {base + 1, 1, bytes.data() + 1, readWrite, &sharedClaim},
        };
        const forge_rt_image_region right[]{
            {base, 1, bytes.data() + 2, readWrite, &secondClaim},
            {base + 1, 1, bytes.data() + 1, readWrite, &sharedClaim},
        };
        const forge_rt_image first{base, 2, left, 2}, second{base, 2, right, 2};
        const forge_rt_image leftOnly{base, 1, left, 1}, rightOnly{base, 1, right, 1};
        const auto a = createInstance(), b = createInstance();
        forge_rt_status firstStatus = FORGE_RT_INTERNAL_ERROR;
        std::latch commit(2);
        std::thread contender([&] {
            commit.arrive_and_wait();
            firstStatus = forge_rt_register_image(a.get(), &first);
        });
        commit.arrive_and_wait();
        const auto secondStatus = forge_rt_register_image(b.get(), &second);
        contender.join();

        if (firstStatus == FORGE_RT_OK) {
            REQUIRE(secondStatus == FORGE_RT_MAPPING_CONFLICT);
            REQUIRE(forge_rt_register_image(b.get(), &rightOnly) == FORGE_RT_OK);
        } else {
            REQUIRE(firstStatus == FORGE_RT_MAPPING_CONFLICT);
            REQUIRE(secondStatus == FORGE_RT_OK);
            REQUIRE(forge_rt_register_image(a.get(), &leftOnly) == FORGE_RT_OK);
        }
    }

    void testEntryRollback() {
        constexpr uint64_t base = 0x4400;
        std::array<uint8_t, 32> bytes{}, marks{};
        uint8_t cell = 42;
        uint64_t claim = 0;
        const forge_rt_image_region row{base, 1, &cell, readWrite, &claim};
        const forge_rt_image image{base, 32, &row, 1};
        const auto replacement = image;
        const forge_rt_stack colliding{base + 8, bytes.size(), bytes.data(), marks.data(),
                                       base + 8};
        const auto process = createInstance();
        Activation active{process.get(), createThread(process.get()), 0xff};
        REQUIRE(active.enter(image, &colliding) == FORGE_RT_MAPPING_CONFLICT);
        REQUIRE(active.id == 0xff);
        REQUIRE(active.enter(replacement) == FORGE_RT_OK);
        REQUIRE(active.leave() == FORGE_RT_OK);
    }

    void testStackAndImageSegments() {
        constexpr uint64_t base = 0x6000;
        std::array<uint8_t, 2> imageBytes{10, 11};
        std::array<uint8_t, 16> bytes{}, marks{};
        uint64_t claim = 0;
        const forge_rt_image_region region{base, 2, imageBytes.data(), readWrite, &claim};
        const forge_rt_image image{base, 2, &region, 1};
        const forge_rt_stack stack{base + 2, bytes.size(), bytes.data(), marks.data(), base + 10};
        const auto process = createInstance();
        Activation active{process.get(), createThread(process.get())};
        REQUIRE(forge_rt_register_image(process.get(), &image) == FORGE_RT_OK);
        REQUIRE(active.enter(image, &stack) == FORGE_RT_OK);

        forge_rt_memory_fault fault{};
        std::array<uint8_t, 4> result{0xdd, 0xdd, 0xdd, 0xdd};
        const auto sentinel = result;
        REQUIRE(active.read(base, result, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 2, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        REQUIRE(result == sentinel);
        const std::array<uint8_t, 4> input{5, 6, 7, 8};
        marks[1] = 0xfe;
        REQUIRE(active.write(base, input, fault) == FORGE_RT_GUEST_FAULT);
        expectFault(fault, {base + 3, FORGE_RT_WRITE, FORGE_RT_FAULT_STACK});
        REQUIRE(imageBytes == std::array<uint8_t, 2>{10, 11});
        REQUIRE(bytes[0] == 0 && bytes[1] == 0 && marks[0] == 0 && marks[1] == 0xfe);

        marks[1] = 0;
        REQUIRE(active.write(base, input, fault) == FORGE_RT_OK);
        REQUIRE(imageBytes == std::array<uint8_t, 2>{5, 6});
        REQUIRE(bytes[0] == 7 && bytes[1] == 8 && marks[0] == 0xff && marks[1] == 0xff);
        REQUIRE(active.read(base, result, fault) == FORGE_RT_OK);
        REQUIRE(result == input);
        REQUIRE(active.leave() == FORGE_RT_OK);
    }

    void testConcurrentEntries() {
        constexpr uint64_t base = 0x18000;
        std::array<uint8_t, 4> bytes{};
        uint64_t claim = 0;
        const forge_rt_image_region row{base, bytes.size(), bytes.data(), readWrite, &claim};
        const forge_rt_image image{base, bytes.size(), &row, 1};
        const auto process = createInstance();
        std::latch ready(bytes.size()), entered(bytes.size());
        std::vector<std::thread> threads;
        threads.reserve(bytes.size());

        auto run = [&](unsigned i, forge_rt_thread_token token) {
            Activation active{process.get(), token};
            ready.arrive_and_wait();
            REQUIRE(active.enter(image) == FORGE_RT_OK);
            entered.arrive_and_wait();
            forge_rt_memory_fault fault{};
            std::array<uint8_t, 1> byte{};

            for (unsigned value = 0; value < 32; ++value) {
                const auto expected = static_cast<uint8_t>(32 * i + value);
                byte[0] = expected;
                REQUIRE(active.write(base + i, byte, fault) == FORGE_RT_OK);
                byte[0] = 0;
                REQUIRE(active.read(base + i, byte, fault) == FORGE_RT_OK);
                REQUIRE(byte[0] == expected);
            }

            REQUIRE(active.leave() == FORGE_RT_OK);
        };

        for (unsigned i = 0; i < bytes.size(); ++i) {
            threads.emplace_back(run, i, createThread(process.get()));
        }

        for (auto &thread : threads) {
            thread.join();
        }

        REQUIRE(bytes == std::array<uint8_t, 4>{31, 63, 95, 127});
    }

    void raceDetach(forge_rt_instance *process, const forge_rt_image &execution, bool forced) {
        constexpr uint64_t base = 0x800000;
        constexpr size_t width = 65536;
        auto first = std::make_unique<uint8_t[]>(width);
        auto second = std::make_unique<uint8_t[]>(width);
        std::fill_n(first.get(), width, 0x27);
        std::fill_n(second.get(), width, 0xb1);
        const forge_rt_image_region rows[]{
            {base, width, first.get(), FORGE_RT_READ, nullptr},
            {base + width, width, second.get(), FORGE_RT_READ, nullptr},
        };
        const forge_rt_image image{base, 2 * width, rows, std::size(rows)};
        REQUIRE(forge_rt_register_image(process, &image) == FORGE_RT_OK);
        Activation reader{process, createThread(process)};
        std::latch race(2), retired(1);
        TransferGate gate;

        std::thread read([&] {
            REQUIRE(reader.enter(execution) == FORGE_RT_OK);
            std::vector<uint8_t> out(2 * width, 0x43);
            forge_rt_memory_fault fault{};
            REQUIRE(reader.read(base, out, fault) == FORGE_RT_OK);
            const auto expected = out;
            REQUIRE(std::all_of(expected.begin(), expected.begin() + width,
                                [](uint8_t byte) { return byte == 0x27; }));
            REQUIRE(std::all_of(expected.begin() + width, expected.end(),
                                [](uint8_t byte) { return byte == 0xb1; }));
            std::fill(out.begin(), out.end(), 0x43);
            const auto sentinel = out;
            race.arrive_and_wait();
            pausedCopy = &gate;
            const auto status = forced
                                    ? forgeTestReadGuest(process, reader.thread, reader.id, base,
                                                         out.size(), out.data(), out.size(), &fault)
                                    : reader.read(base, out, fault);

            pausedCopy = nullptr;

            if (forced) {
                REQUIRE(status == FORGE_RT_OK);
            }

            if (status == FORGE_RT_OK) {
                REQUIRE(out == expected);
            } else {
                REQUIRE(status == FORGE_RT_GUEST_FAULT);
                expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_UNMAPPED});
                REQUIRE(out == sentinel);
            }

            retired.wait();
            const auto before = out;
            REQUIRE(reader.read(base, out, fault) == FORGE_RT_GUEST_FAULT);
            REQUIRE(out == before);
            REQUIRE(reader.leave() == FORGE_RT_OK);
        });

        race.arrive_and_wait();

        if (forced) {
            // The reader has validated both rows and is paused at the transfer. Prove
            // it still holds this process's mapping lock before racing actual removal.
            gate.copyApproved.wait();
            const std::unique_lock check(process->mutex, std::try_to_lock);
            REQUIRE(!check.owns_lock());
            gate.removalAttempted.count_down();
        }

        REQUIRE(forge_rt_detach_image(process, &image) == FORGE_RT_OK);
        first.reset();
        second.reset();
        retired.count_down();
        read.join();
        REQUIRE(forge_rt_thread_destroy(process, reader.thread) == FORGE_RT_OK);
    }

    void testStringService() {
        constexpr uint64_t base = 0x1000;
        std::array<uint8_t, 3> first{'a', 0x80, 'c'};
        std::array<uint8_t, 3> second{'d', 0, 0};
        uint64_t claim = 0;
        const forge_rt_image_region rows[]{
            {base, first.size(), first.data(), FORGE_RT_READ, nullptr},
            {base + first.size(), second.size(), second.data(), readWrite, &claim}};
        const forge_rt_image image{base, 64, rows, std::size(rows)};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        forge_rt_memory_fault fault{17, 18, 19};
        int32_t length = -99;
        auto call = [&](uint64_t address) {
            return forge_rt_lstrlen_a(instance.get(), active.thread, address, &length, &fault);
        };

        REQUIRE(call(0) == FORGE_RT_INVALID_INVOCATION && length == -99);
        REQUIRE(active.enter(image) == FORGE_RT_OK);
        REQUIRE(forge_rt_set_last_error(instance.get(), active.thread, 0xfedcba98) == FORGE_RT_OK);
        REQUIRE(call(base) == FORGE_RT_OK && length == 4);
        REQUIRE(first == (std::array<uint8_t, 3>{'a', 0x80, 'c'}));
        REQUIRE(second == (std::array<uint8_t, 3>{'d', 0, 0}));
        expectFault(fault, {17, 18, 19});
        REQUIRE(call(base + 4) == FORGE_RT_OK && length == 0);
        REQUIRE(call(0) == FORGE_RT_OK && length == 0);
        second[1] = 'e';
        REQUIRE(call(base) == FORGE_RT_OK && length == 5);
        second[2] = 'f';
        REQUIRE(call(base) == FORGE_RT_GUEST_FAULT && length == 5);
        expectFault(fault, {base + 6, FORGE_RT_READ, FORGE_RT_FAULT_UNMAPPED});
        REQUIRE(call(base + 32) == FORGE_RT_GUEST_FAULT && length == 5);
        REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, base, nullptr, &fault) ==
                FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, base, &length, nullptr) ==
                FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_lstrlen_a(nullptr, active.thread, base, &length, &fault) ==
                FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_lstrlen_a(instance.get(), 0, base, &length, &fault) ==
                FORGE_RT_INVALID_THREAD);
        uint32_t last = 0;
        REQUIRE(forge_rt_get_last_error(instance.get(), active.thread, &last) == FORGE_RT_OK);
        REQUIRE(last == 0xfedcba98);
        REQUIRE(active.leave() == FORGE_RT_OK);
        REQUIRE(call(base) == FORGE_RT_INVALID_INVOCATION && length == 5);
        REQUIRE(forge_rt_thread_destroy(instance.get(), active.thread) == FORGE_RT_OK);
        REQUIRE(call(base) == FORGE_RT_INVALID_THREAD && length == 5);
    }

    void testStringLimitAndOverflow() {
        constexpr size_t limit = size_t{1024} * 1024;
        std::vector<uint8_t> bytes(limit + 1, 'x');
        uint64_t claim = 0;
        const forge_rt_image_region row{0x1000, bytes.size(), bytes.data(), readWrite, &claim};
        const forge_rt_image image{row.start, row.size, &row, 1};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        REQUIRE(active.enter(image) == FORGE_RT_OK);
        int32_t length = -1;
        forge_rt_memory_fault fault{17, 18, 19};
        bytes[limit] = 0;
        REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, row.start, &length, &fault) ==
                FORGE_RT_RESOURCE_EXHAUSTED);
        REQUIRE(length == -1);
        expectFault(fault, {17, 18, 19});
        for (const size_t end : {size_t{255}, size_t{256}, size_t{257}, limit - 1}) {
            bytes[end] = 0;
            REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, row.start, &length, &fault) ==
                    FORGE_RT_OK);
            REQUIRE(length == static_cast<int32_t>(end));
            bytes[end] = 'x';
        }

        REQUIRE(active.leave() == FORGE_RT_OK);
        REQUIRE(forge_rt_detach_image(instance.get(), &image) == FORGE_RT_OK);
        uint8_t topByte = 0;
        uint64_t topClaim = 0;
        const forge_rt_image_region top{UINT64_MAX, 1, &topByte, readWrite, &topClaim};
        const forge_rt_image topImage{UINT64_MAX, 1, &top, 1};
        REQUIRE(active.enter(topImage) == FORGE_RT_OK);
        REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, UINT64_MAX, &length, &fault) ==
                FORGE_RT_OK);
        REQUIRE(length == 0);
        topByte = 'x';
        REQUIRE(forge_rt_lstrlen_a(instance.get(), active.thread, UINT64_MAX, &length, &fault) ==
                FORGE_RT_GUEST_FAULT);
        REQUIRE(length == 0);
        expectFault(fault, {UINT64_MAX, FORGE_RT_READ, FORGE_RT_FAULT_OVERFLOW});
        REQUIRE(active.leave() == FORGE_RT_OK);
        REQUIRE(forge_rt_detach_image(instance.get(), &topImage) == FORGE_RT_OK);
    }

    void testStringStackAndPermissions() {
        constexpr uint64_t base = 0x70000000;
        std::array<uint8_t, 64> bytes{}, marks{};
        const forge_rt_stack stack{base, bytes.size(), bytes.data(), marks.data(), base + 48};
        uint8_t denied = 0;
        uint64_t claim = 0;
        const forge_rt_image_region row{0x1000, 1, &denied, FORGE_RT_WRITE, &claim};
        const forge_rt_image image{row.start, row.size, &row, 1};
        const auto instance = createInstance();
        Activation active{instance.get(), createThread(instance.get())};
        REQUIRE(active.enter(image, &stack) == FORGE_RT_OK);
        int32_t length = 42;
        forge_rt_memory_fault fault{};
        auto call = [&](uint64_t address) {
            return forge_rt_lstrlen_a(instance.get(), active.thread, address, &length, &fault);
        };
        REQUIRE(call(row.start) == FORGE_RT_GUEST_FAULT && length == 42);
        expectFault(fault, {row.start, FORGE_RT_READ, FORGE_RT_FAULT_PERMISSION});
        for (uint8_t mark : {uint8_t{0}, uint8_t{17}}) {
            marks[0] = mark;
            REQUIRE(call(base) == FORGE_RT_GUEST_FAULT && length == 42);
            expectFault(fault, {base, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        }

        marks[0] = FORGE_RT_MARK_CONCRETE;
        REQUIRE(call(base) == FORGE_RT_OK && length == 0);
        bytes[0] = 'a';
        REQUIRE(call(base) == FORGE_RT_GUEST_FAULT && length == 0);
        expectFault(fault, {base + 1, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        marks[1] = FORGE_RT_MARK_CONCRETE;
        REQUIRE(call(base) == FORGE_RT_OK && length == 1);
        REQUIRE(call(stack.outerReturn) == FORGE_RT_GUEST_FAULT && length == 1);
        expectFault(fault, {stack.outerReturn, FORGE_RT_READ, FORGE_RT_FAULT_STACK});
        std::thread foreign(
            [&] { REQUIRE(call(base) == FORGE_RT_INVALID_INVOCATION && length == 1); });
        foreign.join();
        REQUIRE(active.leave() == FORGE_RT_OK);
    }

    void testConcurrentDetach() {
        const forge_rt_image execution{0x1000, 16, nullptr, 0};
        const auto process = createInstance();
        REQUIRE(forge_rt_register_image(process.get(), &execution) == FORGE_RT_OK);

        for (unsigned trial = 0; trial < 32; ++trial) {
            raceDetach(process.get(), execution, trial == 0);
        }
    }
} // namespace

// Linked only to the instrumented translation unit that runs the first removal trial.
void forgeMemoryTransferProbe() noexcept {
    REQUIRE(pausedCopy != nullptr);
    pausedCopy->copyApproved.count_down();
    pausedCopy->removalAttempted.wait();
}

void testRuntimeMemory() {
    testBoundedServiceBuffer();
    testStringService();
    testStringLimitAndOverflow();
    testStringStackAndPermissions();
    testSegments();
    testRangeBoundaries();
    testStack();
    testStackAndImageSegments();
    testClaims();
    testSharedImmutableBacking();
    testCompetingClaims();
    testReservations();
    testEntryRollback();
    testConcurrentEntries();
    testConcurrentDetach();
}
