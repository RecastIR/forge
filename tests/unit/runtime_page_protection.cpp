#include "forge/process.h"

#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {
    constexpr uint64_t base = 0x10000000, page = FORGE_RT_GUEST_PAGE_SIZE;
    constexpr uint32_t rw = FORGE_RT_READ | FORGE_RT_WRITE;
    constexpr uint64_t output = FORGE_RT_STACK_BASE + 128;

    void require(bool value, int line) {
        if (!value) {
            std::fprintf(stderr, "page protection check failed at line %d\n", line);
            std::abort();
        }
    }

#define CHECK(...) require((__VA_ARGS__), __LINE__)

    struct Access {
        explicit Access(forge_rt_execution &execution) : execution(execution) {
            CHECK(forge_rt_current_invocation(execution.instance, execution.thread, &token) ==
                  FORGE_RT_OK);
        }

        forge_rt_execution &execution;
        forge_rt_invocation_token token{};
        forge_rt_memory_fault fault{};
        int32_t result = -1;

        forge_rt_status protect(uint64_t address, uint64_t count, uint32_t flags,
                                uint64_t out = output) {
            return forge_rt_virtual_protect(execution.instance, execution.thread, address, count,
                                            flags, out, &result, &fault);
        }

        uint32_t read(uint64_t address) {
            uint32_t value = 0;
            CHECK(forge_rt_read_guest(execution.instance, execution.thread, token, address, 4,
                                      &value, 4, &fault) == FORGE_RT_OK);
            return value;
        }

        forge_rt_status write(uint64_t address, uint32_t value) {
            return forge_rt_write_guest(execution.instance, execution.thread, token, address, 4,
                                        &value, 4, &fault);
        }
    };

    void legacyEntry(forge_rt_execution *execution) {
        Access access(*execution);
        CHECK(access.protect(base, 1, 2) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.result == -1 && access.write(base, 42) == FORGE_RT_OK);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void exercise(forge_rt_execution *execution) {
        Access access(*execution);
        CHECK(access.read(base) == 0);
        const auto alias = base + 2 * page;
        CHECK(access.protect(alias, 1, 2, alias + 12) == FORGE_RT_OK && access.result == 1);
        CHECK(access.read(alias + 12) == 0);
        CHECK(access.protect(alias, 1, 4) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.protect(alias, 1, 4) == FORGE_RT_OK && access.read(output) == 4);
        CHECK(access.protect(base + page, 1, 2) == FORGE_RT_OK && access.read(output) == 8);
        CHECK(access.protect(base + page, 1, 4) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.protect(base + page, 1, 4, base + page + 1) == FORGE_RT_OK);
        CHECK(access.read(base + page + 1) == 4);
        CHECK(access.protect(base + page, 1, 2) == FORGE_RT_OK && access.read(output) == 4);
        CHECK(access.protect(base + page, 1, 4) == FORGE_RT_OK);
        CHECK(access.write(base + page + 1, 0) == FORGE_RT_OK);
        CHECK(access.write(base, 42) == FORGE_RT_OK);
        CHECK(access.protect(base + 11, 1, 2) == FORGE_RT_OK && access.result == 1);
        CHECK(access.read(output) == 4);
        CHECK(access.write(base, 41) == FORGE_RT_GUEST_FAULT);
        CHECK(access.fault.address == base && access.fault.reason == FORGE_RT_FAULT_PERMISSION);

        std::thread foreign([&] {
            int32_t result = -1;
            forge_rt_memory_fault fault{};
            CHECK(forge_rt_virtual_protect(execution->instance, execution->thread, base, page, 4,
                                           output, &result, &fault) == FORGE_RT_INVALID_INVOCATION);
            CHECK(result == -1);
        });
        foreign.join();

        // The third guest page aliases the first private backing. Its own VA remains writable.
        CHECK(access.write(base + 2 * page, 19) == FORGE_RT_OK);
        CHECK(access.read(base) == 19);
        CHECK(access.protect(base, 1, 2) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.protect(base + page - 1, 2, 2) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.write(base + page, 12) == FORGE_RT_GUEST_FAULT);

        // A single scalar can cross a permission boundary inside one native row.
        CHECK(access.protect(base, 1, 4) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.write(base + page - 2, 0x12345678) == FORGE_RT_GUEST_FAULT);
        CHECK(access.fault.address == base + page && access.read(base + page - 2) == 0);
        CHECK(forge_rt_resolve_process_scalar(execution, base + page - 2, 4, FORGE_RT_READ) !=
              nullptr);
        CHECK(access.write(output, 0x12345678) == FORGE_RT_OK);

        // A missing tail in this image is not proof of an uncommitted Windows page.
        CHECK(access.protect(base + 2 * page, 2 * page, 2) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.protect(base + 3 * page, page + 1, 2) == FORGE_RT_OK && access.result == 0);
        CHECK(access.protect(base - page, 1, 2) == FORGE_RT_OK && access.result == 0);
        CHECK(access.read(output) == 1);
        CHECK(access.write(output, 0x12345678) == FORGE_RT_OK);
        CHECK(access.protect(UINT64_MAX - 1, 4, 2) == FORGE_RT_OK && access.result == 0);
        CHECK(access.protect(base, 1, 3) == FORGE_RT_OK && access.result == 0);
        CHECK(access.read(output) == 0x12345678);
        CHECK(access.write(base + 2 * page, 27) == FORGE_RT_OK);
        CHECK(access.protect(base, 1, 0x80000002) == FORGE_RT_OK && access.result == 0);
        CHECK(access.read(output) == 1);
        CHECK(access.protect(base, 1, 0x20000002) == FORGE_RT_OK && access.result == 1);
        CHECK(access.protect(base, 1, 4) == FORGE_RT_OK && access.read(output) == 2);
        CHECK(access.write(output, 0x12345678) == FORGE_RT_OK);
        CHECK(access.protect(base, 1, 0x102) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.protect(base, 1, 0x20) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.protect(FORGE_RT_STACK_BASE, 1, 2) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.read(output) == 0x12345678 && access.write(base, 17) == FORGE_RT_OK);
        CHECK(access.protect(base, 1, 2, 1) == FORGE_RT_OK && access.result == 0);
        uint32_t error{};
        CHECK(forge_rt_get_last_error(execution->instance, execution->thread, &error) ==
                  FORGE_RT_OK &&
              error == 998);
        CHECK(access.protect(base, 1, 2, base + page) == FORGE_RT_OK && access.result == 0);
        CHECK(access.protect(base, 1, 2, base + 3 * page) == FORGE_RT_UNSUPPORTED_PAGE_PROTECTION);
        CHECK(access.protect(base, 1, 2, 0) == FORGE_RT_OK && access.result == 0);
        CHECK(access.write(base, 77) == FORGE_RT_OK);
        CHECK(access.protect(base, 1, 4, base + 12) == FORGE_RT_OK && access.read(base + 12) == 4);
        CHECK(access.protect(base, 1, 2, base + 12) == FORGE_RT_OK && access.result == 1);
        CHECK(access.read(base + 12) == 4 && access.write(base, 1) == FORGE_RT_GUEST_FAULT);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }
} // namespace

void testRuntimePageProtection() {
    constexpr forge_rt_backing backing{2 * page, nullptr, nullptr, 0};
    constexpr forge_rt_region_template rows[]{{base, 2 * page, 0, 0, rw},
                                              {base + 2 * page, page, 0, 0, rw}};
    constexpr forge_rt_section_protection source{0, 4 * page, rw};
    forge_rt_artifact descriptor{FORGE_RT_PROTECTION_ARTIFACT_VERSION,
                                 base,
                                 4 * page,
                                 0,
                                 0,
                                 &backing,
                                 1,
                                 rows,
                                 2,
                                 nullptr,
                                 0,
                                 exercise};
    forge_rt_protection_artifact artifact{
        {{{{descriptor, "test.exe"}, nullptr, 0}, nullptr, 0}, 3}, &source, 1};

    for (int i = 0; i < 3; ++i) {
        forge_rt_process *process = nullptr;
        CHECK(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
        auto broken = artifact;
        broken.sections = nullptr;
        CHECK(forge_rt_process_register(process, &broken.pe.functions.crt.named.artifact) ==
              FORGE_RT_INVALID_ARGUMENT);
        broken = artifact;
        const forge_rt_section_protection contradiction{0, 4 * page,
                                                        FORGE_RT_READ | FORGE_RT_EXECUTE};
        broken.sections = &contradiction;
        CHECK(forge_rt_process_register(process, &broken.pe.functions.crt.named.artifact) ==
              FORGE_RT_INVALID_ARGUMENT);

        // Binding fails after the PE, original protection spans and private backing exist.
        const forge_rt_function_import missing{3 * page, {"kernel32.dll", "VirtualProtect"}};
        broken = artifact;
        broken.pe.functions.functionImports = &missing;
        broken.pe.functions.functionImportCount = 1;
        CHECK(forge_rt_process_register(process, &broken.pe.functions.crt.named.artifact) ==
              FORGE_RT_INVALID_ARGUMENT);
        CHECK(forge_rt_process_register(process, &artifact.pe.functions.crt.named.artifact) ==
              FORGE_RT_OK);
        forge_rt_process_result result{};
        CHECK(forge_rt_process_run(process, nullptr, &result) == FORGE_RT_OK && result.value == 42);
        CHECK(forge_rt_process_destroy(process) == FORGE_RT_OK);
    }

    auto legacy = artifact.pe;
    legacy.functions.crt.named.artifact.version = FORGE_RT_PE_ARTIFACT_VERSION;
    legacy.functions.crt.named.artifact.entry = legacyEntry;
    forge_rt_process *process = nullptr;
    CHECK(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
    CHECK(forge_rt_process_register(process, &legacy.functions.crt.named.artifact) == FORGE_RT_OK);
    forge_rt_process_result result{};
    CHECK(forge_rt_process_run(process, nullptr, &result) == FORGE_RT_OK && result.value == 42);
    CHECK(forge_rt_process_destroy(process) == FORGE_RT_OK);
}
