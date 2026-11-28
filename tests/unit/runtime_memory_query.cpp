#include "../../runtime/src/core/process_image.h"
#include "forge/msvcrt_process.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {
    using namespace forge::runtime;
    constexpr uint64_t base = 0x140000000, page = FORGE_RT_GUEST_PAGE_SIZE;
    constexpr uint64_t output = FORGE_RT_STACK_BASE + 256, data = base + 3 * page;
    constexpr uint32_t rw = FORGE_RT_READ | FORGE_RT_WRITE, rx = FORGE_RT_READ | FORGE_RT_EXECUTE;

    void require(bool ok, const char *expression, int line) {
        if (!ok) {
            std::fprintf(stderr, "runtime_memory_query.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define CHECK(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    struct Query {
        explicit Query(forge_rt_execution &active) : active(active) {
            CHECK(forge_rt_current_invocation(active.instance, active.thread, &token) ==
                  FORGE_RT_OK);
            std::array<uint8_t, 48> seed;
            seed.fill(0xa5);
            CHECK(forge_rt_write_guest(active.instance, active.thread, token, output, seed.size(),
                                       seed.data(), seed.size(), &fault) == FORGE_RT_OK);
        }

        forge_rt_execution &active;
        forge_rt_invocation_token token{};
        forge_rt_memory_fault fault{};
        uint64_t result = UINT64_MAX;

        forge_rt_status call(uint64_t va, uint64_t destination = output, uint64_t length = 48) {
            return forge_rt_virtual_query(active.instance, active.thread, va, destination, length,
                                          &result, &fault);
        }

        template <typename T> T read(uint64_t va) {
            T value{};
            CHECK(forge_rt_read_guest(active.instance, active.thread, token, va, sizeof(T), &value,
                                      sizeof(T), &fault) == FORGE_RT_OK);
            return value;
        }

        forge_rt_status write(uint64_t va) {
            const uint32_t value = 42;
            return forge_rt_write_guest(active.instance, active.thread, token, va, sizeof(value),
                                        &value, sizeof(value), &fault);
        }

        void protect(uint64_t va, uint32_t mode) {
            int32_t ok = 0;
            CHECK(forge_rt_virtual_protect(active.instance, active.thread, va, 1, mode, output, &ok,
                                           &fault) == FORGE_RT_OK &&
                  ok == 1);
        }

        uint32_t error() const {
            uint32_t value{};
            CHECK(forge_rt_get_last_error(active.instance, active.thread, &value) == FORGE_RT_OK);
            return value;
        }
    };

    void checkSlots(Query &query) {
        auto &active = query.active;
        const auto before = query.read<std::array<uint8_t, 48>>(output);
        const uint64_t slot = output + 40;
        active.stackMarks[slot - FORGE_RT_STACK_BASE] = FORGE_RT_MARK_RETURN;
        CHECK(query.call(base, output) == FORGE_RT_GUEST_FAULT);
        CHECK(query.fault.address == slot && query.fault.reason == FORGE_RT_FAULT_STACK);
        active.stackMarks[slot - FORGE_RT_STACK_BASE] = FORGE_RT_MARK_CALLBACK_RETURN;
        dispatchGuestCallback(
            [&] { CHECK(query.call(base, output) == FORGE_RT_UNSUPPORTED_CALLBACK_RETURN); });
        active.stackMarks[slot - FORGE_RT_STACK_BASE] = FORGE_RT_MARK_CONCRETE;
        CHECK((query.read<std::array<uint8_t, 48>>(output) == before));

        CHECK(query.call(base, FORGE_RT_ENTRY_RSP - 40) == FORGE_RT_GUEST_FAULT);
        CHECK(query.fault.address == FORGE_RT_ENTRY_RSP &&
              query.fault.reason == FORGE_RT_FAULT_STACK);
    }

    void checkRejected(Query &query) {
        auto &active = query.active;
        const auto before = query.read<std::array<uint8_t, 48>>(data);
        const auto error = query.error();
        const auto result = query.result;
        std::thread foreign([&] { CHECK(query.call(base, data) == FORGE_RT_INVALID_INVOCATION); });
        foreign.join();

        forge_rt_memory_fault fault{};
        CHECK(forge_rt_virtual_query(active.instance, 0, base, data, 48, &query.result, &fault) ==
              FORGE_RT_INVALID_THREAD);
        CHECK(query.result == result && query.error() == error);
        CHECK((query.read<std::array<uint8_t, 48>>(data) == before));
    }

    void checkBoundaries() {
        constexpr uint32_t large = 0xf0000000;
        constexpr forge_rt_section_protection source[]{{0, large, rx}};
        PageProtections state{source, {}, {}};
        const Reservation adjacent[]{{base, large, nullptr, nullptr, &state},
                                     {base + large, large, nullptr, nullptr, &state}};
        const auto run = queryImageRegion(adjacent, base + page + 15);
        CHECK(run && run->base == base + page && run->allocation == base &&
              run->size == large - page);
        const auto next = queryImageRegion(adjacent, base + large);
        CHECK(next && next->allocation == base + large && next->size == large);

        const Reservation synthetic[]{{base + 100, 32, nullptr, nullptr, nullptr}};
        for (uint64_t offset : {0U, 100U, 132U, 4095U}) {
            CHECK(!queryImageRegion(synthetic, base + offset));
        }
    }

    void checkSourcePages(Query &query) {
        CHECK(query.call(data + page + 17) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint64_t>(output) == data + page);
        CHECK(query.read<uint64_t>(output + 24) == 2 * page);

        CHECK(query.call(base + 10 * page) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint64_t>(output + 24) == page);
        CHECK(query.write(base + 10 * page) == FORGE_RT_GUEST_FAULT);

        // The read-only section ends next to a real gap. Its complete forward span
        // is unknown. A relocation-affected page has two possible effective values.
        const auto before = query.read<std::array<uint8_t, 48>>(output);
        for (uint64_t va :
             {base + 6 * page, base + 7 * page, base + 8 * page, base + 12 * page, output}) {
            CHECK(query.call(va) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
            CHECK((query.read<std::array<uint8_t, 48>>(output) == before));
        }
    }

    void checkPublication(Query &query) {
        const auto initial = query.read<std::array<uint8_t, 48>>(data);
        for (const auto offset : {1U, 2U, 4U}) {
            CHECK(query.call(data, data + offset) == FORGE_RT_OK && query.result == 0);
            CHECK(query.error() == 998);
        }
        CHECK(query.call(data, data, UINT64_MAX) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 998);
        CHECK(query.call(data) == FORGE_RT_OK && query.read<uint32_t>(output + 36) == 8);
        CHECK(query.call(UINT64_MAX, data, 47) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 24);
        CHECK((query.read<std::array<uint8_t, 48>>(data) == initial));
        CHECK(query.call(base, UINT64_MAX - 7) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 998);
        CHECK(query.call(UINT64_MAX, 0) == FORGE_RT_OK && query.error() == 998);
        CHECK(query.call(UINT64_MAX, output) == FORGE_RT_OK && query.error() == 87);
        CHECK(query.call(base, output, UINT64_C(0x100000030)) == FORGE_RT_OK);
        CHECK(query.result == 0 && query.error() == 998);

        // A result can span adjacent rows and can end at the final writable byte.
        CHECK(query.call(base, data + page - 32) == FORGE_RT_OK && query.result == 48);
        CHECK(query.error() == 998 && query.read<uint64_t>(data + page - 32) == base);
        const auto secondEnd = data + 2 * page;
        CHECK(query.call(data + page, secondEnd - 48, 49) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint64_t>(secondEnd - 48 + 24) == 2 * page);
        CHECK(query.read<uint32_t>(secondEnd - 48 + 36) == 4);
        CHECK(query.read<uint8_t>(secondEnd) == 0);
        const auto end = data + 3 * page;
        CHECK(query.call(base, end - 48) == FORGE_RT_OK && query.result == 48);
        const auto before = query.read<std::array<uint8_t, 48>>(end - 48);
        CHECK(query.call(base, end - 48, 49) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 998);
        CHECK((query.read<std::array<uint8_t, 48>>(end - 48) == before));
        CHECK(query.call(base, end - 24) == FORGE_RT_OK && query.result == 0);
        CHECK((query.read<std::array<uint8_t, 48>>(end - 48) == before));
        CHECK(query.call(base, base + 10 * page) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
    }

    void checkUncertainWrite(Query &query) {
        const auto uncertain = base + 8 * page;
        CHECK(query.call(uncertain, uncertain, 47) == FORGE_RT_OK && query.result == 0);
        CHECK(query.call(uncertain) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
        // A failed probe touches the first page and then reaches omitted code.
        CHECK(query.call(uncertain, uncertain, page + 1) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 998 && query.read<uint32_t>(uncertain) == 0);
        CHECK(query.call(uncertain) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint32_t>(output + 36) == 4);
    }

    void checkOmittedProbes(Query &query) {
        constexpr auto omitted = base + 14 * page;
        constexpr auto destination = omitted - 48;
        CHECK(query.call(base, destination, 48) == FORGE_RT_OK && query.result == 48);
        CHECK(query.call(omitted) == FORGE_RT_OK && query.read<uint32_t>(output + 36) == 8);

        const auto saved = query.read<std::array<uint8_t, 48>>(destination);
        CHECK(query.call(base, destination + 8, 48) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
        // The sealed byte row at the third page start still takes precedence.
        CHECK(query.call(base, destination, 2 * page + 49) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
        CHECK((query.read<std::array<uint8_t, 48>>(destination) == saved));
        CHECK(query.call(omitted) == FORGE_RT_OK && query.read<uint32_t>(output + 36) == 8);

        CHECK(query.call(omitted, destination, 49) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint32_t>(destination + 36) == 4);
        CHECK(query.call(omitted) == FORGE_RT_OK && query.read<uint64_t>(output + 24) == page);
        CHECK(query.write(omitted) == FORGE_RT_GUEST_FAULT);
        uint8_t byte{};
        CHECK(forge_rt_read_guest(query.active.instance, query.active.thread, query.token, omitted,
                                  1, &byte, 1, &query.fault) == FORGE_RT_GUEST_FAULT);

        // A bad target still realizes the entire successfully probed prefix.
        CHECK(query.call(UINT64_MAX, destination, page + 49) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 87);
        CHECK(query.call(omitted) == FORGE_RT_OK && query.read<uint64_t>(output + 24) == 2 * page);
    }

    void checkSynthetic(Query &query) {
        auto &active = query.active;
        uint64_t heap{}, command{};
        CHECK(forge_rt_msvcrt_calloc(active.instance, active.thread, 1, 32, &heap) == FORGE_RT_OK);
        CHECK(forge_rt_get_command_line_a(active.instance, active.thread, &command) == FORGE_RT_OK);
        const uint64_t service = query.read<uint64_t>(base + 2 * page);
        CHECK(heap && command && service);
        const uint64_t addresses[]{0, 65535, heap, heap + 32, command, service, output};
        for (const auto address : addresses) {
            CHECK(query.call(address) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
        }

        // The 32-byte heap block accepts a probe at its first byte. The full
        // result still needs 48 writable bytes and cannot publish a prefix.
        CHECK(query.call(base, heap) == FORGE_RT_GUEST_FAULT);
        CHECK(query.fault.address == heap + 32 && query.read<uint64_t>(heap) == 0);
        CHECK(forge_rt_msvcrt_free(active.instance, active.thread, heap) == FORGE_RT_OK);
    }

    // The registered process owns this view until close. The test calls the adapter
    // once after the invocation retires and drops this borrow before destroying it.
    thread_local forge_rt_execution *retiredView = nullptr;

    void entry(forge_rt_execution *active) {
        retiredView = active;
        Query query(*active);
        CHECK(query.call(base + page + 21) == FORGE_RT_OK && query.result == 48);
        CHECK(query.read<uint64_t>(output) == base + page);
        CHECK(query.read<uint64_t>(output + 8) == base);
        CHECK(query.read<uint64_t>(output + 24) == page);
        CHECK(query.read<uint32_t>(output + 36) == 0x20);

        // Code and source-only writable pages have no guest byte mapping.
        uint8_t byte{};
        CHECK(forge_rt_read_guest(active->instance, active->thread, query.token, base + page, 1,
                                  &byte, 1, &query.fault) == FORGE_RT_GUEST_FAULT);
        checkSourcePages(query);
        checkSynthetic(query);
        checkSlots(query);
        checkRejected(query);

        if (active->rcx) {
            CHECK(query.write(data) == FORGE_RT_OK);
            query.protect(data + page, 2);
            CHECK(query.call(data + page) == FORGE_RT_OK && query.result == 48);
            CHECK(query.read<uint32_t>(output + 36) == 2);
            CHECK(query.write(data + page) == FORGE_RT_GUEST_FAULT);
        } else {
            CHECK(query.read<uint32_t>(data) == 0);
            CHECK(query.call(data) == FORGE_RT_OK && query.result == 48);
            CHECK(query.read<uint64_t>(output + 24) == 3 * page);
            CHECK(query.write(data + page) == FORGE_RT_OK);
            checkPublication(query);
        }
        checkOmittedProbes(query);
        checkUncertainWrite(query);
        active->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
        CHECK(query.call(base, data) == FORGE_RT_INVALID_STATE);
    }

    constexpr forge_rt_backing backing{5 * page + 9, nullptr, nullptr, 0};
    constexpr forge_rt_region_template rows[]{
        {base + 2 * page, 8, 0, 4 * page, FORGE_RT_READ},
        {data, page - 16, 0, 0, rw},
        {data + page - 16, 16, 0, page - 16, rw},
        {data + page, page, 0, page, rw},
        {data + 2 * page, page, 0, 2 * page, rw},
        {base + 8 * page, page, 0, 3 * page, rw},
        {base + 13 * page, page, 0, 4 * page + 8, rw},
        {base + 16 * page, 1, 0, 5 * page + 8, FORGE_RT_READ}};
    constexpr forge_rt_section_protection sections[]{
        {page, page, rx},
        {2 * page, page, FORGE_RT_READ},
        {3 * page, 2 * page, rw},
        {5 * page, page, rw},
        {6 * page, page, FORGE_RT_READ},
        {8 * page, page, rw | FORGE_RT_LOADER_MAY_WRITE},
        {9 * page, page, rx},
        {10 * page, page, rw},
        {11 * page, page, FORGE_RT_READ},
        {13 * page, 4 * page, rw},
        {17 * page, page, FORGE_RT_READ}};
    constexpr forge_rt_import getCommand{"kernel32.dll", "GetCommandLineA"};
    constexpr forge_rt_function_import addressOnly{2 * page, {"kernel32.dll", "VirtualQuery"}};
    constexpr forge_rt_artifact descriptor{FORGE_RT_PROTECTION_ARTIFACT_VERSION,
                                           base,
                                           18 * page,
                                           page,
                                           page,
                                           &backing,
                                           1,
                                           rows,
                                           std::size(rows),
                                           &getCommand,
                                           1,
                                           entry};
    constexpr forge_rt_protection_artifact artifact{
        {{{{descriptor, "query.exe"}, nullptr, 0}, &addressOnly, 1}, 3},
        sections,
        std::size(sections)};

    void legacyEntry(forge_rt_execution *active) {
        Query query(*active);
        CHECK(forge_rt_set_last_error(active->instance, active->thread, 73) == FORGE_RT_OK);
        for (const auto destination : {data, output}) {
            CHECK(query.call(base + page, destination) == FORGE_RT_UNSUPPORTED_MEMORY_QUERY);
            CHECK(query.result == UINT64_MAX && query.error() == 73);
        }
        CHECK(query.call(base, data + 1, 47) == FORGE_RT_OK && query.result == 0);
        CHECK(query.error() == 24);
        CHECK(query.call(base, data + 1) == FORGE_RT_OK && query.error() == 998);
        active->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkLegacyImage() {
        constexpr forge_rt_import service{"kernel32.dll", "VirtualQuery"};
        const forge_rt_artifact prefix{FORGE_RT_PE_ARTIFACT_VERSION,
                                       base,
                                       4 * page,
                                       page,
                                       page,
                                       nullptr,
                                       0,
                                       nullptr,
                                       0,
                                       &service,
                                       1,
                                       legacyEntry};
        const forge_rt_pe_artifact legacy{{{{prefix, "legacy.exe"}, nullptr, 0}, nullptr, 0}, 3};
        forge_rt_process *process{};
        CHECK(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
        CHECK(forge_rt_process_register(process, &legacy.functions.crt.named.artifact) ==
              FORGE_RT_OK);
        forge_rt_entry_inputs inputs{};
        forge_rt_process_result result{};
        CHECK(forge_rt_process_run(process, &inputs, &result) == FORGE_RT_OK);
        CHECK(result.kind == FORGE_RT_RETURNED && result.value == 42);
        CHECK(forge_rt_process_destroy(process) == FORGE_RT_OK);
    }

    void checkLoaderVersions() {
        constexpr uint32_t flagged = rw | FORGE_RT_LOADER_MAY_WRITE;
        constexpr forge_rt_section_protection source[]{{page, 4 * page, flagged},
                                                       {5 * page, page, FORGE_RT_READ}};
        PageProtections state{source, {}, {}};
        std::array<uint8_t, 4 * page> bytes{};
        uint64_t claim{};
        const forge_rt_image_region row{base + page, bytes.size(), bytes.data(), rw, &claim};
        const forge_rt_image pe{base, 6 * page, &row, 1};
        const Reservation image{base, 6 * page, &pe, nullptr, &state};
        const auto reservations = std::span(&image, 1);
        // Both v6 and v7 retain whole-section uncertainty.
        for (const auto headers : {0U, 512U}) {
            state.sizeOfHeaders = headers;
            CHECK(!queryImageRegion(reservations, base + 4 * page));
        }

        forge_rt_loader_pages runs[]{{2 * page, 3 * page}};
        state.loaderPages = runs;
        CHECK(!queryImageRegion(reservations, base + page)); // Forward boundary is unknown.
        CHECK(!queryImageRegion(reservations, base + 3 * page));
        const auto clean = queryImageRegion(reservations, base + 4 * page);
        CHECK(clean && clean->size == page && clean->access == PageAccess::ImageCopy);
        CHECK(state.permitsMapping(base, {base + page, 4 * page, 0, 0, rw}));
        ProtectionUpdate change;
        const auto protect = [&](uint64_t va) {
            return queryProtection(reservations, va, {va, va + page - 1}, {output, output + 3},
                                   change);
        };
        CHECK(protect(base + 4 * page) == ProtectionResult::Supported);
        CHECK(change.previous == PageAccess::ImageCopy);
        CHECK(protect(base + 2 * page) == ProtectionResult::Unsupported);
        state.recordWrite({base + 2 * page, base + 3 * page});
        CHECK(queryImageRegion(reservations, base + 2 * page)->size == 2 * page);
        CHECK(queryImageRegion(reservations, base + page)->size == page);

        forge_rt_loader_pages_artifact extended{{artifact, 512}, runs, 1};
        auto &protection = extended.header.protection;
        protection.sections = source;
        protection.sectionCount = std::size(source);
        auto &prefix = protection.pe.functions.crt.named.artifact;
        prefix.version = FORGE_RT_LOADER_PAGES_ARTIFACT_VERSION;
        CHECK(checkArtifact(prefix) == FORGE_RT_OK);
        extended.header.sizeOfHeaders = 2 * page;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.header.sizeOfHeaders = 0;
        CHECK(checkArtifact(prefix) == FORGE_RT_OK);
        for (const auto bad : {forge_rt_loader_pages{page + 1, 2 * page},
                               {0, page},
                               {3 * page, 2 * page},
                               {page, 5 * page}}) {
            runs[0] = bad;
            CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        }
        constexpr forge_rt_loader_pages duplicate[]{{page, 2 * page}, {2 * page, 3 * page}};
        extended.pages = duplicate;
        extended.pageRunCount = 2;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.pages = nullptr;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.pageRunCount = 0;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
    }

    void checkHeaderVersions() {
        forge_rt_section_protection text{2 * page, 2 * page, rx};
        PageProtections state{std::span(&text, 1), {}, {}};
        const Reservation image{base, 4 * page, nullptr, nullptr, &state};
        const auto reservations = std::span(&image, 1);
        CHECK(!queryImageRegion(reservations, base));
        CHECK(!queryImageRegion(reservations, base + page));
        state.sizeOfHeaders = 1024;
        const auto header = queryImageRegion(reservations, base);
        const auto gap = queryImageRegion(reservations, base + page);
        CHECK(header && header->state == ImageState::Committed && header->size == page);
        CHECK(gap && gap->state == ImageState::Reserved && gap->access == PageAccess::None);
        state.sizeOfHeaders = 2 * page;
        CHECK(queryImageRegion(reservations, base)->size == 2 * page);

        forge_rt_query_header_artifact extended{artifact, 1024};
        auto &prefix = extended.protection.pe.functions.crt.named.artifact;
        prefix.version = FORGE_RT_QUERY_HEADER_ARTIFACT_VERSION;
        prefix.regionCount = 0;
        extended.protection.sections = &text;
        extended.protection.sectionCount = 1;
        CHECK(checkArtifact(prefix) == FORGE_RT_OK);
        extended.sizeOfHeaders = 0;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.sizeOfHeaders = 2 * page + 1;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.sizeOfHeaders = 1024;
        text.rva = 3 * page;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);
        extended.protection.sectionCount = 0;
        CHECK(checkArtifact(prefix) == FORGE_RT_INVALID_ARGUMENT);

        state.sizeOfHeaders = 1024;
        CHECK(!state.permitsMapping(base, {base + 1023, 2, 0, 0, FORGE_RT_READ}));
        CHECK(state.permitsMapping(base, {base, 1024, 0, 0, FORGE_RT_READ}));
    }
} // namespace

void testRuntimeMemoryQuery() {
    checkBoundaries();
    checkHeaderVersions();
    checkLegacyImage();
    checkLoaderVersions();
    std::array<forge_rt_process *, 2> processes{};
    for (auto &process : processes) {
        CHECK(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
        CHECK(forge_rt_process_register(process, &artifact.pe.functions.crt.named.artifact) ==
              FORGE_RT_OK);
    }

    for (auto *process : processes) {
        forge_rt_entry_inputs inputs{process == processes.front(), 0};
        forge_rt_process_result result{};
        CHECK(forge_rt_process_run(process, &inputs, &result) == FORGE_RT_OK);
        CHECK(result.kind == FORGE_RT_RETURNED && result.value == 42);
        CHECK(retiredView);
        uint64_t returned = UINT64_MAX;
        forge_rt_memory_fault fault{};
        CHECK(forge_rt_virtual_query(retiredView->instance, retiredView->thread, data, data, 48,
                                     &returned, &fault) == FORGE_RT_INVALID_INVOCATION);
        CHECK(returned == UINT64_MAX);
        retiredView = nullptr;
    }

    for (auto *process : processes) {
        CHECK(forge_rt_process_destroy(process) == FORGE_RT_OK);
    }
}
