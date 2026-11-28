#include "process_image.h"

#include "forge/guest_range.h"

#include <algorithm>
#include <bit>
#include <cstring>

namespace forge::runtime {
    namespace {
        template <typename T> bool validTable(const T *table, uint64_t count) {
            return (count == 0 || table != nullptr) && count <= PTRDIFF_MAX / sizeof(T);
        }

        bool validBacking(const forge_rt_backing &backing) {
            if (!backing.size || backing.size > PTRDIFF_MAX ||
                !validTable(backing.fragments, backing.fragmentCount) ||
                (backing.immutableBytes && backing.fragmentCount)) {
                return false;
            }

            uint64_t previousEnd = 0;

            for (const auto &fragment : tableRows(backing.fragments, backing.fragmentCount)) {
                if (!fragment.size || !fragment.bytes || fragment.offset < previousEnd ||
                    fragment.offset > backing.size ||
                    fragment.size > backing.size - fragment.offset) {
                    return false;
                }

                previousEnd = fragment.offset + fragment.size;
            }

            return true;
        }

        bool validHeaderExtent(const forge_rt_artifact &artifact,
                               const forge_rt_query_header_artifact &extended) {
            const auto sections =
                tableRows(extended.protection.sections, extended.protection.sectionCount);
            if (!extended.sizeOfHeaders || sections.empty() ||
                extended.sizeOfHeaders > sections.front().rva) {
                return false;
            }

            // Some supported SectionAlignment must put the first section exactly
            // after the headers. A larger arbitrary hole has no proved Windows state.
            uint64_t alignmentBits = artifact.base | artifact.size;
            for (const auto &section : sections) {
                alignmentBits |= section.rva;
            }
            const auto alignment = uint64_t{1} << std::countr_zero(alignmentBits);
            return alignment >= FORGE_RT_GUEST_PAGE_SIZE &&
                   sections.front().rva - extended.sizeOfHeaders < alignment;
        }

        bool validLoaderPages(const forge_rt_loader_pages_artifact &extended) {
            if (!extended.pageRunCount || !validTable(extended.pages, extended.pageRunCount)) {
                return false;
            }

            auto runs = tableRows(extended.pages, extended.pageRunCount);
            const auto &source = extended.header.protection;
            constexpr auto flags = FORGE_RT_READ | FORGE_RT_WRITE | FORGE_RT_LOADER_MAY_WRITE;
            constexpr uint32_t mask = FORGE_RT_GUEST_PAGE_SIZE - 1;
            for (const auto &section : tableRows(source.sections, source.sectionCount)) {
                if (section.attributes != flags || (section.rva & mask)) {
                    continue;
                }

                const uint64_t end = uint64_t{section.rva} + section.size;
                if (runs.empty() || runs.front().firstRva >= end) {
                    return false;
                }
                uint64_t next = section.rva;
                while (!runs.empty() && runs.front().firstRva < end) {
                    const auto run = runs.front();
                    if (((run.firstRva | run.lastRva) & mask) || run.firstRva < next ||
                        run.lastRva < run.firstRva || run.lastRva >= end) {
                        return false;
                    }
                    next = uint64_t{run.lastRva} + FORGE_RT_GUEST_PAGE_SIZE;
                    runs = runs.subspan(1);
                }
            }
            return runs.empty();
        }

        forge_rt_process_result runtimeFailure(forge_rt_status status) {
            return {FORGE_RT_RUNTIME_FAILURE, status, 0, {}, 0};
        }

        forge_rt_process_result checkedResult(const forge_rt_process_result &result) {
            switch (result.kind) {
            case FORGE_RT_EXIT_PROCESS:
                if (result.value > UINT32_MAX) {
                    break;
                }

                [[fallthrough]];
            case FORGE_RT_RETURNED:
                if (result.status == FORGE_RT_OK) {
                    return result;
                }

                break;
            case FORGE_RT_EXECUTION_FAULT:
                if (result.status == FORGE_RT_GUEST_FAULT &&
                    (result.fault == FORGE_RT_FAULT_MEMORY ||
                     result.fault == FORGE_RT_FAULT_CONTROL ||
                     result.fault == FORGE_RT_FAULT_ABI)) {
                    return result;
                }

                break;
            case FORGE_RT_UNSUPPORTED:
                return result;
            case FORGE_RT_RUNTIME_FAILURE:
                if (result.status != FORGE_RT_OK && result.status != FORGE_RT_GUEST_FAULT) {
                    return result;
                }

                break;
            default:
                break;
            }

            return runtimeFailure(FORGE_RT_INTERNAL_ERROR);
        }

    } // namespace

    forge_rt_status checkArtifact(const forge_rt_artifact &artifact) {
        if (artifact.version < FORGE_RT_ARTIFACT_VERSION ||
            artifact.version > FORGE_RT_LOADER_PAGES_ARTIFACT_VERSION) {
            return FORGE_RT_ABI_MISMATCH;
        }

        const auto image = GuestRange::fromOffset({artifact.base}, 0, artifact.size);
        constexpr auto stack =
            GuestRange::fromOffset({FORGE_RT_STACK_BASE}, 0, FORGE_RT_STACK_SIZE);

        if (!image || !stack || !artifact.entry || artifact.entryRva >= artifact.size ||
            artifact.peEntryRva >= artifact.size || artifact.entryRva > UINT32_MAX ||
            artifact.peEntryRva > UINT32_MAX ||
            !validTable(artifact.backings, artifact.backingCount) ||
            !validTable(artifact.regions, artifact.regionCount) ||
            !validTable(artifact.imports, artifact.importCount)) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        if (image->overlaps(*stack)) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        if (artifact.version >= FORGE_RT_CRT_ARTIFACT_VERSION) {
            const auto &crt = *reinterpret_cast<const forge_rt_crt_artifact *>(&artifact);

            if (!validTable(crt.dataImports, crt.dataImportCount)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        if (artifact.version >= FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION) {
            const auto &extended =
                *reinterpret_cast<const forge_rt_function_import_artifact *>(&artifact);

            if (!validTable(extended.functionImports, extended.functionImportCount)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        if (artifact.version >= FORGE_RT_PROTECTION_ARTIFACT_VERSION) {
            const auto &extended =
                *reinterpret_cast<const forge_rt_protection_artifact *>(&artifact);
            if (!validTable(extended.sections, extended.sectionCount)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            uint64_t previousEnd = 0;
            for (const auto &section : tableRows(extended.sections, extended.sectionCount)) {
                const auto end = uint64_t{section.rva} + section.size;
                constexpr auto allowed = FORGE_RT_READ | FORGE_RT_WRITE | FORGE_RT_EXECUTE |
                                         FORGE_RT_FIXED_PROTECTION | FORGE_RT_LOADER_MAY_WRITE;
                if (!section.size || section.rva < previousEnd || end > artifact.size ||
                    (section.attributes & ~allowed)) {
                    return FORGE_RT_INVALID_ARGUMENT;
                }
                previousEnd = end;
            }
        }

        if (artifact.version >= FORGE_RT_QUERY_HEADER_ARTIFACT_VERSION) {
            const auto &header =
                *reinterpret_cast<const forge_rt_query_header_artifact *>(&artifact);
            if ((artifact.version == FORGE_RT_QUERY_HEADER_ARTIFACT_VERSION ||
                 header.sizeOfHeaders) &&
                !validHeaderExtent(artifact, header)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }
        if (artifact.version == FORGE_RT_LOADER_PAGES_ARTIFACT_VERSION &&
            !validLoaderPages(
                *reinterpret_cast<const forge_rt_loader_pages_artifact *>(&artifact))) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        for (const auto &binding : tableRows(artifact.imports, artifact.importCount)) {
            if (!binding.dll || !*binding.dll || !binding.name || !*binding.name) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        for (const auto &backing : tableRows(artifact.backings, artifact.backingCount)) {
            if (!validBacking(backing)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        return FORGE_RT_OK;
    }

    ExecutionContext::ExecutionContext() {
        constexpr size_t returnOffset = FORGE_RT_ENTRY_RSP - FORGE_RT_STACK_BASE;
        static_assert(FORGE_RT_ENTRY_RSP % 16 == 8);

        for (unsigned i = 0; i < sizeof(uint64_t); ++i) {
            bytes[returnOffset + i] = static_cast<uint8_t>(FORGE_RT_RETURN_MARKER >> (8 * i));
            marks[returnOffset + i] = FORGE_RT_MARK_RETURN;
        }

        view.stackBytes = bytes.data();
        view.stackMarks = marks.data();
    }

    forge_rt_status ProcessImage::bindRegions() {
        const bool hasProtection = artifact.version >= FORGE_RT_PROTECTION_ARTIFACT_VERSION;
        if (hasProtection) {
            const auto &extended =
                *reinterpret_cast<const forge_rt_protection_artifact *>(&artifact);
            protections.original = tableRows(extended.sections, extended.sectionCount);
        }
        if (artifact.version >= FORGE_RT_QUERY_HEADER_ARTIFACT_VERSION) {
            protections.sizeOfHeaders =
                reinterpret_cast<const forge_rt_query_header_artifact *>(&artifact)->sizeOfHeaders;
        }

        if (artifact.version == FORGE_RT_LOADER_PAGES_ARTIFACT_VERSION) {
            const auto &extended =
                *reinterpret_cast<const forge_rt_loader_pages_artifact *>(&artifact);
            protections.loaderPages = tableRows(extended.pages, extended.pageRunCount);
        }

        backings.resize(static_cast<size_t>(artifact.backingCount));
        const auto templates = tableRows(artifact.backings, artifact.backingCount);

        for (size_t i = 0; i < templates.size(); ++i) {
            const auto &source = templates[i];

            if (source.immutableBytes) {
                continue;
            }

            auto &storage = backings[i].bytes;
            storage.resize(static_cast<size_t>(source.size));

            for (const auto &fragment : tableRows(source.fragments, source.fragmentCount)) {
                std::memcpy(storage.data() + fragment.offset, fragment.bytes, fragment.size);
            }
        }

        regions.reserve(static_cast<size_t>(artifact.regionCount));

        for (const auto &row : tableRows(artifact.regions, artifact.regionCount)) {
            if (row.backing >= templates.size() ||
                (hasProtection && !protections.permitsMapping(artifact.base, row))) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const auto &source = templates[row.backing];

            if (row.offset > source.size || !row.size || row.size > source.size - row.offset ||
                (source.immutableBytes && (row.permissions & FORGE_RT_WRITE))) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const auto *start = static_cast<const uint8_t *>(source.immutableBytes);
            uint64_t *claim = nullptr;

            if (!start) {
                auto &storage = backings[row.backing];
                start = storage.bytes.data();
                claim = &storage.claim;
            }

            regions.push_back({row.start, row.size, start + row.offset, row.permissions, claim});
        }

        image = {artifact.base, artifact.size, regions.data(), regions.size()};
        return FORGE_RT_OK;
    }

    forge_rt_status ProcessImage::prepare() {
        const auto bound = bindRegions();

        if (bound != FORGE_RT_OK) {
            return bound;
        }

        const auto created = forge_rt_thread_create(&instance, &execution.thread);

        if (created != FORGE_RT_OK) {
            return created;
        }

        execution.view.instance = &instance;
        execution.view.thread = execution.thread;
        execution.view.regions = regions.data();

        const auto registered = forge_rt_register_image(&instance, &image);
        if (registered == FORGE_RT_OK && artifact.version >= FORGE_RT_PROTECTION_ARTIFACT_VERSION) {
            // The occurrence is unpublished. Its PE is the first registered reservation.
            instance.reservations.front().protections = &protections;
        }

        return registered;
    }

    forge_rt_status ProcessImage::reserveImportAddresses(uint64_t size, uint64_t alignment) {
        // Both the PE and the parameters are registered. The primary stack will publish its
        // reservation only on entry, so exclude it when choosing the service address range.
        const auto &occupied = instance.reservations;
        auto base = findGuestAllocation(occupied, size, alignment);

        if (base && base < FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE &&
            FORGE_RT_STACK_BASE < base + size) {
            base = findGuestAllocation(occupied, size, alignment,
                                       FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE);
        }

        if (!base) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        functionAddresses = {base, size, nullptr, 0};
        return forge_rt_register_image(&instance, &functionAddresses);
    }

    void ProcessImage::reservePrimaryStackSlot() {
        // All persistent mappings are now registered. Admission inserts the active stack.
        instance.reservations.reserve(instance.reservations.size() + 1);
    }

    void ProcessImage::retire() noexcept {
        // Rollback and close are quiescent. Release borrows while every descriptor,
        // stack, claim word and mapped byte is still owned by the occurrence.
        instance.reservations.clear();
        instance.threads.clear();
        instance.managedExecution = nullptr;
        instance.windows = nullptr;
    }

    forge_rt_status checkManagedInvocation(const forge_rt_instance &owner,
                                           forge_rt_thread_token thread) noexcept {
        const auto *execution = owner.managedExecution;

        if (!execution) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto entry = owner.threads.find(thread);

        if (entry == owner.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (!entry->second.invocation || executingInvocation != entry->second.invocation ||
            execution->thread != thread) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        return FORGE_RT_OK;
    }

    forge_rt_status checkPendingExecution(const forge_rt_instance &owner,
                                          forge_rt_thread_token thread) noexcept {
        const auto status = checkManagedInvocation(owner, thread);
        if (status != FORGE_RT_OK) {
            return status;
        }

        return owner.managedExecution->result.kind ? FORGE_RT_INVALID_STATE : FORGE_RT_OK;
    }

    forge_rt_status publishTerminalResult(forge_rt_instance *instance, forge_rt_thread_token thread,
                                          const forge_rt_process_result &result) noexcept {
        return withInstance(instance, [&](auto &owner) {
            const auto status = checkPendingExecution(owner, thread);
            if (status == FORGE_RT_OK) {
                owner.managedExecution->result = result;
            }

            return status;
        });
    }

    forge_rt_process_result ProcessImage::run() noexcept {
        forge_rt_invocation_token invocation = 0;
        const auto status = enterInvocation(&instance, execution.thread, &image, &execution.stack,
                                            &invocation, Admission::Process);

        if (status != FORGE_RT_OK) {
            return runtimeFailure(status);
        }

        auto &context = execution.view;

        try {
            artifact.entry(&context);
        } catch (const std::bad_alloc &) {
            context.result = runtimeFailure(FORGE_RT_RESOURCE_EXHAUSTED);
        } catch (...) {
            context.result = runtimeFailure(FORGE_RT_INTERNAL_ERROR);
        }

        const auto leave =
            leaveInvocation(&instance, execution.thread, invocation, Admission::Process);
        return leave == FORGE_RT_OK ? checkedResult(context.result) : runtimeFailure(leave);
    }
} // namespace forge::runtime
