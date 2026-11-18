#include "forge/process.h"

#include "forge/guest_range.h"
#include "forge/service_signature.h"
#include "instance.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

using namespace forge;
using namespace forge::runtime;

namespace {
    template <typename T> bool validTable(const T *table, uint64_t count) {
        return (count == 0 || table != nullptr) && count <= PTRDIFF_MAX / sizeof(T);
    }

    template <typename T> std::span<const T> tableRows(const T *table, uint64_t count) {
        return {table, static_cast<size_t>(count)};
    }

    std::span<const forge_rt_data_import> dataImports(const forge_rt_artifact &artifact) {
        if (artifact.version < FORGE_RT_CRT_ARTIFACT_VERSION) {
            return {};
        }

        const auto &crt = *reinterpret_cast<const forge_rt_crt_artifact *>(&artifact);
        return tableRows(crt.dataImports, crt.dataImportCount);
    }

    std::span<const forge_rt_function_import> functionImports(const forge_rt_artifact &artifact) {
        if (artifact.version != FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION) {
            return {};
        }

        const auto &extended =
            *reinterpret_cast<const forge_rt_function_import_artifact *>(&artifact);
        return tableRows(extended.functionImports, extended.functionImportCount);
    }

    bool fromDll(const forge_rt_import &import, std::string_view expected) {
        // The service catalogue uses lowercase DLL names; hand-authored descriptors can
        // carry the original PE spelling. Windows export names are case-sensitive.
        const auto asciiLower = [](char c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; };
        return std::ranges::equal(std::string_view(import.dll), expected, {}, asciiLower);
    }

    bool usesStandardHandles(const forge_rt_import &import) {
        const std::string_view name(import.name);
        return (name == win64::getStdHandle.name || name == win64::writeFile.name) &&
               fromDll(import, win64::getStdHandle.dll);
    }

    bool usesCommandLine(const forge_rt_import &import) {
        const std::string_view name(import.name);
        return (name == win64::getCommandLineA.name || name == win64::getCommandLineW.name) &&
               fromDll(import, win64::getCommandLineA.dll);
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
                fragment.offset > backing.size || fragment.size > backing.size - fragment.offset) {
                return false;
            }

            previousEnd = fragment.offset + fragment.size;
        }

        return true;
    }

    forge_rt_status checkArtifact(const forge_rt_artifact &artifact) {
        if (artifact.version != FORGE_RT_ARTIFACT_VERSION &&
            artifact.version != FORGE_RT_NAMED_ARTIFACT_VERSION &&
            artifact.version != FORGE_RT_CRT_ARTIFACT_VERSION &&
            artifact.version != FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION) {
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

        if (artifact.version == FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION) {
            const auto &extended =
                *reinterpret_cast<const forge_rt_function_import_artifact *>(&artifact);

            if (!validTable(extended.functionImports, extended.functionImportCount)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
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

    struct WritableBacking {
        std::vector<uint8_t> bytes;
        uint64_t claim = 0;
    };

    struct ExecutionContext {
        ExecutionContext() {
            constexpr size_t returnOffset = FORGE_RT_ENTRY_RSP - FORGE_RT_STACK_BASE;
            static_assert(FORGE_RT_ENTRY_RSP % 16 == 8);

            for (unsigned i = 0; i < sizeof(uint64_t); ++i) {
                bytes[returnOffset + i] = static_cast<uint8_t>(FORGE_RT_RETURN_MARKER >> (8 * i));
                marks[returnOffset + i] = FORGE_RT_MARK_RETURN;
            }

            view.stackBytes = bytes.data();
            view.stackMarks = marks.data();
        }

        ExecutionContext(const ExecutionContext &) = delete;
        ExecutionContext &operator=(const ExecutionContext &) = delete;

        std::array<uint8_t, FORGE_RT_STACK_SIZE> bytes{}, marks{};
        forge_rt_stack stack{FORGE_RT_STACK_BASE, FORGE_RT_STACK_SIZE, bytes.data(), marks.data(),
                             FORGE_RT_ENTRY_RSP};
        forge_rt_thread_token thread = 0;
        forge_rt_execution view{};
    };

    struct ProcessImage {
        explicit ProcessImage(const forge_rt_artifact &artifact) : artifact(artifact) {}

        forge_rt_status initialize(const forge_rt_process_startup &startup);
        forge_rt_process_result run() noexcept;

        const forge_rt_artifact &artifact;
        std::vector<WritableBacking> backings;
        std::vector<forge_rt_image_region> regions;
        forge_rt_image image{};
        forge_rt_image functionAddresses{};
        ExecutionContext execution;
        // Destroy the reservation/thread tables before releasing any storage they borrow.
        forge_rt_instance instance;

      private:
        forge_rt_status bindRegions();
        forge_rt_status bindImports(const std::optional<CrtParameters> &crt,
                                    std::span<const forge_rt_data_import> data,
                                    std::span<const forge_rt_function_import> functions);
        forge_rt_status reserveFunctionAddresses();
    };

    forge_rt_status ProcessImage::bindRegions() {
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
            if (row.backing >= templates.size()) {
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

    constexpr uint64_t functionStride = 16;

    uint64_t functionAddress(uint64_t base, const forge_rt_import &target) {
        if (!target.dll || !target.name) {
            return 0;
        }

        const auto *service = std::ranges::find_if(win64::services, [&](const auto &candidate) {
            return candidate.name == target.name && fromDll(target, candidate.dll);
        });
        if (service == std::end(win64::services)) {
            return 0;
        }

        const auto index = static_cast<uint64_t>(service - std::begin(win64::services));
        return base + index * functionStride;
    }

    forge_rt_status ProcessImage::reserveFunctionAddresses() {
        // Both the PE and the parameters are registered. The primary stack will publish its
        // reservation only on entry, so exclude it when choosing the service address range.
        constexpr uint64_t size = std::size(win64::services) * functionStride;
        const auto &occupied = instance.reservations;
        auto base = findGuestAllocation(occupied, size, functionStride);

        if (base && base < FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE &&
            FORGE_RT_STACK_BASE < base + size) {
            base = findGuestAllocation(occupied, size, functionStride,
                                       FORGE_RT_STACK_BASE + FORGE_RT_STACK_SIZE);
        }

        if (!base) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        functionAddresses = {base, size, nullptr, 0};
        return forge_rt_register_image(&instance, &functionAddresses);
    }

    forge_rt_status ProcessImage::bindImports(const std::optional<CrtParameters> &crt,
                                              std::span<const forge_rt_data_import> data,
                                              std::span<const forge_rt_function_import> functions) {
        const auto templates = tableRows(artifact.regions, artifact.regionCount);
        // A guest RVA may alias a different row of the same private backing. Check the
        // bytes the loader will patch as well as the guest addresses it promises to bind.
        std::map<std::pair<uint64_t, uint64_t>, uint64_t> slots;
        const auto overlapsSlot = [&](uint64_t backing, uint64_t offset, uint64_t size) {
            const auto after = slots.lower_bound({backing, offset + size});

            if (after == slots.begin()) {
                return false;
            }

            const auto &[slotBacking, start] = std::prev(after)->first;
            return backing == slotBacking && start + sizeof(uint64_t) > offset;
        };
        const auto stage = [&](uint32_t rva, uint64_t value, uint64_t &previousEnd) {
            const auto end = uint64_t{rva} + sizeof(uint64_t);
            if (!value || rva < previousEnd || end > artifact.size) {
                return false;
            }

            previousEnd = end;
            const auto slot = artifact.base + rva;
            const auto after =
                std::ranges::upper_bound(templates, slot, {}, &forge_rt_region_template::start);

            if (after == templates.begin()) {
                return false;
            }

            const auto &row = *std::prev(after);
            const auto offset = slot - row.start;

            if (backings[row.backing].bytes.empty() || !(row.permissions & FORGE_RT_READ) ||
                offset > row.size || sizeof(value) > row.size - offset) {
                return false;
            }

            const auto start = row.offset + offset;

            if (overlapsSlot(row.backing, start, sizeof(value))) {
                return false;
            }

            slots.emplace(std::pair{row.backing, start}, value);
            return true;
        };

        uint64_t previousEnd = 0;
        for (const auto &binding : data) {
            if (!crt || !stage(binding.slotRva, crt->dataAddress(binding.kind), previousEnd)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        previousEnd = 0;
        for (const auto &binding : functions) {
            const auto address = functionAddress(functionAddresses.base, binding.target);
            if (!stage(binding.slotRva, address, previousEnd)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        for (const auto &row : templates) {
            if ((row.permissions & FORGE_RT_WRITE) &&
                overlapsSlot(row.backing, row.offset, row.size)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        for (const auto &[slot, value] : slots) {
            const auto &[backing, offset] = slot;
            std::memcpy(backings[backing].bytes.data() + offset, &value, sizeof(value));
        }

        return FORGE_RT_OK;
    }

    forge_rt_status ProcessImage::initialize(const forge_rt_process_startup &startup) {
        const auto imports = tableRows(artifact.imports, artifact.importCount);

        if (std::ranges::any_of(imports, usesStandardHandles)) {
            const auto captured = instance.standardHandles.emplace().capture();

            if (captured != FORGE_RT_OK) {
                return captured;
            }
        }

        const CrtImports crt{dataImports(artifact),
                             std::ranges::any_of(imports, [](const auto &binding) {
                                 return win64::crtGetMainArgs.name == binding.name &&
                                        fromDll(binding, win64::crtGetMainArgs.dll);
                             })};
        auto &parameters = instance.parameters.emplace();
        const auto initialized = parameters.initialize(
            instance, artifact, startup, std::ranges::any_of(imports, usesCommandLine), crt);

        if (initialized != FORGE_RT_OK) {
            return initialized;
        }

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

        // Registration validates guest ranges, permissions, and claims atomically.
        // All allocations and potentially failing initialization precede publication.
        instance.reservations.reserve(instance.reservations.size() + 2);
        const auto registered = forge_rt_register_image(&instance, &image);

        if (registered != FORGE_RT_OK) {
            return registered;
        }

        const auto functions = functionImports(artifact);
        if (!functions.empty()) {
            const auto reserved = reserveFunctionAddresses();
            if (reserved != FORGE_RT_OK) {
                return reserved;
            }
        }

        const auto boundImports = crt.data.empty() && functions.empty()
                                      ? FORGE_RT_OK
                                      : bindImports(parameters.crt, crt.data, functions);

        if (boundImports == FORGE_RT_OK) {
            instance.managedExecution = &execution.view;
        }

        return boundImports;
    }

    forge_rt_process_result runtimeFailure(forge_rt_status status) {
        return {FORGE_RT_RUNTIME_FAILURE, status, 0, {}, 0};
    }

    forge_rt_status checkProcessInvocation(const forge_rt_instance &owner,
                                           forge_rt_thread_token thread) {
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

        return execution->result.kind ? FORGE_RT_INVALID_STATE : FORGE_RT_OK;
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
                (result.fault == FORGE_RT_FAULT_MEMORY || result.fault == FORGE_RT_FAULT_CONTROL ||
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
} // namespace

struct forge_rt_process {
    std::mutex mutex;
    forge_rt_process_state state = FORGE_RT_PROCESS_CREATED;
    std::unique_ptr<ProcessImage> image;
};

extern "C" forge_rt_status forge_rt_process_create(uint32_t expectedVersion,
                                                   forge_rt_process **outProcess) noexcept {
    if (!outProcess) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    if (expectedVersion != FORGE_RT_ABI_VERSION) {
        return FORGE_RT_ABI_MISMATCH;
    }

    try {
        *outProcess = new forge_rt_process;
        return FORGE_RT_OK;
    } catch (const std::bad_alloc &) {
        return FORGE_RT_RESOURCE_EXHAUSTED;
    } catch (...) {
        return FORGE_RT_INTERNAL_ERROR;
    }
}

extern "C" forge_rt_status forge_rt_process_register(forge_rt_process *process,
                                                     const forge_rt_artifact *artifact) noexcept {
    return forge_rt_process_register_with_startup(process, artifact, nullptr);
}

extern "C" forge_rt_status
forge_rt_process_register_with_startup(forge_rt_process *process, const forge_rt_artifact *artifact,
                                       const forge_rt_process_startup *startup) noexcept {
    if (!artifact) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(process, [&](auto &owner) {
        if (owner.state == FORGE_RT_PROCESS_READY) {
            if (startup) {
                return FORGE_RT_INVALID_STATE;
            }

            return &owner.image->artifact == artifact ? FORGE_RT_OK : FORGE_RT_MAPPING_CONFLICT;
        }

        if (owner.state != FORGE_RT_PROCESS_CREATED) {
            return owner.state == FORGE_RT_PROCESS_RUNNING ? FORGE_RT_BUSY : FORGE_RT_INVALID_STATE;
        }

        const auto valid = checkArtifact(*artifact);

        if (valid != FORGE_RT_OK) {
            return valid;
        }

        auto staged = std::make_unique<ProcessImage>(*artifact);
        const auto status = staged->initialize(startup ? *startup : forge_rt_process_startup{});

        if (status == FORGE_RT_OK) {
            owner.image = std::move(staged);
            owner.state = FORGE_RT_PROCESS_READY;
        }

        return status;
    });
}

extern "C" forge_rt_status forge_rt_process_get_state(forge_rt_process *process,
                                                      forge_rt_process_state *outState) noexcept {
    if (!outState) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(process, [&](const auto &owner) {
        *outState = owner.state;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status
forge_rt_process_allow_host_output_signals(forge_rt_process *process) noexcept {
    return withInstance(process, [](auto &owner) {
        if (owner.state != FORGE_RT_PROCESS_READY) {
            return owner.state == FORGE_RT_PROCESS_RUNNING ? FORGE_RT_BUSY : FORGE_RT_INVALID_STATE;
        }

        if (auto &handles = owner.image->instance.standardHandles) {
            handles->hostHandlesOutputSignals = true;
        }

        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_process_run(forge_rt_process *process,
                                                const forge_rt_entry_inputs *inputs,
                                                forge_rt_process_result *outResult) noexcept {
    if (!outResult) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    ProcessImage *active = nullptr;
    const auto admitted = withInstance(process, [&](auto &owner) {
        if (owner.state != FORGE_RT_PROCESS_READY) {
            return owner.state == FORGE_RT_PROCESS_RUNNING ? FORGE_RT_BUSY : FORGE_RT_INVALID_STATE;
        }

        active = owner.image.get();

        if (inputs) {
            active->execution.view.rcx = inputs->rcx;
            active->execution.view.rdx = inputs->rdx;
        }

        owner.state = FORGE_RT_PROCESS_RUNNING;
        return FORGE_RT_OK;
    });

    if (admitted != FORGE_RT_OK) {
        return admitted;
    }

    // RUNNING pins the occurrence. No lifecycle or address-space lock spans the guest call.
    const auto result = active->run();
    // Retire the process's descriptors before publishing completion, including on a fault.
    // A host retaining the process to inspect its result can already observe pipe EOF.
    active->instance.standardHandles.reset();

    return withInstance(process, [&](auto &owner) {
        const bool exited =
            result.kind == FORGE_RT_RETURNED || result.kind == FORGE_RT_EXIT_PROCESS;
        owner.state = exited ? FORGE_RT_PROCESS_EXITED : FORGE_RT_PROCESS_FAULTED;
        *outResult = result;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_exit_process(forge_rt_instance *instance,
                                                 forge_rt_thread_token thread,
                                                 uint32_t exitCode) noexcept {
    return withInstance(instance, [&](auto &owner) {
        const auto status = checkProcessInvocation(owner, thread);

        if (status == FORGE_RT_OK) {
            owner.managedExecution->result = {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, exitCode, {}, 0};
        }

        return status;
    });
}

extern "C" forge_rt_status forge_rt_set_unhandled_exception_filter(forge_rt_instance *instance,
                                                                   forge_rt_thread_token thread,
                                                                   uint64_t guestFilter,
                                                                   uint64_t *outPrevious) noexcept {
    if (!outPrevious) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(instance, [&](auto &owner) {
        const auto status = checkProcessInvocation(owner, thread);

        if (status == FORGE_RT_OK) {
            *outPrevious = std::exchange(owner.topLevelExceptionFilter, guestFilter);
        }

        return status;
    });
}

extern "C" forge_rt_status forge_rt_process_close(forge_rt_process *process) noexcept {
    return withInstance(process, [](auto &owner) {
        if (owner.state == FORGE_RT_PROCESS_RUNNING) {
            return FORGE_RT_BUSY;
        }

        owner.image.reset();
        owner.state = FORGE_RT_PROCESS_CLOSED;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_process_destroy(forge_rt_process *process) noexcept {
    const auto status = forge_rt_process_close(process);

    if (status == FORGE_RT_OK) {
        delete process;
    }

    return status;
}
