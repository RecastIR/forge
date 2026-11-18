#include "forge/process.h"

#include "forge/guest_range.h"
#include "instance.h"

#include <array>
#include <cstring>
#include <memory>
#include <span>

using namespace forge;
using namespace forge::runtime;

namespace {
    template <typename T> bool validTable(const T *table, uint64_t count) {
        return (count == 0 || table != nullptr) && count <= PTRDIFF_MAX / sizeof(T);
    }

    template <typename T> std::span<const T> tableRows(const T *table, uint64_t count) {
        return {table, static_cast<size_t>(count)};
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
        if (artifact.version != FORGE_RT_ARTIFACT_VERSION) {
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

        forge_rt_status initialize();
        forge_rt_process_result run() noexcept;

        const forge_rt_artifact &artifact;
        std::vector<WritableBacking> backings;
        std::vector<forge_rt_image_region> regions;
        forge_rt_image image{};
        ExecutionContext execution;
        // Destroy the reservation/thread tables before releasing any storage they borrow.
        forge_rt_instance instance;

      private:
        forge_rt_status bindRegions();
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

    forge_rt_status ProcessImage::initialize() {
        const auto captured = instance.standardHandles.capture();

        if (captured != FORGE_RT_OK) {
            return captured;
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
        instance.reservations.reserve(2); // Image plus the stack published while running.
        const auto registered = forge_rt_register_image(&instance, &image);

        if (registered == FORGE_RT_OK) {
            instance.managedExecution = &execution.view;
        }

        return registered;
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
    if (!artifact) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return withInstance(process, [&](auto &owner) {
        if (owner.state == FORGE_RT_PROCESS_READY) {
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
        const auto status = staged->initialize();

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

        owner.image->instance.standardHandles.hostHandlesOutputSignals = true;
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
        auto *execution = owner.managedExecution;

        if (!execution) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto entry = owner.threads.find(thread);

        if (entry == owner.threads.end()) {
            return FORGE_RT_INVALID_THREAD;
        }

        if (!entry->second.invocation || executingInvocation != entry->second.invocation) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        if (execution->result.kind) {
            return FORGE_RT_INVALID_STATE;
        }

        execution->result = {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, exitCode, {}, 0};
        return FORGE_RT_OK;
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
