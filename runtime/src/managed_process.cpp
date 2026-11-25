#include "compat/process_state.h"
#include "core/process_image.h"
#include "forge/service_signature.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <string_view>
#include <utility>

using namespace forge;
using namespace forge::runtime;

namespace {
    std::span<const forge_rt_data_import> dataImports(const forge_rt_artifact &artifact) {
        if (artifact.version < FORGE_RT_CRT_ARTIFACT_VERSION) {
            return {};
        }

        const auto &crt = *reinterpret_cast<const forge_rt_crt_artifact *>(&artifact);
        return tableRows(crt.dataImports, crt.dataImportCount);
    }

    std::span<const forge_rt_function_import> functionImports(const forge_rt_artifact &artifact) {
        if (artifact.version < FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION) {
            return {};
        }

        const auto &extended =
            *reinterpret_cast<const forge_rt_function_import_artifact *>(&artifact);
        return tableRows(extended.functionImports, extended.functionImportCount);
    }

    const win64::ServiceBinding *findService(const forge_rt_import &target) {
        if (!target.dll || !target.name) {
            return nullptr;
        }

        // Catalogue DLLs are lowercase. Artifacts can preserve the original PE spelling.
        const auto asciiLower = [](char c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; };
        const auto *service = std::ranges::find_if(win64::services, [&](const auto &candidate) {
            return candidate.name == target.name &&
                   std::ranges::equal(std::string_view(target.dll), candidate.dll, {}, asciiLower);
        });
        return service == std::end(win64::services) ? nullptr : service;
    }

    constexpr uint64_t functionStride = 16;

    uint64_t functionAddress(uint64_t base, const forge_rt_import &target) {
        const auto *service = findService(target);
        if (!service) {
            return 0;
        }

        const auto index = static_cast<uint64_t>(service - std::begin(win64::services));
        return base + index * functionStride;
    }

    // Moving the unique_ptr publishes this same occurrence. Its backing and the
    // descriptors that borrow it never move during registration or execution.
    struct LoadedProcess {
        explicit LoadedProcess(const forge_rt_artifact &artifact) : image(artifact) {}

        ~LoadedProcess() { image.retire(); }

        forge_rt_status initialize(const forge_rt_process_startup &startup);

        WindowsProcessState windows;
        ProcessImage image;

      private:
        forge_rt_status bindImports(std::span<const forge_rt_data_import> data,
                                    std::span<const forge_rt_function_import> functions);
    };

    forge_rt_status
    LoadedProcess::bindImports(std::span<const forge_rt_data_import> data,
                               std::span<const forge_rt_function_import> functions) {
        const auto &artifact = image.artifact;
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

            if (image.backings[row.backing].bytes.empty() || !(row.permissions & FORGE_RT_READ) ||
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
            if (!windows.crt ||
                !stage(binding.slotRva, windows.crt->dataAddress(binding.kind), previousEnd)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }
        }

        previousEnd = 0;
        for (const auto &binding : functions) {
            const auto address = functionAddress(image.functionAddresses.base, binding.target);
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
            std::memcpy(image.backings[backing].bytes.data() + offset, &value, sizeof(value));
        }

        return FORGE_RT_OK;
    }

    forge_rt_status LoadedProcess::initialize(const forge_rt_process_startup &startup) {
        const auto &artifact = image.artifact;
        const auto prepared = image.prepare();
        if (prepared != FORGE_RT_OK) {
            return prepared;
        }

        windows.appType.initialize(artifact,
                                   tableRows(image.execution.view.regions, artifact.regionCount));

        bool standardHandles = false, commandLine = false, startupInfo = false;
        CrtImports crt{dataImports(artifact), false};
        for (const auto &import : tableRows(artifact.imports, artifact.importCount)) {
            const auto *service = findService(import);
            if (!service) {
                continue;
            }

            const auto adapter = service->nativeSymbol;
            if (adapter == win64::getStdHandle.nativeSymbol ||
                adapter == win64::writeFile.nativeSymbol ||
                (adapter == win64::crtAmsgExit.nativeSymbol &&
                 windows.appType.value != CrtApplicationType::gui)) {
                standardHandles = true;
            } else if (adapter == win64::getCommandLineA.nativeSymbol ||
                       adapter == win64::getCommandLineW.nativeSymbol) {
                commandLine = true;
            } else if (adapter == win64::getStartupInfoA.nativeSymbol ||
                       adapter == win64::getStartupInfoW.nativeSymbol) {
                startupInfo = true;
            } else if (adapter == win64::crtGetMainArgs.nativeSymbol) {
                crt.mainArgs = true;
            }
        }

        if (startupInfo) {
            const auto status = windows.parameters.startupInfo.setDefaultStrings(artifact, startup);
            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        if (standardHandles) {
            const auto captured = windows.standardHandles.emplace().capture();
            if (captured != FORGE_RT_OK) {
                return captured;
            }
        }

        const auto parameters =
            windows.initializeParameters(image.instance, artifact, startup, commandLine, crt);
        if (parameters != FORGE_RT_OK) {
            return parameters;
        }

        const auto functions = functionImports(artifact);
        if (!functions.empty()) {
            const auto reserved = image.reserveImportAddresses(
                std::size(win64::services) * functionStride, functionStride);
            if (reserved != FORGE_RT_OK) {
                return reserved;
            }
        }

        if (!crt.data.empty() || !functions.empty()) {
            const auto bound = bindImports(crt.data, functions);
            if (bound != FORGE_RT_OK) {
                return bound;
            }
        }

        image.reservePrimaryStackSlot();
        image.instance.windows = &windows;
        image.instance.managedExecution = &image.execution.view;
        return FORGE_RT_OK;
    }

} // namespace

struct forge_rt_process {
    std::mutex mutex;
    forge_rt_process_state state = FORGE_RT_PROCESS_CREATED;
    std::unique_ptr<LoadedProcess> loaded;
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

            return &owner.loaded->image.artifact == artifact ? FORGE_RT_OK
                                                             : FORGE_RT_MAPPING_CONFLICT;
        }

        if (owner.state != FORGE_RT_PROCESS_CREATED) {
            return owner.state == FORGE_RT_PROCESS_RUNNING ? FORGE_RT_BUSY : FORGE_RT_INVALID_STATE;
        }

        const auto valid = checkArtifact(*artifact);

        if (valid != FORGE_RT_OK) {
            return valid;
        }

        auto staged = std::make_unique<LoadedProcess>(*artifact);
        const auto status = staged->initialize(startup ? *startup : forge_rt_process_startup{});

        if (status == FORGE_RT_OK) {
            owner.loaded = std::move(staged);
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

        if (auto &handles = owner.loaded->windows.standardHandles) {
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

    LoadedProcess *active = nullptr;
    const auto admitted = withInstance(process, [&](auto &owner) {
        if (owner.state != FORGE_RT_PROCESS_READY) {
            return owner.state == FORGE_RT_PROCESS_RUNNING ? FORGE_RT_BUSY : FORGE_RT_INVALID_STATE;
        }

        active = owner.loaded.get();

        if (inputs) {
            active->image.execution.view.rcx = inputs->rcx;
            active->image.execution.view.rdx = inputs->rdx;
        }

        owner.state = FORGE_RT_PROCESS_RUNNING;
        return FORGE_RT_OK;
    });

    if (admitted != FORGE_RT_OK) {
        return admitted;
    }

    // RUNNING pins the occurrence. No lifecycle or address-space lock spans the guest call.
    const auto result = active->image.run();
    // Retire the process's descriptors before publishing completion, including on a fault.
    // A host retaining the process to inspect its result can already observe pipe EOF.
    active->windows.standardHandles.reset();

    return withInstance(process, [&](auto &owner) {
        const bool exited =
            result.kind == FORGE_RT_RETURNED || result.kind == FORGE_RT_EXIT_PROCESS;
        owner.state = exited ? FORGE_RT_PROCESS_EXITED : FORGE_RT_PROCESS_FAULTED;
        *outResult = result;
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_process_close(forge_rt_process *process) noexcept {
    return withInstance(process, [](auto &owner) {
        if (owner.state == FORGE_RT_PROCESS_RUNNING) {
            return FORGE_RT_BUSY;
        }

        owner.loaded.reset();
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
