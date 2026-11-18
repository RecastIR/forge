#include "process_parameters.h"

#include "../../core/instance.h"
#include "forge/guest_range.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <span>
#include <string_view>

namespace forge::runtime {
    namespace {
        constexpr size_t characterLimit = 32766;

        // argv[0] has a separate CRT grammar. Surround a spaced executable path with quotes,
        // without doubling backslashes. Embedded quotes cannot be part of a Windows filename.
        forge_rt_status appendArgument(std::string &line, const char *argument, bool identity) {
            if (!argument) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const auto size = strnlen(argument, characterLimit + 1);
            const std::string_view text(argument, size);

            if (size > characterLimit - line.size() ||
                std::ranges::any_of(text, [](unsigned char c) { return c > 127; })) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            if (identity && (text.empty() || text.find('"') != text.npos)) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const bool quote = text.empty() || text.find_first_of(" \t") != text.npos;

            if (quote) {
                line.push_back('"');
            }

            size_t slashes = 0;

            for (const auto character : text) {
                if (!identity && character == '\\') {
                    ++slashes;
                    continue;
                }

                const bool escaped = character == '"';
                line.append(escaped ? 2 * slashes + 1 : slashes, '\\');
                line.push_back(character);
                slashes = 0;
            }

            line.append(quote ? 2 * slashes : slashes, '\\');

            if (quote) {
                line.push_back('"');
            }

            return line.size() <= characterLimit ? FORGE_RT_OK : FORGE_RT_INVALID_ARGUMENT;
        }

        forge_rt_status commandAddress(forge_rt_instance *instance, forge_rt_thread_token thread,
                                       uint64_t *address, size_t index) {
            if (!address) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            forge_rt_invocation_token invocation = 0;
            const auto status = forge_rt_current_invocation(instance, thread, &invocation);

            if (status != FORGE_RT_OK) {
                return status;
            }

            // A live invocation pins the process parameters until synchronous return.
            if (!instance->managedExecution || !instance->parameters ||
                instance->parameters->wide.empty()) {
                return FORGE_RT_INVALID_STATE;
            }

            *address = instance->parameters->rows[index].start;
            return FORGE_RT_OK;
        }
    } // namespace

    forge_rt_status ProcessParameters::buildCommandLine(const forge_rt_artifact &artifact,
                                                        const forge_rt_process_startup &startup) {
        if ((startup.argumentCount && !startup.arguments) ||
            startup.argumentCount > characterLimit) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        std::string defaultPath;
        const char *identity = startup.executablePath;

        if (!identity && artifact.version >= FORGE_RT_NAMED_ARTIFACT_VERSION) {
            const auto *name =
                reinterpret_cast<const forge_rt_named_artifact *>(&artifact)->executableName;

            if (!name || !*name || strnlen(name, characterLimit) == characterLimit ||
                std::string_view(name).find_first_of("\\/") != std::string_view::npos) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            defaultPath = std::string("C:\\") + name;
            identity = defaultPath.c_str();
        }

        const auto first = appendArgument(narrow, identity, true);

        if (first != FORGE_RT_OK) {
            return first;
        }

        for (const auto *argument : std::span(startup.arguments, startup.argumentCount)) {
            if (narrow.size() == characterLimit) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            narrow.push_back(' ');
            const auto status = appendArgument(narrow, argument, false);

            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        return FORGE_RT_OK;
    }

    forge_rt_status ProcessParameters::initialize(forge_rt_instance &instance,
                                                  const forge_rt_artifact &artifact,
                                                  const forge_rt_process_startup &startup,
                                                  bool osCommandLine, CrtImports imports) {
        if (osCommandLine || imports.mainArgs || imports.hasData(FORGE_RT_CRT_ACMDLN)) {
            const auto result = buildCommandLine(artifact, startup);

            if (result != FORGE_RT_OK) {
                return result;
            }
        }

        if (osCommandLine) {
            static_assert(std::endian::native == std::endian::little && sizeof(char16_t) == 2);
            wide.assign(narrow.begin(), narrow.end());
        }

        if (imports.mainArgs || !imports.data.empty()) {
            const auto status = crt.emplace().initialize(imports, narrow, startup);

            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        // Keep all unimplemented TEB fields in a reserved hole. The CRT data and
        // strings live beyond the TEB, not at unimplemented Windows structure offsets.
        constexpr uint64_t parameterOffset = 65536;
        constexpr uint64_t stringOffset = parameterOffset + sizeof(crtErrno);
        const auto narrowSize = narrow.size() + 1;
        const auto wideSize = (wide.size() + 1) * sizeof(char16_t);
        const auto wideOffset = (narrowSize + 1) & ~size_t{1};
        const auto stringEnd = stringOffset + (osCommandLine ? wideOffset + wideSize : 0);
        const auto crtOffset = (stringEnd + 7) & ~uint64_t{7};
        const auto size = crt ? crtOffset + crt->bytes.size() : stringEnd;
        std::array<Reservation, 2> occupied{
            {{artifact.base, artifact.size, nullptr, nullptr},
             {FORGE_RT_STACK_BASE, FORGE_RT_STACK_SIZE, nullptr, nullptr}}};
        std::ranges::sort(occupied, {}, &Reservation::base);
        const auto base = findGuestAllocation(occupied, size, parameterOffset);

        if (!base) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        // Only implemented NT_TIB fields occupy rows. A guest may write its own TIB.
        constexpr auto permissions = FORGE_RT_READ | FORGE_RT_WRITE;
        self = base;
        rows[0] = {base + 8, sizeof(stackBounds), stackBounds.data(), permissions, &tibClaim};
        rows[1] = {base + 0x30, sizeof(self), &self, permissions, &tibClaim};

        rows[2] = {base + parameterOffset, sizeof(crtErrno), &crtErrno, permissions, &tibClaim};

        if (osCommandLine) {
            const auto stringBase = base + stringOffset;
            rows[3] = {stringBase, narrowSize, narrow.c_str(), FORGE_RT_READ, nullptr};
            rows[4] = {stringBase + wideOffset, wideSize, wide.c_str(), FORGE_RT_READ, nullptr};
        }

        size_t rowCount = osCommandLine ? 5 : 3;

        if (crt) {
            const auto crtBase = base + crtOffset;
            crt->relocate(crtBase);
            rows[rowCount++] = {crtBase, crt->bytes.size(), crt->bytes.data(), permissions,
                                &crt->claim};
        }

        mapping = {base, size, rows.data(), rowCount};
        return forge_rt_register_image(&instance, &mapping);
    }
} // namespace forge::runtime

extern "C" forge_rt_status forge_rt_get_command_line_a(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t *outAddress) noexcept {
    return forge::runtime::commandAddress(instance, thread, outAddress, 3);
}

extern "C" forge_rt_status forge_rt_get_command_line_w(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t *outAddress) noexcept {
    return forge::runtime::commandAddress(instance, thread, outAddress, 4);
}

extern "C" uint64_t forge_rt_primary_teb(forge_rt_execution *execution) noexcept {
    if (!execution) {
        return 0;
    }

    forge_rt_invocation_token invocation = 0;
    auto status = forge_rt_current_invocation(execution->instance, execution->thread, &invocation);

    if (status == FORGE_RT_OK) {
        const auto *instance = execution->instance;

        if (instance->managedExecution == execution && instance->parameters) {
            return instance->parameters->mapping.base;
        }

        status = FORGE_RT_INVALID_STATE;
    }

    execution->result = {FORGE_RT_RUNTIME_FAILURE, status, 0, {}, 0};
    return 0;
}
