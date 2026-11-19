#include "process_parameters.h"

#include "../../core/instance.h"
#include "../process_state.h"

#include <algorithm>
#include <cstring>
#include <span>
#include <string_view>

namespace forge::runtime {
    namespace {
        constexpr size_t characterLimit = 32766;

        std::optional<std::string> executableIdentity(const forge_rt_artifact &artifact,
                                                      const forge_rt_process_startup &startup) {
            if (startup.executablePath) {
                const auto length = strnlen(startup.executablePath, characterLimit + 1);
                const std::string_view text(startup.executablePath, length);
                if (length > characterLimit || text.empty() || text.find('"') != text.npos) {
                    return {};
                }

                return std::string(text);
            }

            if (artifact.version < FORGE_RT_NAMED_ARTIFACT_VERSION) {
                return std::string{};
            }

            const auto *name =
                reinterpret_cast<const forge_rt_named_artifact *>(&artifact)->executableName;
            if (!name || !*name || strnlen(name, characterLimit) == characterLimit ||
                std::string_view(name).find_first_of("\\/") != std::string_view::npos) {
                return {};
            }

            return std::string("C:\\") + name;
        }

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
            const auto *windows = instance->windows;
            if (!windows || windows->parameters.wide.empty()) {
                return FORGE_RT_INVALID_STATE;
            }

            *address = windows->rows[index].start;
            return FORGE_RT_OK;
        }
    } // namespace

    forge_rt_status StartupInfo::setDefaultStrings(const forge_rt_artifact &artifact,
                                                   const forge_rt_process_startup &startup) {
        auto identity = executableIdentity(artifact, startup);
        if (!identity) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        shell.emplace();
        desktop.emplace().narrow = "winsta0\\default";
        title.emplace().narrow = std::move(*identity);
        return FORGE_RT_OK;
    }

    forge_rt_status ProcessParameters::buildCommandLine(const forge_rt_artifact &artifact,
                                                        const forge_rt_process_startup &startup) {
        if ((startup.argumentCount && !startup.arguments) ||
            startup.argumentCount > characterLimit) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        const auto identity = executableIdentity(artifact, startup);
        if (!identity) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        const auto first = appendArgument(narrow, identity->c_str(), true);

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

} // namespace forge::runtime

extern "C" forge_rt_status forge_rt_get_command_line_a(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t *outAddress) noexcept {
    return forge::runtime::commandAddress(instance, thread, outAddress,
                                          forge::runtime::WindowsProcessState::narrowCommandRow);
}

extern "C" forge_rt_status forge_rt_get_command_line_w(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t *outAddress) noexcept {
    return forge::runtime::commandAddress(instance, thread, outAddress,
                                          forge::runtime::WindowsProcessState::wideCommandRow);
}

extern "C" uint64_t forge_rt_primary_teb(forge_rt_execution *execution) noexcept {
    if (!execution) {
        return 0;
    }

    forge_rt_invocation_token invocation = 0;
    auto status = forge_rt_current_invocation(execution->instance, execution->thread, &invocation);

    if (status == FORGE_RT_OK) {
        const auto *instance = execution->instance;

        if (instance->managedExecution == execution && instance->windows) {
            return instance->windows->mapping.base;
        }

        status = FORGE_RT_INVALID_STATE;
    }

    execution->result = {FORGE_RT_RUNTIME_FAILURE, status, 0, {}, 0};
    return 0;
}
