#include "crt_parameters.h"

#include "../../core/instance.h"
#include "forge/msvcrt_process.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace forge::runtime {
    namespace {
        constexpr size_t environmentLimit = size_t{1024} * 1024;
        constexpr size_t acmdln = 0, initenv = 8, fmode = 16, commode = 20;

        bool whitespace(char c) { return c == ' ' || c == '\t'; }

        std::string parseArgument(std::string_view command, size_t &pos) {
            std::string argument;
            bool quoted = false;

            while (pos < command.size() && (quoted || !whitespace(command[pos]))) {
                const auto start = pos;

                while (pos < command.size() && command[pos] == '\\') {
                    ++pos;
                }

                const auto slashes = pos - start;

                if (pos < command.size() && command[pos] == '"') {
                    ++pos;
                    argument.append(slashes / 2, '\\');

                    if (slashes % 2) {
                        argument.push_back('"');
                    } else {
                        quoted = !quoted;
                    }
                } else {
                    argument.append(slashes, '\\');

                    if (pos < command.size() && (quoted || !whitespace(command[pos]))) {
                        argument.push_back(command[pos++]);
                    }
                }
            }

            return argument;
        }

        // The OS command line is canonical and already validated. Parse argv[0] with its
        // separate executable-name grammar and the remaining arguments with CRT slash rules.
        std::vector<std::string> parseArguments(std::string_view command) {
            std::vector<std::string> args(1);
            size_t pos = 0;
            bool quoted = false;

            while (pos < command.size() && (quoted || !whitespace(command[pos]))) {
                const auto c = command[pos++];

                if (c == '"') {
                    quoted = !quoted;
                } else {
                    args.front().push_back(c);
                }
            }

            while (pos < command.size()) {
                if (whitespace(command[pos])) {
                    ++pos;
                } else {
                    args.push_back(parseArgument(command, pos));
                }
            }

            return args;
        }
    } // namespace

    void CrtParameters::bind(size_t offset, size_t target) {
        const auto relative = static_cast<uint64_t>(target);
        std::memcpy(bytes.data() + offset, &relative, sizeof(relative));
        fixups.push_back(offset);
    }

    size_t CrtParameters::appendString(std::string_view text) {
        const auto offset = bytes.size();
        bytes.insert(bytes.end(), text.begin(), text.end());
        bytes.push_back(0);
        return offset;
    }

    size_t CrtParameters::appendVector(std::span<const std::string_view> strings) {
        const auto offset = (bytes.size() + 7) & ~size_t{7};
        bytes.resize(offset + (strings.size() + 1) * 8);

        for (size_t i = 0; i < strings.size(); ++i) {
            bind(offset + i * 8, appendString(strings[i]));
        }

        return offset;
    }

    bool CrtImports::hasData(uint32_t kind) const {
        return std::ranges::find(data, kind, &forge_rt_data_import::kind) != data.end();
    }

    forge_rt_status CrtParameters::initialize(CrtImports imports, std::string_view command,
                                              const forge_rt_process_startup &startup) {
        bytes.resize(24);
        const int32_t textMode = 0x4000;
        std::memcpy(bytes.data() + fmode, &textMode, sizeof(textMode));

        if (imports.hasData(FORGE_RT_CRT_ACMDLN)) {
            bind(acmdln, appendString(command));
        }

        if (imports.mainArgs) {
            arguments = parseArguments(command);
        }

        if (!imports.mainArgs && !imports.hasData(FORGE_RT_CRT_INITENV)) {
            return FORGE_RT_OK;
        }

        if ((startup.environmentCount && !startup.environment) ||
            startup.environmentCount > environmentLimit / sizeof(uint64_t)) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        std::vector<std::string_view> variables;
        size_t remaining = environmentLimit;

        for (const auto *item : std::span(startup.environment, startup.environmentCount)) {
            if (!item) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const auto length = strnlen(item, remaining);
            const std::string_view text(item, length);
            const auto equal = text.find('=');

            if (length == remaining || equal == 0 || equal == text.npos ||
                std::ranges::any_of(text, [](unsigned char c) { return c > 127; })) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            variables.push_back(text);
            remaining -= length + 1;
        }

        bind(initenv, appendVector(variables));
        return FORGE_RT_OK;
    }

    void CrtParameters::relocate(uint64_t address) {
        base = address;

        for (const auto offset : fixups) {
            uint64_t pointer;
            std::memcpy(&pointer, bytes.data() + offset, sizeof(pointer));
            pointer += base;
            std::memcpy(bytes.data() + offset, &pointer, sizeof(pointer));
        }

        fixups.clear();
    }

    uint64_t CrtParameters::dataAddress(uint32_t kind) const {
        switch (kind) {
        case FORGE_RT_CRT_ACMDLN:
            return base + acmdln;
        case FORGE_RT_CRT_INITENV:
            return base + initenv;
        case FORGE_RT_CRT_FMODE:
            return base + fmode;
        case FORGE_RT_CRT_COMMODE:
            return base + commode;
        default:
            return 0;
        }
    }
} // namespace forge::runtime

extern "C" forge_rt_status forge_rt_msvcrt_getmainargs(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread, uint64_t argc,
                                                       uint64_t argv, uint64_t environment,
                                                       int32_t expandWildcards,
                                                       uint64_t startupInfo, int32_t *outResult,
                                                       forge_rt_memory_fault *fault) noexcept {
    if (!outResult || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_invocation_token token = 0;
    auto status = forge_rt_current_invocation(instance, thread, &token);

    if (status != FORGE_RT_OK) {
        return status;
    }

    // A prepared argument vector always includes argv[0].
    if (!instance->managedExecution || !instance->parameters || !instance->parameters->crt ||
        instance->parameters->crt->count() == 0) {
        return FORGE_RT_INVALID_STATE;
    }

    int32_t newMode = 0;

    if (startupInfo) {
        status = forge_rt_read_guest(instance, thread, token, startupInfo, 4, &newMode, 4, fault);

        if (status != FORGE_RT_OK) {
            return status;
        }
    }

    if (expandWildcards) {
        return FORGE_RT_UNSUPPORTED_CRT_WILDCARDS;
    }

    if (newMode) {
        return FORGE_RT_UNSUPPORTED_CRT_NEW_MODE;
    }

    struct Output {
        uint64_t address;
        size_t size;
        const void *bytes;
    };

    const auto &crt = *instance->parameters->crt;
    const int32_t count = crt.count();
    uint64_t argumentVector = 0, environmentVector = 0;
    const std::array<Output, 3> outputs{
        {{argc, sizeof(count), &count},
         {argv, sizeof(argumentVector), &argumentVector},
         {environment, sizeof(environmentVector), &environmentVector}}};

    for (const auto &output : outputs) {
        status = forge_rt_validate_guest(instance, thread, token, output.address, output.size,
                                         FORGE_RT_WRITE, fault);

        if (status != FORGE_RT_OK) {
            return status;
        }
    }

    status = forge_rt_read_guest(instance, thread, token, crt.dataAddress(FORGE_RT_CRT_INITENV),
                                 sizeof(environmentVector), &environmentVector,
                                 sizeof(environmentVector), fault);

    if (status != FORGE_RT_OK) {
        return status;
    }

    status = forge::runtime::withInstance(
        instance, [&](auto &owner) { return crt.copyArguments(owner, argumentVector); });

    if (status != FORGE_RT_OK || !argumentVector) {
        if (status == FORGE_RT_OK) {
            *outResult = -1;
        }

        return status;
    }

    for (const auto &output : outputs) {
        status = forge_rt_write_guest(instance, thread, token, output.address, output.size,
                                      output.bytes, output.size, fault);

        if (status != FORGE_RT_OK) {
            return status;
        }
    }

    *outResult = 0;
    return FORGE_RT_OK;
}
