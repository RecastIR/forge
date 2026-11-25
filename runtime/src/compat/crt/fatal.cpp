#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/msvcrt_process.h"

#include <algorithm>
#include <cstring>
#include <string_view>

using namespace forge::runtime;

namespace {
    // Exact redirected stderr bytes from the legacy Windows MSVCRT. Some messages contain
    // a bare LF between sentences. An empty view denotes an unknown identifier.
    constexpr std::string_view fatalMessage(int32_t errorNumber) noexcept {
        switch (errorNumber) {
        case 2:
            return "\r\nruntime error R6002\r\n- floating point support not loaded\r\n";
        case 8:
            return "\r\nruntime error R6008\r\n- not enough space for arguments\r\n";
        case 9:
            return "\r\nruntime error R6009\r\n- not enough space for environment\r\n";
        case 10:
            return "\r\nruntime error \r\nThis application has requested the Runtime to terminate "
                   "it in an unusual way.\nPlease contact the application's support team for more "
                   "information.\r\n";
        case 16:
            return "\r\nruntime error R6016\r\n- not enough space for thread data\r\n";
        case 17:
            return "\r\nruntime error R6017\r\n- unexpected multithread lock error\r\n";
        case 18:
            return "\r\nruntime error R6018\r\n- unexpected heap error\r\n";
        case 19:
            return "\r\nruntime error R6019\r\n- unable to open console device\r\n";
        case 24:
            return "\r\nruntime error R6024\r\n- not enough space for _onexit/atexit table\r\n";
        case 25:
            return "\r\nruntime error R6025\r\n- pure virtual function call\r\n";
        case 26:
            return "\r\nruntime error R6026\r\n- not enough space for stdio initialization\r\n";
        case 27:
            return "\r\nruntime error R6027\r\n- not enough space for lowio initialization\r\n";
        case 28:
            return "\r\nruntime error R6028\r\n- unable to initialize heap\r\n";
        case 30:
            return "\r\nruntime error R6030\r\n- CRT not initialized\r\n";
        case 31:
            return "\r\nruntime error R6031\r\n- Attempt to initialize the CRT more than once.\n"
                   "This indicates a bug in your application.\r\n";
        case 32:
            return "\r\nruntime error R6032\r\n- not enough space for locale information\r\n";
        case 33:
            return "\r\nruntime error R6033\r\n- Attempt to use MSIL code from this assembly "
                   "during native code initialization\nThis indicates a bug in your application. "
                   "It is most likely the result of calling an MSIL-compiled (/clr) function from "
                   "a native constructor or from DllMain.\r\n";
        case 34:
            return "\r\nruntime error R6034\r\nAn application has made an attempt to load the C "
                   "runtime library incorrectly.\nPlease contact the application's support team "
                   "for more information.\r\n";
        case 120:
            return "\r\nruntime error DOMAIN error\r\n";
        case 121:
            return "\r\nruntime error SING error\r\n";
        case 122:
            return "\r\nruntime error TLOSS error\r\n";
        case 252:
            return "\r\nruntime error \r\n";
        case 255:
            return "\r\nruntime error runtime error ";
        default:
            return {};
        }
    }

    void writeFatalDiagnostic(const StandardHandles &handles, std::string_view message) noexcept {
        const auto &output = handles.streams[2].descriptor;

        if (!output || !output->writable() ||
            !output->outputSignalsSafe(handles.hostHandlesOutputSignals)) {
            return;
        }

        auto bytes = std::span(reinterpret_cast<const uint8_t *>(message.data()), message.size());

        while (!bytes.empty()) {
            const auto chunk = bytes.first(output->writeChunkSize(bytes.size()));
            const auto progress = output->write(chunk);

            // A partial native write commits its prefix. The CRT fatal action still exits.
            if (progress.error) {
                return;
            }

            bytes = bytes.subspan(progress.count);
        }
    }

    // Callers check the entire field against the contiguous immutable prefix first.
    template <class T> T headerField(std::span<const forge_rt_image_region> rows, uint64_t offset) {
        T field{};
        auto out = std::as_writable_bytes(std::span(&field, 1));
        for (const auto &row : rows) {
            if (offset >= row.size) {
                offset -= row.size;
                continue;
            }

            const auto count = std::min<uint64_t>(out.size(), row.size - offset);
            std::memcpy(out.data(), static_cast<const uint8_t *>(row.bytes) + offset, count);
            out = out.subspan(count);
            if (out.empty()) {
                break;
            }

            offset = 0;
        }

        return field;
    }

    uint16_t legacySubsystem(uint64_t base, std::span<const forge_rt_image_region> rows) {
        // Registered rows are ordered, disjoint and contained in the image. A read-only
        // row over private backing has a claim, since another guest row may write it.
        uint64_t extent = 0;
        for (const auto &row : rows) {
            if (row.start - base != extent || row.permissions != FORGE_RT_READ || row.claim) {
                break;
            }

            extent += row.size;
        }

        constexpr uint32_t ntOffsetField = 0x3c, dosEnd = ntOffsetField + sizeof(uint32_t);
        if (extent < dosEnd || headerField<uint16_t>(rows, 0) != 0x5a4d) {
            return 0;
        }

        const uint64_t nt = headerField<uint32_t>(rows, ntOffsetField);
        const auto optional = nt + 24;
        if (nt < dosEnd || optional > extent || headerField<uint32_t>(rows, nt) != 0x4550) {
            return 0;
        }

        constexpr uint32_t subsystemOffset = 68;
        const auto size = headerField<uint16_t>(rows, nt + 20);
        if (size < subsystemOffset + sizeof(uint16_t) || size > extent - optional ||
            headerField<uint16_t>(rows, optional) != 0x20b) {
            return 0;
        }

        return headerField<uint16_t>(rows, optional + subsystemOffset);
    }
} // namespace

void CrtApplicationType::initialize(const forge_rt_artifact &artifact,
                                    std::span<const forge_rt_image_region> rows) noexcept {
    // MSVCRT uses the main module's subsystem even when a setter supplies a different value.
    const auto peSubsystem =
        artifact.version >= FORGE_RT_PE_ARTIFACT_VERSION
            ? reinterpret_cast<const forge_rt_pe_artifact &>(artifact).subsystem
            : legacySubsystem(artifact.base, rows);
    if (peSubsystem == 2 || peSubsystem == 3) {
        value = peSubsystem == 2 ? gui : console;
        origin = Origin::PeSubsystem;
    }
}

extern "C" forge_rt_status forge_rt_msvcrt_set_app_type(forge_rt_instance *instance,
                                                        forge_rt_thread_token thread,
                                                        int32_t appType) noexcept {
    return withInstance(instance, [&](auto &owner) {
        const auto status = checkPendingExecution(owner, thread);
        if (status != FORGE_RT_OK) {
            return status;
        }

        auto &type = owner.windows->appType;
        if (type.origin != CrtApplicationType::Origin::PeSubsystem) {
            type.value = appType;
            type.origin = CrtApplicationType::Origin::Setter;
        }

        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_msvcrt_amsg_exit(forge_rt_instance *instance,
                                                     forge_rt_thread_token thread,
                                                     int32_t errorNumber) noexcept {
    bool console = false;
    const auto status = withInstance(instance, [&](const auto &owner) {
        const auto admitted = checkPendingExecution(owner, thread);
        if (admitted != FORGE_RT_OK) {
            return admitted;
        }

        // Headerless host entries historically use console routing before any setter.
        const auto &type = owner.windows->appType;
        console = type.origin == CrtApplicationType::Origin::Default ||
                  type.value == CrtApplicationType::console;
        return FORGE_RT_OK;
    });

    if (status != FORGE_RT_OK) {
        return status;
    }

    const auto message = fatalMessage(errorNumber);
    if (console) {
        // The synchronous invocation pins the process's descriptors until return.
        const auto &handles = instance->windows->standardHandles;
        if (!handles) {
            return FORGE_RT_INVALID_STATE;
        }

        writeFatalDiagnostic(*handles, message.empty() ? "\r\nruntime error " : message);
    } else if (!message.empty() && errorNumber != 252) {
        // MSVCRT skips unknown messages and the newline fragment on its GUI route.
        return FORGE_RT_UNSUPPORTED_CRT_ERROR_ROUTING;
    }

    return publishTerminalResult(instance, thread,
                                 {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, 255, {}, 0});
}
