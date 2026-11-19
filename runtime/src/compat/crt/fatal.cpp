#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/msvcrt_process.h"

#include <string_view>

using namespace forge::runtime;

namespace {
    // Exact redirected stderr bytes from the legacy Windows MSVCRT. Some messages contain
    // a bare LF between sentences. Unknown identifiers emit only the common prefix.
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
            return "\r\nruntime error ";
        }
    }

    void writeFatalDiagnostic(const StandardHandles &handles, int32_t errorNumber) noexcept {
        const auto &output = handles.streams[2].descriptor;

        if (!output || !output->writable() ||
            !output->outputSignalsSafe(handles.hostHandlesOutputSignals)) {
            return;
        }

        const auto message = fatalMessage(errorNumber);
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
} // namespace

extern "C" forge_rt_status forge_rt_msvcrt_amsg_exit(forge_rt_instance *instance,
                                                     forge_rt_thread_token thread,
                                                     int32_t errorNumber) noexcept {
    const auto status = withInstance(
        instance, [thread](auto &owner) { return checkPendingExecution(owner, thread); });

    if (status != FORGE_RT_OK) {
        return status;
    }

    // The synchronous managed invocation pins its Windows state and descriptors until return.
    const auto &handles = instance->windows->standardHandles;

    if (!handles) {
        return FORGE_RT_INVALID_STATE;
    }

    writeFatalDiagnostic(*handles, errorNumber);
    return publishTerminalResult(instance, thread,
                                 {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, 255, {}, 0});
}
