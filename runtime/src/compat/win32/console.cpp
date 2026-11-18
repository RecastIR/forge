#include "../../core/instance.h"
#include "forge/service_memory.h"

#include <algorithm>
#include <array>
#include <cerrno>

using namespace forge::runtime;
using namespace forge::win64;

namespace {
    constexpr uint32_t errorAccessDenied = 5;
    constexpr uint32_t errorInvalidHandle = 6;
    constexpr uint32_t errorWriteFault = 29;
    constexpr uint32_t errorNotSupported = 50;
    constexpr uint32_t errorInvalidParameter = 87;
    constexpr uint32_t errorBrokenPipe = 109;
    constexpr uint32_t errorDiskFull = 112;
    constexpr uint32_t errorRetry = 1237;

    uint32_t windowsWriteError(int error) {
        switch (error) {
        case EBADF:
            return errorInvalidHandle;
        case EACCES:
        case EPERM:
        case EROFS:
            return errorAccessDenied;
        case ENOSPC:
        case EDQUOT:
        case EFBIG:
            return errorDiskFull;
        case EPIPE:
        case ECONNRESET:
            return errorBrokenPipe;
        case EAGAIN:
            return errorRetry;
        default:
            return errorWriteFault;
        }
    }

    template <typename T>
    forge_rt_status win32Failure(forge_rt_instance *instance, forge_rt_thread_token thread,
                                 uint32_t error, T *result, T failure) {
        const auto status = forge_rt_set_last_error(instance, thread, error);

        if (status == FORGE_RT_OK) {
            *result = failure;
        }

        return status;
    }

    struct Transfer {
        forge_rt_status status;
        uint32_t count = 0;
        uint32_t error = 0;
    };

    Transfer transferOutput(const darwin::Descriptor &output, bool hostHandlesOutputSignals,
                            const GuestBuffer<writeFile.arguments[1]> &input, uint32_t length) {
        if (!length) {
            return {FORGE_RT_OK};
        }

        if (!output.outputSignalsSafe(hostHandlesOutputSignals)) {
            return {FORGE_RT_HOST_CONFIGURATION};
        }

        std::array<uint8_t, 16384> storage;
        const auto capacity = output.writeChunkSize(storage.size());
        uint32_t done = 0;

        while (done < length) {
            auto chunk = std::span(storage).first(std::min<size_t>(length - done, capacity));
            const auto read = input.read(done, chunk);

            if (read != FORGE_RT_OK) {
                return {read, done};
            }

            const auto progress = output.write(chunk);
            done += static_cast<uint32_t>(progress.count);

            if (progress.error) {
                return {FORGE_RT_OK, done, windowsWriteError(progress.error)};
            }
        }

        return {FORGE_RT_OK, done};
    }
} // namespace

extern "C" forge_rt_status forge_rt_get_std_handle(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread, uint32_t selector,
                                                   uint64_t *outHandle) noexcept {
    if (!outHandle) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_invocation_token token;
    const auto status = forge_rt_current_invocation(instance, thread, &token);

    if (status != FORGE_RT_OK) {
        return status;
    }

    if (!instance->standardHandles) {
        return FORGE_RT_INVALID_STATE;
    }

    // DWORD(-10), DWORD(-11), DWORD(-12) select stdin, stdout and stderr in that order.
    const uint32_t index = UINT32_C(0xfffffff6) - selector;
    const auto &streams = instance->standardHandles->streams;

    if (index >= streams.size()) {
        return win32Failure(instance, thread, errorInvalidHandle, outHandle, UINT64_MAX);
    }

    *outHandle = streams[index].handle;
    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_write_file(forge_rt_instance *instance,
                                               forge_rt_thread_token thread, uint64_t handle,
                                               uint64_t buffer, uint32_t length, uint64_t written,
                                               uint64_t overlapped, int32_t *outResult,
                                               forge_rt_memory_fault *fault) noexcept {
    if (!outResult || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    ServiceInvocation call{instance, thread, *fault};
    const auto live = call.resolveCurrent();

    if (live != FORGE_RT_OK) {
        return live;
    }

    if (!instance->standardHandles) {
        return FORGE_RT_INVALID_STATE;
    }

    const auto fail = [&](uint32_t error) {
        return win32Failure(instance, thread, error, outResult, int32_t{0});
    };

    if (overlapped) {
        return fail(errorNotSupported);
    }

    const auto args = std::tie(handle, buffer, length, written, overlapped);
    const auto input = guestBuffer<writeFile, 1>(call, args);
    const auto count = guestBuffer<writeFile, 3>(call, args);

    if (length) {
        const auto status = input.validate();

        if (status != FORGE_RT_OK) {
            return status;
        }
    }

    if (!written) {
        return fail(errorInvalidParameter);
    }

    // The checked scalar store preflights the complete DWORD before initializing any byte.
    // A managed run pins its mappings and has exclusive use of the guest stack until return.
    const auto initialized = count.writeScalar(0, uint32_t{0});

    if (initialized != FORGE_RT_OK) {
        return initialized;
    }

    const auto &handles = *instance->standardHandles;
    const auto &streams = handles.streams;
    const auto output = std::ranges::find(streams, handle, &StandardStream::handle);

    if (!handle || output == streams.end()) {
        return fail(errorInvalidHandle);
    }

    if (output == streams.begin() || !output->descriptor->writable()) {
        return fail(errorAccessDenied);
    }

    const auto transfer =
        transferOutput(*output->descriptor, handles.hostHandlesOutputSignals, input, length);

    if (transfer.status != FORGE_RT_OK) {
        return transfer.status;
    }

    if (transfer.count) {
        const auto status = count.writeScalar(0, transfer.count);

        if (status != FORGE_RT_OK) {
            return status;
        }
    }

    if (transfer.error) {
        return fail(transfer.error);
    }

    *outResult = 1;
    return FORGE_RT_OK;
}
