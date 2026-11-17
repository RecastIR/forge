#include "forge/service_memory.h"

#include <algorithm>
#include <array>

namespace {
    // A temporary restriction of this service, independent of the memory bridge.
    constexpr size_t stringLimit = size_t{1024} * 1024;
    constexpr size_t chunkSize = 256;

    struct StringChunk {
        forge_rt_status status;
        size_t length = 0;
        bool terminated = false;
    };

    StringChunk readChunk(const forge::win64::GuestBuffer<forge::win64::nullableString> &string,
                          size_t offset, size_t count) {
        std::array<uint8_t, chunkSize> bytes{};
        const auto status = string.read(offset, std::span(bytes).first(count));
        if (status == FORGE_RT_OK) {
            const auto end = bytes.begin() + static_cast<ptrdiff_t>(count);
            const auto nul = std::find(bytes.begin(), end, uint8_t{0});
            return {FORGE_RT_OK, static_cast<size_t>(nul - bytes.begin()), nul != end};
        }

        if (status != FORGE_RT_GUEST_FAULT) {
            return {status};
        }

        // A speculative chunk may include an inaccessible byte after the terminator.
        // Re-read through the same checked API; failed copies provided no usable bytes.
        for (size_t i = 0; i < count; ++i) {
            uint8_t byte = 0;
            const auto single = string.readScalar(offset + i, byte);
            if (single != FORGE_RT_OK) {
                return {single};
            }

            if (byte == 0) {
                return {FORGE_RT_OK, i, true};
            }
        }

        return {FORGE_RT_OK, count, false};
    }
} // namespace

extern "C" forge_rt_status forge_rt_lstrlen_a(forge_rt_instance *instance,
                                              forge_rt_thread_token thread, uint64_t address,
                                              int32_t *outLength,
                                              forge_rt_memory_fault *fault) noexcept {
    if (!outLength || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_memory_fault detail{};
    forge::win64::ServiceInvocation call{instance, thread, detail};
    const auto status = call.resolveCurrent();
    if (status != FORGE_RT_OK) {
        return status;
    }

    const auto string =
        forge::win64::guestBuffer<forge::win64::stringLength, 0>(call, std::tie(address));
    if (string.absent()) {
        *outLength = 0;
        return FORGE_RT_OK;
    }

    size_t length = 0;
    while (length < stringLimit) {
        const auto count = std::min(chunkSize, stringLimit - length);
        const auto chunk = readChunk(string, length, count);
        if (chunk.status == FORGE_RT_GUEST_FAULT) {
            if (detail.reason == FORGE_RT_FAULT_OVERFLOW) {
                detail.address = address;
            }

            *fault = detail;
        }

        if (chunk.status != FORGE_RT_OK) {
            return chunk.status;
        }

        length += chunk.length;
        if (chunk.terminated) {
            *outLength = static_cast<int32_t>(length);
            return FORGE_RT_OK;
        }
    }

    return FORGE_RT_RESOURCE_EXHAUSTED;
}
