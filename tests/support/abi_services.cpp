#include "abi_services.h"
#include "forge/service_memory.h"

#include <cstdio>

namespace forge::test {
    extern "C" forge_rt_status abiPair(forge_rt_instance *, forge_rt_thread_token, int32_t a,
                                       uint32_t b, int64_t *out) noexcept {
        *out = int64_t{a} * 0x100000000LL + b;
        return FORGE_RT_OK;
    }

    extern "C" forge_rt_status abiTriple(forge_rt_instance *, forge_rt_thread_token, uint64_t a,
                                         int64_t b, uint64_t c, uint64_t *out) noexcept {
        *out = a + static_cast<uint64_t>(b / 2) + 3 * c;
        return FORGE_RT_OK;
    }

    extern "C" forge_rt_status abiFour(forge_rt_instance *, forge_rt_thread_token, int32_t a,
                                       uint32_t b, int64_t c, uint64_t d, int32_t *out) noexcept {
        *out = a == -3 && b == 0xfffffffe && c == -5 && d == 0xfedcba9876543210ULL ? -7 : 0;
        return FORGE_RT_OK;
    }

    extern "C" forge_rt_status abiSix(forge_rt_instance *, forge_rt_thread_token, uint64_t a,
                                      uint64_t b, uint64_t c, uint64_t d, int32_t e, uint64_t f,
                                      uint64_t *out) noexcept {
        std::fputc('S', stdout);
        std::fflush(stdout);
        *out = a + 3 * b + 5 * c + 7 * d + 11 * static_cast<uint64_t>(e) + 13 * f;
        return FORGE_RT_OK;
    }

    extern "C" forge_rt_status abiEcho(forge_rt_instance *, forge_rt_thread_token, uint64_t bits,
                                       uint64_t *out) noexcept {
        *out = bits;
        return FORGE_RT_OK;
    }

    extern "C" forge_rt_status abiTailByte(forge_rt_instance *instance,
                                           forge_rt_thread_token thread, uint64_t start, uint64_t b,
                                           uint64_t c, uint64_t d, uint32_t count, uint32_t *out,
                                           forge_rt_memory_fault *fault) noexcept {
        ServiceInvocation call{instance, thread, *fault};
        auto status = call.resolveCurrent();
        if (status != FORGE_RT_OK) {
            return status;
        }

        const auto buffer = guestBuffer<tailByte, 0>(call, std::tie(start, b, c, d, count));
        uint8_t byte = 0;
        if (count) {
            status = buffer.readScalar(count - 1, byte);
        }

        if (status == FORGE_RT_OK) {
            *out = byte;
        }

        return status;
    }

    extern "C" forge_rt_status abiWrite(forge_rt_instance *instance, forge_rt_thread_token thread,
                                        uint64_t file, uint64_t buffer, uint32_t count,
                                        uint64_t written, uint64_t state, int32_t *out,
                                        forge_rt_memory_fault *fault) noexcept {
        ServiceInvocation call{instance, thread, *fault};
        auto status = call.resolveCurrent();
        if (status != FORGE_RT_OK) {
            return status;
        }

        const auto args = std::tie(file, buffer, count, written, state);
        const auto bytes = guestBuffer<writeProbe, 1>(call, args);
        const auto countSlot = guestBuffer<writeProbe, 3>(call, args);
        const auto record = guestBuffer<writeProbe, 4>(call, args);

        status = bytes.validate();
        if (status != FORGE_RT_OK) {
            return status;
        }

        uint32_t sum = 0;
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t byte;
            status = bytes.readScalar(i, byte);
            if (status != FORGE_RT_OK) {
                return status;
            }
            sum += byte;
        }

        if (!record.absent()) {
            status = record.validate();
            if (status != FORGE_RT_OK) {
                return status;
            }
            uint32_t value;
            status = record.readScalar(0, value);
            if (status != FORGE_RT_OK) {
                return status;
            }
            status = record.writeScalar(0, value + sum);
            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        if (!countSlot.absent()) {
            status = countSlot.writeScalar(0, count);
            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        // This probe publishes its external marker only after all checked guest operations.
        std::fputc('W', stdout);
        std::fflush(stdout);
        *out = file == 0xfedcba9876543210ULL ? static_cast<int32_t>(sum) : 0;
        return FORGE_RT_OK;
    }
} // namespace forge::test
