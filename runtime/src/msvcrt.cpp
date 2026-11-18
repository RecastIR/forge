#include "string_scan.h"

#include <stdexcept>
#include <vector>

using namespace forge::win64;

namespace {
    template <typename Result, typename Operation>
    forge_rt_status checkedCall(forge_rt_instance *instance, forge_rt_thread_token thread,
                                Result *result, forge_rt_memory_fault *fault, Operation operation) {
        if (!result || !fault) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        forge_rt_memory_fault detail{};
        ServiceInvocation call{instance, thread, detail};
        const auto active = call.resolveCurrent();
        if (active != FORGE_RT_OK) {
            return active;
        }

        Result value{};
        const auto status = operation(call, value);
        if (status == FORGE_RT_OK) {
            *result = value;
        } else if (status == FORGE_RT_GUEST_FAULT) {
            *fault = detail;
        }
        return status;
    }

    template <Argument arg>
    forge_rt_status compare(const GuestBuffer<arg> &left, const GuestBuffer<arg> &right,
                            uint64_t count, int32_t &result) {
        for (uint64_t i = 0; i < count; ++i) {
            uint8_t a, b;
            auto status = left.readScalar(i, a);

            if (status != FORGE_RT_OK) {
                return status;
            }

            status = right.readScalar(i, b);

            if (status != FORGE_RT_OK) {
                return status;
            }

            if (!a || a != b) {
                result = (a > b) - (a < b);
                return FORGE_RT_OK;
            }
        }

        result = 0;
        return FORGE_RT_OK;
    }
} // namespace

extern "C" forge_rt_status forge_rt_msvcrt_strlen(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t address,
                                                  uint64_t *result,
                                                  forge_rt_memory_fault *fault) noexcept {
    return checkedCall(instance, thread, result, fault,
                       [&](ServiceInvocation &call, uint64_t &length) {
                           const auto string = guestBuffer<crtStrlen, 0>(call, std::tie(address));
                           return forge::runtime::scanString(string, UINT64_MAX, length);
                       });
}

extern "C" forge_rt_status forge_rt_msvcrt_strcmp(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t left,
                                                  uint64_t right, int32_t *result,
                                                  forge_rt_memory_fault *fault) noexcept {
    return checkedCall(instance, thread, result, fault,
                       [&](ServiceInvocation &call, int32_t &order) {
                           const auto args = std::tie(left, right);
                           return compare(guestBuffer<crtStrcmp, 0>(call, args),
                                          guestBuffer<crtStrcmp, 1>(call, args), UINT64_MAX, order);
                       });
}

extern "C" forge_rt_status forge_rt_msvcrt_strncmp(forge_rt_instance *instance,
                                                   forge_rt_thread_token thread, uint64_t left,
                                                   uint64_t right, uint64_t count, int32_t *result,
                                                   forge_rt_memory_fault *fault) noexcept {
    return checkedCall(instance, thread, result, fault,
                       [&](ServiceInvocation &call, int32_t &order) {
                           const auto args = std::tie(left, right, count);
                           return compare(guestBuffer<crtStrncmp, 0>(call, args),
                                          guestBuffer<crtStrncmp, 1>(call, args), count, order);
                       });
}

extern "C" forge_rt_status forge_rt_msvcrt_memcpy(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread,
                                                  uint64_t destination, uint64_t source,
                                                  uint64_t count, uint64_t *result,
                                                  forge_rt_memory_fault *fault) noexcept {
    return checkedCall(instance, thread, result, fault,
                       [&](ServiceInvocation &call, uint64_t &address) {
                           address = destination;
                           if (count == 0) {
                               return FORGE_RT_OK;
                           }

                           const auto args = std::tie(destination, source, count);
                           const auto input = guestBuffer<crtMemcpy, 1>(call, args);
                           const auto output = guestBuffer<crtMemcpy, 0>(call, args);
                           auto status = input.validate();
                           if (status != FORGE_RT_OK) {
                               return status;
                           }
                           status = output.validate();
                           if (status != FORGE_RT_OK) {
                               return status;
                           }

                           // Each checked transfer covers the whole range. No destination bytes
                           // have been changed if a source mapping disappears or staging cannot be
                           // allocated.
                           try {
                               std::vector<uint8_t> bytes(count);
                               status = input.read(0, bytes);
                               return status == FORGE_RT_OK ? output.write(0, bytes) : status;
                           } catch (const std::bad_alloc &) {
                               return FORGE_RT_RESOURCE_EXHAUSTED;
                           } catch (const std::length_error &) {
                               return FORGE_RT_RESOURCE_EXHAUSTED;
                           }
                       });
}
