#pragma once

#include "forge/guest_range.h"
#include "forge/service_signature.h"

#include <bit>
#include <tuple>

namespace forge::win64 {
    template <class T>
    concept GuestInteger = std::is_integral_v<T> && !std::is_same_v<T, bool> &&
                           !std::is_const_v<T> && !std::is_volatile_v<T>;

    static_assert(std::endian::native == std::endian::little);

    // The synchronous adapter owns this context and the diagnostic until it returns.
    struct ServiceInvocation {
        forge_rt_instance *instance;
        forge_rt_thread_token thread;
        forge_rt_memory_fault &fault;
        forge_rt_invocation_token token = 0;

        forge_rt_status resolveCurrent() {
            return forge_rt_current_invocation(instance, thread, &token);
        }
    };

    template <Argument arg> class GuestBuffer {
      public:
        bool absent() const { return arg.optional && !start.value; }

        uint64_t byteSize() const
            requires(arg.extent == Extent::InitializerEnd || arg.extent == Extent::ElementProduct)
        {
            return size;
        }

        forge_rt_status validate() const
            requires(arg.extent != Extent::CString)
        {
            constexpr uint32_t access = (arg.access != Access::Output ? FORGE_RT_READ : 0u) |
                                        (arg.writes() ? FORGE_RT_WRITE : 0u);
            uint64_t address;
            const auto status = locate(0, size, access, address);
            if (status != FORGE_RT_OK) {
                return status;
            }

            return forge_rt_validate_guest(call.instance, call.thread, call.token, address, size,
                                           access, &call.fault);
        }

        forge_rt_status read(uint64_t offset, std::span<uint8_t> bytes) const
            requires(arg.access != Access::Output)
        {
            uint64_t address;
            const auto status = locate(offset, bytes.size(), FORGE_RT_READ, address);
            if (status != FORGE_RT_OK) {
                return status;
            }

            return forge_rt_read_guest(call.instance, call.thread, call.token, address,
                                       bytes.size(), bytes.data(), bytes.size(), &call.fault);
        }

        forge_rt_status write(uint64_t offset, std::span<const uint8_t> bytes) const
            requires(arg.writes())
        {
            uint64_t address;
            const auto status = locate(offset, bytes.size(), FORGE_RT_WRITE, address);
            if (status != FORGE_RT_OK) {
                return status;
            }

            return forge_rt_write_guest(call.instance, call.thread, call.token, address,
                                        bytes.size(), bytes.data(), bytes.size(), &call.fault);
        }

        // The runtime target and Windows x64 both use little-endian integers.
        template <GuestInteger T>
            requires(arg.access != Access::Output)
        forge_rt_status readScalar(uint64_t offset, T &value) const {
            return read(offset, {reinterpret_cast<uint8_t *>(&value), sizeof(T)});
        }

        template <GuestInteger T>
            requires(arg.writes())
        forge_rt_status writeScalar(uint64_t offset, T value) const {
            return write(offset, {reinterpret_cast<const uint8_t *>(&value), sizeof(T)});
        }

      private:
        template <const ServiceBinding &binding, size_t position, class... Args>
        friend auto guestBuffer(ServiceInvocation &, const std::tuple<Args...> &);

        GuestBuffer(ServiceInvocation &call, GuestAddress start, uint64_t size)
            : call(call), start(start), size(size) {}

        ServiceInvocation &call;
        GuestAddress start;
        uint64_t size;

        forge_rt_status locate(uint64_t offset, uint64_t count, uint32_t access,
                               uint64_t &address) const {
            // Exceeding the declared buffer is an adapter error. The runtime independently
            // checks the actual guest mapping, permissions and marks for every transfer.
            if (offset > size || count > size - offset) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            if (!start.value || offset > UINT64_MAX - start.value) {
                // A zero-byte validation checks the captured token without touching guest memory.
                const auto live = forge_rt_validate_guest(call.instance, call.thread, call.token,
                                                          start.value, 0, access, &call.fault);
                if (live != FORGE_RT_OK) {
                    return live;
                }

                call.fault = {start.value, access,
                              start.value ? FORGE_RT_FAULT_OVERFLOW : FORGE_RT_FAULT_UNMAPPED};
                return FORGE_RT_GUEST_FAULT;
            }

            address = start.value + offset;
            return FORGE_RT_OK;
        }
    };

    template <const ServiceBinding &binding, size_t position, class... Args>
    auto guestBuffer(ServiceInvocation &call, const std::tuple<Args...> &arguments) {
        static_assert(sizeof...(Args) == binding.arguments.size());
        constexpr auto arg = binding.arguments[position];
        static_assert(arg.access != Access::None);
        uint64_t size = UINT64_MAX;
        if constexpr (arg.extent == Extent::CountArgument) {
            size = std::get<arg.size>(arguments);
        } else if constexpr (arg.extent == Extent::Fixed ||
                             (arg.extent == Extent::CString && arg.size)) {
            size = arg.size;
        }

        const GuestAddress first{std::get<position>(arguments)};

        if constexpr (arg.extent == Extent::InitializerEnd) {
            using Table = std::optional<GuestBuffer<arg>>;
            const auto bytes = initializerRangeBytes(first.value, std::get<arg.size>(arguments));

            if (!bytes) {
                return Table{};
            }

            return Table{GuestBuffer<arg>(call, first, *bytes)};
        } else if constexpr (arg.extent == Extent::ElementProduct) {
            using Buffer = std::optional<GuestBuffer<arg>>;
            const auto bytes =
                elementBytes(std::get<arg.size>(arguments), std::get<arg.size + 1>(arguments));
            if (!bytes) {
                return Buffer{};
            }
            return Buffer{GuestBuffer<arg>(call, first, *bytes)};
        } else {
            return GuestBuffer<arg>(call, first, size);
        }
    }
} // namespace forge::win64
