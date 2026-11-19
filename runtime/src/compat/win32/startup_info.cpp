#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/service_memory.h"

#include <algorithm>
#include <bit>
#include <cstddef>

namespace forge::runtime {
    namespace {
        // The payload starts at an even guest VA. Each UTF-16 view ends on an even VA.
        size_t wideOffset(const StartupText &text) { return (text.narrow.size() + 2) & ~size_t{1}; }
    } // namespace

    forge_rt_status StartupInfo::prepare(const StandardHandles *handles, size_t &size) {
        if (reserved.size() > UINT16_MAX) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        if (window.flags & useStdHandles) {
            if (!handles) {
                return FORGE_RT_INVALID_STATE;
            }

            creationHandles = handles->values();
        }

        size = reserved.size();

        for (auto *field : {&shell, &desktop, &title}) {
            if (!*field) {
                continue;
            }

            auto &text = **field;
            // The internal launcher string repertoire is ASCII, shared by the A and W views.
            if (text.narrow.size() > 32766 ||
                std::ranges::any_of(text.narrow, [](unsigned char c) { return !c || c > 127; })) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            text.wide.assign(text.narrow.begin(), text.narrow.end());
            size += wideOffset(text) + (text.wide.size() + 1) * sizeof(char16_t);
        }

        return FORGE_RT_OK;
    }

    size_t StartupInfo::map(uint64_t base, std::span<forge_rt_image_region, maxRows> rows) {
        size_t count = 0;

        for (auto *field : {&shell, &desktop, &title}) {
            if (!*field) {
                continue;
            }

            auto &text = **field;
            text.narrowAddress = base;
            rows[count++] = {base, text.narrow.size() + 1, text.narrow.c_str(), FORGE_RT_READ,
                             nullptr};
            base += wideOffset(text);
            text.wideAddress = base;
            const auto wideBytes = (text.wide.size() + 1) * sizeof(char16_t);
            rows[count++] = {base, wideBytes, text.wide.c_str(), FORGE_RT_READ, nullptr};
            base += wideBytes;
        }

        if (!reserved.empty()) {
            reservedAddress = base;
            rows[count++] = {base, reserved.size(), reserved.data(), FORGE_RT_READ, nullptr};
        }

        return count;
    }

    namespace {
        using namespace win64;

        // Explicit Windows x64 field widths and padding, including the two holes that
        // both system calls must leave untouched. No host address crosses this boundary.
        struct StartupInfo64 {
            uint32_t cb, pad0;
            uint64_t reserved, desktop, title;
            StartupWindow window;
            uint16_t show, reservedSize;
            uint32_t pad1;
            uint64_t reservedData;
            std::array<uint64_t, 3> handles;
        };

        static_assert(sizeof(StartupInfo64) == startupInfoOutput.size &&
                      alignof(StartupInfo64) == 8);
        static_assert(offsetof(StartupInfo64, reserved) == 8 &&
                      offsetof(StartupInfo64, desktop) == 16 &&
                      offsetof(StartupInfo64, title) == 24 &&
                      offsetof(StartupInfo64, window) == 32);
        static_assert(sizeof(StartupWindow) == 32 && offsetof(StartupWindow, flags) == 28);
        static_assert(offsetof(StartupInfo64, show) == 64 &&
                      offsetof(StartupInfo64, reservedSize) == 66 &&
                      offsetof(StartupInfo64, reservedData) == 72 &&
                      offsetof(StartupInfo64, handles) == 80);
        static_assert(sizeof(char16_t) == 2);

        std::optional<StartupInfo64> startupView(const WindowsProcessState &windows, bool ansi) {
            const auto &info = windows.parameters.startupInfo;
            const auto stringAddress = [ansi](const std::optional<StartupText> &text) -> uint64_t {
                if (!text) {
                    return 0;
                }

                return ansi ? text->narrowAddress : text->wideAddress;
            };

            StartupInfo64 value{};
            value.cb = sizeof(value);
            value.reserved = stringAddress(info.shell);
            value.desktop = stringAddress(info.desktop);
            value.title = stringAddress(info.title);
            value.window = info.window;
            value.show = info.show;
            value.reservedSize = static_cast<uint16_t>(info.reserved.size());
            value.reservedData = info.reservedAddress;

            const bool useHandles = (info.window.flags & StartupInfo::useStdHandles) != 0;

            if (ansi) {
                value.handles = info.creationHandles;

                if (!useHandles) {
                    value.handles.fill(UINT64_MAX);
                }
            } else if (useHandles) {
                if (!windows.standardHandles) {
                    return std::nullopt;
                }

                value.handles = windows.standardHandles->values();
            }

            return value;
        }

        template <const ServiceBinding &binding>
        forge_rt_status getStartupInfo(forge_rt_instance *instance, forge_rt_thread_token thread,
                                       GuestAddress address, forge_rt_memory_fault *fault) {
            if (!fault) {
                return FORGE_RT_INVALID_ARGUMENT;
            }

            const auto admitted = withInstance(
                instance, [&](const auto &owner) { return checkPendingExecution(owner, thread); });

            if (admitted != FORGE_RT_OK) {
                return admitted;
            }

            // The current synchronous invocation pins all mappings throughout this call.
            ServiceInvocation call{instance, thread, *fault, executingInvocation};
            const auto output = guestBuffer<binding, 0>(call, std::tie(address.value));
            constexpr bool ansi = &binding == &getStartupInfoA;
            const auto view = startupView(*instance->windows, ansi);

            if (!view) {
                return FORGE_RT_INVALID_STATE;
            }

            const auto &value = *view;
            const auto bytes = std::bit_cast<std::array<uint8_t, sizeof(value)>>(value);

            // Validate all 104 bytes before writing the discontiguous named fields.
            // Writing only the named ranges also preserves uninitialized stack marks.
            auto status = output.validate();

            if (status == FORGE_RT_OK) {
                status = output.writeScalar(0, value.cb);
            }

            if (status == FORGE_RT_OK) {
                constexpr size_t start = offsetof(StartupInfo64, reserved);
                constexpr size_t end = offsetof(StartupInfo64, pad1);
                status = output.write(start, std::span(bytes).subspan<start, end - start>());
            }

            if (status == FORGE_RT_OK) {
                constexpr size_t start = offsetof(StartupInfo64, reservedData);
                const auto end = ansi || (value.window.flags & StartupInfo::useStdHandles)
                                     ? sizeof(value)
                                     : offsetof(StartupInfo64, handles);
                status = output.write(start, std::span(bytes).subspan(start, end - start));
            }

            return status;
        }
    } // namespace
} // namespace forge::runtime

extern "C" forge_rt_status forge_rt_get_startup_info_a(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t address,
                                                       forge_rt_memory_fault *fault) noexcept {
    return forge::runtime::getStartupInfo<forge::win64::getStartupInfoA>(
        instance, thread, forge::GuestAddress{address}, fault);
}

extern "C" forge_rt_status forge_rt_get_startup_info_w(forge_rt_instance *instance,
                                                       forge_rt_thread_token thread,
                                                       uint64_t address,
                                                       forge_rt_memory_fault *fault) noexcept {
    return forge::runtime::getStartupInfo<forge::win64::getStartupInfoW>(
        instance, thread, forge::GuestAddress{address}, fault);
}
