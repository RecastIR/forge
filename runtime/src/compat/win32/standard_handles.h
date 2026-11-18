#pragma once

#include "forge/runtime.h"

#include <array>
#include <cerrno>
#include <span>

namespace forge::runtime {
    enum class StreamKind { RegularFile, TerminalOrNull, Pipe, Socket, OtherDevice };

    struct StandardStream {
        uint64_t handle = 0;
        int descriptor = -1;
        StreamKind kind = StreamKind::OtherDevice;
        bool writable = false;
    };

    class StandardHandles {
      public:
        StandardHandles() = default;
        StandardHandles(const StandardHandles &) = delete;
        StandardHandles &operator=(const StandardHandles &) = delete;
        ~StandardHandles();

        // Called once on an unpublished process. Destruction also releases a partial capture.
        forge_rt_status capture() noexcept;
        std::array<StandardStream, 3> streams{};
        bool hostHandlesOutputSignals = false;
    };

    struct WriteProgress {
        size_t count;
        int error;
    };

    // A write-compatible operation sets errno on failure. A short transfer acknowledges
    // only its prefix; a subsequent failure must retain that progress for the guest.
    template <class Writer> WriteProgress writeAll(std::span<const uint8_t> bytes, Writer write) {
        size_t done = 0;

        while (done < bytes.size()) {
            const auto result = write(bytes.subspan(done));

            if (result > 0) {
                done += static_cast<size_t>(result);
            } else if (result == 0) {
                return {done, EIO};
            } else if (errno != EINTR) {
                return {done, errno};
            }
        }

        return {done, 0};
    }
} // namespace forge::runtime
