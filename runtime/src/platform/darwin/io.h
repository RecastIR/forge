#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace forge::runtime::darwin {
    enum class StreamKind : uint8_t { RegularFile, TerminalOrNull, Pipe, Socket, OtherDevice };

    struct CaptureResult {
        enum class Status : uint8_t { Captured, Unavailable, Exhausted, HostConfiguration };
        Status status;
        int error;
    };

    struct WriteProgress {
        size_t count;
        int error;
    };

    class Descriptor {
      public:
        // Success transfers the close-on-exec duplicate to owner. Failure preserves owner
        // and reports the original errno. The caller retains the source in both cases.
        static CaptureResult capture(int source, std::optional<Descriptor> &owner) noexcept;
        Descriptor(Descriptor &&other) noexcept;
        Descriptor(const Descriptor &) = delete;
        Descriptor &operator=(const Descriptor &) = delete;
        Descriptor &operator=(Descriptor &&) = delete;
        ~Descriptor();

        // Borrows the native descriptor. The owner closes it.
        int get() const noexcept { return fd; }

        StreamKind kind() const noexcept { return streamKind; }

        int accessMode() const noexcept { return mode; }

        bool writable() const noexcept;
        bool outputSignalsSafe(bool hostHandlesOutputSignals) const noexcept;
        size_t writeChunkSize(size_t capacity) const noexcept;
        // Check signal policy once before the transfer and bound each span by writeChunkSize.
        WriteProgress write(std::span<const uint8_t> bytes) const noexcept;

      private:
        explicit Descriptor(int fd) : fd(fd) {}

        int fd;
        StreamKind streamKind = StreamKind::OtherDevice;
        int mode = 0;
    };

    // A write-compatible operation sets errno on failure. Only a positive result commits bytes.
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
} // namespace forge::runtime::darwin
