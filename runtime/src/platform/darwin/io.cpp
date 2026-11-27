#include "io.h"

#include <algorithm>
#include <climits>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace forge::runtime::darwin {
    namespace {
        constexpr int firstPrivateDescriptor = 3;

        using Status = CaptureResult::Status;

        CaptureResult duplicationFailure(int error) {
            if (error == EBADF) {
                return {Status::Unavailable, error};
            }

            if (error == EMFILE || error == ENFILE || error == ENOMEM) {
                return {Status::ResourceExhausted, error};
            }

            // F_DUPFD_CLOEXEC also rejects a minimum outside the soft descriptor limit.
            struct rlimit limit{};

            if (error == EINVAL && ::getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
                limit.rlim_cur <= firstPrivateDescriptor) {
                return {Status::ResourceExhausted, error};
            }

            return {Status::NativeFailure, error};
        }

        StreamKind classify(int descriptor, const struct stat &info) {
            if (S_ISFIFO(info.st_mode)) {
                return StreamKind::Pipe;
            }

            if (S_ISSOCK(info.st_mode)) {
                return StreamKind::Socket;
            }

            if (S_ISREG(info.st_mode)) {
                return StreamKind::RegularFile;
            }

            if (::isatty(descriptor)) {
                return StreamKind::TerminalOrNull;
            }

            struct stat nullDevice{};

            if (S_ISCHR(info.st_mode) && ::stat("/dev/null", &nullDevice) == 0 &&
                info.st_rdev == nullDevice.st_rdev) {
                return StreamKind::TerminalOrNull;
            }

            return StreamKind::OtherDevice;
        }

        ssize_t nativeWrite(int fd, StreamKind kind, std::span<const uint8_t> bytes) {
            return kind == StreamKind::Socket ? ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL)
                                              : ::write(fd, bytes.data(), bytes.size());
        }

        // Darwin reports queued bytes and current pipe capacity together in fstat.
        // A closed reader must reach write(2) so callers see EPIPE.
        std::optional<size_t> pipeSpace(int fd) {
            pollfd state{fd, POLLOUT, 0};
            if (::poll(&state, 1, 0) < 0 || (state.revents & (POLLERR | POLLHUP))) {
                return std::nullopt;
            }
#ifdef __APPLE__
            struct stat info{};
            if (::fstat(fd, &info) == 0 && info.st_size >= 0 && info.st_blksize >= info.st_size) {
                return static_cast<size_t>(info.st_blksize - info.st_size);
            }
#elif defined(F_GETPIPE_SZ)
            const auto capacity = ::fcntl(fd, F_GETPIPE_SZ);
            int used = 0;
            if (capacity >= 0 && ::ioctl(fd, FIONREAD, &used) == 0 && capacity >= used) {
                return static_cast<size_t>(capacity - used);
            }
#endif
            return std::nullopt;
        }

        bool ignoresSignal(int signal) {
            struct sigaction action{};
            return ::sigaction(signal, nullptr, &action) == 0 && action.sa_handler == SIG_IGN;
        }
    } // namespace

    Descriptor::Descriptor(Descriptor &&other) noexcept
        : fd(std::exchange(other.fd, -1)), streamKind(other.streamKind), mode(other.mode) {}

    Descriptor::~Descriptor() {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    CaptureResult Descriptor::capture(int source, std::optional<Descriptor> &owner) noexcept {
        int copy;

        do {
            copy = ::fcntl(source, F_DUPFD_CLOEXEC, firstPrivateDescriptor);
        } while (copy < 0 && errno == EINTR);

        if (copy < 0) {
            return duplicationFailure(errno);
        }

        Descriptor descriptor(copy);
        struct stat info{};
        int result;

        do {
            result = ::fstat(copy, &info);
        } while (result < 0 && errno == EINTR);

        if (result < 0) {
            return {Status::NativeFailure, errno};
        }

        int flags;

        do {
            flags = ::fcntl(copy, F_GETFL);
        } while (flags < 0 && errno == EINTR);

        if (flags < 0) {
            return {Status::NativeFailure, errno};
        }

        descriptor.mode = static_cast<unsigned>(flags) & static_cast<unsigned>(O_ACCMODE);
        descriptor.streamKind = classify(copy, info);
        owner.emplace(std::move(descriptor));
        return {Status::Captured, 0};
    }

    bool Descriptor::writable() const noexcept { return mode == O_WRONLY || mode == O_RDWR; }

    bool Descriptor::outputSignalsSafe(bool hostHandlesOutputSignals) const noexcept {
        if (hostHandlesOutputSignals) {
            return true;
        }

        if (streamKind == StreamKind::RegularFile) {
            struct rlimit limit{};
            return ::getrlimit(RLIMIT_FSIZE, &limit) == 0 &&
                   (limit.rlim_cur == RLIM_INFINITY || ignoresSignal(SIGXFSZ));
        }

        if (streamKind != StreamKind::Pipe && streamKind != StreamKind::OtherDevice) {
            return true;
        }

#ifdef F_GETNOSIGPIPE
        // The flag belongs to the shared open file description, even after dup. Only inspect it.
        if (::fcntl(fd, F_GETNOSIGPIPE) == 1) {
            return true;
        }
#endif

        return ignoresSignal(SIGPIPE);
    }

    size_t Descriptor::writeChunkSize(size_t capacity) const noexcept {
        // Atomic pipe requests cannot commit an unreported prefix if the reader closes.
        return streamKind == StreamKind::Pipe ? std::min(capacity, static_cast<size_t>(PIPE_BUF))
                                              : capacity;
    }

    WriteProgress Descriptor::write(std::span<const uint8_t> bytes) const noexcept {
        return writeAll(bytes, [&](std::span<const uint8_t> remaining) {
            return nativeWrite(fd, streamKind, remaining);
        });
    }

    WriteProgress Descriptor::writeSome(std::span<const uint8_t> bytes) const noexcept {
        if (streamKind == StreamKind::Pipe) {
            const int flags = ::fcntl(fd, F_GETFL);
            if (flags < 0) {
                return {0, errno};
            }
            if ((flags & O_NONBLOCK) && pipeSpace(fd).value_or(bytes.size()) < bytes.size()) {
                return {0, 0};
            }
            // Atomic chunks retain the exact prefix if another host closes the reader.
            const auto limit = writeChunkSize(bytes.size());
            return writeAll(bytes, [&](std::span<const uint8_t> remaining) {
                return nativeWrite(fd, streamKind,
                                   remaining.first(std::min(limit, remaining.size())));
            });
        }

        ssize_t count;
        do {
            count = nativeWrite(fd, streamKind, bytes);
        } while (count < 0 && errno == EINTR);

        return count < 0 ? WriteProgress{0, errno} : WriteProgress{static_cast<size_t>(count), 0};
    }
} // namespace forge::runtime::darwin
