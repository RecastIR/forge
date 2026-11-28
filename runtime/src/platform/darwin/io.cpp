#include "io.h"

#include <algorithm>
#include <climits>
#include <csignal>
#include <fcntl.h>
#ifdef __APPLE__
#include <sys/event.h>
#else
#include <poll.h>
#endif
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

        // A large nonblocking CRT staging block may start only when it fits.
        // A ready result is a snapshot. Subsequent writes still account for their actual prefix.
        std::optional<WriteProgress> checkPipeSpace(int fd, size_t requested) {
#ifdef __APPLE__
            const int queue = ::kqueue();
            if (queue < 0) {
                return WriteProgress{0, errno, true};
            }

            struct kevent change{}, event{};
            EV_SET(&change, static_cast<uintptr_t>(fd), EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
            const timespec now{};
            int ready;
            do {
                ready = ::kevent(queue, &change, 1, &event, 1, &now);
            } while (ready < 0 && errno == EINTR);
            const int error = errno;
            ::close(queue);

            if (ready < 0 || (event.flags & EV_ERROR)) {
                return WriteProgress{0, ready < 0 ? error : static_cast<int>(event.data), true};
            }
            if (ready && !(event.flags & EV_EOF) &&
                event.data >= static_cast<intptr_t>(requested)) {
                return std::nullopt;
            }

            // A Darwin FIFO can report writable space even after its reader closes.
            // A zero-byte write distinguishes EPIPE from a live but undersized pipe.
            ssize_t probe;
            do {
                probe = ::write(fd, "", 0);
            } while (probe < 0 && errno == EINTR);
            return WriteProgress{0, probe < 0 ? errno : EAGAIN};
#elif defined(F_GETPIPE_SZ)
            pollfd state{fd, POLLOUT, 0};
            if (::poll(&state, 1, 0) < 0) {
                return WriteProgress{0, errno, true};
            }
            if (state.revents & (POLLERR | POLLHUP)) {
                return std::nullopt; // Let the write report the native error.
            }

            const auto capacity = ::fcntl(fd, F_GETPIPE_SZ);
            int used = 0;
            if (capacity < 0 || ::ioctl(fd, FIONREAD, &used) < 0) {
                return WriteProgress{0, errno, true};
            }
            if (capacity - used < static_cast<intptr_t>(requested)) {
                return WriteProgress{0, EAGAIN};
            }
            return std::nullopt;
#else
            return WriteProgress{0, ENOTSUP, true};
#endif
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
        if (streamKind == StreamKind::Pipe && bytes.size() > PIPE_BUF) {
            const int flags = ::fcntl(fd, F_GETFL);
            if (flags < 0) {
                return {0, errno, true};
            }
            if (flags & O_NONBLOCK) {
                if (const auto stopped = checkPipeSpace(fd, bytes.size())) {
                    return *stopped;
                }
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
