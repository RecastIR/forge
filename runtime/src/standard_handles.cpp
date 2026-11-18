#include "instance.h"

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace forge::runtime {
    namespace {
        constexpr int firstPrivateDescriptor = 3;

        forge_rt_status duplicationFailure(int error) {
            if (error == EMFILE || error == ENFILE || error == ENOMEM) {
                return FORGE_RT_RESOURCE_EXHAUSTED;
            }

            // F_DUPFD_CLOEXEC also rejects a minimum outside the soft descriptor limit.
            struct rlimit limit{};

            if (error == EINVAL && ::getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
                limit.rlim_cur <= firstPrivateDescriptor) {
                return FORGE_RT_RESOURCE_EXHAUSTED;
            }

            return FORGE_RT_HOST_CONFIGURATION;
        }

        StreamKind streamKind(int descriptor, const struct stat &info) {
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
    } // namespace

    StandardHandles::~StandardHandles() {
        for (const auto &stream : streams) {
            if (stream.descriptor >= 0) {
                ::close(stream.descriptor);
            }
        }
    }

    forge_rt_status StandardHandles::capture() noexcept {
        for (size_t index = 0; index < streams.size(); ++index) {
            auto &stream = streams[index];

            // Never occupy a missing standard slot while capturing a different one.
            do {
                stream.descriptor =
                    ::fcntl(static_cast<int>(index), F_DUPFD_CLOEXEC, firstPrivateDescriptor);
            } while (stream.descriptor < 0 && errno == EINTR);

            if (stream.descriptor < 0) {
                if (errno == EBADF) {
                    continue;
                }

                return duplicationFailure(errno);
            }

            struct stat info{};
            int result;

            do {
                result = ::fstat(stream.descriptor, &info);
            } while (result < 0 && errno == EINTR);

            if (result < 0) {
                return FORGE_RT_HOST_CONFIGURATION;
            }

            int flags;

            do {
                flags = ::fcntl(stream.descriptor, F_GETFL);
            } while (flags < 0 && errno == EINTR);

            if (flags < 0) {
                return FORGE_RT_HOST_CONFIGURATION;
            }

            const int access = flags & O_ACCMODE;
            stream.writable = index != STDIN_FILENO && (access == O_WRONLY || access == O_RDWR);
            stream.kind = streamKind(stream.descriptor, info);

            // Guest handles occupy a separate namespace from small POSIX descriptors.
            // Exhaust before wrapping or issuing the Windows INVALID_HANDLE_VALUE sentinel.
            constexpr uint64_t handleTag = uint64_t{1} << 63;
            const auto generation = issueToken();

            if (!generation || generation >= handleTag - 1) {
                return FORGE_RT_RESOURCE_EXHAUSTED;
            }

            stream.handle = handleTag | generation;
        }

        return FORGE_RT_OK;
    }
} // namespace forge::runtime
