#include "wait.h"

#include <cerrno>
#include <sched.h>
#include <time.h>
#include <unistd.h>

namespace forge::runtime::darwin {
    int yieldThread() noexcept { return ::sched_yield() == 0 ? 0 : errno; }

    int waitForMilliseconds(uint32_t milliseconds) noexcept {
        timespec remaining{static_cast<time_t>(milliseconds / 1000),
                           static_cast<long>(milliseconds % 1000) * 1000000L};

        while (::nanosleep(&remaining, &remaining) != 0) {
            if (errno != EINTR) {
                return errno;
            }
        }

        return 0;
    }

    int waitIndefinitely() noexcept {
        while (::pause() == -1 && errno == EINTR) {
            // A caught signal wakes pause. Block again after its handler returns.
        }

        return errno;
    }
} // namespace forge::runtime::darwin
