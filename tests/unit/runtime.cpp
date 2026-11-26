#include <forge/runtime.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <latch>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

void testRuntimeMemory();
void testRuntimeProcess();
void testRuntimeConsoleProcess(const char *fatalObservations);
void testRuntimeWrite();
void testRuntimeStartupInfo();
void testRuntimePageProtection();

namespace {
    volatile std::sig_atomic_t caughtAlarm = 0;

    void catchAlarm(int) { caughtAlarm = 1; }

    [[noreturn]] void exerciseInterruptedWaits(forge_rt_instance *runtime,
                                               forge_rt_thread_token thread) {
        using namespace std::chrono;
        struct sigaction action{};
        action.sa_handler = catchAlarm;
        sigset_t signals;
        const itimerval periodic{{0, 10000}, {0, 10000}};

        if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGALRM, &action, nullptr) != 0 ||
            sigemptyset(&signals) != 0 || sigaddset(&signals, SIGALRM) != 0 ||
            sigprocmask(SIG_UNBLOCK, &signals, nullptr) != 0 ||
            setitimer(ITIMER_REAL, &periodic, nullptr) != 0) {
            _exit(2);
        }

        const auto start = steady_clock::now();
        const auto status = forge_rt_sleep(runtime, thread, 80);
        uint32_t error = 0;

        if (status != FORGE_RT_OK || steady_clock::now() - start < milliseconds(80) ||
            !caughtAlarm || forge_rt_get_last_error(runtime, thread, &error) != FORGE_RT_OK ||
            error != 42) {
            _exit(1);
        }

        // Catch one alarm and let the next end the child. The adapter test counts pause retries.
        const itimerval twice{{0, 50000}, {0, 50000}};
        action.sa_flags = SA_RESETHAND;

        if (setitimer(ITIMER_REAL, &twice, nullptr) != 0 ||
            sigaction(SIGALRM, &action, nullptr) != 0) {
            _exit(2);
        }

        forge_rt_sleep(runtime, thread, UINT32_MAX);
        _exit(1);
    }

    bool waitsAcrossSignals(forge_rt_instance *runtime, forge_rt_thread_token thread) {
        using namespace std::chrono;
        const auto child = fork();

        if (child < 0) {
            return false;
        }

        if (child == 0) {
            exerciseInterruptedWaits(runtime, thread);
        }

        const auto deadline = steady_clock::now() + seconds(5);
        int status;

        while (steady_clock::now() < deadline) {
            const auto waited = waitpid(child, &status, WNOHANG);

            if (waited == child) {
                return WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM;
            }

            if (waited < 0 && errno != EINTR) {
                return false;
            }

            std::this_thread::sleep_for(milliseconds(10));
        }

        kill(child, SIGKILL);

        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }

        return false;
    }

    bool sleepContract(forge_rt_instance *runtime) {
        using namespace std::chrono;
        forge_rt_thread_token thread = 0;
        uint32_t error = 0;

        if (forge_rt_sleep(nullptr, 0, UINT32_MAX) != FORGE_RT_INVALID_ARGUMENT ||
            forge_rt_sleep(runtime, 0, UINT32_MAX) != FORGE_RT_INVALID_THREAD ||
            forge_rt_thread_create(runtime, &thread) != FORGE_RT_OK ||
            forge_rt_set_last_error(runtime, thread, 42) != FORGE_RT_OK ||
            forge_rt_sleep(runtime, thread, 0) != FORGE_RT_OK ||
            forge_rt_get_last_error(runtime, thread, &error) != FORGE_RT_OK || error != 42) {
            return false;
        }

        const auto start = steady_clock::now();
        const auto status = forge_rt_sleep(runtime, thread, 10);
        const auto elapsed = steady_clock::now() - start;
        return status == FORGE_RT_OK && elapsed >= milliseconds(10) &&
               forge_rt_get_last_error(runtime, thread, &error) == FORGE_RT_OK && error == 42 &&
               waitsAcrossSignals(runtime, thread) &&
               forge_rt_thread_destroy(runtime, thread) == FORGE_RT_OK &&
               forge_rt_sleep(runtime, thread, 0) == FORGE_RT_INVALID_THREAD;
    }

    bool observeRetirement(forge_rt_instance *runtime, forge_rt_thread_token thread,
                           const std::atomic<bool> &replaced) {
        uint32_t value = 0;
        bool retired = false;

        while (!replaced.load()) {
            // Removal may occur between these calls. A token that has already failed
            // validation must never start succeeding again.
            const auto set = forge_rt_set_last_error(runtime, thread, 7);
            const auto get = forge_rt_get_last_error(runtime, thread, &value);
            const bool wrote = !retired && set == FORGE_RT_OK;

            if (!wrote && set != FORGE_RT_INVALID_THREAD) {
                return false;
            }

            if (get == FORGE_RT_INVALID_THREAD) {
                retired = true;
                continue;
            }

            if (get != FORGE_RT_OK || !wrote || value != 7) {
                return false;
            }
        }

        return forge_rt_set_last_error(runtime, thread, 19) == FORGE_RT_INVALID_THREAD &&
               forge_rt_get_last_error(runtime, thread, &value) == FORGE_RT_INVALID_THREAD;
    }

    bool raceDestruction(forge_rt_instance *runtime) {
        forge_rt_thread_token original = 0;

        if (forge_rt_thread_create(runtime, &original) != FORGE_RT_OK) {
            return false;
        }

        if (forge_rt_set_last_error(runtime, original, 23) != FORGE_RT_OK) {
            return false;
        }

        std::latch started(1);
        std::atomic<bool> replaced{false};
        bool readerPassed = true;
        std::thread reader([&] {
            uint32_t value = 0;
            readerPassed =
                forge_rt_get_last_error(runtime, original, &value) == FORGE_RT_OK && value == 23;
            readerPassed &= forge_rt_set_last_error(runtime, original, 7) == FORGE_RT_OK;
            started.count_down();

            readerPassed &= observeRetirement(runtime, original, replaced);
        });

        started.wait();
        uint32_t observed = 0;
        const bool transferred =
            forge_rt_get_last_error(runtime, original, &observed) == FORGE_RT_OK && observed == 7;
        const auto destroyed = forge_rt_thread_destroy(runtime, original);
        forge_rt_thread_token replacement = 0;
        const auto created = forge_rt_thread_create(runtime, &replacement);
        replaced.store(true);
        reader.join();

        uint32_t value = 42;
        return transferred && readerPassed && destroyed == FORGE_RT_OK && created == FORGE_RT_OK &&
               forge_rt_get_last_error(runtime, replacement, &value) == FORGE_RT_OK && value == 0 &&
               forge_rt_thread_destroy(runtime, replacement) == FORGE_RT_OK;
    }
} // namespace

int main(int argc, char **argv) {
    if (argc > 2) {
        std::fputs("Usage: runtime_contract [windows-fatal-observations]\n", stderr);
        return 1;
    }

    forge_rt_instance *runtime = nullptr;

    if (forge_rt_create(FORGE_RT_ABI_VERSION, &runtime) != FORGE_RT_OK) {
        return 1;
    }

    // The wait probes install timers and signal policy only in a single-threaded child.
    bool passed = sleepContract(runtime);
    testRuntimeMemory();
    testRuntimeProcess();
    testRuntimeConsoleProcess(argv[1]);
    testRuntimeWrite();
    testRuntimeStartupInfo();
    testRuntimePageProtection();

    for (unsigned trial = 0; trial < 64 && passed; ++trial) {
        passed = raceDestruction(runtime);
    }

    const auto cleanup = forge_rt_destroy(runtime);

    if (!passed || cleanup != FORGE_RT_OK) {
        std::fputs("Guest thread access or destruction violated its lifetime contract\n", stderr);
        return 1;
    }

    return 0;
}
