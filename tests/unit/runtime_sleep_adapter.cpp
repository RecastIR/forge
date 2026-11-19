#include <forge/runtime.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <latch>
#include <thread>
#include <time.h>

namespace {
    void require(bool passed, const char *expression, int line) {
        if (!passed) {
            std::fprintf(stderr, "runtime_sleep_adapter.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    struct WaitProbe {
        std::latch entered{1}, resume{1};
    };

    thread_local WaitProbe *activeWait = nullptr;
    unsigned yields = 0, pauses = 0;
} // namespace

extern "C" int forgeTestYield() {
    ++yields;
    errno = EIO;
    return -1;
}

extern "C" int forgeTestNanosleep(const timespec *request, timespec *) {
    if (!activeWait) {
        REQUIRE(request->tv_sec == 0 && request->tv_nsec == 1'000'000);
        errno = EIO;
        return -1;
    }

    REQUIRE(request->tv_sec == 4'294'967 && request->tv_nsec == 294'000'000);
    activeWait->entered.count_down();
    activeWait->resume.wait();
    return 0;
}

extern "C" int forgeTestPause() {
    ++pauses;
    REQUIRE(pauses <= 2);
    errno = pauses == 1 ? EINTR : EIO;
    return -1;
}

int main() {
    forge_rt_instance *instance = nullptr;
    forge_rt_thread_token thread = 0;
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &instance) == FORGE_RT_OK);
    REQUIRE(forge_rt_thread_create(instance, &thread) == FORGE_RT_OK);
    REQUIRE(forge_rt_set_last_error(instance, thread, 17) == FORGE_RT_OK);

    REQUIRE(forge_rt_sleep(nullptr, thread, UINT32_MAX) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_sleep(instance, 0, 0) == FORGE_RT_INVALID_THREAD);
    REQUIRE(forge_rt_sleep(instance, thread, 0) == FORGE_RT_INTERNAL_ERROR);
    REQUIRE(forge_rt_sleep(instance, thread, 1) == FORGE_RT_INTERNAL_ERROR);
    REQUIRE(forge_rt_sleep(instance, thread, UINT32_MAX) == FORGE_RT_INTERNAL_ERROR);
    REQUIRE(yields == 1 && pauses == 2);
    uint32_t error = 0;
    REQUIRE(forge_rt_get_last_error(instance, thread, &error) == FORGE_RT_OK && error == 17);

    WaitProbe probe;
    std::thread sleeper([&] {
        activeWait = &probe;
        REQUIRE(forge_rt_sleep(instance, thread, UINT32_MAX - 1) == FORGE_RT_OK);
    });
    probe.entered.wait();
    REQUIRE(forge_rt_set_last_error(instance, thread, 42) == FORGE_RT_OK);
    probe.resume.count_down();
    sleeper.join();

    REQUIRE(forge_rt_get_last_error(instance, thread, &error) == FORGE_RT_OK && error == 42);
    REQUIRE(forge_rt_thread_destroy(instance, thread) == FORGE_RT_OK);
    REQUIRE(forge_rt_destroy(instance) == FORGE_RT_OK);
}
