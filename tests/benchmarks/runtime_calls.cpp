#include "runtime_direct.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
    using Clock = std::chrono::steady_clock;
    constexpr size_t sampleCount = 9;
    constexpr uint32_t warmupPairs = 100000;
    constexpr uint32_t timedPairs = 1000000;
    constexpr size_t lifecycleCount = 4096;
    using Samples = std::array<double, sampleCount>;

    double nanoseconds(Clock::duration duration) {
        return std::chrono::duration<double, std::nano>(duration).count();
    }

    // Both instantiations make two out-of-line calls from the same loop.
    template <auto Set, auto Get, typename State>
    double measurePairs(uint32_t count, State *state, forge_rt_thread_token thread) {
        constexpr uint32_t first = 0x80000000U;
        uint64_t checksum = 0;
        const auto start = Clock::now();

        for (uint32_t i = 0; i < count; ++i) {
            uint32_t value = 0;

            if (Set(state, thread, first + i) != FORGE_RT_OK ||
                Get(state, thread, &value) != FORGE_RT_OK) {
                throw std::runtime_error("state operation failed");
            }

            checksum += value;
        }

        const auto elapsed = Clock::now() - start;
        const uint64_t expected = uint64_t(count) * first + uint64_t(count) * (count - 1) / 2;

        if (checksum != expected) {
            throw std::runtime_error("set/get checksum mismatch");
        }

        return nanoseconds(elapsed) / count;
    }

    struct LifecycleTimes {
        double create;
        double destroy;
    };

    template <typename Handle, typename Create, typename Destroy>
    LifecycleTimes measureLifecycle(Create create, Destroy destroy) {
        std::vector<Handle> handles(lifecycleCount);
        size_t created = 0;
        const auto start = Clock::now();

        while (created < handles.size() && create(&handles[created]) == FORGE_RT_OK) {
            ++created;
        }

        const auto middle = Clock::now();
        bool released = true;

        for (size_t i = 0; i < created; ++i) {
            released &= destroy(handles[i]) == FORGE_RT_OK;
        }

        const auto end = Clock::now();

        if (created != handles.size() || !released) {
            throw std::runtime_error("lifecycle operation failed");
        }

        return {nanoseconds(middle - start) / lifecycleCount,
                nanoseconds(end - middle) / lifecycleCount};
    }

    void printSamples(const char *name, Samples samples, bool pairs = false) {
        std::ranges::sort(samples);
        const double median = samples[sampleCount / 2];
        std::printf("%-18s %9.2f ns  [%.2f, %.2f]", name, median, samples.front(), samples.back());

        if (pairs) {
            std::printf("  %.2f ns/call (pair average)  %.2f M calls/s", median / 2, 2000 / median);
        }

        std::putchar('\n');
    }
} // namespace

int main() try {
    forge_rt_instance *runtime = nullptr;

    if (forge_rt_create(FORGE_RT_ABI_VERSION, &runtime) != FORGE_RT_OK) {
        throw std::runtime_error("runtime creation failed");
    }

    std::unique_ptr<forge_rt_instance, decltype(&forge_rt_destroy)> owner(runtime,
                                                                          forge_rt_destroy);
    forge_rt_thread_token thread = 0;

    if (forge_rt_thread_create(runtime, &thread) != FORGE_RT_OK) {
        throw std::runtime_error("thread creation failed");
    }

    uint32_t cell = 0;
    const auto direct = [&](uint32_t count) {
        return measurePairs<directSet, directGet>(count, &cell, thread);
    };
    const auto checked = [&](uint32_t count) {
        return measurePairs<forge_rt_set_last_error, forge_rt_get_last_error>(count, runtime,
                                                                              thread);
    };
    const auto runtimeLifecycle = [] {
        return measureLifecycle<forge_rt_instance *>(
            [](auto *out) { return forge_rt_create(FORGE_RT_ABI_VERSION, out); }, forge_rt_destroy);
    };
    const auto threadLifecycle = [&] {
        return measureLifecycle<forge_rt_thread_token>(
            [&](auto *out) { return forge_rt_thread_create(runtime, out); },
            [&](auto token) { return forge_rt_thread_destroy(runtime, token); });
    };

    direct(warmupPairs);
    checked(warmupPairs);
    runtimeLifecycle();
    threadLifecycle();
    Samples directTimes{}, checkedTimes{}, difference{}, runtimeCreate{}, runtimeDestroy{},
        threadCreate{}, threadDestroy{};

    for (size_t i = 0; i < sampleCount; ++i) {
        if (i % 2 == 0) {
            directTimes[i] = direct(timedPairs);
            checkedTimes[i] = checked(timedPairs);
        } else {
            checkedTimes[i] = checked(timedPairs);
            directTimes[i] = direct(timedPairs);
        }

        difference[i] = checkedTimes[i] - directTimes[i];
        const auto instances = runtimeLifecycle();
        const auto threads = threadLifecycle();
        runtimeCreate[i] = instances.create;
        runtimeDestroy[i] = instances.destroy;
        threadCreate[i] = threads.create;
        threadDestroy[i] = threads.destroy;
    }

    std::printf("%zu samples, %u warm-up pairs, %u timed pairs, %zu lifecycle objects per batch\n",
                sampleCount, warmupPairs, timedPairs, lifecycleCount);
    std::puts("Median [min, max] per pair or individual lifecycle operation");
    printSamples("direct set/get", directTimes, true);
    printSamples("runtime set/get", checkedTimes, true);
    printSamples("paired difference", difference);
    printSamples("runtime create", runtimeCreate);
    printSamples("runtime destroy", runtimeDestroy);
    printSamples("thread create", threadCreate);
    printSamples("thread destroy", threadDestroy);
    return 0;
} catch (const std::exception &error) {
    std::fprintf(stderr, "runtime benchmark: %s\n", error.what());
    return 1;
}
