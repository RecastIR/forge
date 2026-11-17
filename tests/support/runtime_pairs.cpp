#include "../differential/fixtures/arithmetic/operand.h"
#include "forge/runtime.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

// Match the generated entry symbol in the native C ABI.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int64_t forge_lifted_with_runtime(forge_rt_instance *, forge_rt_thread_token, int64_t,
                                             int64_t);

namespace {
    using Instance = std::unique_ptr<forge_rt_instance, decltype(&forge_rt_destroy)>;

    void checked(forge_rt_status status) {
        if (status != FORGE_RT_OK) {
            throw std::runtime_error("runtime ABI operation failed");
        }
    }

    Instance createInstance() {
        forge_rt_instance *runtime = nullptr;
        checked(forge_rt_create(1, &runtime));
        return {runtime, forge_rt_destroy};
    }

    forge_rt_thread_token createThread(const Instance &instance) {
        forge_rt_thread_token thread = 0;
        checked(forge_rt_thread_create(instance.get(), &thread));
        return thread;
    }

    int probe(const Instance &instance, forge_rt_thread_token thread, std::string_view mode,
              int64_t readOnly) {
        const auto other = createInstance();
        const auto foreign = createThread(other);
        if (mode == "isolation") {
            const auto second = createThread(instance);
            // Seed all three threads before reading any of them again.
            return !(forge_lifted_with_runtime(instance.get(), thread, 5, 0) == 5 &&
                     forge_lifted_with_runtime(instance.get(), second, 19, 0) == 19 &&
                     forge_lifted_with_runtime(other.get(), foreign, 31, 0) == 31 &&
                     forge_lifted_with_runtime(instance.get(), thread, 0, 1) == 5 &&
                     forge_lifted_with_runtime(instance.get(), second, 0, 1) == 19 &&
                     forge_lifted_with_runtime(other.get(), foreign, 0, 1) == 31);
        }

        auto *runtime = instance.get();
        if (mode == "retired") {
            checked(forge_rt_thread_destroy(runtime, thread));
        } else if (mode == "zero") {
            thread = 0;
        } else if (mode == "foreign") {
            thread = foreign;
        } else if (mode == "null") {
            runtime = nullptr;
        } else {
            return 2;
        }

        (void)forge_lifted_with_runtime(runtime, thread, 5, readOnly);
        return 1;
    }

    int benchmark(forge_rt_instance *instance, forge_rt_thread_token thread) {
        constexpr unsigned iterations = 100000;
        std::array<double, 9> samples{};
        for (unsigned batch = 0; batch <= samples.size(); ++batch) {
            uint64_t checksum = 0;
            const auto start = std::chrono::steady_clock::now();
            for (uint64_t i = 0; i < iterations; ++i) {
                checksum += static_cast<uint64_t>(
                    forge_lifted_with_runtime(instance, thread, static_cast<int64_t>(i), 0));
            }

            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (checksum != uint64_t(iterations) * (iterations - 1) / 2) {
                return 1;
            }

            if (batch) {
                samples[batch - 1] =
                    std::chrono::duration<double, std::nano>(elapsed).count() / iterations;
            }
        }

        std::ranges::sort(samples);
        std::printf("%.2f ns/entry (median), range %.2f..%.2f\n", samples[4], samples.front(),
                    samples.back());
        return 0;
    }

    int benchmarkFirstEntry() {
        constexpr unsigned count = 1024;
        std::array<double, 9> samples{};
        for (auto &sample : samples) {
            std::vector<std::pair<Instance, forge_rt_thread_token>> guests;
            guests.reserve(count);
            for (unsigned i = 0; i < count; ++i) {
                auto instance = createInstance();
                auto thread = createThread(instance);
                guests.emplace_back(std::move(instance), thread);
            }

            uint64_t checksum = 0;
            const auto start = std::chrono::steady_clock::now();
            for (const auto &[instance, thread] : guests) {
                checksum +=
                    static_cast<uint64_t>(forge_lifted_with_runtime(instance.get(), thread, 7, 0));
            }

            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (checksum != UINT64_C(7) * count) {
                return 1;
            }
            sample = std::chrono::duration<double, std::nano>(elapsed).count() / count;
        }

        std::ranges::sort(samples);
        std::printf("%.2f ns/first entry (median), range %.2f..%.2f\n", samples[4], samples.front(),
                    samples.back());
        return 0;
    }
} // namespace

int main(int argc, char **argv) try {
    const auto runtime = createInstance();
    const auto thread = createThread(runtime);
    if (argc == 2 && std::string_view(argv[1]) == "--benchmark") {
        return benchmark(runtime.get(), thread);
    }
    if (argc == 2 && std::string_view(argv[1]) == "--benchmark-first-entry") {
        return benchmarkFirstEntry();
    }

    if (argc == 4 && std::string_view(argv[1]) == "--probe") {
        return probe(runtime, thread, argv[2], std::string_view(argv[3]) == "get");
    }

    if (argc < 3 || argc % 2 == 0) {
        return 2;
    }

    std::vector<int64_t> operands(static_cast<size_t>(argc - 1));
    for (size_t i = 0; i < operands.size(); ++i) {
        if (!parse_operand(argv[i + 1], &operands[i])) {
            return 2;
        }
    }

    for (size_t i = 0; i < operands.size(); i += 2) {
        const auto result =
            forge_lifted_with_runtime(runtime.get(), thread, operands[i], operands[i + 1]);
        if (std::printf("%" PRId64 "\n", result) < 0) {
            return 1;
        }
    }

    checked(forge_rt_thread_destroy(runtime.get(), thread));
    return std::fflush(stdout) == 0 ? 0 : 1;
} catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
