#include "../differential/fixtures/arithmetic/operand.h"
#include "forge/runtime.h"

#include <cstdio>
#include <memory>

// NOLINTBEGIN(readability-identifier-naming)
extern "C" int64_t forge_lifted_with_runtime(forge_rt_instance *, forge_rt_thread_token, int64_t,
                                             int64_t);

extern "C" forge_rt_status marker_get_last_error(forge_rt_instance *instance,
                                                 forge_rt_thread_token thread, uint32_t *out) {
    std::fputs("M", stdout);
    std::fflush(stdout);
    return forge_rt_get_last_error(instance, thread, out);
}

// NOLINTEND(readability-identifier-naming)

int main(int argc, char **argv) {
    if (argc < 3 || argc % 2 == 0) {
        return 2;
    }

    forge_rt_instance *raw = nullptr;
    if (forge_rt_create(FORGE_RT_ABI_VERSION, &raw) != FORGE_RT_OK) {
        return 1;
    }

    const std::unique_ptr<forge_rt_instance, decltype(&forge_rt_destroy)> instance(
        raw, forge_rt_destroy);
    forge_rt_thread_token thread = 0;
    if (forge_rt_thread_create(raw, &thread) != FORGE_RT_OK) {
        return 1;
    }

    for (int i = 1; i < argc; i += 2) {
        int64_t mode = 0, selector = 0;
        if (!parse_operand(argv[i], &mode) || !parse_operand(argv[i + 1], &selector)) {
            return 2;
        }

        const auto result = forge_lifted_with_runtime(raw, thread, mode, selector);
        if (std::printf("%" PRId64 "\n", result) < 0) {
            return 1;
        }
    }

    return std::fflush(stdout) == 0 ? 0 : 1;
}
