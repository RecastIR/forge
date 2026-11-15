#include "arithmetic/decimal_pairs.h"

static const uint32_t weights[] = {3, 7, 11, 19};

extern "C" __attribute__((dllexport, noipa)) int64_t global_static(int64_t index, int64_t rounds) {
    static volatile uint32_t total = 17;
    for (unsigned count = static_cast<unsigned>(rounds) & 3U; count != 0; --count) {
        total = total + weights[(static_cast<unsigned>(index) + count) & 3U];
    }
    return total;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, global_static); }
