#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa,
               optimize("O2", "no-if-conversion", "no-if-conversion2", "align-loops=1",
                        "align-jumps=1", "align-labels=1"))) int64_t
cfg_counted_sum(int64_t left, int64_t right) {
    uint64_t n = (uint64_t)left & 31;
    int64_t sum = right & 255;
    for (uint64_t i = 0; i < n; ++i) {
        sum += (int64_t)i;
    }
    return sum;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, cfg_counted_sum); }
