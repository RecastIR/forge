#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa,
               optimize("O2", "no-if-conversion", "no-if-conversion2", "align-loops=1",
                        "align-jumps=1", "align-labels=1"))) int64_t
cfg_shift_loop(int64_t left, int64_t right) {
    uint64_t n = (uint64_t)left;
    int64_t iterations = 0;
    while (n > 1) {
        n >>= 1;
        ++iterations;
    }
    return iterations * 2 + (int64_t)n + (right & 1);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, cfg_shift_loop); }
