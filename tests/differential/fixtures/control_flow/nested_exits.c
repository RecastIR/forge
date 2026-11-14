#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa,
               optimize("O2", "no-if-conversion", "no-if-conversion2", "align-loops=1",
                        "align-jumps=1", "align-labels=1"))) int64_t
cfg_nested_exits(int64_t left, int64_t right) {
    uint64_t outer = (uint64_t)left & 7;
    uint64_t inner = ((uint64_t)left >> 3) & 7;
    uint64_t sum = 0;
    if (right < 0) {
        return -7;
    }

    // At most 56 updates keep sum below 2^60, including the seven outer updates.
    for (uint64_t i = 0; i < outer; ++i) {
        sum = (sum << 1) ^ (i + 1);
        // Count the term i+j+1 directly so MinGW keeps the leaf in volatile registers.
        for (uint64_t term = i + 1; term <= i + inner; ++term) {
            sum = (sum << 1) ^ term;
            if (sum == (uint64_t)right) {
                return (int64_t)((sum << 2) | 1);
            }
        }

        if (i == (uint64_t)right) {
            return (int64_t)((sum << 2) | 2);
        }
    }

    return (int64_t)(sum << 2);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, cfg_nested_exits); }
