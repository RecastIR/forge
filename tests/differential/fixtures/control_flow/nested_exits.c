#include "arithmetic/decimal_pairs.h"

__attribute__((dllexport, noipa,
               optimize("O2", "no-if-conversion", "no-if-conversion2", "align-loops=1",
                        "align-jumps=1", "align-labels=1"))) int64_t
cfg_nested_exits(int64_t left, int64_t right) {
    int64_t n = left & 31;
    int64_t sum = 0;
    if (right < 0) {
        return -7;
    }
    for (int64_t i = 0; i < n; ++i) {
        if (i == right) {
            return sum + 1000;
        }
        if ((i & 1) == 0) {
            sum += i + 7;
        } else {
            sum -= i;
        }
    }
    return sum;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, cfg_nested_exits); }
