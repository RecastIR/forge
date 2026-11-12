#include "decimal_pairs.h"

// Keep the signed comparison as a branch in both PE configurations.
__attribute__((dllexport, noipa, optimize("O2", "no-if-conversion", "no-if-conversion2"))) int64_t
weighted_pair_i64(int64_t left, int64_t right) {
    const int64_t weighted = 3 * (int64_t)(uint32_t)left;
    const int64_t term = (uint32_t)right;
    if (left < right)
        return weighted - term;
    return weighted + term;
}

int main(int argc, char** argv) { return run_decimal_pairs(argc, argv, weighted_pair_i64); }
