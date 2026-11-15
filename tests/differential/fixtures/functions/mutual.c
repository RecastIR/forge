#include "arithmetic/decimal_pairs.h"

static __attribute__((noipa)) unsigned odd_step(unsigned depth, unsigned seed);

static __attribute__((noipa)) unsigned even_step(unsigned depth, unsigned seed) {
    if (depth == 0) {
        return seed;
    }

    return 1 + odd_step(depth - 1, seed + depth);
}

static __attribute__((noipa)) unsigned odd_step(unsigned depth, unsigned seed) {
    if (depth == 0) {
        return seed + 7;
    }

    return 2 + even_step(depth - 1, seed ^ depth);
}

__attribute__((dllexport, noipa)) int64_t call_mutual(int64_t depth, int64_t seed) {
    return (int64_t)even_step((unsigned)depth & 7U, (unsigned)seed);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, call_mutual); }
