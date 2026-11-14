#include "arithmetic/decimal_pairs.h"

static const uint32_t weights[] = {3, 7, 11, 19, 23, 29, 31, 37};

extern "C" __attribute__((dllexport, noipa)) int64_t lookup(int64_t index, int64_t multiplier) {
    return static_cast<int64_t>(weights[static_cast<uint64_t>(index) & 7]) * multiplier;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, lookup); }
