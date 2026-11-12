#include "decimal_pairs.h"
#include <string.h>

__attribute__((dllexport, noipa, optimize("O2"))) int64_t integer_mix(int64_t left, int64_t right) {
    const uint64_t bits = (((uint64_t)left << 29) ^ (uint64_t)right) * (uint64_t)right;
    int64_t result;
    memcpy(&result, &bits, sizeof(result));
    return result;
}

int main(int argc, char** argv) { return run_decimal_pairs(argc, argv, integer_mix); }
