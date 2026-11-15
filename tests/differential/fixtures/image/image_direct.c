#include "arithmetic/decimal_pairs.h"

static const uint32_t bias = 0xfedcba98U;

__attribute__((dllexport, noipa)) int64_t image_direct(int64_t a, int64_t b) {
    return (int64_t)*(const volatile uint32_t *)&bias + a - b;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, image_direct); }
