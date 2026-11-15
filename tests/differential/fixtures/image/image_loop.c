#include "arithmetic/decimal_pairs.h"

static const uint16_t entries[] = {65535, 17, 32768, 9, 0, 3, 23, 42};

__attribute__((dllexport, noipa)) int64_t image_loop(int64_t a, int64_t b) {
    register unsigned count = (unsigned)a & 7U;
    register const volatile uint16_t *cursor = entries;
    register int64_t sum = b;
    while (count != 0) {
        sum += *cursor++;
        --count;
    }
    return sum;
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, image_loop); }
