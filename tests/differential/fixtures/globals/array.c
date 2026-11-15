#include "arithmetic/decimal_pairs.h"

static volatile uint32_t words[] = {0x01234567U, 0x89abcdefU, 0x10203040U, 0xa0b0c0d0U};

__attribute__((dllexport, noipa)) int64_t global_array(int64_t selector, int64_t value) {
    unsigned index = (unsigned)selector & 3U;
    unsigned lane = ((unsigned)selector >> 2) & 3U;
    volatile unsigned char *bytes = (volatile unsigned char *)&words[index];
    bytes[lane] = (unsigned char)value;
    return words[index];
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, global_array); }
