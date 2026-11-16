#include "arithmetic/decimal_pairs.h"

// Distinct runtime operations keep this switch from becoming a table of return values.
__attribute__((dllexport, noipa,
               optimize("O2", "no-reorder-blocks-and-partition", "align-jumps=1",
                        "align-labels=1"))) int64_t
cfg_switch(int64_t index, int64_t value) {
    switch (index) {
    case 0:
        return value & 63;
    case 1:
        return value ^ 9;
    case 2:
        return value | 3;
    case 3:
        return ~value;
    case 4:
        return value == 0;
    case 5:
        return value < 0;
    case 6:
        return (int64_t)((uint64_t)value >> 2);
    default:
        return -17;
    }
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, cfg_switch); }
