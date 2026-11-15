#include "arithmetic/decimal_pairs.h"

static const int16_t entries[] = {-32768, 23, -1, 32767};

__attribute__((dllexport, noipa)) int64_t image_spill(int64_t a, int64_t b) {
    const int16_t *volatile slot;
    if (a < 0) {
        slot = &entries[2];
    } else {
        slot = &entries[0];
    }
    return slot[(uint64_t)b & 1];
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, image_spill); }
