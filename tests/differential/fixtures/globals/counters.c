#include "arithmetic/decimal_pairs.h"

static volatile uint32_t warm = 10;
static volatile uint32_t cold;

__attribute__((dllexport, noipa)) int64_t global_counters(int64_t selector, int64_t delta) {
    if (((uint64_t)selector & 1) == 0) {
        warm += (uint32_t)delta;
    } else {
        cold += (uint32_t)delta;
    }
    return (int64_t)(((uint64_t)warm << 32) | cold);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, global_counters); }
