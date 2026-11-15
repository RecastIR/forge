#include "arithmetic/decimal_pairs.h"

static volatile uint64_t counter = 10;
static volatile uint64_t *volatile current = &counter;

extern "C" __attribute__((dllexport, noipa)) int64_t global_pointer(int64_t delta, int64_t other) {
    volatile uint64_t *volatile saved = current;
    *saved = *saved + static_cast<uint64_t>(delta);
    counter = counter + static_cast<uint64_t>(other);
    return static_cast<int64_t>(*saved);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, global_pointer); }
