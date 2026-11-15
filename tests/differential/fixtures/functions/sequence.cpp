#include "arithmetic/decimal_pairs.h"

static volatile uint64_t counter = 10;

extern "C" __attribute__((noipa)) uint64_t increment(uint64_t delta) {
    volatile uint64_t local = counter + delta;
    counter = local;
    return local;
}

extern "C" __attribute__((noipa)) uint64_t pair(uint64_t a, const volatile uint64_t *b) {
    const uint64_t first = increment(a);
    return first + increment(*b);
}

extern "C" __attribute__((dllexport, noipa)) int64_t call_sequence(int64_t count, int64_t seed) {
    volatile uint64_t local = static_cast<uint64_t>(seed);
    const unsigned n = static_cast<unsigned>(count) & 3U;
    const volatile uint64_t bounded = n;
    uint64_t total = pair(local, &bounded);

    for (unsigned i = 0; i < n; ++i) {
        total += increment(local + i);
    }

    if (count < 0) {
        total += pair(n, &local);
    }

    return static_cast<int64_t>(total + counter);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, call_sequence); }
