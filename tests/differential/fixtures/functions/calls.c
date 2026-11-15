#ifdef CALL_PAIR_DRIVER
#include "arithmetic/decimal_pairs.h"
#else
#include "streams.h"
#include <string.h>
#endif

// Keep a real Windows x64 call with two arguments passed on the stack.
__attribute__((noinline)) unsigned combine(unsigned a, unsigned b, unsigned c, unsigned d,
                                           unsigned e, unsigned f) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f;
}

__attribute__((noinline)) unsigned descend(unsigned depth, unsigned seed) {
    if (depth == 0) {
        return seed;
    }
    const unsigned child = descend(depth - 1, seed + depth);
    return combine(seed, depth, child, seed ^ depth, child >> 1, seed + child);
}

#ifdef CALL_PAIR_DRIVER
__attribute__((dllexport, noipa)) int64_t call_recursive(int64_t depth, int64_t seed) {
    // An unsigned result is zero-extended for the two-argument native entry.
    return (int64_t)descend((unsigned)depth & 7U, (unsigned)seed);
}

int main(int argc, char **argv) { return run_decimal_pairs(argc, argv, call_recursive); }
#else
int main(int argc, char **argv) {
    if (!open_binary_streams() || argc != 2 || strlen(argv[1]) != 1 || argv[1][0] < '1' ||
        argv[1][0] > '6') {
        return 2;
    }
    printf("calls=%u\n", descend((unsigned)(argv[1][0] - '0'), 3));
    return 0;
}
#endif
