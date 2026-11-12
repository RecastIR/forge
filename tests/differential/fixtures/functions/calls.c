#include "streams.h"
#include <string.h>

// Keep a real Windows x64 call with two arguments passed on the stack.
__attribute__((noinline)) unsigned combine(unsigned a, unsigned b, unsigned c, unsigned d,
                                           unsigned e, unsigned f) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f;
}

__attribute__((noinline)) unsigned descend(unsigned depth, unsigned seed) {
    if (depth == 0)
        return seed;
    const unsigned child = descend(depth - 1, seed + depth);
    return combine(seed, depth, child, seed ^ depth, child >> 1, seed + child);
}

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc != 2 || strlen(argv[1]) != 1 || argv[1][0] < '1' ||
        argv[1][0] > '6')
        return 2;
    printf("calls=%u\n", descend((unsigned)(argv[1][0] - '0'), 3));
    return 0;
}
