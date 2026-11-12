#include "streams.h"
#include <inttypes.h>
#include <string.h>

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc != 2 || strlen(argv[1]) != 2 ||
        strspn(argv[1], "0123456789") != 2)
        return 2;

    const int a = 19 * (argv[1][0] - '0') - 111;
    const int b = argv[1][1] - '0' + 1;
    const uint32_t u = (uint32_t)a;
    const uint32_t mix = ((UINT32_C(0x9e3779b9) + u) * (uint32_t)b) ^ (u | UINT32_C(0xa55a));
    const uint32_t rotated = (mix << b) | (mix >> (32 - b));
    printf("sum=%d product=%d quotient=%d bits=%" PRIu32 "\n", a + b, (a - b) * b, a / b, rotated);
    return 0;
}
