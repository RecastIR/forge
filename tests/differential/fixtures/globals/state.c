#include "streams.h"

static const unsigned weights[] = {3, 5, 11, 17};
static unsigned bias = 7;
static unsigned total;

static void advance(unsigned index) {
    static unsigned calls;
    bias += weights[index % 4];
    total += bias * ++calls;
}

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc != 2)
        return 2;
    for (const char* c = argv[1]; *c; ++c)
        advance((unsigned char)*c);
    printf("bias=%u total=%u\n", bias, total);
    return 0;
}
