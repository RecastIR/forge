#include "streams.h"

static int score(char c) {
    if (c == '-') {
        return -7;
    }
    if (c >= '0' && c <= '9') {
        const int digit = c - '0';
        if (digit % 2 == 0) {
            return digit / 2;
        }
        return 3 * digit;
    }
    switch (c) {
    case 'A':
        return 11;
    case 'B':
        return -5;
    case 'C':
        return 8;
    default:
        return 3;
    }
}

int main(int argc, char **argv) {
    if (!open_binary_streams() || argc != 2) {
        return 2;
    }
    for (const char *c = argv[1]; *c; ++c) {
        printf("%d\n", score(*c));
    }
    return 0;
}
