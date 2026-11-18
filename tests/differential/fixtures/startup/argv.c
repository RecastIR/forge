#include <string.h>

static volatile int initialized = 40;
static volatile int zero_initialized;

int main(int argc, char **argv) {
    if (argc != 3) {
        return 1;
    }
    if (strcmp(argv[1], "hello world") != 0) {
        return 2;
    }
    if (strcmp(argv[2], "forge") != 0) {
        return 3;
    }
    if (zero_initialized != 0) {
        return 4;
    }

    zero_initialized = 2;
    return initialized + zero_initialized;
}
