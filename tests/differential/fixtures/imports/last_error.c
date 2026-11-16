#include "arithmetic/operand.h"
#include "streams.h"
#include <stdlib.h>

extern int64_t last_error(int64_t value, int64_t mode);

int main(int argc, char **argv) {
    if (!open_binary_streams() || argc < 3 || argc % 2 == 0) {
        return 2;
    }
    int64_t *args = calloc((size_t)argc, sizeof(*args));
    if (!args) {
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        if (!parse_operand(argv[i], &args[i])) {
            free(args);
            return 2;
        }
    }
    // No CRT calls between guest invocations: a read-only invocation observes its predecessor.
    for (int i = 1; i < argc; i += 2) {
        args[i] = last_error(args[i], args[i + 1]);
    }
    for (int i = 1; i < argc; i += 2) {
        if (printf("%" PRId64 "\n", args[i]) < 0) {
            free(args);
            return 1;
        }
    }
    free(args);
    return fflush(stdout) == 0 ? 0 : 1;
}
