#pragma once

#include "operand.h"
#include "streams.h"

static inline int run_decimal_pairs(int argc, char** argv, int64_t (*function)(int64_t, int64_t)) {
    if (!open_binary_streams() || argc < 3 || argc % 2 == 0)
        return 2;
    for (int i = 1; i < argc; i += 2) {
        int64_t left, right;
        if (!parse_operand(argv[i], &left) || !parse_operand(argv[i + 1], &right))
            return 2;
        if (printf("%" PRId64 "\n", function(left, right)) < 0)
            return 1;
    }
    return fflush(stdout) == 0 ? 0 : 1;
}
