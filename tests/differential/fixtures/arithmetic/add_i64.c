#include "operand.h"
#include "streams.h"

// Keep a real, exported register-only leaf in both MinGW build configurations.
__attribute__((dllexport, noipa, optimize("O2"))) int64_t add_i64(int64_t left, int64_t right) {
    return left + right;
}

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc < 3 || argc % 2 == 0)
        return 2;
    for (int i = 1; i < argc; i += 2) {
        int64_t left, right;
        if (!parse_operand(argv[i], &left) || !parse_operand(argv[i + 1], &right))
            return 2;
        if (printf("%" PRId64 "\n", add_i64(left, right)) < 0)
            return 1;
    }
    return fflush(stdout) == 0 ? 0 : 1;
}
