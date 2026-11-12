#include "decimal_pairs.h"

// Keep a real, exported register-only leaf in both MinGW build configurations.
__attribute__((dllexport, noipa, optimize("O2"))) int64_t add_i64(int64_t left, int64_t right) {
    return left + right;
}

int main(int argc, char** argv) { return run_decimal_pairs(argc, argv, add_i64); }
