#include "decimal_pairs.h"

// Each manifest selects one assembled leaf for its Windows driver and native lift.
extern int64_t FIXTURE_FUNCTION(int64_t left, int64_t right);

int main(int argc, char** argv) { return run_decimal_pairs(argc, argv, FIXTURE_FUNCTION); }
