#include "../differential/fixtures/arithmetic/operand.h"
#include <cinttypes>
#include <cstdio>

extern "C" std::int64_t forge_lifted(std::int64_t, std::int64_t);

int main(int argc, char** argv) {
    if (argc < 3 || argc % 2 == 0)
        return 2;
    for (int i = 1; i < argc; i += 2) {
        std::int64_t left, right;
        if (!parse_operand(argv[i], &left) || !parse_operand(argv[i + 1], &right))
            return 2;
        if (std::printf("%" PRId64 "\n", forge_lifted(left, right)) < 0)
            return 1;
    }
    return std::fflush(stdout) == 0 ? 0 : 1;
}
