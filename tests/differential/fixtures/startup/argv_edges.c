#include <string.h>

int main(int argc, char **argv) {
    if (argc != 7 || !argv[0] || argv[argc] != NULL) {
        return 1;
    }

    const char *name = argv[0];
    for (const char *p = name; *p; ++p) {
        if (*p == '\\') {
            name = p + 1;
        }
    }
    if (strcmp(name, "crt_argv_edges.exe") != 0) {
        return 2;
    }

    const char *expected[] = {"",       "a\tb", "quoted\"value", "two\\\\\"quotes", "with space\\",
                              "plain\\"};
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], expected[i - 1]) != 0) {
            return 2 + i;
        }
    }
    return 42;
}
