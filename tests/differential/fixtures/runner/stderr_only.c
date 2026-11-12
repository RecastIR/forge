#include "streams.h"

int main(void) {
    if (!open_binary_streams() || fputs("runner-error\n", stderr) == EOF || fflush(stderr) != 0) {
        return 1;
    }
    return 0;
}
