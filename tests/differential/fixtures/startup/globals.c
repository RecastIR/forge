static volatile int initialized = 40;
static volatile int zero_initialized;

int main(void) {
    if (zero_initialized != 0 || initialized != 40) {
        return 1;
    }

    zero_initialized = 2;
    return initialized + zero_initialized;
}
